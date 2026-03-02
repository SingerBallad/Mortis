#include <Mortis/Process.hpp>

#include <Mortis/Platform/Win32Utils.hpp>

#include <algorithm>
#include <array>
#include <string>
#include <utility>

// clang-format off
#include <Windows.h>
#include <Psapi.h>
// clang-format on

#pragma comment(lib, "Psapi.lib")

namespace Mortis {

auto Process::Self() -> Process& {
    static Process instance;
    return instance;
}

auto Process::FindModule(std::string_view moduleName) -> std::optional<Module> {
    HMODULE hMod = Win32Detail::ResolveModuleHandle(moduleName);
    if (!hMod) return std::nullopt;

    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), hMod, &mi, sizeof(mi))) return std::nullopt;

    auto path = Win32Detail::QueryModulePath(hMod);
    if (path.empty()) path = "main";
    return Module(std::move(path), reinterpret_cast<Address>(mi.lpBaseOfDll), mi.SizeOfImage);
}

auto Process::EnumerateModules() -> std::vector<Module> {
    std::vector<Module> result;
    std::array<HMODULE, 1024> mods{};
    DWORD                      needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), mods.data(), sizeof(mods), &needed)) return result;

    const auto count = std::min<std::size_t>(mods.size(), needed / sizeof(HMODULE));
    for (std::size_t i = 0; i < count; ++i) {
        MODULEINFO mi{};
        if (!GetModuleInformation(GetCurrentProcess(), mods[i], &mi, sizeof(mi))) continue;
        auto path = Win32Detail::QueryModulePath(mods[i]);
        if (path.empty()) path = "unknown";
        result.emplace_back(std::move(path), reinterpret_cast<Address>(mi.lpBaseOfDll), mi.SizeOfImage);
    }
    return result;
}

auto Process::ReadMemory(void* dest, const Address source, const std::size_t size) -> Result<void> {
    if (size == 0) return Result<void>::Ok();
    const auto mbi = Win32Detail::QueryRegion(source);
    if (!mbi || !Win32Detail::IsCommitted(*mbi) || !Win32Detail::IsReadableProtection(mbi->Protect)
        || !Win32Detail::RegionCoversRange(*mbi, source, size))
        return Result<void>::Err(ErrorCode::MemoryNotReadable, "Memory at address is not readable");
    auto* src = reinterpret_cast<const std::uint8_t*>(source);
    std::copy_n(src, size, static_cast<std::uint8_t*>(dest));
    return Result<void>::Ok();
}

auto Process::WriteMemory(const Address dest, const void* source, const std::size_t size) -> Result<void> {
    if (size == 0) return Result<void>::Ok();
    const auto mbi      = Win32Detail::QueryRegion(dest);
    const bool writable =
        mbi && Win32Detail::IsCommitted(*mbi) && Win32Detail::IsWritableProtection(mbi->Protect)
        && Win32Detail::RegionCoversRange(*mbi, dest, size);

    if (writable) {
        auto* src = static_cast<const std::uint8_t*>(source);
        std::copy_n(src, size, reinterpret_cast<std::uint8_t*>(dest));
        return Result<void>::Ok();
    }

    DWORD oldProtect = 0;
    if (!VirtualProtect(reinterpret_cast<void*>(dest), size, PAGE_EXECUTE_READWRITE, &oldProtect))
        return Result<void>::Err(ErrorCode::ProtectionFailed, "Failed to change memory protection for write");

    auto* src = static_cast<const std::uint8_t*>(source);
    std::copy_n(src, size, reinterpret_cast<std::uint8_t*>(dest));
    VirtualProtect(reinterpret_cast<void*>(dest), size, oldProtect, &oldProtect);
    return Result<void>::Ok();
}

auto Process::SetProtection(const Address address, const std::size_t size, const MemoryProtection newProtection)
    -> Result<MemoryProtection> {
    DWORD oldProtect = 0;
    if (!VirtualProtect(reinterpret_cast<void*>(address), size, Win32Detail::ToNativeProtection(newProtection), &oldProtect))
        return Result<MemoryProtection>::Err(ErrorCode::ProtectionFailed, "VirtualProtect failed");
    return Result<MemoryProtection>::Ok(Win32Detail::FromNativeProtection(oldProtect));
}

auto Process::SetProtectionRaw(const Address address, const std::size_t size, const MemoryProtection newProtection)
    -> Result<void> {
    DWORD oldProtect = 0;
    if (!VirtualProtect(reinterpret_cast<void*>(address), size, Win32Detail::ToNativeProtection(newProtection), &oldProtect))
        return Result<void>::Err(ErrorCode::ProtectionFailed, "VirtualProtect failed");
    return Result<void>::Ok();
}

auto Process::QueryProtection(const Address address) -> Result<MemoryProtection> {
    const auto mbi = Win32Detail::QueryRegion(address);
    if (!mbi)
        return Result<MemoryProtection>::Err(ErrorCode::ProtectionFailed, "VirtualQuery failed");
    return Result<MemoryProtection>::Ok(Win32Detail::FromNativeProtection(mbi->Protect));
}

auto Process::IsReadable(const Address address, const std::size_t size) -> bool {
    const auto mbi = Win32Detail::QueryRegion(address);
    return mbi && Win32Detail::IsCommitted(*mbi) && Win32Detail::IsReadableProtection(mbi->Protect)
        && Win32Detail::RegionCoversRange(*mbi, address, size);
}

auto Process::IsWritable(const Address address, const std::size_t size) -> bool {
    const auto mbi = Win32Detail::QueryRegion(address);
    return mbi && Win32Detail::IsCommitted(*mbi) && Win32Detail::IsWritableProtection(mbi->Protect)
        && Win32Detail::RegionCoversRange(*mbi, address, size);
}

auto Module::findExport(const std::string_view symbolName) const -> std::optional<Address> {
    const auto  hMod = reinterpret_cast<HMODULE>(base_);
    auto* proc = GetProcAddress(hMod, std::string(symbolName).c_str());
    if (!proc) return std::nullopt;
    return reinterpret_cast<Address>(proc);
}

auto Module::enumerateExports() const -> std::unordered_map<std::string, Address> {
    std::unordered_map<std::string, Address> result;

    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base_);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return result;

    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base_ + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return result;

    const auto& [virtualAddress, size] = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (virtualAddress == 0) return result;

    auto* exports   = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(base_ + virtualAddress);
    auto* names     = reinterpret_cast<const DWORD*>(base_ + exports->AddressOfNames);
    auto* ordinals  = reinterpret_cast<const WORD*>(base_ + exports->AddressOfNameOrdinals);
    auto* functions = reinterpret_cast<const DWORD*>(base_ + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; ++i) {
        auto* name = reinterpret_cast<const char*>(base_ + names[i]);
        auto  addr = base_ + functions[ordinals[i]];
        result.emplace(std::string(name), addr);
    }
    return result;
}

auto Module::findSection(const std::string_view sectionName) const -> std::optional<std::pair<Address, std::size_t>> {
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base_);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return std::nullopt;

    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base_ + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return std::nullopt;

    auto* section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        const std::string_view secName(
            reinterpret_cast<const char*>(section->Name),
            strnlen(reinterpret_cast<const char*>(section->Name), 8)
        );
        if (sectionName == secName) {
            return std::pair{base_ + section->VirtualAddress, static_cast<std::size_t>(section->Misc.VirtualSize)};
        }
    }
    return std::nullopt;
}

} // namespace Mortis
