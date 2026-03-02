#include <Mortis/Config.hpp>
#include <Mortis/Detail/ImportHookImpl.hpp>
#include <Mortis/Platform/Win32Utils.hpp>

#include <string>
#include <string_view>

#include <Windows.h>

namespace Mortis::ImportHookImpl {

namespace {

auto FindImportDescriptor(HMODULE hModule, const std::string_view targetModule) -> IMAGE_IMPORT_DESCRIPTOR* {
    const auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(hModule);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    const auto  base = reinterpret_cast<std::uintptr_t>(hModule);
    const auto* nt   = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    const auto& [virtualAddress, size] = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (virtualAddress == 0) return nullptr;

    for (auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + virtualAddress); desc->Name != 0; ++desc) {
        if (auto* dllName = reinterpret_cast<const char*>(base + desc->Name);
            Win32Detail::CaseInsensitiveEqual(std::string_view(dllName), targetModule))
            return desc;
    }
    return nullptr;
}

} // anonymous namespace

auto PatchImportEntry(
    const std::string_view moduleName,
    const std::string_view importModule,
    const std::string_view functionName,
    void*                  newFunction,
    void**                 originalFunction
) -> Result<void> {
    HMODULE hMod = Win32Detail::ResolveModuleHandle(moduleName);
    if (!hMod) return Result<void>::Err(ErrorCode::ModuleNotFound, "Module not found");

    const auto* desc = FindImportDescriptor(hMod, importModule);
    if (!desc) return Result<void>::Err(ErrorCode::ImportNotFound, "Import descriptor not found");

    const auto base  = reinterpret_cast<std::uintptr_t>(hMod);
    auto*      thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->FirstThunk);

    for (auto* origThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->OriginalFirstThunk);
         origThunk->u1.AddressOfData != 0;
         ++origThunk, ++thunk) {
        if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal)) continue;

        auto* importByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + origThunk->u1.AddressOfData);
        if (std::string_view(importByName->Name) != functionName) continue;

        *originalFunction = reinterpret_cast<void*>(thunk->u1.Function);

        DWORD oldProtect = 0;
        if (!VirtualProtect(&thunk->u1.Function, sizeof(thunk->u1.Function), PAGE_EXECUTE_READWRITE, &oldProtect))
            return Result<void>::Err(ErrorCode::ProtectionFailed, "Failed to unprotect IAT entry");
        thunk->u1.Function = reinterpret_cast<ULONG_PTR>(newFunction);
        VirtualProtect(&thunk->u1.Function, sizeof(thunk->u1.Function), oldProtect, &oldProtect);
        return Result<void>::Ok();
    }
    return Result<void>::Err(ErrorCode::ImportNotFound, "Import entry not found");
}

auto UnpatchImportEntry(
    const std::string_view moduleName,
    const std::string_view importModule,
    const std::string_view functionName,
    void*                  originalFunction
) -> Result<void> {
    HMODULE hMod = Win32Detail::ResolveModuleHandle(moduleName);
    if (!hMod) return Result<void>::Err(ErrorCode::ModuleNotFound, "Module not found");

    const auto* desc = FindImportDescriptor(hMod, importModule);
    if (!desc) return Result<void>::Err(ErrorCode::ImportNotFound, "Import descriptor not found");

    const auto base  = reinterpret_cast<std::uintptr_t>(hMod);
    auto*      thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->FirstThunk);

    for (auto* origThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->OriginalFirstThunk);
         origThunk->u1.AddressOfData != 0;
         ++origThunk, ++thunk) {
        if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal)) continue;

        auto* importByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + origThunk->u1.AddressOfData);
        if (std::string_view(importByName->Name) != functionName) continue;

        DWORD oldProtect = 0;
        if (!VirtualProtect(&thunk->u1.Function, sizeof(thunk->u1.Function), PAGE_EXECUTE_READWRITE, &oldProtect))
            return Result<void>::Err(ErrorCode::ProtectionFailed, "Failed to unprotect IAT entry");
        thunk->u1.Function = reinterpret_cast<ULONG_PTR>(originalFunction);
        VirtualProtect(&thunk->u1.Function, sizeof(thunk->u1.Function), oldProtect, &oldProtect);
        return Result<void>::Ok();
    }
    return Result<void>::Err(ErrorCode::ImportNotFound, "Import entry not found");
}

} // namespace Mortis::ImportHookImpl
