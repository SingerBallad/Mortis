#include <Mortis/Inject.hpp>

#ifdef MORTIS_OS_WINDOWS

#include <Mortis/Config.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// clang-format off
#include <Windows.h>
#include <Psapi.h>
#include <intsafe.h>
// clang-format on

namespace Mortis {
namespace {
// Portions of the import-table and .detour payload handling are derived from
// Microsoft Detours 4.x, which is distributed under the MIT license.

constexpr DWORD kMaxSupportedImageSections = 32;
constexpr DWORD kDetourSectionSignature    = 0x00727444; // "Dtr\0"

constexpr GUID kExeRestoreGuid = {
    0xbda26f34,
    0xbc82,
    0x4829,
    {0x9e, 0x64, 0x74, 0x2c, 0x04, 0xc8, 0x4f, 0xa0}
};

constexpr DWORD kRemoteThreadAccess =
    PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;

#ifdef MORTIS_ARCH_X64
constexpr WORD kSupportedMachine = IMAGE_FILE_MACHINE_AMD64;
#elif defined(MORTIS_ARCH_ARM64)
constexpr WORD kSupportedMachine = IMAGE_FILE_MACHINE_ARM64;
#else
constexpr WORD kSupportedMachine = 0;
#endif

#pragma pack(push, 8)
struct DetourSectionHeader {
    DWORD cbHeaderSize = 0;
    DWORD nSignature   = 0;
    DWORD nDataOffset  = 0;
    DWORD cbDataSize   = 0;

    DWORD nOriginalImportVirtualAddress      = 0;
    DWORD nOriginalImportSize                = 0;
    DWORD nOriginalBoundImportVirtualAddress = 0;
    DWORD nOriginalBoundImportSize           = 0;

    DWORD nOriginalIatVirtualAddress = 0;
    DWORD nOriginalIatSize           = 0;
    DWORD nOriginalSizeOfImage       = 0;
    DWORD cbPrePE                    = 0;

    DWORD nOriginalClrFlags = 0;
    DWORD reserved1         = 0;
    DWORD reserved2         = 0;
    DWORD reserved3         = 0;
};

struct DetourSectionRecord {
    DWORD cbBytes   = 0;
    DWORD nReserved = 0;
    GUID  guid{};
};

struct DetourClrHeader {
    ULONG                cb                  = 0;
    USHORT               MajorRuntimeVersion = 0;
    USHORT               MinorRuntimeVersion = 0;
    IMAGE_DATA_DIRECTORY MetaData{};
    ULONG                Flags = 0;
};

struct ExeRestore {
    DWORD cb    = 0;
    DWORD cbidh = 0;
    DWORD cbinh = 0;
    DWORD cbclr = 0;

    PBYTE pidh = nullptr;
    PBYTE pinh = nullptr;
    PBYTE pclr = nullptr;

    IMAGE_DOS_HEADER idh{};

    union {
        IMAGE_NT_HEADERS64 inh64;
        BYTE               raw[sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER) * kMaxSupportedImageSections];
    };

    DetourClrHeader clr{};
};
#pragma pack(pop)

struct RemotePayload {
    void* address = nullptr;
    DWORD size    = 0;
};

struct UniqueHandle {
    HANDLE handle = nullptr;

    UniqueHandle() noexcept = default;
    explicit UniqueHandle(HANDLE value) noexcept : handle(value) {}
    UniqueHandle(const UniqueHandle&)                    = delete;
    auto operator=(const UniqueHandle&) -> UniqueHandle& = delete;

    UniqueHandle(UniqueHandle&& other) noexcept : handle(std::exchange(other.handle, nullptr)) {}

    auto operator=(UniqueHandle&& other) noexcept -> UniqueHandle& {
        if (this != &other) {
            reset();
            handle = std::exchange(other.handle, nullptr);
        }
        return *this;
    }

    ~UniqueHandle() { reset(); }

    [[nodiscard]] explicit operator bool() const noexcept {
        return handle != nullptr && handle != INVALID_HANDLE_VALUE;
    }

    [[nodiscard]] auto get() const noexcept -> HANDLE { return handle; }

    [[nodiscard]] auto release() noexcept -> HANDLE { return std::exchange(handle, nullptr); }

    void reset(HANDLE value = nullptr) noexcept {
        if (handle != nullptr && handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
        handle = value;
    }
};

struct RemoteAllocation {
    HANDLE process = nullptr;
    void*  address = nullptr;

    RemoteAllocation() noexcept = default;
    RemoteAllocation(HANDLE proc, void* addr) noexcept : process(proc), address(addr) {}
    RemoteAllocation(const RemoteAllocation&)                    = delete;
    auto operator=(const RemoteAllocation&) -> RemoteAllocation& = delete;

    RemoteAllocation(RemoteAllocation&& other) noexcept
    : process(std::exchange(other.process, nullptr)),
      address(std::exchange(other.address, nullptr)) {}

    auto operator=(RemoteAllocation&& other) noexcept -> RemoteAllocation& {
        if (this != &other) {
            reset();
            process = std::exchange(other.process, nullptr);
            address = std::exchange(other.address, nullptr);
        }
        return *this;
    }

    ~RemoteAllocation() { reset(); }

    [[nodiscard]] auto get() const noexcept -> void* { return address; }

    [[nodiscard]] auto release() noexcept -> void* {
        process = nullptr;
        return std::exchange(address, nullptr);
    }

    void reset() noexcept {
        if (process != nullptr && address != nullptr) VirtualFreeEx(process, address, 0, MEM_RELEASE);
        process = nullptr;
        address = nullptr;
    }
};

[[nodiscard]] auto LastErrorMessage(const ErrorCode code, const std::string_view action) -> ErrorInfo {
    return ErrorInfo{code, std::string(action) + " failed (GetLastError=" + std::to_string(GetLastError()) + ")"};
}

template <typename T>
[[nodiscard]] auto ErrWin32(const ErrorCode code, const std::string_view action) -> Result<T> {
    return Result<T>(std::unexpected(LastErrorMessage(code, action)));
}

[[nodiscard]] auto ErrWin32Void(const ErrorCode code, const std::string_view action) -> Result<void> {
    return Result<void>(std::unexpected(LastErrorMessage(code, action)));
}

[[nodiscard]] auto GuidEqual(const GUID& left, const GUID& right) noexcept -> bool {
    return left.Data1 == right.Data1 && left.Data2 == right.Data2 && left.Data3 == right.Data3
        && std::equal(std::begin(left.Data4), std::end(left.Data4), std::begin(right.Data4));
}

[[nodiscard]] auto CaseInsensitiveEqual(const std::wstring_view left, const std::wstring_view right) -> bool {
    return left.size() == right.size()
        && CompareStringOrdinal(
               left.data(),
               static_cast<int>(left.size()),
               right.data(),
               static_cast<int>(right.size()),
               TRUE
           ) == CSTR_EQUAL;
}

[[nodiscard]] auto FileNameOf(const std::wstring_view path) -> std::wstring_view {
    const auto pos = path.find_last_of(L"\\/");
    return pos == std::wstring_view::npos ? path : path.substr(pos + 1);
}

[[nodiscard]] auto AbsolutePath(const std::filesystem::path& path) -> Result<std::filesystem::path> {
    if (path.empty()) return Result<std::filesystem::path>::Err(ErrorCode::InvalidArgument, "DLL path is empty");

    std::error_code ec;
    auto            absolute = std::filesystem::absolute(path, ec);
    if (ec) return Result<std::filesystem::path>::Err(ErrorCode::InvalidArgument, "Cannot make path absolute");

    if (!std::filesystem::exists(absolute, ec) || ec)
        return Result<std::filesystem::path>::Err(ErrorCode::InvalidArgument, "DLL path does not exist");

    return Result<std::filesystem::path>::Ok(std::move(absolute));
}

[[nodiscard]] auto WideToAnsiStrict(const std::wstring& wide) -> Result<std::string> {
    if (wide.empty()) return Result<std::string>::Err(ErrorCode::InvalidArgument, "String is empty");

    BOOL      usedDefaultChar = FALSE;
    const int size =
        WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, wide.c_str(), -1, nullptr, 0, nullptr, &usedDefaultChar);
    if (size <= 1 || usedDefaultChar)
        return Result<std::string>::Err(ErrorCode::InvalidArgument, "Path cannot be represented in the ANSI code page");

    std::string out(static_cast<std::size_t>(size - 1), '\0');
    usedDefaultChar   = FALSE;
    const int written = WideCharToMultiByte(
        CP_ACP,
        WC_NO_BEST_FIT_CHARS,
        wide.c_str(),
        -1,
        out.data(),
        size,
        nullptr,
        &usedDefaultChar
    );
    if (written != size || usedDefaultChar)
        return Result<std::string>::Err(ErrorCode::InvalidArgument, "Path cannot be represented in the ANSI code page");

    return Result<std::string>::Ok(std::move(out));
}

template <typename T>
[[nodiscard]] auto ReadRemote(HANDLE process, const void* address, T& value) -> bool {
    SIZE_T bytesRead = 0;
    return ReadProcessMemory(process, address, &value, sizeof(T), &bytesRead) && bytesRead == sizeof(T);
}

[[nodiscard]] auto ReadRemoteBytes(HANDLE process, const void* address, void* buffer, const std::size_t size) -> bool {
    SIZE_T bytesRead = 0;
    return ReadProcessMemory(process, address, buffer, size, &bytesRead) && bytesRead == size;
}

[[nodiscard]] auto WriteRemoteBytes(HANDLE process, void* address, const void* buffer, const std::size_t size) -> bool {
    SIZE_T bytesWritten = 0;
    return WriteProcessMemory(process, address, buffer, size, &bytesWritten) && bytesWritten == size;
}

[[nodiscard]] auto PageProtectAdjustExecute(const DWORD oldProtect, DWORD newProtect) -> DWORD {
    constexpr DWORD kExecuteMask   = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    constexpr DWORD kAttributeMask = PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE;

    if ((oldProtect & kExecuteMask) != 0) {
        if ((newProtect & kExecuteMask) == 0) newProtect = (newProtect << 4) | (newProtect & kAttributeMask);
    } else if ((newProtect & kExecuteMask) != 0) {
        newProtect = ((newProtect & kExecuteMask) >> 4) | (newProtect & kAttributeMask);
    }
    return newProtect;
}

[[nodiscard]] auto
ProtectSameExecute(HANDLE process, void* address, const SIZE_T size, const DWORD protect, DWORD& oldProtect) -> bool {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQueryEx(process, address, &mbi, sizeof(mbi)) == 0) return false;
    return VirtualProtectEx(process, address, size, PageProtectAdjustExecute(mbi.Protect, protect), &oldProtect);
}

[[nodiscard]] auto IsReadableRegion(const MEMORY_BASIC_INFORMATION& mbi) -> bool {
    return mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0;
}

[[nodiscard]] auto LocalRangeReadable(const void* address, const std::size_t size) -> bool {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(address, &mbi, sizeof(mbi)) == 0 || !IsReadableRegion(mbi)) return false;

    const auto regionStart = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
    const auto regionEnd   = regionStart + mbi.RegionSize;
    const auto rangeStart  = reinterpret_cast<std::uintptr_t>(address);
    const auto rangeEnd    = rangeStart + size;
    return rangeEnd > rangeStart && rangeStart >= regionStart && rangeEnd <= regionEnd;
}

[[nodiscard]] auto
LoadNtHeaderFromProcess(HANDLE process, HMODULE module, IMAGE_NT_HEADERS64& ntHeader, void** remoteNtHeader = nullptr)
    -> bool {
    ntHeader = {};
    if (remoteNtHeader != nullptr) *remoteNtHeader = nullptr;
    if (module == nullptr) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQueryEx(process, module, &mbi, sizeof(mbi)) == 0 || !IsReadableRegion(mbi)) return false;

    IMAGE_DOS_HEADER dos{};
    if (!ReadRemote(process, module, dos)) return false;

    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < static_cast<LONG>(sizeof(dos))
        || static_cast<std::uint64_t>(dos.e_lfanew) > mbi.RegionSize) {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return false;
    }

    auto  ntAddress = reinterpret_cast<std::uintptr_t>(module) + dos.e_lfanew;
    auto* ntPtr     = reinterpret_cast<void*>(ntAddress);
    if (!ReadRemote(process, ntPtr, ntHeader)) return false;
    if (ntHeader.Signature != IMAGE_NT_SIGNATURE) {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return false;
    }

    if (remoteNtHeader != nullptr) *remoteNtHeader = ntPtr;
    return true;
}

struct RemoteModuleEntry {
    HMODULE            module         = nullptr;
    IMAGE_NT_HEADERS64 ntHeader       = {};
    void*              remoteNtHeader = nullptr;
};


[[nodiscard]] auto ScanRemoteModules(HANDLE process) -> std::vector<RemoteModuleEntry> {
    std::vector<RemoteModuleEntry> entries;
    MEMORY_BASIC_INFORMATION       mbi{};

    // 0x10000: first valid address past the Windows null-pointer guard region.
    auto cursor = std::uintptr_t{0x10000};

    for (;;) {
        if (VirtualQueryEx(process, reinterpret_cast<void*>(cursor), &mbi, sizeof(mbi)) == 0) break;
        if ((mbi.RegionSize & 0xfff) == 0xfff) break;

        auto regionEnd = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (regionEnd <= cursor) break;
        cursor = regionEnd;

        if (!IsReadableRegion(mbi)) continue;

        RemoteModuleEntry entry{};
        entry.module = static_cast<HMODULE>(mbi.BaseAddress);
        if (LoadNtHeaderFromProcess(process, entry.module, entry.ntHeader, &entry.remoteNtHeader))
            entries.push_back(entry);
    }

    return entries;
}

[[nodiscard]] auto FindMainModuleInProcess(HANDLE process) -> Result<HMODULE> {
    HMODULE exe = nullptr;
    for (const auto& entry : ScanRemoteModules(process)) {
        if ((entry.ntHeader.FileHeader.Characteristics & IMAGE_FILE_DLL) == 0) exe = entry.module;
    }

    if (exe == nullptr) return Result<HMODULE>::Err(ErrorCode::ProcessInjectFailed, "Main executable module not found");
    return Result<HMODULE>::Ok(exe);
}

[[nodiscard]] auto FindDetourSectionInRemoteModule(
    HANDLE                    process,
    HMODULE                   module,
    const IMAGE_NT_HEADERS64& ntHeader,
    void*                     remoteNtHeader
) -> void* {
    if (ntHeader.FileHeader.SizeOfOptionalHeader == 0) {
        SetLastError(ERROR_EXE_MARKED_INVALID);
        return nullptr;
    }

    auto sectionBase = reinterpret_cast<std::uintptr_t>(remoteNtHeader) + sizeof(ntHeader.Signature)
                     + sizeof(ntHeader.FileHeader) + ntHeader.FileHeader.SizeOfOptionalHeader;

    for (DWORD i = 0; i < ntHeader.FileHeader.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER section{};
        auto*                sectionAddr = reinterpret_cast<void*>(sectionBase + sizeof(section) * i);
        if (!ReadRemote(process, sectionAddr, section)) return nullptr;
        if (std::memcmp(section.Name, ".detour", sizeof(section.Name)) != 0) continue;
        if (section.VirtualAddress == 0 || section.SizeOfRawData == 0) break;
        SetLastError(NO_ERROR);
        return reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(module) + section.VirtualAddress);
    }

    SetLastError(ERROR_EXE_MARKED_INVALID);
    return nullptr;
}

[[nodiscard]] auto FindPayloadInRemoteDetourSection(HANDLE process, const GUID& guid, void* remoteDetourSection)
    -> Result<RemotePayload> {
    auto* data = static_cast<std::uint8_t*>(remoteDetourSection);

    DetourSectionHeader header{};
    if (!ReadRemote(process, data, header))
        return ErrWin32<RemotePayload>(ErrorCode::RemoteMemoryFailed, "ReadProcessMemory");

    if (header.cbHeaderSize < sizeof(DetourSectionHeader) || header.nSignature != kDetourSectionSignature
        || header.cbDataSize < header.cbHeaderSize) {
        return Result<RemotePayload>::Err(ErrorCode::PayloadInvalid, "Invalid .detour section header");
    }

    if (header.nDataOffset == 0) header.nDataOffset = header.cbHeaderSize;
    if (header.nDataOffset < header.cbHeaderSize || header.nDataOffset >= header.cbDataSize)
        return Result<RemotePayload>::Err(ErrorCode::PayloadInvalid, "Invalid .detour payload offset");

    DWORD offset = header.nDataOffset;
    while (offset + sizeof(DetourSectionRecord) <= header.cbDataSize) {
        DetourSectionRecord record{};
        if (!ReadRemote(process, data + offset, record))
            return ErrWin32<RemotePayload>(ErrorCode::RemoteMemoryFailed, "ReadProcessMemory");

        if (record.cbBytes < sizeof(record) || offset + record.cbBytes > header.cbDataSize)
            return Result<RemotePayload>::Err(ErrorCode::PayloadInvalid, "Invalid .detour payload record");

        if (GuidEqual(record.guid, guid)) {
            SetLastError(NO_ERROR);
            return Result<RemotePayload>::Ok(
                RemotePayload{data + offset + sizeof(record), record.cbBytes - static_cast<DWORD>(sizeof(record))}
            );
        }
        offset += record.cbBytes;
    }

    return Result<RemotePayload>::Err(ErrorCode::PayloadNotFound, "Payload not found");
}

[[maybe_unused]] [[nodiscard]] auto FindRemotePayload(HANDLE process, const GUID& guid) -> Result<RemotePayload> {
    if (process == nullptr) return Result<RemotePayload>::Err(ErrorCode::InvalidArgument, "Process handle is null");

    for (const auto& entry : ScanRemoteModules(process)) {
        auto* detourSection =
            FindDetourSectionInRemoteModule(process, entry.module, entry.ntHeader, entry.remoteNtHeader);
        if (detourSection == nullptr) continue;
        auto payload = FindPayloadInRemoteDetourSection(process, guid, detourSection);
        if (payload) return payload;
    }

    return Result<RemotePayload>::Err(ErrorCode::PayloadNotFound, "Payload not found");
}

[[nodiscard]] auto CopyPayloadToProcess(HANDLE process, const GUID& guid, const void* payload, const DWORD payloadSize)
    -> Result<void*> {
    if (process == nullptr) return Result<void*>::Err(ErrorCode::InvalidArgument, "Process handle is null");
    if (payload == nullptr && payloadSize != 0)
        return Result<void*>::Err(ErrorCode::InvalidArgument, "Payload is null");

    const DWORD totalSize = sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER)
                          + sizeof(DetourSectionHeader) + sizeof(DetourSectionRecord) + payloadSize;

    auto* base = static_cast<std::uint8_t*>(
        VirtualAllocEx(process, nullptr, totalSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
    );
    if (base == nullptr) return ErrWin32<void*>(ErrorCode::RemoteMemoryFailed, "VirtualAllocEx");

    RemoteAllocation allocation(process, base);
    auto*            cursor = base;

    IMAGE_DOS_HEADER dos{};
    dos.e_magic  = IMAGE_DOS_SIGNATURE;
    dos.e_lfanew = sizeof(dos);
    if (!WriteRemoteBytes(process, cursor, &dos, sizeof(dos)))
        return ErrWin32<void*>(ErrorCode::RemoteMemoryFailed, "WriteProcessMemory");
    cursor += sizeof(dos);

    IMAGE_NT_HEADERS64 nt{};
    nt.Signature                       = IMAGE_NT_SIGNATURE;
    nt.FileHeader.Machine              = kSupportedMachine;
    nt.FileHeader.NumberOfSections     = 1;
    nt.FileHeader.SizeOfOptionalHeader = sizeof(nt.OptionalHeader);
    nt.FileHeader.Characteristics      = IMAGE_FILE_DLL;
    nt.OptionalHeader.Magic            = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt.OptionalHeader.SizeOfImage      = totalSize;
    if (!WriteRemoteBytes(process, cursor, &nt, sizeof(nt)))
        return ErrWin32<void*>(ErrorCode::RemoteMemoryFailed, "WriteProcessMemory");
    cursor += sizeof(nt);

    IMAGE_SECTION_HEADER section{};
    std::memcpy(section.Name, ".detour", sizeof(section.Name));
    section.VirtualAddress = static_cast<DWORD>((cursor + sizeof(section)) - base);
    section.SizeOfRawData  = sizeof(DetourSectionHeader) + sizeof(DetourSectionRecord) + payloadSize;
    if (!WriteRemoteBytes(process, cursor, &section, sizeof(section)))
        return ErrWin32<void*>(ErrorCode::RemoteMemoryFailed, "WriteProcessMemory");
    cursor += sizeof(section);

    DetourSectionHeader detourHeader{};
    detourHeader.cbHeaderSize = sizeof(detourHeader);
    detourHeader.nSignature   = kDetourSectionSignature;
    detourHeader.nDataOffset  = sizeof(DetourSectionHeader);
    detourHeader.cbDataSize   = sizeof(DetourSectionHeader) + sizeof(DetourSectionRecord) + payloadSize;
    if (!WriteRemoteBytes(process, cursor, &detourHeader, sizeof(detourHeader)))
        return ErrWin32<void*>(ErrorCode::RemoteMemoryFailed, "WriteProcessMemory");
    cursor += sizeof(detourHeader);

    DetourSectionRecord record{};
    record.cbBytes = sizeof(record) + payloadSize;
    record.guid    = guid;
    if (!WriteRemoteBytes(process, cursor, &record, sizeof(record)))
        return ErrWin32<void*>(ErrorCode::RemoteMemoryFailed, "WriteProcessMemory");
    cursor += sizeof(record);

    if (payloadSize != 0 && !WriteRemoteBytes(process, cursor, payload, payloadSize))
        return ErrWin32<void*>(ErrorCode::RemoteMemoryFailed, "WriteProcessMemory");

    (void)allocation.release();
    SetLastError(NO_ERROR);
    return Result<void*>::Ok(cursor);
}

[[nodiscard]] auto FindDetourSectionInLocalModule(HMODULE module) -> void* {
    auto* base = reinterpret_cast<std::uint8_t*>(module);
    if (!LocalRangeReadable(base, sizeof(IMAGE_DOS_HEADER))) return nullptr;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    if (dos->e_lfanew < static_cast<LONG>(sizeof(IMAGE_DOS_HEADER))) return nullptr;
    if (!LocalRangeReadable(base + dos->e_lfanew, sizeof(IMAGE_NT_HEADERS64))) return nullptr;

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    if (!LocalRangeReadable(IMAGE_FIRST_SECTION(nt), nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)))
        return nullptr;

    auto* section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        if (std::memcmp(section->Name, ".detour", sizeof(section->Name)) == 0 && section->VirtualAddress != 0
            && section->SizeOfRawData != 0) {
            return base + section->VirtualAddress;
        }
    }
    return nullptr;
}


[[nodiscard]] auto ScanLocalModules() -> std::vector<HMODULE> {
    std::vector<HMODULE>     modules;
    MEMORY_BASIC_INFORMATION mbi{};
    auto                     cursor = std::uintptr_t{0x10000};

    while (VirtualQuery(reinterpret_cast<void*>(cursor), &mbi, sizeof(mbi)) != 0) {
        if ((mbi.RegionSize & 0xfff) == 0xfff) break;

        auto regionEnd = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (regionEnd <= cursor) break;
        cursor = regionEnd;

        if (!IsReadableRegion(mbi)) continue;

        auto* base = static_cast<std::uint8_t*>(mbi.BaseAddress);
        if (!LocalRangeReadable(base, sizeof(IMAGE_DOS_HEADER))) continue;

        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < static_cast<LONG>(sizeof(IMAGE_DOS_HEADER)))
            continue;
        if (!LocalRangeReadable(base + dos->e_lfanew, sizeof(IMAGE_NT_HEADERS64))) continue;

        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        if (nt->Signature == IMAGE_NT_SIGNATURE) modules.push_back(static_cast<HMODULE>(mbi.BaseAddress));
    }

    return modules;
}

[[nodiscard]] auto FindLocalPayload(const GUID& guid) -> Result<RemotePayload> {
    for (auto module : ScanLocalModules()) {
        auto* detourSection = static_cast<std::uint8_t*>(FindDetourSectionInLocalModule(module));
        if (detourSection == nullptr) continue;

        auto* header = reinterpret_cast<DetourSectionHeader*>(detourSection);
        if (header->cbHeaderSize < sizeof(DetourSectionHeader) || header->nSignature != kDetourSectionSignature
            || header->cbDataSize < header->cbHeaderSize) {
            continue;
        }

        DWORD offset = header->nDataOffset == 0 ? header->cbHeaderSize : header->nDataOffset;
        while (offset + sizeof(DetourSectionRecord) <= header->cbDataSize) {
            auto* record = reinterpret_cast<DetourSectionRecord*>(detourSection + offset);
            if (record->cbBytes < sizeof(DetourSectionRecord) || offset + record->cbBytes > header->cbDataSize) break;
            if (GuidEqual(record->guid, guid)) {
                return Result<RemotePayload>::Ok(
                    RemotePayload{record + 1, record->cbBytes - static_cast<DWORD>(sizeof(*record))}
                );
            }
            offset += record->cbBytes;
        }
    }
    return Result<RemotePayload>::Err(ErrorCode::PayloadNotFound, "Payload not found");
}

[[nodiscard]] auto GetContainingLocalModule(void* address) -> HMODULE {
    auto addr = reinterpret_cast<std::uintptr_t>(address);
    for (auto module : ScanLocalModules()) {
        auto* base       = reinterpret_cast<std::uint8_t*>(module);
        auto* dos        = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        auto* nt         = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        auto  moduleBase = reinterpret_cast<std::uintptr_t>(base);
        if (addr >= moduleBase && addr < moduleBase + nt->OptionalHeader.SizeOfImage) return module;
    }
    return nullptr;
}

[[nodiscard]] auto FreeLocalPayload(void* payload) -> Result<void> {
    auto* module = GetContainingLocalModule(payload);
    if (module == nullptr) return Result<void>::Err(ErrorCode::PayloadInvalid, "Payload owner module not found");
    if (!VirtualFree(module, 0, MEM_RELEASE)) return ErrWin32Void(ErrorCode::RemoteMemoryFailed, "VirtualFree");
    return Result<void>::Ok();
}

[[nodiscard]] auto RecordExeRestore(HANDLE process, HMODULE module, ExeRestore& restore) -> Result<void> {
    restore    = {};
    restore.cb = sizeof(restore);

    restore.pidh  = reinterpret_cast<PBYTE>(module);
    restore.cbidh = sizeof(restore.idh);
    if (!ReadRemote(process, restore.pidh, restore.idh))
        return ErrWin32Void(ErrorCode::RemoteMemoryFailed, "ReadProcessMemory");

    restore.pinh  = restore.pidh + restore.idh.e_lfanew;
    restore.cbinh = FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader);
    if (!ReadRemoteBytes(process, restore.pinh, &restore.inh64, restore.cbinh))
        return ErrWin32Void(ErrorCode::RemoteMemoryFailed, "ReadProcessMemory");

    restore.cbinh = FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) + restore.inh64.FileHeader.SizeOfOptionalHeader
                  + restore.inh64.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);

    if (restore.cbinh > sizeof(restore.raw))
        return Result<void>::Err(ErrorCode::UnsupportedArchitecture, "Executable has too many section headers");

    if (!ReadRemoteBytes(process, restore.pinh, &restore.inh64, restore.cbinh))
        return ErrWin32Void(ErrorCode::RemoteMemoryFailed, "ReadProcessMemory");

    const auto& clrDirectory = restore.inh64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
    if (clrDirectory.VirtualAddress != 0 && clrDirectory.Size != 0) {
        restore.pclr  = restore.pidh + clrDirectory.VirtualAddress;
        restore.cbclr = sizeof(restore.clr);
        if (!ReadRemote(process, restore.pclr, restore.clr))
            return ErrWin32Void(ErrorCode::RemoteMemoryFailed, "ReadProcessMemory");
    }

    return Result<void>::Ok();
}

[[nodiscard]] auto FindAndAllocateNearBase(HANDLE process, std::uint8_t* module, std::uint8_t* base, const DWORD size)
    -> std::uint8_t* {
    MEMORY_BASIC_INFORMATION mbi{};
    constexpr std::uintptr_t k4Gb = (std::uintptr_t{1} << 32) - 1;

    auto moduleAddr = reinterpret_cast<std::uintptr_t>(module);
    auto baseAddr   = reinterpret_cast<std::uintptr_t>(base);
    auto cursor     = baseAddr;

    for (;;) {
        if (VirtualQueryEx(process, reinterpret_cast<void*>(cursor), &mbi, sizeof(mbi)) == 0) break;
        if ((mbi.RegionSize & 0xfff) == 0xfff) break;

        auto regionEnd = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (regionEnd <= cursor) break;
        cursor = regionEnd;

        if (mbi.State != MEM_FREE) continue;

        auto address = std::max(reinterpret_cast<std::uintptr_t>(mbi.BaseAddress), baseAddr);
        address      = (address + 0xffff) & ~std::uintptr_t{0xffff};

        if (address + size - 1 - moduleAddr > k4Gb) return nullptr;

        for (; address < regionEnd; address += 0x10000) {
            auto* allocated = static_cast<std::uint8_t*>(VirtualAllocEx(
                process,
                reinterpret_cast<void*>(address),
                size,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE
            ));
            if (allocated == nullptr) continue;
            auto allocatedAddr = reinterpret_cast<std::uintptr_t>(allocated);
            if (allocatedAddr + size - 1 - moduleAddr > k4Gb) {
                VirtualFreeEx(process, allocated, 0, MEM_RELEASE);
                return nullptr;
            }
            return allocated;
        }
    }
    return nullptr;
}

[[nodiscard]] auto PadToDword(const DWORD value) -> DWORD { return (value + 3u) & ~3u; }

[[nodiscard]] auto PadToDwordPtr(const DWORD value) -> DWORD {
    return (value + static_cast<DWORD>(sizeof(void*) - 1)) & ~static_cast<DWORD>(sizeof(void*) - 1);
}

[[nodiscard]] auto DwordFromSize(const std::size_t value, DWORD& out) -> bool {
    if (value > std::numeric_limits<DWORD>::max()) return false;
    out = static_cast<DWORD>(value);
    return true;
}

[[nodiscard]] auto UpdateImports64(HANDLE process, HMODULE module, const std::span<const std::string> dlls)
    -> Result<void> {
    if (dlls.empty()) return Result<void>::Err(ErrorCode::InvalidArgument, "DLL list is empty");

    auto* moduleBase = reinterpret_cast<std::uint8_t*>(module);

    IMAGE_DOS_HEADER dos{};
    if (!ReadRemote(process, moduleBase, dos)) return ErrWin32Void(ErrorCode::RemoteMemoryFailed, "ReadProcessMemory");

    IMAGE_NT_HEADERS64 nt{};
    if (!ReadRemote(process, moduleBase + dos.e_lfanew, nt))
        return ErrWin32Void(ErrorCode::RemoteMemoryFailed, "ReadProcessMemory");

    if (nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC || nt.FileHeader.Machine != kSupportedMachine)
        return Result<void>::Err(ErrorCode::UnsupportedArchitecture, "Only native PE32+ targets are supported");

    auto& importDirectory = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    auto& boundDirectory  = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
    auto& iatDirectory    = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];

    boundDirectory.VirtualAddress = 0;
    boundDirectory.Size           = 0;

    const DWORD sectionTable =
        dos.e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) + nt.FileHeader.SizeOfOptionalHeader;

    for (DWORD i = 0; i < nt.FileHeader.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER section{};
        if (!ReadRemote(process, moduleBase + sectionTable + sizeof(section) * i, section))
            return ErrWin32Void(ErrorCode::RemoteMemoryFailed, "ReadProcessMemory");

        if (iatDirectory.VirtualAddress == 0 && importDirectory.VirtualAddress >= section.VirtualAddress
            && importDirectory.VirtualAddress < section.VirtualAddress + section.SizeOfRawData) {
            iatDirectory.VirtualAddress = section.VirtualAddress;
            iatDirectory.Size           = section.SizeOfRawData;
        }
    }

    if (importDirectory.VirtualAddress != 0 && importDirectory.Size == 0) {
        auto* descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(moduleBase + importDirectory.VirtualAddress);
        while (true) {
            IMAGE_IMPORT_DESCRIPTOR current{};
            if (!ReadRemote(process, descriptor, current))
                return ErrWin32Void(ErrorCode::RemoteMemoryFailed, "ReadProcessMemory");
            importDirectory.Size += sizeof(IMAGE_IMPORT_DESCRIPTOR);
            if (current.Name == 0) break;
            ++descriptor;
        }
    }

    DWORD nOldDlls = importDirectory.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    DWORD nNewDlls = 0;
    if (!DwordFromSize(dlls.size(), nNewDlls)) return Result<void>::Err(ErrorCode::InvalidArgument, "Too many DLLs");

    DWORD descriptorBytes = 0;
    if (DWordMult(sizeof(IMAGE_IMPORT_DESCRIPTOR), nOldDlls + nNewDlls + 1, &descriptorBytes) != S_OK)
        return Result<void>::Err(ErrorCode::InvalidArgument, "Import descriptor size overflow");

    const DWORD thunkTableOffset = PadToDwordPtr(descriptorBytes);

    DWORD thunkBytes = 0;
    if (DWordMult(sizeof(IMAGE_THUNK_DATA64) * 4, nNewDlls, &thunkBytes) != S_OK)
        return Result<void>::Err(ErrorCode::InvalidArgument, "Import thunk size overflow");

    DWORD stringOffset = 0;
    if (DWordAdd(thunkTableOffset, thunkBytes, &stringOffset) != S_OK)
        return Result<void>::Err(ErrorCode::InvalidArgument, "Import table size overflow");

    DWORD totalSize = stringOffset;
    for (const auto& dll : dlls) {
        DWORD nameBytes = 0;
        if (!DwordFromSize(dll.size() + 1, nameBytes) || DWordAdd(totalSize, PadToDword(nameBytes), &totalSize) != S_OK)
            return Result<void>::Err(ErrorCode::InvalidArgument, "Import string table size overflow");
    }

    std::vector<std::uint8_t> newImports(totalSize, 0);

    auto allocationAddr = reinterpret_cast<std::uintptr_t>(moduleBase)
                        + static_cast<std::uintptr_t>(nt.OptionalHeader.BaseOfCode) + nt.OptionalHeader.SizeOfCode
                        + nt.OptionalHeader.SizeOfInitializedData + nt.OptionalHeader.SizeOfUninitializedData;
    auto moduleAddr = reinterpret_cast<std::uintptr_t>(moduleBase);
    if (allocationAddr < moduleAddr) allocationAddr = moduleAddr;
    auto* allocationBase = reinterpret_cast<std::uint8_t*>(allocationAddr);

    auto* remoteImports = FindAndAllocateNearBase(process, moduleBase, allocationBase, totalSize);
    if (remoteImports == nullptr) return ErrWin32Void(ErrorCode::RemoteMemoryFailed, "VirtualAllocEx");

    RemoteAllocation remoteImportAllocation(process, remoteImports);

    const auto remoteRva64 = reinterpret_cast<std::uintptr_t>(remoteImports) - moduleAddr;
    if (remoteRva64 > std::numeric_limits<DWORD>::max())
        return Result<void>::Err(ErrorCode::RemoteMemoryFailed, "Import table allocation is too far from image base");
    const auto remoteRva = static_cast<DWORD>(remoteRva64);

    auto* descriptors = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(newImports.data());
    if (importDirectory.VirtualAddress != 0 && nOldDlls != 0) {
        const auto oldBytes = nOldDlls * sizeof(IMAGE_IMPORT_DESCRIPTOR);
        if (!ReadRemoteBytes(process, moduleBase + importDirectory.VirtualAddress, &descriptors[nNewDlls], oldBytes))
            return ErrWin32Void(ErrorCode::RemoteMemoryFailed, "ReadProcessMemory");
    }

    DWORD stringCursor = stringOffset;
    for (DWORD i = 0; i < nNewDlls; ++i) {
        const auto& dll = dlls[i];
        std::memcpy(newImports.data() + stringCursor, dll.c_str(), dll.size() + 1);

        DWORD thunkOffset                 = thunkTableOffset + sizeof(IMAGE_THUNK_DATA64) * (4 * i);
        descriptors[i].OriginalFirstThunk = remoteRva + thunkOffset;
        auto* originalThunk               = reinterpret_cast<IMAGE_THUNK_DATA64*>(newImports.data() + thunkOffset);
        originalThunk[0].u1.Ordinal       = IMAGE_ORDINAL_FLAG64 | 1;
        originalThunk[1].u1.Ordinal       = 0;

        thunkOffset                   = thunkTableOffset + sizeof(IMAGE_THUNK_DATA64) * ((4 * i) + 2);
        descriptors[i].FirstThunk     = remoteRva + thunkOffset;
        auto* firstThunk              = reinterpret_cast<IMAGE_THUNK_DATA64*>(newImports.data() + thunkOffset);
        firstThunk[0].u1.Ordinal      = IMAGE_ORDINAL_FLAG64 | 1;
        firstThunk[1].u1.Ordinal      = 0;
        descriptors[i].TimeDateStamp  = 0;
        descriptors[i].ForwarderChain = 0;
        descriptors[i].Name           = remoteRva + stringCursor;

        stringCursor += PadToDword(static_cast<DWORD>(dll.size() + 1));
    }

    if (!WriteRemoteBytes(process, remoteImports, newImports.data(), stringCursor))
        return ErrWin32Void(ErrorCode::RemoteMemoryFailed, "WriteProcessMemory");

    if (iatDirectory.VirtualAddress == 0) {
        iatDirectory.VirtualAddress = remoteRva;
        iatDirectory.Size           = totalSize;
    }

    importDirectory.VirtualAddress = remoteRva;
    importDirectory.Size           = totalSize;
    nt.OptionalHeader.CheckSum     = 0;

    DWORD oldProtect = 0;
    if (!ProtectSameExecute(process, moduleBase, nt.OptionalHeader.SizeOfHeaders, PAGE_EXECUTE_READWRITE, oldProtect))
        return ErrWin32Void(ErrorCode::ProtectionFailed, "VirtualProtectEx");

    const auto restoreHeaderProtection = [&] {
        DWORD ignored = 0;
        VirtualProtectEx(process, moduleBase, nt.OptionalHeader.SizeOfHeaders, oldProtect, &ignored);
    };

    if (!WriteRemoteBytes(process, moduleBase, &dos, sizeof(dos))) {
        restoreHeaderProtection();
        return ErrWin32Void(ErrorCode::RemoteMemoryFailed, "WriteProcessMemory");
    }

    if (!WriteRemoteBytes(process, moduleBase + dos.e_lfanew, &nt, sizeof(nt))) {
        restoreHeaderProtection();
        return ErrWin32Void(ErrorCode::RemoteMemoryFailed, "WriteProcessMemory");
    }

    restoreHeaderProtection();
    (void)remoteImportAllocation.release();
    return Result<void>::Ok();
}

[[nodiscard]] auto ConvertDllPathsForImportTable(const std::span<const std::filesystem::path> dlls)
    -> Result<std::vector<std::string>> {
    if (dlls.empty()) return Result<std::vector<std::string>>::Err(ErrorCode::InvalidArgument, "DLL list is empty");

    std::vector<std::string> converted;
    converted.reserve(dlls.size());

    for (const auto& dll : dlls) {
        auto absolute = AbsolutePath(dll);
        if (!absolute) return Result<std::vector<std::string>>::Err(absolute.code(), absolute.error());

        auto ansi = WideToAnsiStrict(absolute->wstring());
        if (!ansi) return Result<std::vector<std::string>>::Err(ansi.code(), ansi.error());
        converted.push_back(std::move(ansi.value()));
    }
    return Result<std::vector<std::string>>::Ok(std::move(converted));
}

[[nodiscard]] auto RemoteModuleBaseByPath(HANDLE process, const std::wstring& dllPath) -> Address {
    std::array<HMODULE, 1024> modules{};
    DWORD                     needed = 0;
    if (!EnumProcessModulesEx(
            process,
            modules.data(),
            static_cast<DWORD>(modules.size() * sizeof(HMODULE)),
            &needed,
            LIST_MODULES_ALL
        ))
        return 0;

    const auto count = std::min<std::size_t>(modules.size(), needed / sizeof(HMODULE));
    const auto name  = FileNameOf(dllPath);

    for (std::size_t i = 0; i < count; ++i) {
        std::wstring buffer(32768, L'\0');
        const DWORD  len = GetModuleFileNameExW(process, modules[i], buffer.data(), static_cast<DWORD>(buffer.size()));
        if (len == 0) continue;
        buffer.resize(len);

        if (CaseInsensitiveEqual(buffer, dllPath) || CaseInsensitiveEqual(FileNameOf(buffer), name))
            return reinterpret_cast<Address>(modules[i]);
    }
    return 0;
}

[[nodiscard]] auto ResolveRemoteProcAddress(HANDLE process, const wchar_t* moduleName, const char* procName)
    -> Result<void*> {
    const auto localModule = GetModuleHandleW(moduleName);
    if (localModule == nullptr) return ErrWin32<void*>(ErrorCode::ModuleNotFound, "GetModuleHandleW");

    const auto localProc = GetProcAddress(localModule, procName);
    if (localProc == nullptr) return ErrWin32<void*>(ErrorCode::ImportNotFound, "GetProcAddress");

    std::array<HMODULE, 1024> modules{};
    DWORD                     needed = 0;
    if (!EnumProcessModulesEx(
            process,
            modules.data(),
            static_cast<DWORD>(modules.size() * sizeof(HMODULE)),
            &needed,
            LIST_MODULES_ALL
        ))
        return Result<void*>::Ok(reinterpret_cast<void*>(localProc));

    const auto count = std::min<std::size_t>(modules.size(), needed / sizeof(HMODULE));
    for (std::size_t i = 0; i < count; ++i) {
        std::wstring path(32768, L'\0');
        const DWORD  len = GetModuleFileNameExW(process, modules[i], path.data(), static_cast<DWORD>(path.size()));
        if (len == 0) continue;
        path.resize(len);

        if (!CaseInsensitiveEqual(FileNameOf(path), moduleName)) continue;
        const auto offset = reinterpret_cast<std::uintptr_t>(localProc) - reinterpret_cast<std::uintptr_t>(localModule);
        return Result<void*>::Ok(reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(modules[i]) + offset));
    }

    return Result<void*>::Ok(reinterpret_cast<void*>(localProc));
}
} // namespace

ProcessInfo::ProcessInfo() noexcept = default;

ProcessInfo::ProcessInfo(PROCESS_INFORMATION info) noexcept : info_(info) {}

ProcessInfo::ProcessInfo(ProcessInfo&& other) noexcept : info_(std::exchange(other.info_, PROCESS_INFORMATION{})) {}

auto ProcessInfo::operator=(ProcessInfo&& other) noexcept -> ProcessInfo& {
    if (this != &other) {
        close();
        info_ = std::exchange(other.info_, PROCESS_INFORMATION{});
    }
    return *this;
}

ProcessInfo::~ProcessInfo() { close(); }

auto ProcessInfo::isValid() const noexcept -> bool { return info_.hProcess != nullptr; }

auto ProcessInfo::processHandle() const noexcept -> HANDLE { return info_.hProcess; }

auto ProcessInfo::threadHandle() const noexcept -> HANDLE { return info_.hThread; }

auto ProcessInfo::processId() const noexcept -> DWORD { return info_.dwProcessId; }

auto ProcessInfo::threadId() const noexcept -> DWORD { return info_.dwThreadId; }

auto ProcessInfo::native() const noexcept -> const PROCESS_INFORMATION& { return info_; }

auto ProcessInfo::resume() -> Result<void> {
    if (info_.hThread == nullptr) return Result<void>::Err(ErrorCode::InvalidArgument, "Thread handle is null");
    if (ResumeThread(info_.hThread) == static_cast<DWORD>(-1))
        return ErrWin32Void(ErrorCode::ProcessCreateFailed, "ResumeThread");
    return Result<void>::Ok();
}

auto ProcessInfo::terminate(const UINT exitCode) -> Result<void> {
    if (info_.hProcess == nullptr) return Result<void>::Err(ErrorCode::InvalidArgument, "Process handle is null");
    if (!TerminateProcess(info_.hProcess, exitCode))
        return ErrWin32Void(ErrorCode::ProcessCreateFailed, "TerminateProcess");
    return Result<void>::Ok();
}

auto ProcessInfo::release() noexcept -> PROCESS_INFORMATION { return std::exchange(info_, PROCESS_INFORMATION{}); }

void ProcessInfo::close() noexcept {
    if (info_.hThread != nullptr) {
        CloseHandle(info_.hThread);
        info_.hThread = nullptr;
    }
    if (info_.hProcess != nullptr) {
        CloseHandle(info_.hProcess);
        info_.hProcess = nullptr;
    }
    info_.dwProcessId = 0;
    info_.dwThreadId  = 0;
}

ProcessCreateOptions::ProcessCreateOptions() noexcept { startupInfo.cb = sizeof(startupInfo); }

auto RemoteThreadInjector::Inject(
    HANDLE                       process,
    const std::filesystem::path& dllPath,
    const RemoteThreadOptions    options
) -> Result<InjectionResult> {
    if (process == nullptr) return Result<InjectionResult>::Err(ErrorCode::InvalidArgument, "Process handle is null");

    auto absolute = AbsolutePath(dllPath);
    if (!absolute) return Result<InjectionResult>::Err(absolute.code(), absolute.error());

    const auto dllWide = absolute->wstring();
    const auto bytes   = (dllWide.size() + 1) * sizeof(wchar_t);

    auto* remotePath = VirtualAllocEx(process, nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (remotePath == nullptr) return ErrWin32<InjectionResult>(ErrorCode::RemoteMemoryFailed, "VirtualAllocEx");
    RemoteAllocation remotePathAllocation(process, remotePath);

    if (!WriteRemoteBytes(process, remotePath, dllWide.c_str(), bytes))
        return ErrWin32<InjectionResult>(ErrorCode::RemoteMemoryFailed, "WriteProcessMemory");

    auto loadLibrary = ResolveRemoteProcAddress(process, L"kernel32.dll", "LoadLibraryW");
    if (!loadLibrary) return Result<InjectionResult>::Err(loadLibrary.code(), loadLibrary.error());

    auto thread = UniqueHandle(CreateRemoteThread(
        process,
        nullptr,
        0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibrary.value()),
        remotePath,
        0,
        nullptr
    ));
    if (!thread) return ErrWin32<InjectionResult>(ErrorCode::ProcessInjectFailed, "CreateRemoteThread");

    InjectionResult result{};
    result.processId = GetProcessId(process);

    if (!options.waitForCompletion) {
        (void)remotePathAllocation.release();
        result.threadExitCode = STILL_ACTIVE;
        return Result<InjectionResult>::Ok(result);
    }

    const DWORD waitResult = WaitForSingleObject(thread.get(), options.waitTimeoutMs);
    if (waitResult == WAIT_TIMEOUT) {
        (void)remotePathAllocation.release();
        return Result<InjectionResult>::Err(ErrorCode::ProcessInjectFailed, "Remote LoadLibraryW timed out");
    }
    if (waitResult != WAIT_OBJECT_0)
        return ErrWin32<InjectionResult>(ErrorCode::ProcessInjectFailed, "WaitForSingleObject");

    if (!GetExitCodeThread(thread.get(), &result.threadExitCode))
        return ErrWin32<InjectionResult>(ErrorCode::ProcessInjectFailed, "GetExitCodeThread");

    if (result.threadExitCode == 0)
        return Result<InjectionResult>::Err(ErrorCode::ProcessInjectFailed, "Remote LoadLibraryW returned null");

    result.remoteModuleBase = RemoteModuleBaseByPath(process, dllWide);
    remotePathAllocation.reset();
    return Result<InjectionResult>::Ok(result);
}

auto RemoteThreadInjector::Inject(
    const DWORD                  processId,
    const std::filesystem::path& dllPath,
    const RemoteThreadOptions    options
) -> Result<InjectionResult> {
    auto process = UniqueHandle(OpenProcess(kRemoteThreadAccess, FALSE, processId));
    if (!process) return ErrWin32<InjectionResult>(ErrorCode::ProcessInjectFailed, "OpenProcess");
    return Inject(process.get(), dllPath, options);
}

auto ImportTableInjector::CreateProcessWithDlls(
    const ProcessCreateOptions&                  options,
    const std::span<const std::filesystem::path> dlls
) -> Result<ProcessInfo> {
    auto converted = ConvertDllPathsForImportTable(dlls);
    if (!converted) return Result<ProcessInfo>::Err(converted.code(), converted.error());

    std::wstring application;
    LPCWSTR      applicationPtr = nullptr;
    if (!options.application.empty()) {
        application    = options.application.wstring();
        applicationPtr = application.c_str();
    }

    std::wstring commandLine    = options.commandLine;
    LPWSTR       commandLinePtr = commandLine.empty() ? nullptr : commandLine.data();
    if (applicationPtr == nullptr && commandLinePtr == nullptr)
        return Result<ProcessInfo>::Err(ErrorCode::InvalidArgument, "Application or command line is required");

    std::wstring currentDirectory;
    LPCWSTR      currentDirectoryPtr = nullptr;
    if (!options.currentDirectory.empty()) {
        currentDirectory    = options.currentDirectory.wstring();
        currentDirectoryPtr = currentDirectory.c_str();
    }

    STARTUPINFOW startupInfo = options.startupInfo;
    if (startupInfo.cb == 0) startupInfo.cb = sizeof(startupInfo);

    PROCESS_INFORMATION nativeInfo{};
    const DWORD         creationFlags = options.creationFlags | CREATE_SUSPENDED;
    if (!CreateProcessW(
            applicationPtr,
            commandLinePtr,
            options.processAttributes,
            options.threadAttributes,
            options.inheritHandles ? TRUE : FALSE,
            creationFlags,
            options.environment,
            currentDirectoryPtr,
            &startupInfo,
            &nativeInfo
        )) {
        return ErrWin32<ProcessInfo>(ErrorCode::ProcessCreateFailed, "CreateProcessW");
    }

    ProcessInfo process(nativeInfo);

    auto update = UpdateSuspendedProcessWithDlls(process.processHandle(), dlls);
    if (!update) {
        (void)process.terminate(~0u);
        return Result<ProcessInfo>::Err(update.code(), update.error());
    }

    if ((options.creationFlags & CREATE_SUSPENDED) == 0) {
        auto resume = process.resume();
        if (!resume) {
            (void)process.terminate(~0u);
            return Result<ProcessInfo>::Err(resume.code(), resume.error());
        }
    }

    return Result<ProcessInfo>::Ok(std::move(process));
}

auto ImportTableInjector::UpdateSuspendedProcessWithDlls(
    HANDLE                                       process,
    const std::span<const std::filesystem::path> dlls
) -> Result<void> {
    auto converted = ConvertDllPathsForImportTable(dlls);
    if (!converted) return Result<void>::Err(converted.code(), converted.error());

    auto mainModule = FindMainModuleInProcess(process);
    if (!mainModule) return Result<void>::Err(mainModule.code(), mainModule.error());

    IMAGE_NT_HEADERS64 nt{};
    if (!LoadNtHeaderFromProcess(process, mainModule.value(), nt))
        return ErrWin32Void(ErrorCode::ProcessInjectFailed, "Read target PE headers");

    if (nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC || nt.FileHeader.Machine != kSupportedMachine)
        return Result<void>::Err(ErrorCode::UnsupportedArchitecture, "Only native PE32+ targets are supported");

    ExeRestore restore{};
    if (auto record = RecordExeRestore(process, mainModule.value(), restore); !record) return record;

    if (auto update = UpdateImports64(process, mainModule.value(), std::span<const std::string>(converted.value()));
        !update) {
        return update;
    }

    if (restore.pclr != nullptr) {
        DetourClrHeader clr  = restore.clr;
        clr.Flags           &= ~COMIMAGE_FLAGS_ILONLY;

        DWORD oldProtect = 0;
        if (!ProtectSameExecute(process, restore.pclr, sizeof(clr), PAGE_READWRITE, oldProtect))
            return ErrWin32Void(ErrorCode::ProtectionFailed, "VirtualProtectEx");
        if (!WriteRemoteBytes(process, restore.pclr, &clr, sizeof(clr))) {
            DWORD ignored = 0;
            VirtualProtectEx(process, restore.pclr, sizeof(clr), oldProtect, &ignored);
            return ErrWin32Void(ErrorCode::RemoteMemoryFailed, "WriteProcessMemory");
        }
        DWORD ignored = 0;
        VirtualProtectEx(process, restore.pclr, sizeof(clr), oldProtect, &ignored);
    }

    auto payload = CopyPayloadToProcess(process, kExeRestoreGuid, &restore, sizeof(restore));
    if (!payload) return Result<void>::Err(payload.code(), payload.error());
    return Result<void>::Ok();
}

auto ImportTableInjector::RestoreAfterWith() -> Result<void> {
    auto payload = FindLocalPayload(kExeRestoreGuid);
    if (!payload) return Result<void>::Err(payload.code(), payload.error());

    auto* restore = static_cast<ExeRestore*>(payload->address);
    if (restore == nullptr || restore->cb != sizeof(*restore) || restore->cb > payload->size)
        return Result<void>::Err(ErrorCode::PayloadInvalid, "Invalid restore payload");

    DWORD oldDos = 0;
    if (!ProtectSameExecute(GetCurrentProcess(), restore->pidh, restore->cbidh, PAGE_EXECUTE_READWRITE, oldDos))
        return ErrWin32Void(ErrorCode::ProtectionFailed, "VirtualProtect");

    DWORD oldNt = 0;
    if (!ProtectSameExecute(GetCurrentProcess(), restore->pinh, restore->cbinh, PAGE_EXECUTE_READWRITE, oldNt)) {
        DWORD ignored = 0;
        VirtualProtect(restore->pidh, restore->cbidh, oldDos, &ignored);
        return ErrWin32Void(ErrorCode::ProtectionFailed, "VirtualProtect");
    }

    std::memcpy(restore->pidh, &restore->idh, restore->cbidh);
    std::memcpy(restore->pinh, &restore->inh64, restore->cbinh);

    bool restoredClr = true;
    if (restore->pclr != nullptr && restore->clr.Flags == reinterpret_cast<DetourClrHeader*>(restore->pclr)->Flags) {
        DWORD oldClr = 0;
        if (ProtectSameExecute(GetCurrentProcess(), restore->pclr, restore->cbclr, PAGE_EXECUTE_READWRITE, oldClr)) {
            std::memcpy(restore->pclr, &restore->clr, restore->cbclr);
            DWORD ignored = 0;
            VirtualProtect(restore->pclr, restore->cbclr, oldClr, &ignored);
        } else {
            restoredClr = false;
        }
    }

    DWORD ignored = 0;
    VirtualProtect(restore->pinh, restore->cbinh, oldNt, &ignored);
    VirtualProtect(restore->pidh, restore->cbidh, oldDos, &ignored);

    if (!restoredClr) return ErrWin32Void(ErrorCode::ProtectionFailed, "VirtualProtect");
    return FreeLocalPayload(restore);
}
} // namespace Mortis

#endif // MORTIS_OS_WINDOWS
