/// @file Win32Utils.hpp
/// @brief Shared Win32 utility functions used across platform implementations.
#pragma once

#include <Mortis/Config.hpp>
#include <Mortis/Process.hpp>

#include <algorithm>
#include <cctype>
#include <optional>
#include <string>
#include <string_view>

// clang-format off
#include <Windows.h>
// clang-format on

namespace Mortis::Win32Detail {

constexpr DWORD kWritableProtectionMask =
    PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

/// @brief Convert portable MemoryProtection flags to Win32 PAGE_* constants.
inline auto ToNativeProtection(const MemoryProtection prot) -> DWORD {
    const bool r = HasFlag(prot, MemoryProtection::Read);
    const bool w = HasFlag(prot, MemoryProtection::Write);
    const bool x = HasFlag(prot, MemoryProtection::Execute);
    if (x && w) return PAGE_EXECUTE_READWRITE;
    if (x && r) return PAGE_EXECUTE_READ;
    if (x) return PAGE_EXECUTE;
    if (w) return PAGE_READWRITE;
    if (r) return PAGE_READONLY;
    return PAGE_NOACCESS;
}

/// @brief Convert Win32 PAGE_* constants to portable MemoryProtection flags.
inline auto FromNativeProtection(DWORD prot) -> MemoryProtection {
    switch (prot & 0xFF) {
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return MemoryProtection::ReadWriteExec;
    case PAGE_EXECUTE_READ:
        return MemoryProtection::Read | MemoryProtection::Execute;
    case PAGE_EXECUTE:
        return MemoryProtection::Execute;
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
        return MemoryProtection::Read | MemoryProtection::Write;
    case PAGE_READONLY:
        return MemoryProtection::Read;
    case PAGE_NOACCESS:
    default:
        return MemoryProtection::None;
    }
}

/// @brief Case-insensitive string comparison (ASCII-safe).
inline auto CaseInsensitiveEqual(std::string_view a, std::string_view b) -> bool {
    if (a.size() != b.size()) return false;
    return std::equal(a.begin(), a.end(), b.begin(), [](const char ca, const char cb) {
        return std::tolower(static_cast<unsigned char>(ca)) == std::tolower(static_cast<unsigned char>(cb));
    });
}

inline auto IsCommitted(const MEMORY_BASIC_INFORMATION& mbi) -> bool { return mbi.State == MEM_COMMIT; }

inline auto IsReadableProtection(const DWORD protect) -> bool { return (protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0; }

inline auto IsWritableProtection(const DWORD protect) -> bool { return (protect & kWritableProtectionMask) != 0; }

inline auto RegionCoversRange(const MEMORY_BASIC_INFORMATION& mbi, const Address address, std::size_t size) -> bool {
    if (size == 0) size = 1;
    const auto regionStart = reinterpret_cast<Address>(mbi.BaseAddress);
    const auto regionEnd   = regionStart + static_cast<Address>(mbi.RegionSize);
    const auto endAddress  = address + static_cast<Address>(size);
    if (regionEnd <= regionStart || endAddress <= address) return false;
    return address >= regionStart && endAddress <= regionEnd;
}

inline auto QueryRegion(const Address address) -> std::optional<MEMORY_BASIC_INFORMATION> {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi)) == 0) return std::nullopt;
    return mbi;
}

inline auto ResolveModuleHandle(const std::string_view moduleName) -> HMODULE {
    if (moduleName.empty()) return GetModuleHandleW(nullptr);
    return GetModuleHandleA(std::string(moduleName).c_str());
}

inline auto QueryModulePath(const HMODULE module) -> std::string {
    std::wstring widePath(256, L'\0');
    while (true) {
        const auto len = GetModuleFileNameW(module, widePath.data(), static_cast<DWORD>(widePath.size()));
        if (len == 0) return {};

        if (len < widePath.size() - 1) {
            const int utf8Size =
                WideCharToMultiByte(CP_UTF8, 0, widePath.data(), static_cast<int>(len), nullptr, 0, nullptr, nullptr);
            if (utf8Size <= 0) return {};

            std::string utf8Path(static_cast<std::size_t>(utf8Size), '\0');
            const int   written = WideCharToMultiByte(
                CP_UTF8,
                0,
                widePath.data(),
                static_cast<int>(len),
                utf8Path.data(),
                utf8Size,
                nullptr,
                nullptr
            );
            if (written != utf8Size) return {};
            return utf8Path;
        }

        widePath.resize(widePath.size() * 2);
    }
}

template <typename FnType>
inline auto ResolveNtdllProc(const char* procName) -> FnType {
    if (!procName || procName[0] == '\0') return nullptr;
    const auto ntdll = Process::FindModule("ntdll.dll");
    if (!ntdll) return nullptr;
    const auto exportAddr = ntdll->findExport(procName);
    if (!exportAddr) return nullptr;
    return reinterpret_cast<FnType>(*exportAddr);
}

} // namespace Mortis::Win32Detail
