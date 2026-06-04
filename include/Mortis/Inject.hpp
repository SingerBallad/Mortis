#pragma once

#include <Mortis/Config.hpp>
#include <Mortis/Result.hpp>

#ifdef MORTIS_OS_WINDOWS

#include <filesystem>
#include <span>
#include <string>

// clang-format off
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
// clang-format on

namespace Mortis {

/// @brief RAII wrapper around PROCESS_INFORMATION.
struct ProcessInfo {
    ProcessInfo() noexcept;
    explicit ProcessInfo(PROCESS_INFORMATION info) noexcept;

    ProcessInfo(const ProcessInfo&)                    = delete;
    auto operator=(const ProcessInfo&) -> ProcessInfo& = delete;

    ProcessInfo(ProcessInfo&& other) noexcept;
    auto operator=(ProcessInfo&& other) noexcept -> ProcessInfo&;

    ~ProcessInfo();

    [[nodiscard]] auto isValid() const noexcept -> bool;
    [[nodiscard]] auto processHandle() const noexcept -> HANDLE;
    [[nodiscard]] auto threadHandle() const noexcept -> HANDLE;
    [[nodiscard]] auto processId() const noexcept -> DWORD;
    [[nodiscard]] auto threadId() const noexcept -> DWORD;
    [[nodiscard]] auto native() const noexcept -> const PROCESS_INFORMATION&;

    [[nodiscard]] auto resume() -> Result<void>;
    [[nodiscard]] auto terminate(UINT exitCode) -> Result<void>;
    [[nodiscard]] auto release() noexcept -> PROCESS_INFORMATION;
    void               close() noexcept;

private:
    PROCESS_INFORMATION info_{};
};

/// @brief Options for CreateProcessW-based process creation.
struct ProcessCreateOptions {
    std::filesystem::path application;
    std::wstring          commandLine;
    LPSECURITY_ATTRIBUTES processAttributes = nullptr;
    LPSECURITY_ATTRIBUTES threadAttributes  = nullptr;
    bool                  inheritHandles    = false;
    DWORD                 creationFlags     = 0;
    LPVOID                environment       = nullptr;
    std::filesystem::path currentDirectory;
    STARTUPINFOW          startupInfo{};

    ProcessCreateOptions() noexcept;
};

/// @brief Options for LoadLibraryW remote-thread injection.
struct RemoteThreadOptions {
    bool  waitForCompletion = true;
    DWORD waitTimeoutMs     = INFINITE;
};

/// @brief Result details for a successful DLL injection.
struct InjectionResult {
    Address remoteModuleBase = 0;
    DWORD   threadExitCode   = 0;
    DWORD   processId        = 0;
};

/// @brief Inject a DLL into an existing process using CreateRemoteThread + LoadLibraryW.
struct RemoteThreadInjector {
    RemoteThreadInjector() = delete;

    [[nodiscard]] static auto
    Inject(HANDLE process, const std::filesystem::path& dllPath, RemoteThreadOptions options = {})
        -> Result<InjectionResult>;

    [[nodiscard]] static auto
    Inject(DWORD processId, const std::filesystem::path& dllPath, RemoteThreadOptions options = {})
        -> Result<InjectionResult>;
};

/// @brief Inject DLLs into a newly-created or initially-suspended process by editing its import table.
struct ImportTableInjector {
    ImportTableInjector() = delete;

    [[nodiscard]] static auto
    CreateProcessWithDlls(const ProcessCreateOptions& options, std::span<const std::filesystem::path> dlls)
        -> Result<ProcessInfo>;

    [[nodiscard]] static auto
    UpdateSuspendedProcessWithDlls(HANDLE process, std::span<const std::filesystem::path> dlls) -> Result<void>;

    [[nodiscard]] static auto RestoreAfterWith() -> Result<void>;
};

} // namespace Mortis

#endif // MORTIS_OS_WINDOWS
