#include <Mortis/Inject.hpp>

#include <gtest/gtest.h>

#include <Windows.h>

#include <array>
#include <chrono>
#include <filesystem>
#include <string>
#include <thread>

using namespace Mortis;

namespace {

class ScopedEnvironmentVariable {
public:
    ScopedEnvironmentVariable(const wchar_t* name, const std::wstring& value) : name_(name) {
        const DWORD needed = GetEnvironmentVariableW(name_.c_str(), nullptr, 0);
        if (needed > 0) {
            oldValue_.resize(needed - 1);
            GetEnvironmentVariableW(name_.c_str(), oldValue_.data(), needed);
            hadOldValue_ = true;
        }
        SetEnvironmentVariableW(name_.c_str(), value.c_str());
    }

    ScopedEnvironmentVariable(const ScopedEnvironmentVariable&)                    = delete;
    auto operator=(const ScopedEnvironmentVariable&) -> ScopedEnvironmentVariable& = delete;

    ~ScopedEnvironmentVariable() {
        SetEnvironmentVariableW(name_.c_str(), hadOldValue_ ? oldValue_.c_str() : nullptr);
    }

private:
    std::wstring name_;
    std::wstring oldValue_;
    bool         hadOldValue_ = false;
};

auto TestBinaryDirectory() -> std::filesystem::path {
    std::wstring buffer(MAX_PATH, L'\0');
    DWORD        length = 0;
    while (true) {
        length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0) return {};
        if (length < buffer.size() - 1) break;
        buffer.resize(buffer.size() * 2);
    }
    buffer.resize(length);
    return std::filesystem::path(buffer).parent_path();
}

auto InjectionTargetPath() -> std::filesystem::path {
    return TestBinaryDirectory() / L"MortisInjectionTarget.exe";
}

auto InjectionDllPath() -> std::filesystem::path {
    return TestBinaryDirectory() / L"MortisInjectionDll.dll";
}

auto UniqueSignalPath() -> std::filesystem::path {
    return std::filesystem::temp_directory_path()
         / (L"MortisInject_" + std::to_wstring(GetCurrentProcessId()) + L"_"
            + std::to_wstring(GetTickCount64()) + L".txt");
}

auto WaitForFile(const std::filesystem::path& path, const DWORD timeoutMs) -> bool {
    const auto start = GetTickCount64();
    while (GetTickCount64() - start < timeoutMs) {
        std::error_code ec;
        if (std::filesystem::exists(path, ec) && !ec) return true;
        Sleep(50);
    }
    return false;
}

auto LaunchTarget(const std::filesystem::path& target) -> Result<ProcessInfo> {
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);

    PROCESS_INFORMATION info{};
    std::wstring        commandLine = L"\"" + target.wstring() + L"\"";
    if (!CreateProcessW(
            target.wstring().c_str(),
            commandLine.data(),
            nullptr,
            nullptr,
            FALSE,
            0,
            nullptr,
            nullptr,
            &startup,
            &info
        )) {
        return Result<ProcessInfo>::Err(ErrorCode::ProcessCreateFailed, "CreateProcessW failed");
    }
    return Result<ProcessInfo>::Ok(ProcessInfo(info));
}

} // namespace

TEST(Inject, RemoteThreadInjectsDll) {
    const auto target = InjectionTargetPath();
    const auto dll    = InjectionDllPath();
    ASSERT_TRUE(std::filesystem::exists(target));
    ASSERT_TRUE(std::filesystem::exists(dll));

    const auto signal = UniqueSignalPath();
    std::filesystem::remove(signal);
    ScopedEnvironmentVariable signalEnv(L"MORTIS_INJECT_SIGNAL", signal.wstring());
    ScopedEnvironmentVariable sleepEnv(L"MORTIS_INJECT_TARGET_SLEEP_MS", L"10000");

    auto process = LaunchTarget(target);
    ASSERT_TRUE(process) << process.error();

    auto injected = RemoteThreadInjector::Inject(process->processHandle(), dll);
    if (!injected) {
        (void)process->terminate(0);
        FAIL() << injected.error();
    }
    EXPECT_EQ(injected->processId, process->processId());
    EXPECT_NE(injected->threadExitCode, 0u);
    EXPECT_NE(injected->remoteModuleBase, 0u);
    EXPECT_TRUE(WaitForFile(signal, 5000));

    (void)process->terminate(0);
    WaitForSingleObject(process->processHandle(), 5000);
    std::filesystem::remove(signal);
}

TEST(Inject, ImportTableCreateProcessWithDlls) {
    const auto target = InjectionTargetPath();
    const auto dll    = InjectionDllPath();
    ASSERT_TRUE(std::filesystem::exists(target));
    ASSERT_TRUE(std::filesystem::exists(dll));

    const auto signal = UniqueSignalPath();
    std::filesystem::remove(signal);
    ScopedEnvironmentVariable signalEnv(L"MORTIS_INJECT_SIGNAL", signal.wstring());
    ScopedEnvironmentVariable sleepEnv(L"MORTIS_INJECT_TARGET_SLEEP_MS", L"250");

    ProcessCreateOptions options;
    options.application = target;

    const std::array dlls{dll};
    auto             process = ImportTableInjector::CreateProcessWithDlls(options, std::span<const std::filesystem::path>(dlls));
    ASSERT_TRUE(process) << process.error();

    EXPECT_TRUE(WaitForFile(signal, 5000));
    EXPECT_EQ(WaitForSingleObject(process->processHandle(), 5000), WAIT_OBJECT_0);
    std::filesystem::remove(signal);
}
