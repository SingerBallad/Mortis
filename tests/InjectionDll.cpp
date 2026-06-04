#include <Mortis/Inject.hpp>

#include <Windows.h>

extern "C" __declspec(dllexport) void WINAPI MortisInjectionMarker() {}

namespace {

void SignalLoaded() {
    wchar_t path[MAX_PATH]{};
    const auto length = GetEnvironmentVariableW(L"MORTIS_INJECT_SIGNAL", path, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) return;

    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return;

    const char message[] = "loaded";
    DWORD      written   = 0;
    WriteFile(file, message, sizeof(message) - 1, &written, nullptr);
    CloseHandle(file);
}

} // namespace

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(instance);
        (void)Mortis::ImportTableInjector::RestoreAfterWith();
        SignalLoaded();
    }
    return TRUE;
}
