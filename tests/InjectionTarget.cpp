#include <Windows.h>

#include <cwchar>

namespace {

auto QuerySleepMs() -> DWORD {
    wchar_t buffer[32]{};
    const auto length = GetEnvironmentVariableW(L"MORTIS_INJECT_TARGET_SLEEP_MS", buffer, 32);
    if (length == 0 || length >= 32) return 30000;

    wchar_t* end   = nullptr;
    const auto time = std::wcstoul(buffer, &end, 10);
    if (end == buffer || time > 60000) return 30000;
    return static_cast<DWORD>(time);
}

} // namespace

int main() {
    Sleep(QuerySleepMs());
    return 0;
}
