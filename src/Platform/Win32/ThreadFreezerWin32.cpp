#include <Mortis/Hook/ThreadFreezer.hpp>
#include <Mortis/Platform/Win32Utils.hpp>

// clang-format off
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>
// clang-format on

namespace Mortis::HookEngine {

namespace {

/// @brief NtGetNextThread — fast thread enumeration (Vista+).
using NtGetNextThread_t = NTSTATUS(NTAPI*)(
    HANDLE      ProcessHandle,
    HANDLE      ThreadHandle,
    ACCESS_MASK DesiredAccess,
    ULONG       HandleAttributes,
    ULONG       Flags,
    PHANDLE     NewThreadHandle
);

auto GetNtGetNextThread() -> NtGetNextThread_t {
    static const auto fn = Win32Detail::ResolveNtdllProc<NtGetNextThread_t>("NtGetNextThread");
    return fn;
}

auto GetIp(const CONTEXT& ctx) -> std::uint64_t {
#ifdef MORTIS_ARCH_X64
    return ctx.Rip;
#else
    return ctx.Pc;
#endif
}

void SetIp(CONTEXT& ctx, std::uint64_t ip) {
#ifdef MORTIS_ARCH_X64
    ctx.Rip = ip;
#else
    ctx.Pc = ip;
#endif
}

/// @brief Enumerate threads using NtGetNextThread (fast path).
/// @return true if threads were enumerated, false if API not available.
auto EnumerateFast(std::vector<void*>& handles) -> bool {
    auto ntGetNextThread = GetNtGetNextThread();
    if (!ntGetNextThread) return false;

    const DWORD           currentTid = GetCurrentThreadId();
    HANDLE                hProcess   = GetCurrentProcess();
    HANDLE                hThread    = nullptr;
    constexpr ACCESS_MASK kAccess =
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION;

    while (true) {
        HANDLE   hNext  = nullptr;
        NTSTATUS status = ntGetNextThread(hProcess, hThread, kAccess, 0, 0, &hNext);
        if (hThread) CloseHandle(hThread);
        if (status != 0) break; // STATUS_NO_MORE_ENTRIES or error

        hThread = hNext;

        // Skip the calling thread.
        if (GetThreadId(hThread) == currentTid) continue;

        if (SuspendThread(hThread) != static_cast<DWORD>(-1)) {
            // Duplicate so we keep a handle after advancing the iterator.
            HANDLE hDup = nullptr;
            if (DuplicateHandle(hProcess, hThread, hProcess, &hDup, kAccess, FALSE, 0)) {
                handles.push_back(hDup);
            } else {
                ResumeThread(hThread);
            }
        }
    }
    if (hThread) CloseHandle(hThread);
    return true;
}

} // anonymous namespace

auto ThreadFreezer::Create() -> Result<ThreadFreezer> {
    ThreadFreezer freezer;

    if (!EnumerateFast(freezer.handles_)) {
        // Fallback: Toolhelp snapshot (slower, but universally available).
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) {
            return Result<ThreadFreezer>::Err(ErrorCode::HookInstallFailed, "CreateToolhelp32Snapshot failed");
        }

        DWORD currentTid = GetCurrentThreadId();
        DWORD currentPid = GetCurrentProcessId();

        THREADENTRY32 te{};
        te.dwSize = sizeof(te);
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID != currentPid) continue;
                if (te.th32ThreadID == currentTid) continue;

                HANDLE hThread =
                    OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                if (!hThread) continue;

                if (SuspendThread(hThread) != static_cast<DWORD>(-1)) {
                    freezer.handles_.push_back(hThread);
                } else {
                    CloseHandle(hThread);
                }
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
    }

    return Result<ThreadFreezer>::Ok(std::move(freezer));
}

ThreadFreezer::~ThreadFreezer() {
    for (auto* h : handles_) {
        ResumeThread(h);
        CloseHandle(h);
    }
}

void ThreadFreezer::remapThreadIPs(
    void*                             target,
    const std::size_t                 prologueSize,
    void*                             trampoline,
    const std::span<const AlignEntry> alignMap
) const {
    const auto targetAddr     = reinterpret_cast<std::uint64_t>(target);
    const auto trampolineAddr = reinterpret_cast<std::uint64_t>(trampoline);

    for (auto* h : handles_) {
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_CONTROL;
        if (!GetThreadContext(h, &ctx)) continue;

        const auto ip = GetIp(ctx);
        if (ip < targetAddr || ip >= targetAddr + prologueSize) continue;

        const auto offset = static_cast<std::uint8_t>(ip - targetAddr);
        for (const auto& [targetOffset, trampolineOffset] : alignMap) {
            if (targetOffset == offset) {
                SetIp(ctx, trampolineAddr + trampolineOffset);
                SetThreadContext(h, &ctx);
                break;
            }
        }
    }
}

void ThreadFreezer::reverseRemapThreadIPs(
    void*                             trampoline,
    void*                             target,
    const std::span<const AlignEntry> alignMap
) const {
    if (alignMap.empty()) return;

    const auto trampolineAddr = reinterpret_cast<std::uint64_t>(trampoline);
    const auto targetAddr     = reinterpret_cast<std::uint64_t>(target);
    const auto relocatedSize  = static_cast<std::size_t>(alignMap.back().trampolineOffset);

    for (auto* h : handles_) {
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_CONTROL;
        if (!GetThreadContext(h, &ctx)) continue;

        const auto ip = GetIp(ctx);
        if (ip < trampolineAddr || ip >= trampolineAddr + relocatedSize) continue;

        const auto offset = static_cast<std::uint8_t>(ip - trampolineAddr);
        for (const auto& [targetOffset, trampolineOffset] : alignMap) {
            if (trampolineOffset == offset) {
                SetIp(ctx, targetAddr + targetOffset);
                SetThreadContext(h, &ctx);
                break;
            }
        }
    }
}

} // namespace Mortis::HookEngine
