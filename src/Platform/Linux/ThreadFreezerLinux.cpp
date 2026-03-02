#include <Mortis/Hook/ThreadFreezer.hpp>

#include <dirent.h>
#include <linux/futex.h>
#include <sched.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <ucontext.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <limits>
#include <vector>

namespace Mortis::HookEngine {

namespace {

/// @brief Maximum number of threads simultaneously frozen.
constexpr int kMaxFrozenThreads = 4096;

/// @brief Signal used for thread freezing (first available real-time signal).
// NOLINTNEXTLINE(cert-err58-cpp)
const int kFreezeSignal = SIGRTMIN;

/// @brief Global freeze coordination state (serialized by g_hookMutex).
struct FreezeState {
    /// Futex word: 1 = freeze active, 0 = threads should resume.
    std::atomic<std::int32_t> active{0};

    /// Number of threads that entered the handler and are ready.
    std::atomic<int> readyCount{0};

    /// Number of threads that fully exited the handler.
    std::atomic<int> exitCount{0};

    /// Number of stored context pointers.
    std::atomic<int> contextCount{0};

    /// Saved ucontext pointers from each frozen thread.
    std::atomic<ucontext_t*> contexts[kMaxFrozenThreads]{};

    void Reset() {
        active.store(0, std::memory_order_relaxed);
        readyCount.store(0, std::memory_order_relaxed);
        exitCount.store(0, std::memory_order_relaxed);
        contextCount.store(0, std::memory_order_relaxed);
        for (auto& ctx : contexts) {
            ctx.store(nullptr, std::memory_order_relaxed);
        }
    }
};

FreezeState g_freezeState;

/// @brief Signal handler: stores ucontext, then blocks on futex until released.
void FreezeSignalHandler(int /*sig*/, siginfo_t* /*info*/, void* rawCtx) {
    auto* uc = static_cast<ucontext_t*>(rawCtx);

    // Store context pointer so the main thread can remap our IP.
    if (const int slot = g_freezeState.contextCount.fetch_add(1, std::memory_order_relaxed); slot < kMaxFrozenThreads) {
        g_freezeState.contexts[slot].store(uc, std::memory_order_release);
    }

    // Signal readiness.
    g_freezeState.readyCount.fetch_add(1, std::memory_order_release);

    // Block until released.  futex(2) is async-signal-safe (raw syscall).
    while (g_freezeState.active.load(std::memory_order_acquire) != 0) {
        syscall(SYS_futex, &g_freezeState.active, FUTEX_WAIT, 1, nullptr, nullptr, 0);
    }

    // Signal handler exit so the destructor can confirm completion.
    g_freezeState.exitCount.fetch_add(1, std::memory_order_release);
}

/// @brief Read the instruction pointer from a ucontext.
auto GetIP(const ucontext_t* uc) -> std::uint64_t {
#ifdef MORTIS_ARCH_X64
    return static_cast<std::uint64_t>(uc->uc_mcontext.gregs[REG_RIP]);
#elif defined(MORTIS_ARCH_ARM64)
    return static_cast<std::uint64_t>(uc->uc_mcontext.pc);
#else
    (void)uc;
    return 0;
#endif
}

/// @brief Write the instruction pointer in a ucontext.
void SetIP(ucontext_t* uc, const std::uint64_t ip) {
#ifdef MORTIS_ARCH_X64
    uc->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(ip);
#elif defined(MORTIS_ARCH_ARM64)
    uc->uc_mcontext.pc = ip;
#else
    (void)uc;
    (void)ip;
#endif
}

/// @brief Remap an IP from a source region to a destination region
///        using the AlignEntry map.
///
/// @return Remapped IP, or 0 if the IP is not within the source region.
auto RemapIP(
    const std::uint64_t               ip,
    const std::uint64_t               srcBase,
    const std::size_t                 srcSize,
    const std::uint64_t               dstBase,
    const std::span<const AlignEntry> alignMap,
    const bool                        reverse
) -> std::uint64_t {
    if (ip < srcBase || ip >= srcBase + srcSize) return 0;

    const auto offset = ip - srcBase;

    for (std::size_t i = 0; i + 1 < alignMap.size(); ++i) {
        std::uint8_t loSrc, hiSrc, loDst;
        if (!reverse) {
            loSrc = alignMap[i].targetOffset;
            hiSrc = alignMap[i + 1].targetOffset;
            loDst = alignMap[i].trampolineOffset;
        } else {
            loSrc = alignMap[i].trampolineOffset;
            hiSrc = alignMap[i + 1].trampolineOffset;
            loDst = alignMap[i].targetOffset;
        }
        if (offset >= loSrc && offset < hiSrc) {
            return dstBase + loDst + (offset - loSrc);
        }
    }

    // Exact sentinel match — map to the end of the destination.
    if (!alignMap.empty()) {
        const auto sentinelSrc =
            static_cast<std::uint8_t>(reverse ? alignMap.back().trampolineOffset : alignMap.back().targetOffset);
        if (offset == sentinelSrc) {
            const auto sentinelDst =
                static_cast<std::uint8_t>(reverse ? alignMap.back().targetOffset : alignMap.back().trampolineOffset);
            return dstBase + sentinelDst;
        }
    }
    return 0;
}

} // anonymous namespace

auto ThreadFreezer::Create() -> Result<ThreadFreezer> {
    ThreadFreezer freezer;
    const auto    selfTid = static_cast<pid_t>(syscall(SYS_gettid));

    // Reset global state (safe — serialised by g_hookMutex).
    g_freezeState.Reset();

    DIR* dir = opendir("/proc/self/task");
    if (!dir) {
        return Result<ThreadFreezer>::Err(ErrorCode::HookInstallFailed, "Cannot open /proc/self/task");
    }

    std::vector<pid_t> tids;
    struct dirent*     ent;
    while ((ent = readdir(dir)) != nullptr) {
        if (ent->d_name[0] == '.') continue;
        const pid_t tid = std::atoi(ent->d_name);
        if (tid == 0 || tid == selfTid) continue;
        tids.push_back(tid);
    }
    closedir(dir);

    if (tids.empty()) {
        return Result<ThreadFreezer>::Ok(std::move(freezer));
    }

    // Install signal handler with SA_SIGINFO to receive ucontext.
    struct sigaction sa{};
    struct sigaction oldSa{};
    sa.sa_sigaction = FreezeSignalHandler;
    sa.sa_flags     = SA_SIGINFO | SA_RESTART;
    sigfillset(&sa.sa_mask); // Block all other signals inside handler.
    if (sigaction(kFreezeSignal, &sa, &oldSa) != 0) {
        return Result<ThreadFreezer>::Err(ErrorCode::HookInstallFailed, "Failed to install freeze signal handler");
    }

    // Mark freeze as active BEFORE sending signals.
    g_freezeState.active.store(1, std::memory_order_release);

    // Send the freeze signal to every other thread via tgkill(2).
    freezer.handles_.reserve(tids.size());
    int sentCount = 0;
    for (const pid_t tid : tids) {
        if (syscall(SYS_tgkill, getpid(), tid, kFreezeSignal) == 0) {
            freezer.handles_.push_back(tid);
            ++sentCount;
        }
    }

    // Wait for all signaled threads to enter the handler.
    if (sentCount > 0) {
        using Clock             = std::chrono::steady_clock;
        constexpr auto kTimeout = std::chrono::milliseconds(500);
        const auto     deadline = Clock::now() + kTimeout;
        while (g_freezeState.readyCount.load(std::memory_order_acquire) < sentCount) {
            if (Clock::now() >= deadline) break;
            sched_yield();
        }
    }

    // Restore old signal handler (all signals already delivered).
    sigaction(kFreezeSignal, &oldSa, nullptr);

    if (g_freezeState.contextCount.load(std::memory_order_acquire) > kMaxFrozenThreads) {
        return Result<ThreadFreezer>::Err(
            ErrorCode::HookInstallFailed,
            "Thread context count (" + std::to_string(g_freezeState.contextCount.load(std::memory_order_relaxed))
                + ") exceeds kMaxFrozenThreads (" + std::to_string(kMaxFrozenThreads)
                + "); IP remapping may be incomplete"
        );
    }

    return Result<ThreadFreezer>::Ok(std::move(freezer));
}

ThreadFreezer::~ThreadFreezer() {
    if (handles_.empty()) return;

    const int sentCount = static_cast<int>(handles_.size());

    // Release all frozen threads by clearing the futex word.
    g_freezeState.active.store(0, std::memory_order_release);
    syscall(
        SYS_futex,
        &g_freezeState.active,
        FUTEX_WAKE,
        std::numeric_limits<std::int32_t>::max(),
        nullptr,
        nullptr,
        0
    );

    // Wait for all threads to fully exit the signal handler before
    // returning.  This prevents a subsequent ThreadFreezer from
    // interfering with threads still unwinding from the old handler.
    {
        using Clock             = std::chrono::steady_clock;
        constexpr auto kTimeout = std::chrono::milliseconds(500);
        const auto     deadline = Clock::now() + kTimeout;
        while (g_freezeState.exitCount.load(std::memory_order_acquire) < sentCount) {
            if (Clock::now() >= deadline) break;
            sched_yield();
        }
    }

    g_freezeState.Reset();
}

void ThreadFreezer::remapThreadIPs(
    void*                             target,
    const std::size_t                 prologueSize,
    void*                             trampoline,
    const std::span<const AlignEntry> alignMap
) const {
    if (handles_.empty() || alignMap.empty()) return;

    const auto targetAddr     = reinterpret_cast<std::uint64_t>(target);
    const auto trampolineAddr = reinterpret_cast<std::uint64_t>(trampoline);

    const int count = g_freezeState.contextCount.load(std::memory_order_acquire);
    for (int i = 0; i < count && i < kMaxFrozenThreads; ++i) {
        auto* uc = g_freezeState.contexts[i].load(std::memory_order_acquire);
        if (!uc) continue;

        const auto ip = GetIP(uc);
        if (const auto remapped = RemapIP(ip, targetAddr, prologueSize, trampolineAddr, alignMap, false);
            remapped != 0) {
            SetIP(uc, remapped);
        }
    }
}

void ThreadFreezer::reverseRemapThreadIPs(void* trampoline, void* target, std::span<const AlignEntry> alignMap) const {
    if (handles_.empty() || alignMap.empty()) return;

    const auto trampolineAddr = reinterpret_cast<std::uint64_t>(trampoline);
    const auto targetAddr     = reinterpret_cast<std::uint64_t>(target);

    // The sentinel entry gives us the total relocated code size.
    const std::size_t relocatedSize = alignMap.back().trampolineOffset;

    const int count = g_freezeState.contextCount.load(std::memory_order_acquire);
    for (int i = 0; i < count && i < kMaxFrozenThreads; ++i) {
        auto* uc = g_freezeState.contexts[i].load(std::memory_order_acquire);
        if (!uc) continue;

        const auto ip = GetIP(uc);
        if (const auto remapped = RemapIP(ip, trampolineAddr, relocatedSize, targetAddr, alignMap, true);
            remapped != 0) {
            SetIP(uc, remapped);
        }
    }
}

} // namespace Mortis::HookEngine
