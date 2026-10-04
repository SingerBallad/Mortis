#include <Mortis/Hook/ThreadFreezer.hpp>

#include <dirent.h>
#include <linux/futex.h>
#include <sched.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <ucontext.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <vector>

namespace Mortis::HookEngine {

namespace {

/// @brief Maximum number of threads simultaneously frozen.
constexpr int kMaxFrozenThreads = 4096;

/// @brief Upper bound on spins waiting for frozen threads to restore their signal
///        mask on teardown (sigreturn is near-instant, so this breaks after one or
///        two passes in practice; the cap only bounds the pathological case where a
///        thread re-blocks the freeze signal for its own reasons — the stability
///        re-read on the next enumeration still catches a straggler).
constexpr int kMaskRestoreMaxSpins = 2'000;

/// @brief How many times to re-read a thread's SigBlk before concluding it
///        *genuinely* blocks the freeze signal rather than merely unwinding from a
///        previous freeze's handler (where the kernel masks it until sigreturn).
///        A transient clears within a read or two; genuine blockers are rare, so a
///        small count keeps the hot path (Remove's retry loop) cheap.
constexpr int kBlockerConfirmReads = 8;

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

    /// TID of the thread that stored each context (parallel to @ref contexts),
    /// so the freeze can tell which signalled threads have acknowledged without a
    /// wall-clock timeout.
    std::atomic<pid_t> ackTids[kMaxFrozenThreads]{};

    void Reset() {
        active.store(0, std::memory_order_relaxed);
        readyCount.store(0, std::memory_order_relaxed);
        exitCount.store(0, std::memory_order_relaxed);
        contextCount.store(0, std::memory_order_relaxed);
        for (auto& ctx : contexts) {
            ctx.store(nullptr, std::memory_order_relaxed);
        }
        for (auto& t : ackTids) {
            t.store(0, std::memory_order_relaxed);
        }
    }
};

FreezeState g_freezeState;

/// @brief Bit mask value for a signal number in a /proc SigBlk-style mask.
/// @param sig Signal number (1-based, as used by the kernel/sigaction).
constexpr auto SignalBit(const int sig) -> std::uint64_t { return std::uint64_t{1} << (sig - 1); }

/// @brief Read a thread's blocked-signal mask from /proc/self/task/<tid>/status.
/// @return The blocked mask, or 0 if it cannot be read (treat as "blocks nothing").
auto ReadBlockedMask(const pid_t tid) -> std::uint64_t {
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/self/task/%d/status", static_cast<int>(tid));

    std::FILE* file = std::fopen(path, "re");
    if (!file) return 0;

    std::uint64_t mask = 0;
    char          line[256];
    while (std::fgets(line, sizeof(line), file) != nullptr) {
        if (std::strncmp(line, "SigBlk:", 7) == 0) {
            mask = std::strtoull(line + 7, nullptr, 16);
            break;
        }
    }
    std::fclose(file);
    return mask;
}

/// @brief Whether a signalled thread can no longer acknowledge the freeze — it has
///        exited, or our signal is pending on it yet blocked, so it will never be
///        delivered (the thread blocked freezeSig after we sent it).  Used to drop
///        laggards so the ready-wait always terminates.
auto LaggardCannotRespond(const pid_t tid, const std::uint64_t freezeBit) -> bool {
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/self/task/%d/status", static_cast<int>(tid));

    std::FILE* file = std::fopen(path, "re");
    if (!file) return true; // Exited.

    std::uint64_t pending = 0;
    std::uint64_t blocked = 0;
    int           seen    = 0;
    char          line[256];
    while (seen < 2 && std::fgets(line, sizeof(line), file) != nullptr) {
        if (std::strncmp(line, "SigPnd:", 7) == 0) {
            pending = std::strtoull(line + 7, nullptr, 16);
            ++seen;
        } else if (std::strncmp(line, "SigBlk:", 7) == 0) {
            blocked = std::strtoull(line + 7, nullptr, 16);
            ++seen;
        }
    }
    std::fclose(file);
    return (pending & blocked & freezeBit) != 0;
}

/// @brief Signal handler: stores ucontext, then blocks on futex until released.
void FreezeSignalHandler(int /*sig*/, siginfo_t* /*info*/, void* rawCtx) {
    auto* uc = static_cast<ucontext_t*>(rawCtx);

    if (g_freezeState.active.load(std::memory_order_acquire) == 0) return;

    if (const int slot = g_freezeState.contextCount.fetch_add(1, std::memory_order_relaxed); slot < kMaxFrozenThreads) {
        g_freezeState.contexts[slot].store(uc, std::memory_order_release);
        g_freezeState.ackTids[slot].store(static_cast<pid_t>(syscall(SYS_gettid)), std::memory_order_release);
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

    struct ThreadInfo {
        pid_t         tid;
        std::uint64_t blocked;
    };
    std::vector<ThreadInfo> threads;
    std::uint64_t           blockedUnion = 0;

    struct dirent* ent;
    while ((ent = readdir(dir)) != nullptr) {
        if (ent->d_name[0] == '.') continue;
        const pid_t tid = std::atoi(ent->d_name);
        if (tid == 0 || tid == selfTid) continue;
        const std::uint64_t blocked = ReadBlockedMask(tid);
        threads.push_back({tid, blocked});
        blockedUnion |= blocked;
    }
    closedir(dir);

    if (threads.empty()) {
        return Result<ThreadFreezer>::Ok(std::move(freezer));
    }

    struct sigaction sa{};
    struct sigaction oldSa{};
    sa.sa_sigaction = FreezeSignalHandler;
    sa.sa_flags     = SA_SIGINFO | SA_RESTART;
    sigfillset(&sa.sa_mask); // Block all signals inside the handler: prevents a
                             // rapid re-freeze from re-entering the handler on a
                             // thread still unwinding from the previous one.

    int freezeSig = 0;
    for (int candidate = SIGRTMIN; candidate <= SIGRTMAX; ++candidate) {
        if ((blockedUnion & SignalBit(candidate)) != 0) continue;
        if (sigaction(candidate, &sa, &oldSa) == 0) {
            freezeSig = candidate;
            break;
        }
    }
    if (freezeSig == 0) {
        for (int candidate = SIGRTMIN; candidate <= SIGRTMAX; ++candidate) {
            if (sigaction(candidate, &sa, &oldSa) == 0) {
                freezeSig = candidate;
                break;
            }
        }
    }
    if (freezeSig == 0) {
        return Result<ThreadFreezer>::Err(ErrorCode::HookInstallFailed, "Failed to install freeze signal handler");
    }
    freezer.freezeSig_ = freezeSig;

    const std::uint64_t freezeBit = SignalBit(freezeSig);

    const auto genuinelyBlocks = [freezeBit](const pid_t tid) {
        for (int i = 0; i < kBlockerConfirmReads; ++i) {
            if ((ReadBlockedMask(tid) & freezeBit) == 0) return false; // transient — cleared
            sched_yield();
        }
        return true; // stayed blocked across every read — genuine
    };

    std::vector<pid_t> toSignal;
    toSignal.reserve(threads.size());
    for (const auto& [tid, blocked] : threads) {
        if ((blocked & freezeBit) == 0 || !genuinelyBlocks(tid)) {
            toSignal.push_back(tid);
        }
        // else: genuine blocker — left unfrozen (see above).
    }

    g_freezeState.active.store(1, std::memory_order_release);

    // Send the freeze signal via tgkill(2) to the threads that can run the handler.
    freezer.handles_.reserve(toSignal.size());
    for (const pid_t tid : toSignal) {
        if (syscall(SYS_tgkill, getpid(), tid, freezeSig) == 0) {
            freezer.handles_.push_back(tid);
        }
    }

    std::vector<pid_t> pending = freezer.handles_;
    while (!pending.empty()) {
        const int acked = std::min(g_freezeState.contextCount.load(std::memory_order_acquire), kMaxFrozenThreads);
        for (int i = 0; i < acked; ++i) {
            if (const pid_t t = g_freezeState.ackTids[i].load(std::memory_order_acquire); t != 0) {
                std::erase(pending, t);
            }
        }
        if (pending.empty()) break;
        std::erase_if(pending, [freezeBit](const pid_t t) { return LaggardCannotRespond(t, freezeBit); });
        if (pending.empty()) break;
        sched_yield();
    }

    // Restore old signal handler (all signals already delivered).
    sigaction(freezeSig, &oldSa, nullptr);

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

    while (g_freezeState.exitCount.load(std::memory_order_acquire)
           < g_freezeState.readyCount.load(std::memory_order_acquire)) {
        sched_yield();
    }

    if (freezeSig_ != 0) {
        const std::uint64_t freezeBit = SignalBit(freezeSig_);
        for (int spins = 0; spins < kMaskRestoreMaxSpins; ++spins) {
            bool allRestored = true;
            for (const pid_t tid : handles_) {
                if ((ReadBlockedMask(tid) & freezeBit) != 0) {
                    allRestored = false;
                    break;
                }
            }
            if (allRestored) break;
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

void ThreadFreezer::remapRange(const std::uint64_t lo, const std::uint64_t hi, const std::uint64_t dest) const {
    if (handles_.empty() || lo >= hi) return;

    const int count = g_freezeState.contextCount.load(std::memory_order_acquire);
    for (int i = 0; i < count && i < kMaxFrozenThreads; ++i) {
        auto* uc = g_freezeState.contexts[i].load(std::memory_order_acquire);
        if (!uc) continue;

        if (const auto ip = GetIP(uc); ip >= lo && ip < hi) {
            SetIP(uc, dest);
        }
    }
}

auto ThreadFreezer::anyThreadInRange(const std::uint64_t lo, const std::uint64_t hi) const -> bool {
    if (handles_.empty() || lo >= hi) return false;

    const int count = g_freezeState.contextCount.load(std::memory_order_acquire);
    for (int i = 0; i < count && i < kMaxFrozenThreads; ++i) {
        auto* uc = g_freezeState.contexts[i].load(std::memory_order_acquire);
        if (!uc) continue;
        if (const auto ip = GetIP(uc); ip >= lo && ip < hi) return true;
    }
    return false;
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
