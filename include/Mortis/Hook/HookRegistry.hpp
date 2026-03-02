#pragma once

#include <Mortis/Config.hpp>

#include <algorithm>
#include <cstdint>
#include <mutex>
#include <ranges>
#include <unordered_map>
#include <vector>

namespace Mortis::HookEngine {
/// @brief Maps target prologue offset to trampoline offset.
struct AlignEntry {
    std::uint8_t targetOffset     = 0; ///< Offset in the original function.
    std::uint8_t trampolineOffset = 0; ///< Corresponding offset in the trampoline.
};

/// @brief A node in a hook chain, ordered by (priority, sequence).
struct ChainNode {
    int           priority            = 0;       ///< Lower = higher priority.
    std::uint64_t sequence            = 0;       ///< Monotonic insertion counter (FIFO for same priority).
    void*         detourRawFn         = nullptr; ///< Raw function pointer dispatching to the detour.
    void**        originalPtrLocation = nullptr; ///< Where to write the next-in-chain address.

    auto operator<(const ChainNode& rhs) const noexcept -> bool {
        if (priority != rhs.priority) return priority < rhs.priority;
        return sequence < rhs.sequence;
    }
};

/// @brief Persistent record for a single installed inline hook.
struct HookEntry {
    void*                     originalTarget = nullptr;    ///< Original function address.
    void*                     trampoline     = nullptr;    ///< Allocated trampoline buffer.
    std::size_t               trampolineSize = 0;          ///< Size of the trampoline buffer.
    std::vector<std::uint8_t> savedPrologue;               ///< Backup of the overwritten prologue bytes.
    std::size_t               prologueSize = 0;            ///< Number of bytes overwritten.
    std::vector<AlignEntry>   alignMap;                    ///< Instruction boundary mapping.
    void*                     codeAfterPrologue = nullptr; ///< First instruction after the overwritten region.
    std::size_t               jumpSize          = 0;       ///< Size of the jump written at the target entry.
    std::size_t               entryOffset       = 0;       ///< Offset of callable prologue in the trampoline.
    std::size_t               codeInOffset      = 0;       ///< Offset of code-in JMP in the trampoline (x64).
    std::vector<ChainNode>    chain;                       ///< Ordered hook chain.
    std::uint64_t             nextSequence = 0;            ///< Monotonic counter for chain insertion.
};

/// @brief Thread-safe global registry of active hooks, keyed by trampoline address.
class HookRegistry {
public:
    static auto Instance() -> HookRegistry& {
        static HookRegistry instance;
        return instance;
    }

    /// @brief Register a new hook entry.
    void add(void* trampolineKey, HookEntry entry) {
        std::lock_guard lock(mutex_);
        entries_[trampolineKey] = std::move(entry);
    }

    /// @brief Find a hook entry by its trampoline address.
    /// @return Pointer to the entry, or nullptr if not found.
    auto find(void* trampolineKey) -> HookEntry* {
        std::lock_guard lock(mutex_);
        const auto      it = entries_.find(trampolineKey);
        return it != entries_.end() ? &it->second : nullptr;
    }

    /// @brief Find a hook entry by the original target address.
    auto findByTarget(const void* target) -> HookEntry* {
        std::lock_guard lock(mutex_);
        for (auto& entry : entries_ | std::views::values) {
            if (entry.originalTarget == target) return &entry;
        }
        return nullptr;
    }

    /// @brief Find a hook entry whose trampoline buffer contains @p addr.
    auto findContainingTrampoline(const void* addr) -> HookEntry* {
        std::lock_guard lock(mutex_);
        const auto      a = reinterpret_cast<std::uintptr_t>(addr);
        for (auto& entry : entries_ | std::views::values) {
            if (const auto base = reinterpret_cast<std::uintptr_t>(entry.trampoline);
                a >= base && a < base + entry.trampolineSize)
                return &entry;
        }
        return nullptr;
    }

    /// @brief Remove a hook entry by its trampoline address.
    void remove(void* trampolineKey) {
        std::lock_guard lock(mutex_);
        entries_.erase(trampolineKey);
    }

    /// @brief Invoke a callback for each registered hook entry.
    /// @tparam F Callable with signature void(void* key, HookEntry& entry).
    template <typename F>
    void forEach(F&& fn) {
        std::lock_guard lock(mutex_);
        for (auto& [key, entry] : entries_) fn(key, entry);
    }

    /// @brief Return the number of active hooks.
    [[nodiscard]] auto size() -> std::size_t {
        std::lock_guard lock(mutex_);
        return entries_.size();
    }

private:
    HookRegistry() = default;

    std::mutex                           mutex_;
    std::unordered_map<void*, HookEntry> entries_;
};
} // namespace Mortis::HookEngine
