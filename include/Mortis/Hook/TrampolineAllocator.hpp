#pragma once

#include <Mortis/Hook/InstructionRelocator.hpp>
#include <Mortis/Result.hpp>

#include <deque>
#include <mutex>
#include <span>
#include <vector>

namespace Mortis::HookEngine {

/// @brief A single 64KB (or system-page-aligned) region of trampoline memory.
struct TrampolineRegion {
    void*       base     = nullptr; ///< Base address of the allocated region.
    std::size_t size     = 0;       ///< Region size in bytes.
    std::size_t used     = 0;       ///< Number of slots currently in use.
    std::size_t capacity = 0;       ///< Total slots in this region.

    /// @brief Slot-level free list (indices of freed slots).
    std::vector<std::size_t> freeList;
};

/// @brief Thread-safe allocator for trampoline memory.
class TrampolineAllocator {
public:
    static auto Instance() -> TrampolineAllocator& {
        static TrampolineAllocator instance;
        return instance;
    }

    ~TrampolineAllocator();

    TrampolineAllocator(const TrampolineAllocator&)                    = delete;
    auto operator=(const TrampolineAllocator&) -> TrampolineAllocator& = delete;

    /// @brief Allocate a trampoline slot near target (arch-specific branch range).
    [[nodiscard]] auto allocate(std::uint64_t nearAddr) -> Result<std::span<std::uint8_t>>;

    /// @brief Free a previously allocated trampoline slot.
    void free(void* slot);

private:
    TrampolineAllocator() = default;

    /// @brief Attempt to allocate a slot from an existing region.
    auto allocateFromExisting(std::uint64_t nearAddr) -> std::span<std::uint8_t>;

    /// @brief Allocate a new region within architecture near-range of nearAddr.
    auto allocateNewRegion(std::uint64_t nearAddr) -> Result<TrampolineRegion*>;

    /// @brief Slide-search for a free virtual address near @p center.
    auto findFreePageNear(std::uint64_t center, std::size_t size) -> Result<void*>;

    std::mutex                   mutex_{};
    std::deque<TrampolineRegion> regions_{};
};

} // namespace Mortis::HookEngine
