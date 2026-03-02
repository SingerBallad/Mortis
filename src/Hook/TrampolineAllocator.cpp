#include <Mortis/Hook/TrampolineAllocator.hpp>

#ifdef MORTIS_ARCH_ARM64
#include <Mortis/Arch/ARM64.hpp>
#endif

#include <algorithm>
#include <cstring>

#ifdef MORTIS_OS_WINDOWS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#else
#include <cinttypes>
#include <fstream>
#include <string>
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace Mortis::HookEngine {

namespace {

/// @brief Region size (64KB — Detours compatibility).
constexpr std::size_t kRegionSize = 64 * 1024;

#ifdef MORTIS_ARCH_X64
/// @brief Near-range limit for x64 JMP rel32.
constexpr std::int64_t kX64NearRange = 0x7FFF0000LL; // leave some slack
#endif

[[maybe_unused]] constexpr std::int64_t kDefaultNearRange = 0x7FFF0000LL;

#ifdef MORTIS_ARCH_ARM64
/// @brief Near-range limit for ARM64 B imm26 (leave one instruction for slack).
constexpr std::int64_t kArm64BranchRange = ARM64::kBRange - static_cast<std::int64_t>(ARM64::kInsnSize);
#endif

#if defined(MORTIS_ARCH_X64) || defined(MORTIS_ARCH_ARM64)
constexpr std::size_t kSlotSize = kTrampolineSlotSize;
#else
// Fallback for IDE static analysis when architecture macros are unavailable.
constexpr std::size_t kSlotSize = 184;
#endif

auto GetNearRange() -> std::int64_t {
#ifdef MORTIS_ARCH_X64
    return kX64NearRange;
#elif defined(MORTIS_ARCH_ARM64)
    return kArm64BranchRange;
#else
    // Fallback for static-analysis contexts without CMake-defined arch macros.
    return kDefaultNearRange;
#endif
}

/// @brief System page size (cached at first use).
auto GetPageSize() -> std::size_t {
#ifdef MORTIS_OS_WINDOWS
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    return static_cast<std::size_t>(si.dwAllocationGranularity);
#else
    return static_cast<std::size_t>(sysconf(_SC_PAGESIZE));
#endif
}

/// @brief Round up to allocation granularity.
auto AlignUp(const std::size_t value, const std::size_t alignment) -> std::size_t {
    return (value + alignment - 1) & ~(alignment - 1);
}

/// @brief Check if @p addr is within architecture near-range of @p center.
auto IsInRange(const std::uint64_t addr, const std::uint64_t center) -> bool {
    const auto delta = static_cast<std::int64_t>(addr) - static_cast<std::int64_t>(center);
    const auto range = GetNearRange();
    return delta >= -range && delta <= range;
}

/// @brief Free a page allocation.
void FreePages(void* base, [[maybe_unused]] std::size_t size) {
#ifdef MORTIS_OS_WINDOWS
    VirtualFree(base, 0, MEM_RELEASE);
#else
    munmap(base, size);
#endif
}

} // anonymous namespace

// Public API
TrampolineAllocator::~TrampolineAllocator() {
    for (auto& region : regions_) {
        if (region.base) FreePages(region.base, region.size);
    }
}

auto TrampolineAllocator::allocate(const std::uint64_t nearAddr) -> Result<std::span<std::uint8_t>> {
    std::lock_guard lock(mutex_);

    // 1. Try existing regions first.
    if (const auto existing = allocateFromExisting(nearAddr); !existing.empty())
        return Result<std::span<std::uint8_t>>::Ok(existing);

    // 2. Allocate a new region.
    auto regionResult = allocateNewRegion(nearAddr);
    if (!regionResult)
        return Result<std::span<std::uint8_t>>::Err(regionResult.code(), regionResult.error());

    const auto* region = *regionResult;
    (void)region; // used indirectly via AllocateFromExisting
    const auto slot = allocateFromExisting(nearAddr);
    if (slot.empty()) {
        return Result<std::span<std::uint8_t>>::Err(
            ErrorCode::HookInstallFailed,
            "Failed to allocate from freshly created region"
        );
    }
    return Result<std::span<std::uint8_t>>::Ok(slot);
}

void TrampolineAllocator::free(void* slot) {
    std::lock_guard lock(mutex_);
    const auto      addr = static_cast<std::uint8_t*>(slot);

    for (auto& region : regions_) {
        if (const auto base = static_cast<std::uint8_t*>(region.base); addr >= base && addr < base + region.size) {
            const auto index = static_cast<std::size_t>(addr - base) / kSlotSize;

            // Guard against double-free: if this slot is already in the free list, bail.
            if (std::find(region.freeList.begin(), region.freeList.end(), index) != region.freeList.end()) {
                return;
            }

            if (region.used > 0) --region.used;

            // Recycle this slot on subsequent allocations.
            region.freeList.push_back(index);

            // Zero-fill slot for safety.
            std::memset(addr, 0xCC, kSlotSize);
            return;
        }
    }
}

// Private helpers
auto TrampolineAllocator::allocateFromExisting(const std::uint64_t nearAddr) -> std::span<std::uint8_t> {
    for (auto& region : regions_) {
        if (!IsInRange(reinterpret_cast<std::uint64_t>(region.base), nearAddr)) continue;

        const auto base = static_cast<std::uint8_t*>(region.base);

        // Prefer free-list recycling.
        if (!region.freeList.empty()) {
            auto idx = region.freeList.back();
            region.freeList.pop_back();
            ++region.used;
            return {base + idx * kSlotSize, kSlotSize};
        }

        // Linear bump.
        if (region.used < region.capacity) {
            auto offset = region.used * kSlotSize;
            ++region.used;
            return {base + offset, kSlotSize};
        }
    }
    return {};
}

auto TrampolineAllocator::allocateNewRegion(std::uint64_t nearAddr) -> Result<TrampolineRegion*> {
    auto pageResult = findFreePageNear(nearAddr, kRegionSize);
    if (!pageResult) return Result<TrampolineRegion*>::Err(pageResult.code(), pageResult.error());

    void*            base = *pageResult;
    TrampolineRegion region;
    region.base     = base;
    region.size     = kRegionSize;
    region.used     = 0;
    region.capacity = kRegionSize / kSlotSize;

    // Fill with INT3 / UDF for safety.
    std::memset(base, 0xCC, kRegionSize);

    regions_.push_back(std::move(region));
    return Result<TrampolineRegion*>::Ok(&regions_.back());
}

auto TrampolineAllocator::findFreePageNear(const std::uint64_t center, const std::size_t size) -> Result<void*> {
    const auto pageGranularity = GetPageSize();
    const auto alignedSize     = AlignUp(size, pageGranularity);

#ifdef MORTIS_OS_WINDOWS
    // VirtualQuery sliding search
    // range: [lo, hi].
    const auto nearRange = GetNearRange();
    auto lo = static_cast<std::uint64_t>(
        std::max(static_cast<std::int64_t>(center) - nearRange, static_cast<std::int64_t>(0x10000))
    );
    const auto hi = center + static_cast<std::uint64_t>(nearRange);

    // Round to allocation granularity.
    lo = AlignUp(lo, pageGranularity);

    // Alternate low/high search from center outward.
    auto probeHi = AlignUp(center, pageGranularity);
    auto probeLo = probeHi >= pageGranularity ? probeHi - pageGranularity : 0ULL;

    for (int attempts = 0; attempts < 4096; ++attempts) {
        // Try high side.
        if (probeHi <= hi) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<void*>(probeHi), &mbi, sizeof(mbi)) > 0) {
                if (mbi.State == MEM_FREE && mbi.RegionSize >= alignedSize) {
                    const auto candidate = AlignUp(reinterpret_cast<std::size_t>(mbi.BaseAddress), pageGranularity);
                    auto*      page      = VirtualAlloc(
                        reinterpret_cast<void*>(candidate),
                        alignedSize,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE
                    );
                    if (page && IsInRange(reinterpret_cast<std::uint64_t>(page), center))
                        return Result<void*>::Ok(page);
                    if (page) VirtualFree(page, 0, MEM_RELEASE);
                }
                probeHi = reinterpret_cast<std::uint64_t>(mbi.BaseAddress) + mbi.RegionSize;
                probeHi = AlignUp(probeHi, pageGranularity);
            } else {
                probeHi = hi + 1; // stop
            }
        }

        // Try low side.
        if (probeLo >= lo) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<void*>(probeLo), &mbi, sizeof(mbi)) > 0) {
                if (mbi.State == MEM_FREE && mbi.RegionSize >= alignedSize) {
                    const auto candidate = AlignUp(reinterpret_cast<std::size_t>(mbi.BaseAddress), pageGranularity);
                    auto*      page      = VirtualAlloc(
                        reinterpret_cast<void*>(candidate),
                        alignedSize,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE
                    );
                    if (page && IsInRange(reinterpret_cast<std::uint64_t>(page), center))
                        return Result<void*>::Ok(page);
                    if (page) VirtualFree(page, 0, MEM_RELEASE);
                }
            }
            probeLo = probeLo >= pageGranularity ? probeLo - pageGranularity : 0;
        }

        if (probeHi > hi && probeLo < lo) break;
    }

#else
        const auto nearRange = GetNearRange();

    // Linux: scan /proc/self/maps for gaps (Dobby 3-level approach)

    struct MemRange {
        std::uint64_t start;
        std::uint64_t end;
    };
    std::vector<MemRange> mappings;

    {
        std::ifstream maps("/proc/self/maps");
        std::string   line;
        while (std::getline(maps, line)) {
            std::uint64_t s = 0, e = 0;
            if (std::sscanf(line.c_str(), "%" SCNx64 "-%" SCNx64, &s, &e) == 2) mappings.push_back({s, e});
        }
    }

    std::sort(mappings.begin(), mappings.end(), [](auto& a, auto& b) { return a.start < b.start; });

    // Find gaps between existing mappings.
    auto tryGap = [&](std::uint64_t gapStart, std::uint64_t gapEnd) -> void* {
        if (gapEnd <= gapStart) return nullptr;
        auto aligned = AlignUp(static_cast<std::size_t>(gapStart), pageGranularity);
        if (aligned + alignedSize > gapEnd) return nullptr;
        if (!IsInRange(aligned, center)) return nullptr;

        void* p = mmap(
            reinterpret_cast<void*>(aligned),
            alignedSize,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
            -1,
            0
        );
        if (p != MAP_FAILED) return p;
        return nullptr;
    };

    // Search outward from center.
    for (std::size_t i = 0; i < mappings.size(); ++i) {
        auto gapStart = (i == 0) ? 0x10000ULL : mappings[i - 1].end;
        auto gapEnd   = mappings[i].start;

        if (auto* p = tryGap(gapStart, gapEnd)) {
            if (IsInRange(reinterpret_cast<std::uint64_t>(p), center)) return Result<void*>::Ok(p);
            munmap(p, alignedSize);
        }
    }

    // Try after last mapping.
    if (!mappings.empty()) {
        auto gapStart = mappings.back().end;
        auto gapEnd   = gapStart + static_cast<std::uint64_t>(nearRange);
        if (auto* p = tryGap(gapStart, gapEnd)) return Result<void*>::Ok(p);
    }

    // Fallback: let OS decide.
    {
        void* p = mmap(nullptr, alignedSize, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p != MAP_FAILED && IsInRange(reinterpret_cast<std::uint64_t>(p), center)) return Result<void*>::Ok(p);
        if (p != MAP_FAILED) munmap(p, alignedSize);
    }

#endif

    return Result<void*>::Err(ErrorCode::HookInstallFailed, "Cannot allocate trampoline memory near target");
}

} // namespace Mortis::HookEngine
