#pragma once

#include <Mortis/Config.hpp>
#include <Mortis/Process.hpp>

#include <algorithm>
#include <charconv>
#include <fstream>
#include <link.h>
#include <optional>
#include <string>
#include <sys/mman.h>
#include <utility>
#include <vector>

namespace Mortis::LinuxDetail {

struct ProcMapEntry {
    Address start = 0;
    Address end   = 0;
    bool    read  = false;
    bool    write = false;
    bool    exec  = false;
};

/// @brief Convert a MemoryProtection bitmask to native Linux mprotect flags.
inline auto ToNativeProtection(const MemoryProtection prot) -> int {
    int flags = PROT_NONE;
    if (HasFlag(prot, MemoryProtection::Read)) flags |= PROT_READ;
    if (HasFlag(prot, MemoryProtection::Write)) flags |= PROT_WRITE;
    if (HasFlag(prot, MemoryProtection::Execute)) flags |= PROT_EXEC;
    return flags;
}

/// @brief Compute the contiguous load range [lo, hi) from PT_LOAD segments.
inline auto ComputeLoadRange(const dl_phdr_info* info) -> std::optional<std::pair<Address, std::size_t>> {
    Address lo = ~Address{0}, hi = 0;
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        if (info->dlpi_phdr[i].p_type != PT_LOAD) continue;
        const auto segStart = info->dlpi_addr + info->dlpi_phdr[i].p_vaddr;
       const  auto segEnd   = segStart + info->dlpi_phdr[i].p_memsz;
        if (segStart < lo) lo = segStart;
        if (segEnd > hi) hi = segEnd;
    }
    if (hi <= lo) return std::nullopt;
    return std::pair{lo, (hi - lo)};
}

inline auto ParseProcMapLine(const std::string_view line) -> std::optional<ProcMapEntry> {
    const auto dashPos  = line.find('-');
    const auto spacePos = line.find(' ', dashPos == std::string::npos ? 0 : dashPos + 1);
    if (dashPos == std::string::npos || spacePos == std::string::npos) return std::nullopt;

    ProcMapEntry entry{};
    if (const auto [p1, e1] = std::from_chars(line.data(), line.data() + dashPos, entry.start, 16); e1 != std::errc{}) return std::nullopt;
    if (const auto [p2, e2] = std::from_chars(line.data() + dashPos + 1, line.data() + spacePos, entry.end, 16);
        e2 != std::errc{} || entry.end <= entry.start) return std::nullopt;

    const auto permsPos = spacePos + 1;
    if (permsPos + 2 >= line.size()) return std::nullopt;
    entry.read  = line[permsPos] == 'r';
    entry.write = line[permsPos + 1] == 'w';
    entry.exec  = line[permsPos + 2] == 'x';
    return entry;
}

template <typename Fn>
void ForEachProcMapEntry(Fn&& fn) {
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) return;

    std::string line;
    while (std::getline(maps, line)) {
        auto entry = ParseProcMapLine(line);
        if (!entry) continue;
        if (!fn(*entry)) break;
    }
}

inline auto GetReadableMappedRanges(const Address regionBase, const std::size_t regionSize)
    -> std::vector<std::pair<Address, std::size_t>> {
    std::vector<std::pair<Address, std::size_t>> ranges;
    if (regionSize == 0) return ranges;

    const Address regionEnd = regionBase + regionSize;
    if (regionEnd <= regionBase) return ranges;

    ForEachProcMapEntry([&](const ProcMapEntry& entry) {
        if (!entry.read) return true;
        const Address overlapStart = std::max(entry.start, regionBase);
        if (const Address overlapEnd = std::min(entry.end, regionEnd); overlapEnd > overlapStart) {
            ranges.emplace_back(overlapStart, overlapEnd - overlapStart);
        }
        return true;
    });

    return ranges;
}

} // namespace Mortis::LinuxDetail
