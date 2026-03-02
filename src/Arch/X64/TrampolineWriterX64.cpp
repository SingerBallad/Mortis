#include <Mortis/Arch/X64.hpp>
#include <Mortis/Hook/TrampolineWriter.hpp>

#include <algorithm>
#include <cstring>
#include <limits>

namespace Mortis::HookEngine {

namespace {

/// @brief Write 14-byte absolute jump at a raw pointer.
void WriteAbsJump64(std::span<std::uint8_t, X64::kAbsJmpSize> dst, const std::uint64_t target) {
    dst[0] = X64::kGroupFF;
    dst[1] = X64::kJmpIndirect;
    std::memset(dst.data() + 2, 0, 4);
    std::memcpy(dst.data() + 6, &target, sizeof(target));
}

} // anonymous namespace

auto WriteTrampoline(
    std::span<std::uint8_t>          slot,
    const std::vector<std::uint8_t>& relocated,
    const std::uint64_t              jumpBackTo,
    const std::uint64_t              detourAddr
) -> Result<TrampolineLayout> {
    // [code-in 14B]
    // [prologue]
    // [jump-back 14B]

    if (const auto totalNeeded = X64::kAbsJmpSize + relocated.size() + X64::kAbsJmpSize; slot.size() < totalNeeded) {
        return Result<TrampolineLayout>::Err(ErrorCode::HookInstallFailed, "Trampoline slot too small for x64 layout");
    }

    // fill entire slot
    std::memset(slot.data(), X64::kInt3, slot.size());

    TrampolineLayout layout;
    std::size_t      cursor = 0;

    // 1. JMP [RIP+0] → detour
    layout.codeInOffset = cursor;
    WriteAbsJump64(std::span<std::uint8_t, X64::kAbsJmpSize>(slot.data() + cursor, X64::kAbsJmpSize), detourAddr);
    cursor += X64::kAbsJmpSize;

    // 2. Relocated prologue
    layout.entryOffset = cursor;
    std::memcpy(slot.data() + cursor, relocated.data(), relocated.size());
    cursor += relocated.size();

    // 3. JMP [RIP+0] → originalCode
    WriteAbsJump64(std::span<std::uint8_t, X64::kAbsJmpSize>(slot.data() + cursor, X64::kAbsJmpSize), jumpBackTo);
    cursor += X64::kAbsJmpSize;

    layout.totalUsed = cursor;
    return Result<TrampolineLayout>::Ok(layout);
}

auto BuildEntryJump(const std::uint64_t target, const std::uint64_t dest, const std::size_t patchSize)
    -> Result<std::vector<std::uint8_t>> {
    if (patchSize < X64::kJmpRel32Size) {
        return Result<std::vector<std::uint8_t>>::Err(
            ErrorCode::HookInstallFailed,
            "Patch size too small for x64 JMP rel32"
        );
    }

    const auto delta = static_cast<std::int64_t>(dest) - static_cast<std::int64_t>(target + X64::kJmpRel32Size);

    if (delta < std::numeric_limits<std::int32_t>::min() || delta > std::numeric_limits<std::int32_t>::max()) {
        return Result<std::vector<std::uint8_t>>::Err(
            ErrorCode::HookInstallFailed,
            "Code-in is too far for JMP rel32 (need ±2GB)"
        );
    }

    std::vector<std::uint8_t> patch;
    patch.push_back(X64::kJmpRel32);
    const auto rel32 = static_cast<std::int32_t>(delta);
    const auto p     = reinterpret_cast<const std::uint8_t*>(&rel32);
    patch.insert(patch.end(), p, p + 4);

    // NOP-fill remainder.
    while (patch.size() < patchSize) patch.push_back(X64::kNop);

    return Result<std::vector<std::uint8_t>>::Ok(std::move(patch));
}

} // namespace Mortis::HookEngine
