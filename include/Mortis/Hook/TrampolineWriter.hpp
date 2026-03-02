#pragma once

#include <Mortis/Hook/InstructionRelocator.hpp>

#include <Mortis/Result.hpp>

#include <cstdint>
#include <span>

namespace Mortis::HookEngine {

/// @brief Describes the layout inside a filled trampoline slot.
struct TrampolineLayout {
    std::size_t entryOffset  = 0; ///< Offset (in slot) where the callable trampoline code starts.
    std::size_t codeInOffset = 0; ///< (x64) Offset of the code-in JMP to detour; 0 on ARM64.
    std::size_t totalUsed    = 0; ///< Total bytes written into the slot.
};

/// @brief Fill a trampoline slot with code-in, prologue, and jump-back.
[[nodiscard]] auto WriteTrampoline(
    std::span<std::uint8_t>          slot,
    const std::vector<std::uint8_t>& relocated,
    std::uint64_t                    jumpBackTo,
    std::uint64_t                    detourAddr
) -> Result<TrampolineLayout>;

/// @brief Build entry-point jump bytes for the target function.
[[nodiscard]] auto BuildEntryJump(std::uint64_t target, std::uint64_t dest, std::size_t patchSize)
    -> Result<std::vector<std::uint8_t>>;

} // namespace Mortis::HookEngine
