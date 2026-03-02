#pragma once

#include <Mortis/Hook/Disassembler.hpp>
#include <Mortis/Hook/HookRegistry.hpp>

#include <Mortis/Result.hpp>

#include <cstdint>
#include <vector>

namespace Mortis::HookEngine {

/// @brief Result of relocating a sequence of instructions.
struct RelocationResult {
    std::vector<std::uint8_t> code;     ///< Relocated machine code bytes.
    std::vector<AlignEntry>   alignMap; ///< Source ↔ trampoline offset mapping.
};

/// @brief Relocate prologue instructions to a trampoline address.
[[nodiscard]] auto RelocateInstructions(const PrologueInfo& prologue, std::uint64_t trampolineBase)
    -> Result<RelocationResult>;

#ifdef MORTIS_ARCH_X64
inline constexpr std::size_t kJumpSize           = 5;  ///< JMP rel32 (Detours-style 2-level).
inline constexpr std::size_t kMaxTrampolineCode  = 72; ///< 30 B code + 14 B jump-back + margin.
inline constexpr std::size_t kTrampolineSlotSize = 96; ///< Detours-compatible slot.
#elif defined(MORTIS_ARCH_ARM64)
inline constexpr std::size_t kJumpSize           = 4;   ///< Prefer single B imm26 when trampoline is near.
inline constexpr std::size_t kMaxTrampolineCode  = 144; ///< ARM64 instructions can expand 4x.
inline constexpr std::size_t kTrampolineSlotSize = 184; ///< Detours ARM64-compatible slot.
#endif

} // namespace Mortis::HookEngine
