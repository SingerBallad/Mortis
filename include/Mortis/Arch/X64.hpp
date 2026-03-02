#pragma once

#include <cstddef>
#include <cstdint>

namespace Mortis::HookEngine::X64 {

// Single-byte opcodes
/// @name Unconditional branches
/// @{
constexpr std::uint8_t kJmpRel8   = 0xEB; ///< JMP rel8
constexpr std::uint8_t kJmpRel32  = 0xE9; ///< JMP rel32
constexpr std::uint8_t kCallRel32 = 0xE8; ///< CALL rel32
/// @}

/// @name Conditional branches (rel8)
/// @{
constexpr std::uint8_t kJccRel8Lo = 0x70; ///< First Jcc rel8 opcode (JO)
constexpr std::uint8_t kJccRel8Hi = 0x7F; ///< Last  Jcc rel8 opcode (JG)
constexpr std::uint8_t kCondMask  = 0x0F; ///< Mask to extract condition code
/// @}

/// @name Padding / filler
/// @{
constexpr std::uint8_t kNop  = 0x90; ///< Single-byte NOP
constexpr std::uint8_t kInt3 = 0xCC; ///< INT3 (breakpoint / filler)
/// @}

/// @name Prefixes
/// @{
constexpr std::uint8_t kOperandSize = 0x66; ///< Operand-size override prefix
constexpr std::uint8_t kRepPrefix   = 0xF3; ///< REP / REPE prefix
constexpr std::uint8_t kRet         = 0xC3; ///< Near RET
/// @}

/// @name Two-byte opcode escape
/// @{
constexpr std::uint8_t k0F          = 0x0F; ///< Two-byte opcode escape prefix
constexpr std::uint8_t kJccRel32Lo  = 0x80; ///< First Jcc rel32 second byte (0F 80)
constexpr std::uint8_t kJccRel32Hi  = 0x8F; ///< Last  Jcc rel32 second byte (0F 8F)
constexpr std::uint8_t kMultiNop2nd = 0x1F; ///< Multi-byte NOP second byte (0F 1F ...)
/// @}

// Indirect jump / call (ModR/M-based)
/// @name FF-group opcodes (reg field selects operation)
/// @{
constexpr std::uint8_t kGroupFF      = 0xFF; ///< FF opcode group
constexpr std::uint8_t kJmpIndirect  = 0x25; ///< FF 25 — JMP [RIP+disp32]
constexpr std::uint8_t kCallIndirect = 0x15; ///< FF 15 — CALL [RIP+disp32]
/// @}

// ModR/M encoding for RIP-relative addressing
/// @brief Mask to test mod (bits 7-6) + r/m (bits 2-0) in ModR/M.
constexpr std::uint8_t kModRMMask = 0xC7;
/// @brief RIP-relative addressing: mod=00, r/m=101.
constexpr std::uint8_t kModRMRip = 0x05;

// Multibyte NOP patterns  (length → first N bytes)
// These are partial patterns used for recognition; see Disassembler.cpp.
/// @name Multibyte NOP third bytes (after 0F 1F)
/// @{
constexpr std::uint8_t kNop3_modrm = 0x00; ///< 3B: 0F 1F 00
constexpr std::uint8_t kNop4_modrm = 0x40; ///< 4B: 0F 1F 40 00
constexpr std::uint8_t kNop5_modrm = 0x44; ///< 5B: 0F 1F 44 00 00
constexpr std::uint8_t kNop7_modrm = 0x80; ///< 7B: 0F 1F 80 00 00 00 00
constexpr std::uint8_t kNop8_modrm = 0x84; ///< 8B: 0F 1F 84 00 00 00 00 00
/// @}

// Instruction / encoding sizes
/// @brief Size of JMP rel32 entry-point jump (E9 xx xx xx xx).
constexpr std::size_t kJmpRel32Size = 5;

/// @brief Size of CALL rel32 (E8 xx xx xx xx).
constexpr std::size_t kCallRel32Size = 5;

/// @brief Size of a Jcc rel32 (0F 8x xx xx xx xx).
constexpr std::size_t kJccRel32Size = 6;

/// @brief Size of an absolute indirect jump: FF 25 00000000 + 8-byte addr.
constexpr std::size_t kAbsJmpSize = 14;

/// @brief RE-P RET sequence size (F3 C3).
constexpr std::size_t kRepRetSize = 2;

/// @brief Dobby-style absolute call: FF 15 02000000 EB 08 <addr64>.
constexpr std::size_t kAbsCallSize = 16;

/// @brief disp32 for the absolute call trick: call [rip+2].
constexpr std::int32_t kAbsCallDisp = 2;

/// @brief jmp short offset for the absolute call trick: skip 8-byte addr.
constexpr std::uint8_t kAbsCallSkip = 0x08;

} // namespace Mortis::HookEngine::X64
