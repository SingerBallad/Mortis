#pragma once

#include <cstddef>
#include <cstdint>

namespace Mortis::HookEngine::ARM64 {
// NOP / Filler
constexpr std::uint32_t kNop = 0xD503201F; ///< NOP instruction

// Scratch register (ABI IP1 — linker/trampoline use)
constexpr int kScratchReg = 17; ///< X17 register index

// Instruction identification masks
//
// Usage:  (insn & kMask) == kPattern
/// @name B / BL  (±128 MB, imm26)
/// @{
constexpr std::uint32_t kB_BL_Mask    = 0x7C000000;
constexpr std::uint32_t kB_BL_Pattern = 0x14000000;
constexpr std::uint32_t kBL_Bit       = 1u << 31;   ///< set → BL, clear → B
constexpr std::uint32_t kB_BL_ImmMask = 0xFC000000; ///< opcode bits (keep)
constexpr std::uint32_t kImm26Mask    = 0x03FFFFFF;
/// @}

/// @name B.cond  (±1 MB, imm19)
/// @{
constexpr std::uint32_t kBcond_Mask    = 0xFF000010;
constexpr std::uint32_t kBcond_Pattern = 0x54000000;
constexpr std::uint32_t kBcond_Base    = 0x54000000; ///< template for re-encoding
/// @}

/// @name CBZ / CBNZ  (±1 MB, imm19)
/// @{
constexpr std::uint32_t kCBZ_Mask    = 0x7E000000;
constexpr std::uint32_t kCBZ_Pattern = 0x34000000;
constexpr std::uint32_t kCBZ_InvBit  = 1u << 24; ///< flip → CBZ ↔ CBNZ
/// @}

/// @name TBZ / TBNZ  (±32 KB, imm14)
/// @{
constexpr std::uint32_t kTBZ_Mask       = 0x7E000000;
constexpr std::uint32_t kTBZ_Pattern    = 0x36000000;
constexpr std::uint32_t kTBZ_InvBit     = 1u << 24;   ///< flip → TBZ ↔ TBNZ
constexpr std::uint32_t kImm14ClearMask = 0xFFF8001F; ///< clear imm14 field [18:5]
constexpr std::uint32_t kImm14Mask      = 0x3FFF;     ///< raw 14-bit value mask
/// @}

/// @name ADR / ADRP  (imm21, page-relative for ADRP)
/// @{
constexpr std::uint32_t kADR_Mask    = 0x1F000000;
constexpr std::uint32_t kADR_Pattern = 0x10000000;
constexpr std::uint32_t kADRP_Bit    = 1u << 31;  ///< set → ADRP, clear → ADR
constexpr std::uint64_t kPageMask    = ~0xFFFULL; ///< 4 KB page alignment mask
/// @}

/// @name LDR literal  (±1 MB, imm19)
/// @{
constexpr std::uint32_t kLdrLit_Mask    = 0x3B000000;
constexpr std::uint32_t kLdrLit_Pattern = 0x18000000;
constexpr std::uint32_t kLdrLit_VBit    = 0x04000000; ///< V bit → FP/NEON
/// @}

/// @name imm19 field (shared by B.cond / CBZ / LDR literal)
/// @{
constexpr std::uint32_t kImm19ClearMask = 0xFF00001F; ///< clear imm19 field [23:5]
constexpr std::uint32_t kImm19Mask      = 0x7FFFF;    ///< raw 19-bit value mask
constexpr int           kImm19Shift     = 5;          ///< imm19 bit position
/// @}

/// @name Condition code field (B.cond)
/// @{
constexpr std::uint32_t kCondFieldMask = 0x0F; ///< cond in bits [3:0]
/// @}

// Instruction templates (base encodings)
/// @name Branch register
/// @{
constexpr std::uint32_t kBR_Base  = 0xD61F0000; ///< BR  Xn  (Rn in [9:5])
constexpr std::uint32_t kBLR_Base = 0xD63F0000; ///< BLR Xn
/// @}

/// @name LDR (PC-relative literal)
/// @{
constexpr std::uint32_t kLdrX_Lit_Base = 0x58000000; ///< LDR Xt, label (imm19)
/// @}

/// @name Move wide immediate
/// @{
constexpr std::uint32_t kMOVZ_X_Base  = 0xD2800000; ///< MOVZ Xd, #imm16{, LSL #hw}
constexpr std::uint32_t kMOVN_X_Base  = 0x92800000; ///< MOVN Xd, #imm16{, LSL #hw}
constexpr std::uint32_t kMOVK_X_Base  = 0xF2800000; ///< MOVK Xd, #imm16{, LSL #hw}
constexpr int           kMoveImmShift = 5;          ///< imm16 starts at bit 5
constexpr int           kMoveHwShift  = 21;         ///< hw (halfword selector) at bit 21
/// @}

/// @name Load / Store (unsigned offset)
/// @{
constexpr std::uint32_t kLdrW_Base  = 0xB9400000; ///< LDR  Wt, [Xn]
constexpr std::uint32_t kLdrX_Base  = 0xF9400000; ///< LDR  Xt, [Xn]
constexpr std::uint32_t kLdrsw_Base = 0xB9800000; ///< LDRSW Xt, [Xn]
constexpr std::uint32_t kLdrS_UOff  = 0xBD400000; ///< LDR  St, [Xn] (32-bit FP)
constexpr std::uint32_t kLdrD_UOff  = 0xFD400000; ///< LDR  Dt, [Xn] (64-bit FP)
constexpr std::uint32_t kLdrQ_UOff  = 0x3DC00000; ///< LDR  Qt, [Xn] (128-bit FP/SIMD)
/// @}

// Sizes
/// @brief Size of the absolute branch sequence: LDR X17, #8; BR X17; .quad addr
constexpr std::size_t kAbsBranchSize = 16;

/// @brief Single ARM64 instruction size.
constexpr std::size_t kInsnSize = 4;

/// @brief imm19 skip value (5) to jump over an absolute branch sequence.
constexpr std::uint32_t kSkipAbsBranch = 5;

// Range limits (signed, in bytes, for relocation distance checks)
/// @brief B / BL: ±128 MB (2^27).
constexpr std::int64_t kBRange = 1LL << 27;

/// @brief B.cond / CBZ / CBNZ / LDR literal: ±1 MB (2^20).
constexpr std::int64_t kImm19Range = 1LL << 20;

/// @brief TBZ / TBNZ: ±32 KB (2^15).
constexpr std::int64_t kImm14Range = 1LL << 15;
} // namespace Mortis::HookEngine::ARM64
