#include <Mortis/Arch/ARM64.hpp>
#include <Mortis/Hook/InstructionRelocator.hpp>

#include <array>
#include <cstring>

namespace Mortis::HookEngine {

namespace {

using namespace ARM64;

struct Emitter {
    std::vector<std::uint8_t>& buf;

    void Inst(const std::uint32_t v) const {
        const auto p = reinterpret_cast<const std::uint8_t*>(&v);
        buf.insert(buf.end(), p, p + 4);
    }

    void Addr64(const std::uint64_t v) const {
        const auto p = reinterpret_cast<const std::uint8_t*>(&v);
        buf.insert(buf.end(), p, p + 8);
    }

    void AbsoluteBranch(const std::uint64_t target) const {
        Inst(kLdrX_Lit_Base | (2 << kImm19Shift) | kScratchReg);
        Inst(kBR_Base | kScratchReg << 5);
        Addr64(target);
    }

    void AbsoluteBranchLink(const std::uint64_t target) const {
        Inst(kLdrX_Lit_Base | 2 << kImm19Shift | kScratchReg);
        Inst(kBLR_Base | kScratchReg << 5);
        Addr64(target);
    }

    void MovImm64(const std::uint32_t rd, const std::uint64_t imm) const {
        std::array<std::uint16_t, 4> pieces{};
        for (int i = 0; i < 4; ++i) pieces[i] = static_cast<std::uint16_t>((imm >> (i * 16)) & 0xFFFF);

        int zeros = 0, fffs = 0;
        for (const auto piece : pieces) {
            if (piece == 0) ++zeros;
            if (piece == 0xFFFF) ++fffs;
        }

        const bool useMovn = fffs > zeros;
        bool       first   = true;
        for (int i = 0; i < 4; ++i) {
            const std::uint16_t piece = pieces[i];
            if (const std::uint16_t defPiece = useMovn ? 0xFFFF : 0x0000; !first && piece == defPiece) continue;

            if (first) {
                if (useMovn) {
                    std::uint32_t inst  = kMOVN_X_Base;
                    inst               |= rd;
                    inst               |= static_cast<std::uint16_t>(~piece) << kMoveImmShift;
                    inst               |= static_cast<std::uint32_t>(i) << kMoveHwShift;
                    Inst(inst);
                } else {
                    std::uint32_t inst  = kMOVZ_X_Base;
                    inst               |= rd;
                    inst               |= static_cast<std::uint32_t>(piece) << kMoveImmShift;
                    inst               |= static_cast<std::uint32_t>(i) << kMoveHwShift;
                    Inst(inst);
                }
                first = false;
            } else {
                std::uint32_t inst  = kMOVK_X_Base;
                inst               |= rd;
                inst               |= static_cast<std::uint32_t>(piece) << kMoveImmShift;
                inst               |= static_cast<std::uint32_t>(i) << kMoveHwShift;
                Inst(inst);
            }
        }
    }
};

auto Bits(const std::uint32_t val, const int lo, const int hi) -> std::uint32_t {
    return (val >> lo) & ((1u << (hi - lo + 1)) - 1u);
}

auto SignExtend(const std::uint64_t val, const int bitWidth) -> std::int64_t {
    const auto shift = 64 - bitWidth;
    return static_cast<std::int64_t>(val << shift) >> shift;
}

auto DecodeB(const std::uint32_t insn, const std::uint64_t pc) -> std::uint64_t {
    const auto imm26  = Bits(insn, 0, 25);
    const auto offset = SignExtend(imm26, 26) * 4;
    return pc + static_cast<std::uint64_t>(offset);
}

auto DecodeImm19(const std::uint32_t insn, const std::uint64_t pc) -> std::uint64_t {
    const auto imm19  = Bits(insn, 5, 23);
    const auto offset = SignExtend(imm19, 19) * 4;
    return pc + static_cast<std::uint64_t>(offset);
}

auto DecodeImm14(const std::uint32_t insn, const std::uint64_t pc) -> std::uint64_t {
    const auto imm14  = Bits(insn, 5, 18);
    const auto offset = SignExtend(imm14, 14) * 4;
    return pc + static_cast<std::uint64_t>(offset);
}

auto DecodeAdrOffset(const std::uint32_t insn, const std::uint64_t pc) -> std::uint64_t {
    const auto immlo  = Bits(insn, 29, 30);
    const auto immhi  = Bits(insn, 5, 23);
    const auto imm    = (immhi << 2) | immlo;
    const auto offset = SignExtend(imm, 21);
    if ((insn & kADRP_Bit) != 0) return (pc & kPageMask) + static_cast<std::uint64_t>(offset << 12);
    return pc + static_cast<std::uint64_t>(offset);
}

auto IsB_BL(const std::uint32_t i) -> bool { return (i & kB_BL_Mask) == kB_BL_Pattern; }
auto IsBcond(const std::uint32_t i) -> bool { return (i & kBcond_Mask) == kBcond_Pattern; }
auto IsCBZ(const std::uint32_t i) -> bool { return (i & kCBZ_Mask) == kCBZ_Pattern; }
auto IsTBZ(const std::uint32_t i) -> bool { return (i & kTBZ_Mask) == kTBZ_Pattern; }
auto IsADR(const std::uint32_t i) -> bool { return (i & kADR_Mask) == kADR_Pattern; }
auto IsLdrLiteral(const std::uint32_t i) -> bool { return (i & kLdrLit_Mask) == kLdrLit_Pattern; }

} // anonymous namespace

auto RelocateInstructions(const PrologueInfo& prologue, const std::uint64_t trampolineBase)
    -> Result<RelocationResult> {
    RelocationResult result;
    const Emitter    emit{result.code};
    std::size_t      srcOffset = 0;

    for (const auto& decoded : prologue.instructions) {
        const auto origPC = decoded.address;
        const auto newPC  = trampolineBase + result.code.size();

        AlignEntry ae;
        ae.targetOffset     = static_cast<std::uint8_t>(srcOffset);
        ae.trampolineOffset = static_cast<std::uint8_t>(result.code.size());
        result.alignMap.push_back(ae);

        if (decoded.detail.id == 0 || decoded.bytes.size() != 4) {
            emit.Inst(*reinterpret_cast<const std::uint32_t*>(decoded.bytes.data()));
            srcOffset += decoded.bytes.size();
            continue;
        }

        std::uint32_t insn{};
        std::memcpy(&insn, decoded.bytes.data(), 4);

        // B / BL
        if (IsB_BL(insn)) {
            const auto target = DecodeB(insn, origPC);
            const bool isBL   = (insn & kBL_Bit) != 0;

            if (const auto delta = static_cast<std::int64_t>(target) - static_cast<std::int64_t>(newPC);
                delta >= -kBRange && delta < kBRange) {
                const auto          imm26   = static_cast<std::uint32_t>(delta >> 2 & kImm26Mask);
                const std::uint32_t newInsn = (insn & kB_BL_ImmMask) | imm26;
                emit.Inst(newInsn);
            } else {
                if (isBL) emit.AbsoluteBranchLink(target);
                else emit.AbsoluteBranch(target);
            }
            srcOffset += 4;
            continue;
        }

        // B.cond
        if (IsBcond(insn)) {
            const auto target = DecodeImm19(insn, origPC);
            const auto cond   = Bits(insn, 0, 3);

            if (const auto delta = static_cast<std::int64_t>(target) - static_cast<std::int64_t>(newPC);
                delta >= -kImm19Range && delta < kImm19Range) {
                const auto          imm19   = static_cast<std::uint32_t>(delta >> 2 & kImm19Mask);
                const std::uint32_t newInsn = (insn & kImm19ClearMask) | (imm19 << kImm19Shift);
                emit.Inst(newInsn);
            } else {
                const auto          invCond  = cond ^ 1;
                const std::uint32_t skipInsn = kBcond_Base | invCond | (kSkipAbsBranch << kImm19Shift);
                emit.Inst(skipInsn);
                emit.AbsoluteBranch(target);
            }
            srcOffset += 4;
            continue;
        }

        // CBZ / CBNZ
        if (IsCBZ(insn)) {
            const auto target = DecodeImm19(insn, origPC);

            if (const auto delta = static_cast<std::int64_t>(target) - static_cast<std::int64_t>(newPC);
                delta >= -kImm19Range && delta < kImm19Range) {
                const auto          imm19   = static_cast<std::uint32_t>(delta >> 2 & kImm19Mask);
                const std::uint32_t newInsn = (insn & kImm19ClearMask) | (imm19 << kImm19Shift);
                emit.Inst(newInsn);
            } else {
                std::uint32_t invInsn = insn ^ kCBZ_InvBit;
                invInsn               = (invInsn & kImm19ClearMask) | (kSkipAbsBranch << kImm19Shift);
                emit.Inst(invInsn);
                emit.AbsoluteBranch(target);
            }
            srcOffset += 4;
            continue;
        }

        // 4. TBZ / TBNZ
        if (IsTBZ(insn)) {
            const auto target = DecodeImm14(insn, origPC);

            if (const auto delta = static_cast<std::int64_t>(target) - static_cast<std::int64_t>(newPC);
                delta >= -kImm14Range && delta < kImm14Range) {
                const auto          imm14   = static_cast<std::uint32_t>(delta >> 2 & kImm14Mask);
                const std::uint32_t newInsn = (insn & kImm14ClearMask) | (imm14 << kImm19Shift);
                emit.Inst(newInsn);
            } else {
                std::uint32_t invInsn = insn ^ kTBZ_InvBit;
                invInsn               = (invInsn & kImm14ClearMask) | (kSkipAbsBranch << kImm19Shift);
                emit.Inst(invInsn);
                emit.AbsoluteBranch(target);
            }
            srcOffset += 4;
            continue;
        }

        // 5. ADR / ADRP
        if (IsADR(insn)) {
            const auto target = DecodeAdrOffset(insn, origPC);
            const auto rd     = Bits(insn, 0, 4);
            emit.MovImm64(rd, target);
            srcOffset += 4;
            continue;
        }

        // 6. LDR literal
        if (IsLdrLiteral(insn)) {
            const auto target = DecodeImm19(insn, origPC);
            const auto rt     = Bits(insn, 0, 4);
            const auto opc    = Bits(insn, 30, 31);

            if (const auto delta = static_cast<std::int64_t>(target) - static_cast<std::int64_t>(newPC);
                delta >= -kImm19Range && delta < kImm19Range) {
                const auto          imm19   = static_cast<std::uint32_t>(delta >> 2 & kImm19Mask);
                const std::uint32_t newInsn = (insn & kImm19ClearMask) | (imm19 << kImm19Shift);
                emit.Inst(newInsn);
            } else {
                if (const bool isFp = (insn & kLdrLit_VBit) != 0; !isFp && opc <= 1) {
                    emit.MovImm64(rt, target);
                    if (opc == 0) emit.Inst(kLdrW_Base | rt | rt << 5);
                    else emit.Inst(kLdrX_Base | rt | rt << 5);
                } else {
                    emit.MovImm64(kScratchReg, target);
                    std::uint32_t loadInsn{};
                    if (isFp) {
                        switch (opc) {
                        case 0:
                            loadInsn = kLdrS_UOff;
                            break;
                        case 1:
                            loadInsn = kLdrD_UOff;
                            break;
                        default:
                            loadInsn = kLdrQ_UOff;
                            break;
                        }
                        loadInsn |= rt | kScratchReg << 5;
                    } else {
                        loadInsn = kLdrsw_Base | rt | kScratchReg << 5;
                    }
                    emit.Inst(loadInsn);
                }
            }
            srcOffset += 4;
            continue;
        }

        // 7. Default — copy unchanged
        emit.Inst(insn);
        srcOffset += 4;
    }

    AlignEntry sentinel;
    sentinel.targetOffset     = static_cast<std::uint8_t>(srcOffset);
    sentinel.trampolineOffset = static_cast<std::uint8_t>(result.code.size());
    result.alignMap.push_back(sentinel);

    return Result<RelocationResult>::Ok(std::move(result));
}

} // namespace Mortis::HookEngine
