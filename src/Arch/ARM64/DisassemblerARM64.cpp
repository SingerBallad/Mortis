#include <Mortis/Arch/ARM64.hpp>
#include <Mortis/Hook/Disassembler.hpp>

#include <array>
#include <cstring>

namespace Mortis::HookEngine {

auto Disassembler::IsTerminating(const cs_insn& insn) -> bool {
    if (insn.id == ARM64_INS_RET) return true;
    if (insn.id == ARM64_INS_B) {
        if (const auto& arm64 = insn.detail->arm64; arm64.cc == ARM64_CC_INVALID || arm64.cc == ARM64_CC_AL)
            return true;
    }
    if (insn.id == ARM64_INS_BR) return true;
    return false;
}

auto Disassembler::IsCodeFiller(const std::uint8_t* code, std::size_t remaining) -> std::size_t {
    if (remaining < 4) return 0;
    std::uint32_t insn{};
    std::memcpy(&insn, code, 4);
    if (insn == ARM64::kNop) return 4;
    return 0;
}

auto Disassembler::SkipJumpStubs(void* code) -> void* {
    auto* pb = static_cast<std::uint8_t*>(code);

    for (int i = 0; i < 5; ++i) { // max 5 hops to prevent infinite loop on malformed code
        std::uint32_t w0;
        std::memcpy(&w0, pb, 4);

        // B imm26 — unconditional branch (4 bytes)
        if ((w0 & ARM64::kB_BL_Mask) == ARM64::kB_BL_Pattern && !(w0 & ARM64::kBL_Bit)) {
            const auto imm26  = w0 & ARM64::kImm26Mask;
            auto       offset = static_cast<std::int64_t>(imm26);
            if (offset & 1LL << 25) offset |= ~((1LL << 26) - 1);
            offset        *= 4;
            const auto pc  = reinterpret_cast<std::uint64_t>(pb);
            pb             = reinterpret_cast<std::uint8_t*>(pc + static_cast<std::uint64_t>(offset));
            continue;
        }

        // LDR Xn, #8; BR Xn; .quad addr — absolute branch (16 bytes)
        {
            std::uint32_t w1{};
            std::memcpy(&w1, pb + 4, 4);
            constexpr auto expectedLdr = ARM64::kLdrX_Lit_Base | 2u << ARM64::kImm19Shift;
            if (const auto rd = w0 & 0x1Fu; (w0 & ~0x1Fu) == expectedLdr && w1 == (ARM64::kBR_Base | rd << 5)) {
                std::uint64_t target;
                std::memcpy(&target, pb + 8, 8);
                pb = reinterpret_cast<std::uint8_t*>(target);
                continue;
            }
        }

        // ADRP Xn, page; ADD Xn, Xn, #off; BR Xn — ILT thunk (12 bytes)
        if ((w0 & 0x9F000000) == 0x90000000) {
            std::array<std::uint32_t, 3> w{};
            std::memcpy(w.data(), pb, 12);
            if (const auto rd = w[0] & 0x1Fu; (w[1] & 0xFFC003E0) == (0x91000000 | rd << 5) && (w[1] & 0x1Fu) == rd
                                              && w[2] == (0xD61F0000u | rd << 5)) {
                auto       pc    = reinterpret_cast<std::uint64_t>(pb);
                const auto immlo = w[0] >> 29 & 0x3u;
                const auto immhi = w[0] >> 5 & 0x7FFFFu;
                auto       imm21 = static_cast<std::int64_t>(immhi << 2 | immlo);
                if (imm21 & 1LL << 20) imm21 |= ~((1LL << 21) - 1);
                const auto adrpTarget  = (pc & ~0xFFFULL) + static_cast<std::uint64_t>(imm21 << 12);
                const auto imm12       = w[1] >> 10 & 0xFFFu;
                const auto finalTarget = adrpTarget + imm12;
                pb                     = reinterpret_cast<std::uint8_t*>(finalTarget);
                continue;
            }
        }

        break;
    }

    return pb;
}

} // namespace Mortis::HookEngine
