/// @brief x64-specific Disassembler methods.

#include <Mortis/Arch/X64.hpp>
#include <Mortis/Hook/Disassembler.hpp>

#include <cstring>

namespace Mortis::HookEngine {

auto Disassembler::IsTerminating(const cs_insn& insn) -> bool {
    if (insn.id == X86_INS_RET || insn.id == X86_INS_INT3) return true;
    if (insn.id == X86_INS_JMP) return true;
    if (insn.size == X64::kRepRetSize && insn.bytes[0] == X64::kRepPrefix && insn.bytes[1] == X64::kRet) return true;
    return false;
}

auto Disassembler::IsCodeFiller(const std::uint8_t* code, const std::size_t remaining) -> std::size_t {
    if (remaining < 1) return 0;
    if (code[0] == X64::kInt3) return 1;
    if (code[0] == X64::kNop) return 1;
    if (remaining >= 2 && code[0] == X64::kOperandSize && code[1] == X64::kNop) return 2;
    if (remaining >= 3 && code[0] == X64::k0F && code[1] == X64::kMultiNop2nd) {
        if (code[2] == X64::kNop3_modrm) return 3;
        if (remaining >= 4 && code[2] == X64::kNop4_modrm && code[3] == 0x00) return 4;
        if (remaining >= 5 && code[2] == X64::kNop5_modrm && code[3] == 0x00 && code[4] == 0x00) return 5;
    }
    if (remaining >= 6 && code[0] == X64::kOperandSize && code[1] == X64::k0F && code[2] == X64::kMultiNop2nd
        && code[3] == X64::kNop5_modrm && code[4] == 0x00 && code[5] == 0x00)
        return 6;
    if (remaining >= 7 && code[0] == X64::k0F && code[1] == X64::kMultiNop2nd && code[2] == X64::kNop7_modrm
        && code[3] == 0x00 && code[4] == 0x00 && code[5] == 0x00 && code[6] == 0x00)
        return 7;
    if (remaining >= 8 && code[0] == X64::k0F && code[1] == X64::kMultiNop2nd && code[2] == X64::kNop8_modrm
        && code[3] == 0x00 && code[4] == 0x00 && code[5] == 0x00 && code[6] == 0x00 && code[7] == 0x00)
        return 8;
    if (remaining >= 9 && code[0] == X64::kOperandSize && code[1] == X64::k0F && code[2] == X64::kMultiNop2nd
        && code[3] == X64::kNop8_modrm && code[4] == 0x00 && code[5] == 0x00 && code[6] == 0x00 && code[7] == 0x00
        && code[8] == 0x00)
        return 9;
    return 0;
}

auto Disassembler::SkipJumpStubs(void* code) -> void* {
    auto* pb = static_cast<std::uint8_t*>(code);

    for (int i = 0; i < 5; ++i) {
        // jmp [rip+disp32]  — FF 25 xx xx xx xx
        if (pb[0] == X64::kGroupFF && pb[1] == X64::kJmpIndirect) {
            std::int32_t disp{};
            std::memcpy(&disp, pb + 2, 4);
            auto* target = *reinterpret_cast<void**>(pb + 6 + disp);
            pb           = static_cast<std::uint8_t*>(target);
            continue;
        }
        // jmp rel32  — E9 xx xx xx xx
        if (pb[0] == X64::kJmpRel32) {
            std::int32_t off{};
            std::memcpy(&off, pb + 1, 4);
            pb = pb + X64::kJmpRel32Size + off;
            continue;
        }
        // jmp rel8 (hot-patch)  — EB xx
        if (pb[0] == X64::kJmpRel8) {
            const auto off = static_cast<std::int8_t>(pb[1]);
            pb             = pb + 2 + off;
            continue;
        }
        // MOV RAX, imm64; JMP RAX  — 48 B8 <imm64> FF E0
        if (pb[0] == 0x48 && pb[1] == 0xB8 && pb[10] == X64::kGroupFF && pb[11] == 0xE0) {
            std::uint64_t target{};
            std::memcpy(&target, pb + 2, 8);
            pb = reinterpret_cast<std::uint8_t*>(target);
            continue;
        }
        break;
    }

    return pb;
}

} // namespace Mortis::HookEngine
