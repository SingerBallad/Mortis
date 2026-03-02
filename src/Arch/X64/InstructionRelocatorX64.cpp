/// @brief x64 instruction relocation: RIP-relative, JMP/CALL rel32, Jcc, LOOP/JECXZ.

#include <Mortis/Arch/X64.hpp>
#include <Mortis/Hook/InstructionRelocator.hpp>

#include <cstring>
#include <limits>

namespace Mortis::HookEngine {

namespace {

constexpr auto kInt32Min = std::numeric_limits<std::int32_t>::min();
constexpr auto kInt32Max = std::numeric_limits<std::int32_t>::max();

struct Emitter {
    std::vector<std::uint8_t>& buf;

    void Byte(const std::uint8_t v) const { buf.push_back(v); }
    void Int32(const std::int32_t v) const {
        const auto p = reinterpret_cast<const std::uint8_t*>(&v);
        buf.insert(buf.end(), p, p + 4);
    }
    void Int64(const std::int64_t v) const {
        const auto p = reinterpret_cast<const std::uint8_t*>(&v);
        buf.insert(buf.end(), p, p + 8);
    }
    void Raw(const std::uint8_t* data, const std::size_t n) const { buf.insert(buf.end(), data, data + n); }

    void AbsoluteJump(const std::uint64_t target) const {
        Byte(X64::kGroupFF);
        Byte(X64::kJmpIndirect);
        Int32(0);
        Int64(static_cast<std::int64_t>(target));
    }

    void AbsoluteCall(const std::uint64_t target) const {
        Byte(X64::kGroupFF);
        Byte(X64::kCallIndirect);
        Int32(X64::kAbsCallDisp);
        Byte(X64::kJmpRel8);
        Byte(X64::kAbsCallSkip);
        Int64(static_cast<std::int64_t>(target));
    }
};

} // anonymous namespace

auto RelocateInstructions(const PrologueInfo& prologue, const std::uint64_t trampolineBase)
    -> Result<RelocationResult> {
    RelocationResult result;
    const Emitter    emit{result.code};
    std::size_t      srcOffset = 0;

    for (const auto& [address, bytes, detail, ripDispOffset] : prologue.instructions) {
        const auto&         insn      = detail;
        const std::uint8_t* bytesData = bytes.data();
        const auto          instrSize = bytes.size();
        const auto          origPC    = address;

        // Guard against uint8_t overflow in alignment offsets.
        if (srcOffset > std::numeric_limits<std::uint8_t>::max()
            || result.code.size() > std::numeric_limits<std::uint8_t>::max()) {
            return Result<RelocationResult>::Err(
                ErrorCode::HookInstallFailed,
                "Relocation offset exceeds uint8_t range at " + std::to_string(address)
            );
        }

        AlignEntry ae;
        ae.targetOffset     = static_cast<std::uint8_t>(srcOffset);
        ae.trampolineOffset = static_cast<std::uint8_t>(result.code.size());
        result.alignMap.push_back(ae);

        if (insn.id == 0) {
            emit.Raw(bytesData, instrSize);
            srcOffset += instrSize;
            continue;
        }

        const auto newPC = trampolineBase + result.code.size();

        // 1. LOOP / JECXZ
        if (insn.id == X86_INS_LOOP || insn.id == X86_INS_LOOPE || insn.id == X86_INS_LOOPNE || insn.id == X86_INS_JECXZ
            || insn.id == X86_INS_JRCXZ) {
            const auto relByte = static_cast<std::int8_t>(bytesData[instrSize - 1]);
            const auto target  = origPC + instrSize + relByte;
            const auto delta   = static_cast<std::int64_t>(target - (newPC + instrSize));
            if (delta < -128 || delta > 127)
                return Result<RelocationResult>::Err(
                    ErrorCode::HookInstallFailed,
                    "Cannot relocate LOOP/JECXZ instruction at " + std::to_string(origPC)
                );
            emit.Raw(bytesData, instrSize - 1);
            emit.Byte(static_cast<std::uint8_t>(static_cast<std::int8_t>(delta)));
            srcOffset += instrSize;
            continue;
        }

        // 2. JMP rel8 (0xEB)
        if (insn.id == X86_INS_JMP && instrSize == 2 && bytesData[0] == X64::kJmpRel8) {
            const auto target = origPC + 2 + static_cast<std::int8_t>(bytesData[1]);
            if (const auto delta = static_cast<std::int64_t>(target - (newPC + X64::kJmpRel32Size));
                delta >= kInt32Min && delta <= kInt32Max) {
                emit.Byte(X64::kJmpRel32);
                emit.Int32(static_cast<std::int32_t>(delta));
            } else {
                emit.AbsoluteJump(target);
            }
            srcOffset += instrSize;
            continue;
        }

        // 3. Jcc rel8 (0x70-0x7F)
        if (instrSize == 2 && bytesData[0] >= X64::kJccRel8Lo && bytesData[0] <= X64::kJccRel8Hi) {
            const auto condCode = static_cast<std::uint8_t>(bytesData[0] & X64::kCondMask);
            const auto target   = origPC + 2 + static_cast<std::int8_t>(bytesData[1]);
            if (const auto delta = static_cast<std::int64_t>(target - (newPC + X64::kJccRel32Size));
                delta >= kInt32Min && delta <= kInt32Max) {
                emit.Byte(X64::k0F);
                emit.Byte(static_cast<std::uint8_t>(X64::kJccRel32Lo | condCode));
                emit.Int32(static_cast<std::int32_t>(delta));
            } else {
                emit.Byte(static_cast<std::uint8_t>(X64::kJccRel8Lo | (condCode ^ 1)));
                emit.Byte(X64::kAbsJmpSize);
                emit.AbsoluteJump(target);
            }
            srcOffset += instrSize;
            continue;
        }

        // 4. JMP rel32 (0xE9)
        if (insn.id == X86_INS_JMP && instrSize == 5 && bytesData[0] == X64::kJmpRel32) {
            std::int32_t off{};
            std::memcpy(&off, bytesData + 1, 4);
            const auto target = origPC + 5 + off;
            if (const auto delta = static_cast<std::int64_t>(target - (newPC + X64::kJmpRel32Size));
                delta >= kInt32Min && delta <= kInt32Max) {
                emit.Byte(X64::kJmpRel32);
                emit.Int32(static_cast<std::int32_t>(delta));
            } else {
                emit.AbsoluteJump(target);
            }
            srcOffset += instrSize;
            continue;
        }

        // 5. CALL rel32 (0xE8)
        if (insn.id == X86_INS_CALL && instrSize == 5 && bytesData[0] == X64::kCallRel32) {
            std::int32_t off{};
            std::memcpy(&off, bytesData + 1, 4);
            const auto target = origPC + X64::kCallRel32Size + off;
            if (const auto delta = static_cast<std::int64_t>(target - (newPC + X64::kCallRel32Size));
                delta >= kInt32Min && delta <= kInt32Max) {
                emit.Byte(X64::kCallRel32);
                emit.Int32(static_cast<std::int32_t>(delta));
            } else {
                emit.AbsoluteCall(target);
            }
            srcOffset += instrSize;
            continue;
        }

        // 6. Jcc rel32 (0x0F 0x80-0x8F)
        if (instrSize == 6 && bytesData[0] == X64::k0F && bytesData[1] >= X64::kJccRel32Lo
            && bytesData[1] <= X64::kJccRel32Hi) {
            const auto   condCode = static_cast<std::uint8_t>(bytesData[1] & X64::kCondMask);
            std::int32_t off{};
            std::memcpy(&off, bytesData + 2, 4);
            const auto target = origPC + 6 + off;
            if (const auto delta = static_cast<std::int64_t>(target - (newPC + X64::kJccRel32Size));
                delta >= kInt32Min && delta <= kInt32Max) {
                emit.Byte(X64::k0F);
                emit.Byte(static_cast<std::uint8_t>(X64::kJccRel32Lo | condCode));
                emit.Int32(static_cast<std::int32_t>(delta));
            } else {
                emit.Byte(static_cast<std::uint8_t>(X64::kJccRel8Lo | (condCode ^ 1)));
                emit.Byte(X64::kAbsJmpSize);
                emit.AbsoluteJump(target);
            }
            srcOffset += instrSize;
            continue;
        }

        // 7. RIP-relative memory operand
        if (const int dispOff = ripDispOffset; dispOff >= 0) {
            emit.Raw(bytesData, instrSize);
            std::int32_t oldDisp{};
            std::memcpy(&oldDisp, bytesData + dispOff, 4);
            const auto origTarget = static_cast<std::int64_t>(origPC) + static_cast<std::int64_t>(instrSize) + oldDisp;
            const auto newDisp = origTarget - (static_cast<std::int64_t>(newPC) + static_cast<std::int64_t>(instrSize));
            if (newDisp < kInt32Min || newDisp > kInt32Max) {
                return Result<RelocationResult>::Err(
                    ErrorCode::HookInstallFailed,
                    "RIP-relative displacement overflow at " + std::to_string(origPC)
                        + " — trampoline too far from data target"
                );
            }
            auto       newDisp32 = static_cast<std::int32_t>(newDisp);
            const auto patchPos  = result.code.size() - instrSize + static_cast<std::size_t>(dispOff);
            std::memcpy(&result.code[patchPos], &newDisp32, 4);
            srcOffset += instrSize;
            continue;
        }

        // 8. Default
        emit.Raw(bytesData, instrSize);
        srcOffset += instrSize;
    }

    AlignEntry sentinel;
    sentinel.targetOffset     = static_cast<std::uint8_t>(srcOffset);
    sentinel.trampolineOffset = static_cast<std::uint8_t>(result.code.size());
    result.alignMap.push_back(sentinel);

    return Result<RelocationResult>::Ok(std::move(result));
}

} // namespace Mortis::HookEngine
