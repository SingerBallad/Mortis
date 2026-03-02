#include <Mortis/Hook/Disassembler.hpp>

#include <Mortis/Config.hpp>
#include <Mortis/Result.hpp>

#include <cstring>

namespace Mortis::HookEngine {

// Construction / destruction
Disassembler::Disassembler() {
    cs_err err{};
#ifdef MORTIS_ARCH_X64
    err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle_);
#elif defined(MORTIS_ARCH_ARM64)
    err = cs_open(CS_ARCH_AARCH64, CS_MODE_ARM, &handle_);
#endif
    if (err != CS_ERR_OK) return;
    cs_option(handle_, CS_OPT_DETAIL, CS_OPT_ON);
}

Disassembler::~Disassembler() {
    if (handle_) cs_close(&handle_);
}

auto Disassembler::analyzePrologue(void* target, const std::size_t minBytes, const std::size_t maxBytes) const
    -> Result<PrologueInfo> {
    if (!handle_) return Result<PrologueInfo>::Err(ErrorCode::HookInstallFailed, "Capstone not initialized");

    auto*      codePtr  = static_cast<const std::uint8_t*>(target);
    const auto codeAddr = reinterpret_cast<std::uint64_t>(target);

    cs_insn*          insns = nullptr;
    const std::size_t count = cs_disasm(handle_, codePtr, maxBytes, codeAddr, 0, &insns);
    if (count == 0)
        return Result<PrologueInfo>::Err(
            ErrorCode::HookInstallFailed,
            "Failed to disassemble target function prologue"
        );

    PrologueInfo info{};
    info.totalBytes = 0;

    for (std::size_t i = 0; i < count; ++i) {
        DecodedInsn decoded;
        decoded.address = insns[i].address;
        decoded.bytes.assign(insns[i].bytes, insns[i].bytes + insns[i].size);
        decoded.detail = insns[i]; // Copy the full cs_insn (value fields only)

        // Extract RIP-relative displacement offset (x64 only).
#ifdef MORTIS_ARCH_X64
        if (insns[i].detail) {
            const auto& x86 = insns[i].detail->x86;
            for (std::uint8_t j = 0; j < x86.op_count; ++j) {
                if (x86.operands[j].type == X86_OP_MEM && x86.operands[j].mem.base == X86_REG_RIP) {
                    if (x86.encoding.disp_offset != 0 && x86.encoding.disp_size == 4)
                        decoded.ripDispOffset = x86.encoding.disp_offset;
                    break;
                }
            }
        }
#endif

        info.totalBytes += insns[i].size;
        info.instructions.push_back(std::move(decoded));

        if (info.totalBytes >= minBytes) break;

        // If we hit a terminating instruction before minBytes, try to consume
        // filler bytes (NOP / int3) after it
        if (IsTerminating(insns[i])) {
            const auto* filler    = codePtr + info.totalBytes;
            auto        remaining = maxBytes - info.totalBytes;
            while (info.totalBytes < minBytes) {
                const auto n = IsCodeFiller(filler, remaining);
                if (n == 0) break;
                // Record filler as a pseudo-instruction.
                DecodedInsn pad;
                pad.address = codeAddr + info.totalBytes;
                pad.bytes.assign(filler, filler + n);
                std::memset(&pad.detail, 0, sizeof(pad.detail));
                pad.detail.size = static_cast<std::uint16_t>(n);
                info.instructions.push_back(std::move(pad));
                info.totalBytes += n;
                filler          += n;
                remaining       -= n;
            }
            break;
        }
    }

    cs_free(insns, count);

    if (info.totalBytes < minBytes)
        return Result<PrologueInfo>::Err(
            ErrorCode::HookInstallFailed,
            "Target function too short to hook (need " + std::to_string(minBytes) + " bytes, found "
                + std::to_string(info.totalBytes) + ")"
        );

    return Result<PrologueInfo>::Ok(std::move(info));
}

} // namespace Mortis::HookEngine
