#include <Mortis/Arch/ARM64.hpp>
#include <Mortis/Hook/TrampolineWriter.hpp>

#include <algorithm>
#include <cstring>

namespace Mortis::HookEngine {

namespace {

/// @brief 16-byte absolute branch: LDR X17, #8; BR X17; .quad target
void WriteAbsBranchARM64(std::span<std::uint8_t, ARM64::kAbsBranchSize> dst, const std::uint64_t target) {
    constexpr std::uint32_t ldr = ARM64::kLdrX_Lit_Base | 2 << ARM64::kImm19Shift | ARM64::kScratchReg;
    std::memcpy(dst.data(), &ldr, sizeof(ldr));
    constexpr std::uint32_t br = ARM64::kBR_Base | ARM64::kScratchReg << 5;
    std::memcpy(dst.data() + 4, &br, sizeof(br));
    std::memcpy(dst.data() + 8, &target, sizeof(target));
}

} // anonymous namespace

auto WriteTrampoline(
    std::span<std::uint8_t>          slot,
    const std::vector<std::uint8_t>& relocated,
    const std::uint64_t              jumpBackTo,
    const std::uint64_t              detourAddr
) -> Result<TrampolineLayout> {
    // ARM64 two-level layout (consistent with x64 Detours pattern):
    // [code-in 16B]   LDR X17, #8; BR X17; .quad detourAddr
    // [prologue]      <relocated bytes>
    // [jump-back 16B] LDR X17, #8; BR X17; .quad jumpBackTo

    if (const auto totalNeeded = ARM64::kAbsBranchSize + relocated.size() + ARM64::kAbsBranchSize;
        slot.size() < totalNeeded) {
        return Result<TrampolineLayout>::Err(
            ErrorCode::HookInstallFailed,
            "Trampoline slot too small for ARM64 layout"
        );
    }

    std::memset(slot.data(), 0x00, slot.size());

    TrampolineLayout layout;
    std::size_t      cursor = 0;

    // Code-in: LDR X17, #8; BR X17; .quad detourAddr
    layout.codeInOffset = cursor;
    WriteAbsBranchARM64(
        std::span<std::uint8_t, ARM64::kAbsBranchSize>(slot.data() + cursor, ARM64::kAbsBranchSize),
        detourAddr
    );
    cursor += ARM64::kAbsBranchSize;

    // Relocated prologue.
    layout.entryOffset = cursor;
    std::memcpy(slot.data() + cursor, relocated.data(), relocated.size());
    cursor += relocated.size();

    // Jump-back: LDR X17, #8; BR X17; .quad jumpBackTo
    WriteAbsBranchARM64(
        std::span<std::uint8_t, ARM64::kAbsBranchSize>(slot.data() + cursor, ARM64::kAbsBranchSize),
        jumpBackTo
    );
    cursor += ARM64::kAbsBranchSize;

    layout.totalUsed = cursor;
    return Result<TrampolineLayout>::Ok(layout);
}

auto BuildEntryJump([[maybe_unused]] const std::uint64_t target, const std::uint64_t dest, const std::size_t patchSize)
    -> Result<std::vector<std::uint8_t>> {
    if (patchSize < ARM64::kInsnSize) {
        return Result<std::vector<std::uint8_t>>::Err(ErrorCode::HookInstallFailed, "Patch size too small for ARM64");
    }

    std::vector<std::uint8_t> patch;

    if (const auto delta = static_cast<std::int64_t>(dest) - static_cast<std::int64_t>(target);
        delta % 4 == 0 && delta >= -ARM64::kBRange && delta < ARM64::kBRange) {
        // B imm26
        const auto imm26 = static_cast<std::uint32_t>((delta >> 2) & ARM64::kImm26Mask);
        const auto bInsn = ARM64::kB_BL_Pattern | imm26;
        const auto p     = reinterpret_cast<const std::uint8_t*>(&bInsn);
        patch.insert(patch.end(), p, p + 4);
    } else {
        if (patchSize < ARM64::kAbsBranchSize) {
            return Result<std::vector<std::uint8_t>>::Err(
                ErrorCode::HookInstallFailed,
                "Patch size too small for ARM64 absolute entry jump"
            );
        }
        patch.resize(ARM64::kAbsBranchSize);
        WriteAbsBranchARM64(std::span<std::uint8_t, ARM64::kAbsBranchSize>(patch.data(), ARM64::kAbsBranchSize), dest);
    }

    // NOP-fill
    while (patch.size() < patchSize) {
        const auto np = reinterpret_cast<const std::uint8_t*>(&ARM64::kNop);
        patch.insert(patch.end(), np, np + 4);
    }

    return Result<std::vector<std::uint8_t>>::Ok(std::move(patch));
}

} // namespace Mortis::HookEngine
