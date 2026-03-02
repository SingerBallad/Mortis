#include <Mortis/Hook/CodePatcher.hpp>
#include <Mortis/Hook/Disassembler.hpp>
#include <Mortis/Hook/HookRegistry.hpp>
#include <Mortis/Hook/InstructionRelocator.hpp>
#include <Mortis/Hook/ThreadFreezer.hpp>
#include <Mortis/Hook/TrampolineAllocator.hpp>
#include <Mortis/Hook/TrampolineWriter.hpp>
#include <Mortis/Process.hpp>

#ifdef MORTIS_ARCH_X64
#include <Mortis/Arch/X64.hpp>
#elif defined(MORTIS_ARCH_ARM64)
#include <Mortis/Arch/ARM64.hpp>
#endif

#include <Mortis/Detail/HookBackend.hpp>

#include <algorithm>
#include <array>
#include <cstring>
#include <mutex>
#include <span>

namespace Mortis::HookBackendImpl {

/// @brief Global mutex serializing hook install/remove operations.
static std::mutex g_hookMutex;

//  Chain helpers

/// @brief Rewire hook chain for priority-ordered execution.
static void RewireChain(HookEngine::HookEntry& entry) {
    using namespace HookEngine;

    auto& chain = entry.chain;
    if (chain.empty()) return;

    // Sort by (priority ASC, sequence ASC).
    std::sort(chain.begin(), chain.end());

    auto* trampolineEntry = static_cast<std::uint8_t*>(entry.trampoline) + entry.entryOffset;

    // Wire each node's "original" to the next node, or to the trampoline.
    for (std::size_t i = 0; i < chain.size(); ++i) {
        void* nextTarget;
        if (i + 1 < chain.size()) {
            nextTarget = chain[i + 1].detourRawFn; // next hook in chain
        } else {
            nextTarget = trampolineEntry; // real original (trampoline)
        }
        if (chain[i].originalPtrLocation) {
            *chain[i].originalPtrLocation = nextTarget;
        }
    }

    // Patch the code-in absolute jump to point to the first hook's detour.
    // Both architectures now use a two-level trampoline with code-in.
#ifdef MORTIS_ARCH_X64
    constexpr std::size_t kCodeInAddrOffset = 6;                // FF 25 [4B disp] <8B addr>
    constexpr std::size_t kCodeInTotalSize  = X64::kAbsJmpSize; // 14
#elif defined(MORTIS_ARCH_ARM64)
    constexpr std::size_t kCodeInAddrOffset = 8;                     // LDR X17,#8; BR X17; <8B addr>
    constexpr std::size_t kCodeInTotalSize  = ARM64::kAbsBranchSize; // 16
#endif
    auto*      codeInBase  = static_cast<std::uint8_t*>(entry.trampoline) + entry.codeInOffset;
    auto       codeInBytes = std::span<std::uint8_t, kCodeInTotalSize>(codeInBase, kCodeInTotalSize);
    auto       addrSlot    = codeInBytes.subspan<kCodeInAddrOffset, sizeof(std::uint64_t)>();
    const auto firstDetour = reinterpret_cast<std::uint64_t>(chain[0].detourRawFn);

    // Atomic 8-byte store to prevent torn reads in the code-in slot.
#if defined(MORTIS_ARCH_X64) && (defined(MORTIS_COMPILER_GCC) || defined(MORTIS_COMPILER_CLANG))
    __asm__ volatile("movq %1, (%0)" ::"r"(addrSlot.data()), "r"(firstDetour) : "memory");
#else
    std::memcpy(addrSlot.data(), &firstDetour, sizeof(firstDetour));
#endif
    FlushCode(codeInBase, kCodeInTotalSize);
}

/// @brief Follow jump stubs but stop when encountering our own hook entry.
static auto SkipJumpStubsSafe(void* code) -> void* {
    using namespace HookEngine;
    auto* pb = static_cast<std::uint8_t*>(code);

    for (int i = 0; i < 5; ++i) {
#ifdef MORTIS_ARCH_X64
        // FF 25: JMP [RIP+disp32] — IAT thunk
        if (pb[0] == X64::kGroupFF && pb[1] == X64::kJmpIndirect) {
            std::int32_t disp{};
            std::memcpy(&disp, pb + 2, 4);
            auto* resolved = *reinterpret_cast<void**>(pb + 6 + disp);
            pb             = static_cast<std::uint8_t*>(resolved);
            continue;
        }
        // E9: JMP rel32 — our entry patch uses this; stop if dest is trampoline.
        if (pb[0] == X64::kJmpRel32) {
            std::int32_t off{};
            std::memcpy(&off, pb + 1, 4);
            auto* dest = pb + X64::kJmpRel32Size + off;
            if (HookRegistry::Instance().findContainingTrampoline(dest)) {
                break;
            }
            pb = dest;
            continue;
        }
        // EB: JMP rel8 — hot-patch
        if (pb[0] == X64::kJmpRel8) {
            const auto off = static_cast<std::int8_t>(pb[1]);
            pb             = pb + 2 + off;
            continue;
        }
        // 48 B8 <imm64> FF E0: MOV RAX, imm64; JMP RAX
        if (pb[0] == 0x48 && pb[1] == 0xB8 && pb[10] == X64::kGroupFF && pb[11] == 0xE0) {
            std::uint64_t absTarget{};
            std::memcpy(&absTarget, pb + 2, 8);
            pb = reinterpret_cast<std::uint8_t*>(absTarget);
            continue;
        }
#elif defined(MORTIS_ARCH_ARM64)
        std::uint32_t w0;
        std::memcpy(&w0, pb, 4);

        // B imm26 — unconditional branch (linker veneer)
        if ((w0 & ARM64::kB_BL_Mask) == ARM64::kB_BL_Pattern && !(w0 & ARM64::kBL_Bit)) {
           const  auto imm26  = w0 & ARM64::kImm26Mask;
            auto offset = static_cast<std::int64_t>(imm26);
            if (offset & (1LL << 25)) offset |= ~((1LL << 26) - 1);
            offset  *= 4;
            auto pc  = reinterpret_cast<std::uint64_t>(pb);
            auto* dest = reinterpret_cast<std::uint8_t*>(pc + static_cast<std::uint64_t>(offset));
            if (HookRegistry::Instance().findContainingTrampoline(dest)) {
                break;
            }
            pb = dest;
            continue;
        }

        // LDR Xn, #8; BR Xn; .quad addr — our entry patch; stop if dest is trampoline.
        {
            std::uint32_t w1;
            std::memcpy(&w1, pb + 4, 4);
            constexpr auto expectedLdr = ARM64::kLdrX_Lit_Base | (2u << ARM64::kImm19Shift);
            if (const auto rd = w0 & 0x1Fu; (w0 & ~0x1Fu) == expectedLdr && w1 == (ARM64::kBR_Base | (rd << 5))) {
                std::uint64_t target;
                std::memcpy(&target, pb + 8, 8);
                if (HookRegistry::Instance().findContainingTrampoline(reinterpret_cast<void*>(target))) {
                    break;
                }
                pb = reinterpret_cast<std::uint8_t*>(target);
                continue;
            }
        }

        // ADRP Xn, page; ADD Xn, Xn, #off; BR Xn — ILT thunk (12 bytes)
        if ((w0 & 0x9F000000) == 0x90000000) {
            std::array<std::uint32_t, 3> w{};
            std::memcpy(w.data(), pb, 12);
            if (const auto rd = w[0] & 0x1Fu; (w[1] & 0xFFC003E0) == (0x91000000 | (rd << 5)) && (w[1] & 0x1Fu) == rd
                && w[2] == (0xD61F0000u | (rd << 5))) {
               const  auto pc    = reinterpret_cast<std::uint64_t>(pb);
               const  auto immlo = (w[0] >> 29) & 0x3u;
               const  auto immhi = (w[0] >> 5) & 0x7FFFFu;
                auto imm21 = static_cast<std::int64_t>((immhi << 2) | immlo);
                if (imm21 & (1LL << 20)) imm21 |= ~((1LL << 21) - 1);
               const  auto adrpTarget  = (pc & ~0xFFFULL) + static_cast<std::uint64_t>(imm21 << 12);
               const  auto imm12       = (w[1] >> 10) & 0xFFFu;
               const  auto finalTarget = adrpTarget + imm12;
                pb               = reinterpret_cast<std::uint8_t*>(finalTarget);
                continue;
            }
        }
#endif
        break;
    }
    return pb;
}

//  Install
auto Install(void*& target, void* detour, int priority, void** originalPtrLocation) -> Result<void> {
    std::lock_guard lock(g_hookMutex);
    using namespace HookEngine;

    auto originalTarget = target;

    // Chain-aware jump-stub resolution.
    if (auto* resolved = SkipJumpStubsSafe(originalTarget); resolved != originalTarget) {
        originalTarget = resolved;
    }
    auto targetAddr = reinterpret_cast<std::uint64_t>(originalTarget);
    auto detourAddr = reinterpret_cast<std::uint64_t>(detour);

    // Check if this target already has an active hook chain.
    if (auto* existing = HookRegistry::Instance().findByTarget(originalTarget)) {
        // Add to existing chain
        ChainNode node;
        node.priority            = priority;
        node.sequence            = existing->nextSequence++;
        node.detourRawFn         = detour;
        node.originalPtrLocation = originalPtrLocation;
        existing->chain.push_back(node);

        RewireChain(*existing);

        // Return the shared trampoline callable.
        target = static_cast<std::uint8_t*>(existing->trampoline) + existing->entryOffset;
        return Result<void>::Ok();
    }

    // First hook on this target
    Disassembler disasm;

    // decode at least kJumpSize bytes.
    constexpr std::size_t kMaxPrologueBytes = 64;
    auto                  prologueResult    = disasm.analyzePrologue(originalTarget, kJumpSize, kMaxPrologueBytes);
    if (!prologueResult) {
        return Result<void>::Err(ErrorCode::HookInstallFailed, "Prologue analysis failed: " + prologueResult.error());
    }
    auto& prologue = *prologueResult;

    if (prologue.totalBytes < kJumpSize) {
        return Result<void>::Err(ErrorCode::HookInstallFailed, "Prologue too short for entry jump");
    }

    // Allocate trampoline slot near the target.
    auto slotResult = TrampolineAllocator::Instance().allocate(targetAddr);
    if (!slotResult) {
        return Result<void>::Err(slotResult.code(), slotResult.error());
    }
    auto slot = *slotResult;

    // Relocate prologue instructions into the trampoline.
    auto trampolineBase = reinterpret_cast<std::uint64_t>(slot.data());

    // Relocated code starts after the code-in region.
    std::uint64_t relocBase = trampolineBase;
#ifdef MORTIS_ARCH_X64
    relocBase += X64::kAbsJmpSize; // 14-byte code-in
#elif defined(MORTIS_ARCH_ARM64)
    relocBase += ARM64::kAbsBranchSize; // 16-byte code-in
#endif

    auto relocResult = RelocateInstructions(prologue, relocBase);
    if (!relocResult) {
        TrampolineAllocator::Instance().free(slot.data());
        return Result<void>::Err(relocResult.code(), relocResult.error());
    }
    auto& [code, alignMap] = *relocResult;

    // 6. Build trampoline: relocated code + jump-back.
    auto codeAfterPrologue = targetAddr + prologue.totalBytes;
    auto trampolineResult  = WriteTrampoline(slot, code, codeAfterPrologue, detourAddr);
    if (!trampolineResult) {
        TrampolineAllocator::Instance().free(slot.data());
        return Result<void>::Err(trampolineResult.code(), trampolineResult.error());
    }
    auto& [entryOffset, codeInOffset, totalUsed] = *trampolineResult;

    // Flush instruction cache for the trampoline.
    FlushCode(slot.data(), totalUsed);

    // Build entry-jump bytes.
    // Both architectures use a two-level trampoline: entry → code-in → detour.
    std::uint64_t entryDest = trampolineBase + codeInOffset;

    auto jumpResult = BuildEntryJump(targetAddr, entryDest, prologue.totalBytes);
    if (!jumpResult) {
        TrampolineAllocator::Instance().free(slot.data());
        return Result<void>::Err(jumpResult.code(), jumpResult.error());
    }
    auto& jumpBytes = *jumpResult;

    // Save original prologue.
    auto savedResult = SavePrologue(originalTarget, prologue.totalBytes);
    if (!savedResult) {
        TrampolineAllocator::Instance().free(slot.data());
        return Result<void>::Err(savedResult.code(), savedResult.error());
    }

    // Freeze threads + remap IPs + patch entry.
#ifdef MORTIS_OS_LINUX
    const auto patchAddr = reinterpret_cast<Address>(originalTarget);
    const auto patchSize = jumpBytes.size();
    auto       oldProt   = Process::QueryProtection(patchAddr);
    if (!oldProt) {
        TrampolineAllocator::Instance().free(slot.data());
        return Result<void>::Err(oldProt.error());
    }
    if (auto setProt = Process::SetProtectionRaw(patchAddr, patchSize, MemoryProtection::ReadWriteExec); !setProt) {
        TrampolineAllocator::Instance().free(slot.data());
        return Result<void>::Err(setProt.error());
    }
#endif
    Result<void> patchResult = Result<void>::Ok();
    {
        auto freezerResult = ThreadFreezer::Create();
        if (!freezerResult) {
            TrampolineAllocator::Instance().free(slot.data());
            return Result<void>::Err(freezerResult.code(), freezerResult.error());
        }
        auto& freezer = *freezerResult;

        auto* trampolineEntry = slot.data() + entryOffset;
        freezer.remapThreadIPs(originalTarget, prologue.totalBytes, trampolineEntry, alignMap);

#ifdef MORTIS_OS_LINUX
        patchResult = PatchEntryAssumeWritable(originalTarget, std::span<const std::uint8_t>(jumpBytes));
#else
        patchResult = PatchEntry(originalTarget, std::span<const std::uint8_t>(jumpBytes));
#endif
    }
#ifdef MORTIS_OS_LINUX
    (void)Process::SetProtectionRaw(patchAddr, patchSize, oldProt.value());
#endif
    if (!patchResult) {
        TrampolineAllocator::Instance().free(slot.data());
        return Result<void>::Err(patchResult.code(), patchResult.error());
    }

    // Register the hook with a single-node chain.
    HookEntry entry;
    entry.originalTarget    = originalTarget;
    entry.trampoline        = slot.data();
    entry.trampolineSize    = slot.size();
    entry.savedPrologue     = std::move(*savedResult);
    entry.prologueSize      = prologue.totalBytes;
    entry.alignMap          = std::move(alignMap);
    entry.codeAfterPrologue = reinterpret_cast<void*>(codeAfterPrologue);
    entry.jumpSize          = jumpBytes.size();
    entry.entryOffset       = entryOffset;
    entry.codeInOffset      = codeInOffset;

    ChainNode firstNode;
    firstNode.priority            = priority;
    firstNode.sequence            = 0;
    firstNode.detourRawFn         = detour;
    firstNode.originalPtrLocation = originalPtrLocation;
    entry.chain.push_back(firstNode);
    entry.nextSequence = 1;

    auto* trampolineCallable = slot.data() + entryOffset;

    // Set the original-function pointer for the first chain node.
    if (originalPtrLocation) {
        *originalPtrLocation = trampolineCallable;
    }

    HookRegistry::Instance().add(trampolineCallable, std::move(entry));

    // Update target to point to the callable trampoline.
    target = trampolineCallable;

    return Result<void>::Ok();
}

//  Remove
auto Remove(void*& target, const void* detour) -> Result<void> {
    std::lock_guard lock(g_hookMutex);
    using namespace HookEngine;

    // target is the trampoline callable; look up the hook.
    auto* entry = HookRegistry::Instance().find(target);
    if (!entry) {
        return Result<void>::Err(ErrorCode::HookRemoveFailed, "No hook entry found for this trampoline");
    }

    // Find the chain node for this detour.
    const auto it = std::ranges::find_if(entry->chain, [detour](const ChainNode& n) {
        return n.detourRawFn == detour;
    });

    if (it == entry->chain.end()) {
        return Result<void>::Err(ErrorCode::HookRemoveFailed, "Detour not found in hook chain");
    }

    // Chain has more than one node, partial removal
    if (entry->chain.size() > 1) {
        entry->chain.erase(it);
        RewireChain(*entry);

        // Return original target so the handle can re-enable later.
        target = entry->originalTarget;
        return Result<void>::Ok();
    }

    // Last node, full removal
    entry->chain.erase(it);

    // Freeze threads + restore prologue.
    {
#ifdef MORTIS_OS_LINUX
        const auto patchAddr = reinterpret_cast<Address>(entry->originalTarget);
        const auto patchSize = entry->savedPrologue.size();
        auto       oldProt   = Process::QueryProtection(patchAddr);
        if (!oldProt) {
            return Result<void>::Err(oldProt.error());
        }
        if (const auto setProt = Process::SetProtectionRaw(patchAddr, patchSize, MemoryProtection::ReadWriteExec); !setProt) {
            return Result<void>::Err(setProt.error());
        }
#endif
        Result<void> unpatchResult = Result<void>::Ok();
        {
            const auto freezerResult = ThreadFreezer::Create();
            if (!freezerResult) {
                return Result<void>::Err(freezerResult.code(), freezerResult.error());
            }
          const   auto& freezer = *freezerResult;

            auto* trampolineEntry = static_cast<std::uint8_t*>(target);
            freezer.reverseRemapThreadIPs(trampolineEntry, entry->originalTarget, entry->alignMap);

#ifdef MORTIS_OS_LINUX
            unpatchResult =
                UnpatchEntryAssumeWritable(entry->originalTarget, std::span<const std::uint8_t>(entry->savedPrologue));
#else
            unpatchResult = UnpatchEntry(entry->originalTarget, std::span<const std::uint8_t>(entry->savedPrologue));
#endif
        }
#ifdef MORTIS_OS_LINUX
        (void)Process::SetProtectionRaw(patchAddr, patchSize, oldProt.value());
#endif
        if (!unpatchResult) {
            return Result<void>::Err(unpatchResult.code(), unpatchResult.error());
        }
    }

    // Free the trampoline slot.
    TrampolineAllocator::Instance().free(entry->trampoline);

    // Restore target pointer to original function.
    auto* originalTarget = entry->originalTarget;
    HookRegistry::Instance().remove(target);
    target = originalTarget;

    return Result<void>::Ok();
}

} // namespace Mortis::HookBackendImpl
