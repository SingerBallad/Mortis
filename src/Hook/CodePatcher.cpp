#include <Mortis/Hook/CodePatcher.hpp>
#include <Mortis/Process.hpp>

#include <cstring>

#ifdef MORTIS_OS_WINDOWS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace Mortis::HookEngine {

// FlushCode
void FlushCode(void* address, const std::size_t size) {
#ifdef MORTIS_OS_WINDOWS
    FlushInstructionCache(GetCurrentProcess(), address, size);
#else
    // GCC/Clang built-in: __builtin___clear_cache.
    auto* begin = static_cast<char*>(address);
    __builtin___clear_cache(begin, begin + size);
#endif
}

// SavePrologue
auto SavePrologue(void* target, const std::size_t size) -> Result<std::vector<std::uint8_t>> {
    std::vector<std::uint8_t> saved(size);
    const auto                addr = reinterpret_cast<Address>(target);

    if (const auto result = Process::ReadMemory(saved.data(), addr, size); !result) {
        return Result<std::vector<std::uint8_t>>::Err(
            ErrorCode::MemoryNotReadable,
            "Failed to save prologue bytes: " + result.error()
        );
    }
    return Result<std::vector<std::uint8_t>>::Ok(std::move(saved));
}

// PatchEntry
auto PatchEntry(void* target, const std::span<const std::uint8_t> jumpBytes) -> Result<void> {
    const auto addr = reinterpret_cast<Address>(target);

    // Change protection to RWX (guard held until function returns).
    const auto guard = ScopedProtect::Create(addr, jumpBytes.size(), MemoryProtection::ReadWriteExec);
    if (!guard) {
        return Result<void>::Err(ErrorCode::ProtectionFailed, "PatchEntry: cannot set RWX: " + guard.error());
    }

    // Write the jump bytes.
    if (const auto wr = Process::WriteMemory(addr, jumpBytes.data(), jumpBytes.size()); !wr) {
        return Result<void>::Err(ErrorCode::MemoryNotWritable, "PatchEntry: write failed: " + wr.error());
    }

    // Flush instruction cache.
    FlushCode(target, jumpBytes.size());

    return Result<void>::Ok();
}

// PatchEntryAssumeWritable
auto PatchEntryAssumeWritable(void* target, const std::span<const std::uint8_t> jumpBytes) -> Result<void> {
    std::memcpy(target, jumpBytes.data(), jumpBytes.size());
    FlushCode(target, jumpBytes.size());
    return Result<void>::Ok();
}

// UnpatchEntry
auto UnpatchEntry(void* target, const std::span<const std::uint8_t> savedPrologue) -> Result<void> {
    const auto addr = reinterpret_cast<Address>(target);

    if (const auto guard = ScopedProtect::Create(addr, savedPrologue.size(), MemoryProtection::ReadWriteExec); !guard) {
        return Result<void>::Err(ErrorCode::ProtectionFailed, "UnpatchEntry: cannot set RWX: " + guard.error());
    }

    if (const auto wr = Process::WriteMemory(addr, savedPrologue.data(), savedPrologue.size()); !wr) {
        return Result<void>::Err(ErrorCode::MemoryNotWritable, "UnpatchEntry: write failed: " + wr.error());
    }

    FlushCode(target, savedPrologue.size());

    return Result<void>::Ok();
}

// UnpatchEntryAssumeWritable
auto UnpatchEntryAssumeWritable(void* target, const std::span<const std::uint8_t> savedPrologue) -> Result<void> {
    std::memcpy(target, savedPrologue.data(), savedPrologue.size());
    FlushCode(target, savedPrologue.size());
    return Result<void>::Ok();
}

} // namespace Mortis::HookEngine
