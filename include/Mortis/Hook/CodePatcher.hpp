#pragma once

#include <Mortis/Result.hpp>

#include <cstdint>
#include <span>
#include <vector>

namespace Mortis::HookEngine {

/// @brief Patch function entry with a jump (handles page protection).
[[nodiscard]] auto PatchEntry(void* target, std::span<const std::uint8_t> jumpBytes) -> Result<void>;

/// @brief Restore the original prologue at the target function entry.
[[nodiscard]] auto UnpatchEntry(void* target, std::span<const std::uint8_t> savedPrologue) -> Result<void>;

/// @brief Save the prologue bytes before overwriting.
[[nodiscard]] auto SavePrologue(void* target, std::size_t size) -> Result<std::vector<std::uint8_t>>;

/// @brief Flush the instruction cache for a range.
void FlushCode(void* address, std::size_t size);

/// @brief Patch function entry (assumes RWX, skips protection).
[[nodiscard]] auto PatchEntryAssumeWritable(void* target, std::span<const std::uint8_t> jumpBytes) -> Result<void>;

/// @brief Restore the original prologue (assumes memory is writable).
///
/// @param target         The function entry address.
/// @param savedPrologue  Original bytes that were overwritten.
/// @return Success or error.
[[nodiscard]] auto UnpatchEntryAssumeWritable(void* target, std::span<const std::uint8_t> savedPrologue) -> Result<void>;

} // namespace Mortis::HookEngine
