#pragma once

#include <Mortis/Result.hpp>

namespace Mortis::HookBackendImpl {

/// @brief Install an inline hook on target, returning trampoline.
auto Install(void*& target, void* detour, int priority = 0, void** originalPtrLocation = nullptr) -> Result<void>;

/// @brief Remove a previously installed inline hook.
auto Remove(void*& target, const void* detour) -> Result<void>;

} // namespace Mortis::HookBackendImpl
