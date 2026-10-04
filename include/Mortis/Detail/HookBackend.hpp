#pragma once

#include <Mortis/Result.hpp>

#include <atomic>
#include <cstddef>

namespace Mortis::HookBackendImpl {

/// @brief Install an inline hook on target, returning trampoline.
/// @param activeCounter Slot's in-flight-call counter, drained on removal before the trampoline is freed.
/// @param dispatchSpan  Byte span of the slot's dispatch stub, for removal's quiescence probe.
auto Install(
    void*&            target,
    void*             detour,
    int               priority            = 0,
    void**            originalPtrLocation = nullptr,
    std::atomic<int>* activeCounter       = nullptr,
    std::size_t       dispatchSpan        = 0
) -> Result<void>;

/// @brief Remove a previously installed inline hook.
auto Remove(void*& target, const void* detour) -> Result<void>;

} // namespace Mortis::HookBackendImpl
