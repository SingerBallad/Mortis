#pragma once

#include <Mortis/Hook/HookRegistry.hpp>
#include <Mortis/Platform/PlatformTypes.hpp>

#include <Mortis/Config.hpp>
#include <Mortis/Result.hpp>

#include <cstdint>
#include <span>
#include <vector>

namespace Mortis::HookEngine {

/// @brief Suspends all threads for safe code patching; resumes on destruction.
class ThreadFreezer {
public:
    ThreadFreezer(const ThreadFreezer&)                              = delete;
    auto operator=(const ThreadFreezer&) -> ThreadFreezer&           = delete;
    ThreadFreezer(ThreadFreezer&& other) noexcept                    = default;
    auto operator=(ThreadFreezer&& other) noexcept -> ThreadFreezer& = default;
    ~ThreadFreezer();

    /// @brief Create a ThreadFreezer (suspends all other threads).
    [[nodiscard]] static auto Create() -> Result<ThreadFreezer>;

    /// @brief Remap frozen thread IPs from target prologue to trampoline.
    void remapThreadIPs(
        void*                       target,
        std::size_t                 prologueSize,
        void*                       trampoline,
        std::span<const AlignEntry> alignMap
    ) const;

    /// @brief Reverse-remap thread IPs from trampoline back to target.
    void reverseRemapThreadIPs(void* trampoline, void* target, std::span<const AlignEntry> alignMap) const;

private:
    ThreadFreezer() = default;

    /// Platform-specific thread handle alias.
    using HandleType = PlatformDetail::NativeThreadHandle;
    std::vector<HandleType> handles_;
};

} // namespace Mortis::HookEngine
