#pragma once

#include <Mortis/Config.hpp>
#include <Mortis/Detail/HookBackend.hpp>
#include <Mortis/Detail/MemberFnAddress.hpp>
#include <Mortis/Detail/SlotPool.hpp>
#include <Mortis/Detail/TypeTraits.hpp>
#include <Mortis/Result.hpp>

#include <utility>

namespace Mortis {

/// @brief Handle for an active inline hook.
/// @tparam Sig Function signature (e.g., int(int, int)).
template <FunctionSignature Sig>
class InlineHookHandle {
    using Traits  = FunctionTraits<Sig>;
    using FnPtr   = Traits::Pointer;
    using SlotMgr = Detail::SlotPool<Sig>;

public:
    InlineHookHandle(const InlineHookHandle&)                    = delete;
    auto operator=(const InlineHookHandle&) -> InlineHookHandle& = delete;

    InlineHookHandle(InlineHookHandle&& other) noexcept
    : targetFn_(std::exchange(other.targetFn_, nullptr)),
      detourFn_(std::exchange(other.detourFn_, nullptr)),
      slotIndex_(std::exchange(other.slotIndex_, -1)),
      enabled_(std::exchange(other.enabled_, false)),
      priority_(std::exchange(other.priority_, 0)),
      originalPtrLocation_(std::exchange(other.originalPtrLocation_, nullptr)) {}

    auto operator=(InlineHookHandle&& other) noexcept -> InlineHookHandle& {
        if (this != &other) {
            if (enabled_) (void)disable();
            Destroy();
            targetFn_            = std::exchange(other.targetFn_, nullptr);
            detourFn_            = std::exchange(other.detourFn_, nullptr);
            slotIndex_           = std::exchange(other.slotIndex_, -1);
            enabled_             = std::exchange(other.enabled_, false);
            priority_            = std::exchange(other.priority_, 0);
            originalPtrLocation_ = std::exchange(other.originalPtrLocation_, nullptr);
        }
        return *this;
    }

    ~InlineHookHandle() {
        if (enabled_) {
            if (const auto result = disable(); !result) {
                // disable() failed, leak slot to avoid dangling dispatch.
                slotIndex_ = -1;
                return;
            }
        }
        Destroy();
    }

    /// @brief Disable the hook (restore original code).
    /// @return Success or error.
    [[nodiscard]] auto disable() -> Result<void> {
        if (!enabled_) return Result<void>::Ok();
        auto       target = reinterpret_cast<void*>(targetFn_);
        const auto detour = reinterpret_cast<void*>(detourFn_);
        if (auto result = HookBackendImpl::Remove(target, detour); !result) return result;
        targetFn_ = reinterpret_cast<FnPtr>(target);
        enabled_  = false;
        return Result<void>::Ok();
    }

    /// @brief Re-enable a previously disabled hook.
    /// @return Success or error.
    [[nodiscard]] auto enable() -> Result<void> {
        if (enabled_) return Result<void>::Ok();
        auto       target = reinterpret_cast<void*>(targetFn_);
        const auto detour = reinterpret_cast<void*>(detourFn_);
        if (auto result = HookBackendImpl::Install(target, detour, priority_, originalPtrLocation_); !result)
            return result;
        targetFn_ = reinterpret_cast<FnPtr>(target);
        enabled_  = true;
        return Result<void>::Ok();
    }

    /// @return Whether the hook is currently active.
    [[nodiscard]] auto isEnabled() const noexcept -> bool { return enabled_; }

    /// @brief Callable pointer to the original function.
    [[nodiscard]] auto original() const noexcept -> FnPtr { return targetFn_; }

private:
    friend struct InlineHook;

    InlineHookHandle() = default;

    InlineHookHandle(FnPtr target, FnPtr detour, int slotIndex, int priority = 0, void** originalPtrLocation = nullptr)
    : targetFn_(target),
      detourFn_(detour),
      slotIndex_(slotIndex),
      enabled_(true),
      priority_(priority),
      originalPtrLocation_(originalPtrLocation) {}

    void Destroy() {
        if (slotIndex_ >= 0) {
            SlotMgr::Instance().release(slotIndex_);
            slotIndex_ = -1;
        }
    }

    FnPtr  targetFn_            = nullptr;
    FnPtr  detourFn_            = nullptr;
    int    slotIndex_           = -1;
    bool   enabled_             = false;
    int    priority_            = 0;
    void** originalPtrLocation_ = nullptr;
};

/// @brief Factory for creating inline hooks.
struct InlineHook {
    InlineHook() = delete;

    /// @brief Create an inline hook at a raw address.
    template <FunctionSignature Sig, DetourCallable<Sig> Detour>
    [[nodiscard]] static auto Create(Address target, Detour&& detour, int priority = 0)
        -> Result<InlineHookHandle<Sig>> {
        return CreateImpl<Sig>(target, std::forward<Detour>(detour), priority);
    }

    /// @brief Create an inline hook from a typed function pointer.
    template <FreeFunctionPointer Fn, typename Detour>
        requires DetourCallable<std::remove_cvref_t<Detour>, Detail::DeducedSignature<Fn>>
    [[nodiscard]] static auto Create(Fn fn, Detour&& detour, int priority = 0)
        -> Result<InlineHookHandle<Detail::DeducedSignature<Fn>>> {
        return CreateImpl<Detail::DeducedSignature<Fn>>(
            reinterpret_cast<Address>(fn),
            std::forward<Detour>(detour),
            priority
        );
    }

    /// @brief Create an inline hook on a member function.
    template <auto MemFn, typename Detour>
        requires MemberFunctionPointer<decltype(MemFn)>
    [[nodiscard]] static auto CreateMember(Detour&& detour, int priority = 0)
        -> Result<InlineHookHandle<typename Detail::MemberToFreeSig<decltype(MemFn)>::Type>> {
        using FreeSig = Detail::MemberToFreeSig<decltype(MemFn)>::Type;
        auto addr     = Detail::MemberFnAddress(MemFn);
        return CreateImpl<FreeSig>(addr, std::forward<Detour>(detour), priority);
    }

    /// @brief Create an inline hook, auto-deducing signature from detour.
    template <AutoDeducibleDetour Detour>
    [[nodiscard]] static auto Create(Address target, Detour&& detour, int priority = 0)
        -> Result<InlineHookHandle<Detail::DetourSignature<Detour>>> {
        using Sig = Detail::DetourSignature<Detour>;
        return CreateImpl<Sig>(target, std::forward<Detour>(detour), priority);
    }

    /// @brief Hook a member function at a given runtime address.
    template <auto MemFn, typename Detour>
        requires MemberFunctionPointer<decltype(MemFn)>
    [[nodiscard]] static auto CreateMember(Address target, Detour&& detour, int priority = 0)
        -> Result<InlineHookHandle<typename Detail::MemberToFreeSig<decltype(MemFn)>::Type>> {
        using FreeSig = Detail::MemberToFreeSig<decltype(MemFn)>::Type;
        return CreateImpl<FreeSig>(target, std::forward<Detour>(detour), priority);
    }

private:
    template <FunctionSignature Sig, typename Detour>
    static auto CreateImpl(Address target, Detour&& detour, int priority = 0) -> Result<InlineHookHandle<Sig>> {
        DetourDiagnostics<Sig, Detour>::Validate();

        using Traits  = FunctionTraits<Sig>;
        using FnPtr   = Traits::Pointer;
        using SlotMgr = Detail::SlotPool<Sig>;

        auto& pool  = SlotMgr::Instance();
        auto  alloc = pool.allocate(std::forward<Detour>(detour));
        if (!alloc) return Result<InlineHookHandle<Sig>>::Err(ErrorCode::NoFreeSlots, "No free inline-hook slots");

        auto [slotIndex, rawFn] = *alloc;

        auto       targetFn   = reinterpret_cast<FnPtr>(target);
        auto       targetVoid = reinterpret_cast<void*>(targetFn);
        const auto detourVoid = reinterpret_cast<void*>(rawFn);
        auto*      origSlot   = pool.originalSlot(slotIndex);

        if (auto installResult = HookBackendImpl::Install(targetVoid, detourVoid, priority, origSlot); !installResult) {
            pool.release(slotIndex);
            return Result<InlineHookHandle<Sig>>::Err(installResult.code(), installResult.error());
        }

        targetFn = reinterpret_cast<FnPtr>(targetVoid);

        return Result<InlineHookHandle<Sig>>::Ok(InlineHookHandle<Sig>(targetFn, rawFn, slotIndex, priority, origSlot));
    }
};

} // namespace Mortis
