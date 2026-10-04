#pragma once

#include <Mortis/Config.hpp>
#include <Mortis/Detail/TypeTraits.hpp>

#include <array>
#include <atomic>
#include <functional>
#include <mutex>
#include <optional>
#include <thread>
#include <utility>
#include <version>

namespace Mortis::Detail {

/// @brief Fixed-size pool of static trampolines per function signature.
template <typename Sig, int MaxSlots = kDefaultMaxHookSlots>
class SlotPool;

template <typename R, typename... Args, int MaxSlots>
class SlotPool<R(Args...), MaxSlots> {
public:
    using FnPtr = R (*)(Args...);
#if defined(__cpp_lib_move_only_function) && __cpp_lib_move_only_function >= 202110L
    using Detour = std::move_only_function<R(OriginalFunction<R(Args...)>&, Args...)>;
#else
    using Detour = std::function<R(OriginalFunction<R(Args...)>&, Args...)>;
#endif

    /// @return The global singleton instance.
    static auto Instance() -> SlotPool& {
        static SlotPool instance;
        return instance;
    }

    /// @brief Allocate a slot and bind a detour callable.
    /// @tparam D Detour type (deduced).
    /// @param detour The user's detour function.
    /// @return Pair of (slot index, raw function pointer), or nullopt if full.
    template <typename D>
    auto allocate(D&& detour) -> std::optional<std::pair<int, FnPtr>> {
        std::lock_guard lock(mutex_);
        for (int i = 0; i < MaxSlots; ++i) {
            if (!occupied_[i]) {
                occupied_[i] = true;
                detours_[i]  = Detour(std::forward<D>(detour));
                return std::pair{i, kTable[i]};
            }
        }
        return std::nullopt;
    }

    /// @brief Release a previously allocated slot.
    void release(int index) {
        while (active_[index].load(std::memory_order_acquire) != 0) {
            std::this_thread::yield();
        }
        std::lock_guard lock(mutex_);
        occupied_[index]  = false;
        detours_[index]   = nullptr;
        originals_[index] = nullptr;
    }

    /// @brief Set the original function pointer for a slot.
    void setOriginal(int index, FnPtr original) {
        std::lock_guard lock(mutex_);
        originals_[index] = original;
    }

    /// @brief Get a writable pointer to the original-function slot.
    auto originalSlot(int index) -> void** { return reinterpret_cast<void**>(&originals_[index]); }

    /// @brief Get the in-flight-call counter for a slot.
    auto activeCounter(int index) -> std::atomic<int>* { return &active_[index]; }

    static auto dispatchSpan(int index) -> std::size_t {
        const auto               self    = reinterpret_cast<std::uintptr_t>(kTable[index]);
        constexpr std::uintptr_t kCap    = 4096;
        std::uintptr_t           nearest = self + kCap;
        for (const auto fn : kTable) {
            const auto a = reinterpret_cast<std::uintptr_t>(fn);
            if (a > self && a < nearest) nearest = a;
        }
        return static_cast<std::size_t>(nearest - self);
    }

private:
    SlotPool() = default;

    template <int I>
    static auto Trampoline(Args... args) -> R {
        active_[I].fetch_add(1, std::memory_order_acquire);
        struct ActiveGuard {
            int idx;
            ~ActiveGuard() { active_[idx].fetch_sub(1, std::memory_order_release); }
        } guard{I};

        auto&                        self = Instance();
        OriginalFunction<R(Args...)> orig(&self.originals_[I]);
        return self.detours_[I](orig, std::forward<Args>(args)...);
    }

    /// @brief Build the compile-time lookup table of trampoline function pointers.
    template <int... Is>
    static constexpr auto MakeTable(std::integer_sequence<int, Is...>) -> std::array<FnPtr, MaxSlots> {
        return {&Trampoline<Is>...};
    }

    static constexpr auto kTable = MakeTable(std::make_integer_sequence<int, MaxSlots>{});

    std::mutex                   mutex_;
    std::array<bool, MaxSlots>   occupied_{};
    std::array<Detour, MaxSlots> detours_{};
    std::array<FnPtr, MaxSlots>  originals_{};

    static inline std::atomic<int> active_[MaxSlots] = {};
};

} // namespace Mortis::Detail
