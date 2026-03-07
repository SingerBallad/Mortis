#pragma once

#include <Mortis/Config.hpp>
#include <Mortis/Detail/TypeTraits.hpp>
#include <Mortis/InlineHook.hpp>
#include <Mortis/MemoryScanner.hpp>
#include <Mortis/Result.hpp>

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>
#include <type_traits>


#define MORTIS_VA_EXPAND(X) X

namespace Mortis {

/**
 * @brief Hook priority enum.
 * @details The higher priority, the hook will be executed earlier
 */
enum class HookPriority : int {
    Highest = 0,
    High    = 100,
    Normal  = 200,
    Low     = 300,
    Lowest  = 400,
};

namespace Detail {

template <typename T>
struct IsConstMemberFun : std::false_type {};

template <class T, class Ret, class... Args>
struct IsConstMemberFun<Ret (T::*)(Args...) const> : std::true_type {};

template <typename T>
constexpr bool IsConstMemberFunV = IsConstMemberFun<T>::value;

template <typename T>
struct AddConstAtMemberFun {
    using type = T;
};

template <class T, class Ret, class... Args>
struct AddConstAtMemberFun<Ret (T::*)(Args...)> {
    using type = Ret (T::*)(Args...) const;
};

template <typename T>
using AddConstAtMemberFunT = typename AddConstAtMemberFun<T>::type;

template <typename T>
    requires(std::is_pointer_v<T> || std::is_member_function_pointer_v<T>)
inline Address ResolveIdentifier(T ptr) {
    if constexpr (std::is_member_function_pointer_v<T>) {
        return MemberFnAddress(ptr);
    } else {
        return reinterpret_cast<Address>(ptr);
    }
}

inline Address ResolveIdentifier(std::string_view sig) {
    if (auto res = MemoryScanner::FindFirst("", sig)) {
        return res.get();
    }
    return 0; // Return 0 on failure to find pattern
}

inline Address ResolveIdentifier(SignatureView sig) {
    if (auto res = MemoryScanner::FindFirst("", sig)) {
        return res.get();
    }
    return 0;
}

inline Address ResolveIdentifier(Address addr) { return addr; }

template <typename T>
struct ExtractSig;

template <typename R, typename... A>
struct ExtractSig<R (*)(A...)> {
    using Type = R(A...);
};
template <typename R, typename C, typename... A>
struct ExtractSig<R (C::*)(A...)> {
    using Type = R(C*, A...);
};
template <typename R, typename C, typename... A>
struct ExtractSig<R (C::*)(A...) const> {
    using Type = R(const C*, A...);
};
template <typename R, typename C, typename... A>
struct ExtractSig<R (C::*)(A...) noexcept> {
    using Type = R(C*, A...);
};
template <typename R, typename C, typename... A>
struct ExtractSig<R (C::*)(A...) const noexcept> {
    using Type = R(const C*, A...);
};

template <typename Sig, typename DefType, bool IsMember>
struct HookInvoker;

template <typename R, typename... Args, typename DefType>
struct HookInvoker<R(Args...), DefType, false> {
    static R invoke(::Mortis::Detail::OriginalFunction<R(Args...)>&, Args... args) {
        return DefType::detour(::std::forward<Args>(args)...);
    }
};

template <typename R, typename C, typename... Args, typename DefType>
struct HookInvoker<R(C*, Args...), DefType, true> {
    static R invoke(::Mortis::Detail::OriginalFunction<R(C*, Args...)>&, C* self, Args... args) {
        return static_cast<DefType*>(self)->detour(::std::forward<Args>(args)...);
    }
};

template <typename R, typename C, typename... Args, typename DefType>
struct HookInvoker<R(const C*, Args...), DefType, true> {
    static R invoke(::Mortis::Detail::OriginalFunction<R(const C*, Args...)>&, const C* self, Args... args) {
        return static_cast<const DefType*>(self)->detour(::std::forward<Args>(args)...);
    }
};

template <class... Ts>
class HookRegistrar {
public:
    static void hook() { (((++Ts::_AutoHookCount == 1) ? (void)Ts::hook() : (void)0), ...); }
    static void unhook() { (((--Ts::_AutoHookCount == 0) ? (void)Ts::unhook() : (void)0), ...); }
    HookRegistrar() noexcept { hook(); }
    ~HookRegistrar() noexcept { unhook(); }
    HookRegistrar(const HookRegistrar&) noexcept { ((++Ts::_AutoHookCount), ...); }
    HookRegistrar& operator=(const HookRegistrar& other) noexcept {
        if (this != std::addressof(other)) {
            ((++Ts::_AutoHookCount), ...);
        }
        return *this;
    }
    HookRegistrar(HookRegistrar&&) noexcept            = default;
    HookRegistrar& operator=(HookRegistrar&&) noexcept = default;
};

struct EmptyHookTarget {};

} // namespace Detail
} // namespace Mortis

#define MORTIS_HOOK_IMPL(REGISTER, FUNC_PTR, STATIC, MACRO_CALL, DEF_TYPE, TYPE, PRIORITY, IDENTIFIER, RET_TYPE, ...)  \
    struct DEF_TYPE : public TYPE {                                                                                    \
        inline static ::std::atomic_uint _AutoHookCount{};                                                             \
                                                                                                                       \
    private:                                                                                                           \
        using _RawFuncType      = RET_TYPE FUNC_PTR(__VA_ARGS__);                                                      \
        using _RawConstFuncType = ::Mortis::Detail::AddConstAtMemberFunT<_RawFuncType>;                                \
                                                                                                                       \
        template <class T>                                                                                             \
        struct _ConstDetector {                                                                                        \
            [[maybe_unused]] static constexpr bool value = false;                                                      \
            explicit constexpr _ConstDetector(T) {}                                                                    \
        };                                                                                                             \
        template <class T>                                                                                             \
        [[maybe_unused]] _ConstDetector(T) -> _ConstDetector<T>;                                                       \
        [[maybe_unused]] _ConstDetector(_RawFuncType) -> _ConstDetector<_RawFuncType>;                                 \
        template <>                                                                                                    \
        struct _ConstDetector<_RawConstFuncType> {                                                                     \
            [[maybe_unused]] static constexpr bool value = true;                                                       \
            explicit constexpr _ConstDetector(_RawConstFuncType) {}                                                    \
        };                                                                                                             \
        template <class T = _RawFuncType, std::enable_if_t<std::is_member_function_pointer_v<T>, int> = 0>             \
        [[maybe_unused]] _ConstDetector(_RawConstFuncType) -> _ConstDetector<_RawConstFuncType>;                       \
                                                                                                                       \
        static constexpr bool _IsConstMemberFunction = decltype(_ConstDetector{IDENTIFIER})::value;                    \
                                                                                                                       \
        using _OriginFuncType = ::std::conditional_t<_IsConstMemberFunction, _RawConstFuncType, _RawFuncType>;         \
                                                                                                                       \
        using _MortisSig = typename ::Mortis::Detail::ExtractSig<_OriginFuncType>::Type;                               \
                                                                                                                       \
        inline static ::std::optional<::Mortis::InlineHookHandle<_MortisSig>> _Handle{};                               \
                                                                                                                       \
    public:                                                                                                            \
        template <class T>                                                                                             \
            requires(::std::is_polymorphic_v<TYPE> && ::std::is_base_of_v<T, TYPE>)                                    \
        [[nodiscard]] TYPE* thisFor() {                                                                                \
            return static_cast<decltype(this)>(reinterpret_cast<T*>(this));                                            \
        }                                                                                                              \
                                                                                                                       \
        template <class... Args>                                                                                       \
        STATIC RET_TYPE origin(Args&&... params) {                                                                     \
            return MACRO_CALL(::std::forward<Args>(params)...);                                                        \
        }                                                                                                              \
                                                                                                                       \
        STATIC RET_TYPE detour(__VA_ARGS__);                                                                           \
                                                                                                                       \
        static ::Mortis::Result<void> hook() {                                                                         \
            if (_Handle) return ::Mortis::Result<void>::Ok(); /* Already hooked */                                     \
                                                                                                                       \
            ::Mortis::Address targetAddr = ::Mortis::Detail::ResolveIdentifier(IDENTIFIER);                            \
            if (!targetAddr) {                                                                                         \
                return ::Mortis::Result<void>::Err(                                                                    \
                    ::Mortis::ErrorCode::InvalidArgument,                                                              \
                    "Failed to resolve identifier"                                                                     \
                );                                                                                                     \
            }                                                                                                          \
            auto hookRes = ::Mortis::InlineHook::Create<_MortisSig>(                                                   \
                targetAddr,                                                                                            \
                &::Mortis::Detail::                                                                                    \
                    HookInvoker<_MortisSig, DEF_TYPE, ::std::is_member_function_pointer_v<_OriginFuncType>>::invoke,   \
                static_cast<int>(PRIORITY)                                                                             \
            );                                                                                                         \
            if (!hookRes) {                                                                                            \
                return ::Mortis::Result<void>::Err(hookRes.code(), hookRes.error());                                   \
            }                                                                                                          \
            _Handle.emplace(::std::move(hookRes.value()));                                                             \
            return ::Mortis::Result<void>::Ok();                                                                       \
        }                                                                                                              \
                                                                                                                       \
        static ::Mortis::Result<void> unhook() {                                                                       \
            if (!_Handle) return ::Mortis::Result<void>::Ok();                                                         \
            auto res = _Handle->disable();                                                                             \
            if (res.has_value()) {                                                                                     \
                _Handle.reset();                                                                                       \
            }                                                                                                          \
            return res;                                                                                                \
        }                                                                                                              \
    };                                                                                                                 \
    REGISTER;                                                                                                          \
    RET_TYPE DEF_TYPE::detour(__VA_ARGS__)

#define MORTIS_AUTO_REG_HOOK_IMPL(FUNC_PTR, STATIC, MACRO_CALL, DEF_TYPE, ...)                                         \
    MORTIS_VA_EXPAND(MORTIS_HOOK_IMPL(                                                                                 \
        inline ::Mortis::Detail::HookRegistrar<DEF_TYPE> DEF_TYPE##AutoRegister,                                       \
        FUNC_PTR,                                                                                                      \
        STATIC,                                                                                                        \
        MACRO_CALL,                                                                                                    \
        DEF_TYPE,                                                                                                      \
        __VA_ARGS__                                                                                                    \
    ))

#define MORTIS_MANUAL_REG_HOOK_IMPL(...) MORTIS_VA_EXPAND(MORTIS_HOOK_IMPL(, __VA_ARGS__))

#define MORTIS_STATIC_HOOK_IMPL(...)                                                                                   \
    MORTIS_VA_EXPAND(MORTIS_MANUAL_REG_HOOK_IMPL((*), static, _Handle->original(), __VA_ARGS__))

#define MORTIS_AUTO_STATIC_HOOK_IMPL(...)                                                                              \
    MORTIS_VA_EXPAND(MORTIS_AUTO_REG_HOOK_IMPL((*), static, _Handle->original(), __VA_ARGS__))

#define MORTIS_INSTANCE_HOOK_IMPL(DEF_TYPE, TYPE, ...)                                                                 \
    MORTIS_VA_EXPAND(                                                                                                  \
        MORTIS_MANUAL_REG_HOOK_IMPL((TYPE::*), , (_Handle->original())(this, ...), DEF_TYPE, TYPE, __VA_ARGS__)        \
    ) // Note: Member instance original calling requires explicit object mapping depending on how free functions are
      // bound, but for instance hooks Mortis translates them to free function signature `(this, args...)` so
      // `_Handle->original()(this, params...)` is used in origin() macro override via `(_Handle->original())(this,
      // params...)` trick. Wait, Mortis origin() macro is `MACRO_CALL(::std::forward<Args>(params)...)` -> if we pass
      // `(_Handle->original())(this, \` as MACRO_CALL it won't work syntactically well.
      // Let's refine the MACRO_CALL:
      // In member function hook, origin implementation:
      // return _Handle->original()(this, ::std::forward<Args>(params)...);

// We need a helper to format MACRO_CALL for instance properly:
#define MORTIS_INSTANCE_MACRO_CALL(...) _Handle->original()(this, __VA_ARGS__)
#define MORTIS_STATIC_MACRO_CALL(...)   _Handle->original()(__VA_ARGS__)

// Redefining origin for Mortis:
#undef MORTIS_STATIC_HOOK_IMPL
#define MORTIS_STATIC_HOOK_IMPL(...)                                                                                   \
    MORTIS_VA_EXPAND(MORTIS_MANUAL_REG_HOOK_IMPL((*), static, MORTIS_STATIC_MACRO_CALL, __VA_ARGS__))

#undef MORTIS_AUTO_STATIC_HOOK_IMPL
#define MORTIS_AUTO_STATIC_HOOK_IMPL(...)                                                                              \
    MORTIS_VA_EXPAND(MORTIS_AUTO_REG_HOOK_IMPL((*), static, MORTIS_STATIC_MACRO_CALL, __VA_ARGS__))

#undef MORTIS_INSTANCE_HOOK_IMPL
#define MORTIS_INSTANCE_HOOK_IMPL(DEF_TYPE, TYPE, ...)                                                                 \
    MORTIS_VA_EXPAND(MORTIS_MANUAL_REG_HOOK_IMPL((TYPE::*), , MORTIS_INSTANCE_MACRO_CALL, DEF_TYPE, TYPE, __VA_ARGS__))

#undef MORTIS_AUTO_INSTANCE_HOOK_IMPL
#define MORTIS_AUTO_INSTANCE_HOOK_IMPL(DEF_TYPE, TYPE, ...)                                                            \
    MORTIS_VA_EXPAND(MORTIS_AUTO_REG_HOOK_IMPL((TYPE::*), , MORTIS_INSTANCE_MACRO_CALL, DEF_TYPE, TYPE, __VA_ARGS__))

// User API

/**
 * @brief Register a hook for a typed static function.
 * @param DEF_TYPE The name of the hook definition.
 * @param PRIORITY Mortis::HookPriority The priority of the hook.
 * @param TYPE The type which the function belongs to.
 * @param IDENTIFIER The identifier of the hook. It can be a function pointer, symbol, address or a signature.
 * @param RET_TYPE The return type of the hook.
 * @param ... The parameters of the hook.
 *
 * @note register or unregister by calling DEF_TYPE::hook() and DEF_TYPE::unhook().
 */
#define MORTIS_TYPE_STATIC_HOOK(DEF_TYPE, PRIORITY, TYPE, IDENTIFIER, RET_TYPE, ...)                                   \
    MORTIS_VA_EXPAND(MORTIS_STATIC_HOOK_IMPL(DEF_TYPE, TYPE, PRIORITY, IDENTIFIER, RET_TYPE, __VA_ARGS__))

/**
 * @brief Register a hook for a static function.
 * @param DEF_TYPE The name of the hook definition.
 * @param PRIORITY Mortis::HookPriority The priority of the hook.
 * @param IDENTIFIER The identifier of the hook. It can be a function pointer, symbol, address or a signature.
 * @param RET_TYPE The return type of the hook.
 * @param ... The parameters of the hook.
 *
 * @note register or unregister by calling DEF_TYPE::hook() and DEF_TYPE::unhook().
 */
#define MORTIS_STATIC_HOOK(DEF_TYPE, PRIORITY, IDENTIFIER, RET_TYPE, ...)                                              \
    MORTIS_VA_EXPAND(MORTIS_STATIC_HOOK_IMPL(                                                                          \
        DEF_TYPE,                                                                                                      \
        ::Mortis::Detail::EmptyHookTarget,                                                                             \
        PRIORITY,                                                                                                      \
        IDENTIFIER,                                                                                                    \
        RET_TYPE,                                                                                                      \
        __VA_ARGS__                                                                                                    \
    ))

/**
 * @brief Register a hook for a typed static function.
 * @details The hook will be automatically registered and unregistered.
 * @see MORTIS_TYPE_STATIC_HOOK for usage.
 */
#define MORTIS_AUTO_TYPE_STATIC_HOOK(DEF_TYPE, PRIORITY, TYPE, IDENTIFIER, RET_TYPE, ...)                              \
    MORTIS_VA_EXPAND(MORTIS_AUTO_STATIC_HOOK_IMPL(DEF_TYPE, TYPE, PRIORITY, IDENTIFIER, RET_TYPE, __VA_ARGS__))

/**
 * @brief Register a hook for a static function.
 * @details The hook will be automatically registered and unregistered.
 * @see MORTIS_STATIC_HOOK for usage.
 */
#define MORTIS_AUTO_STATIC_HOOK(DEF_TYPE, PRIORITY, IDENTIFIER, RET_TYPE, ...)                                         \
    MORTIS_VA_EXPAND(MORTIS_AUTO_STATIC_HOOK_IMPL(                                                                     \
        DEF_TYPE,                                                                                                      \
        ::Mortis::Detail::EmptyHookTarget,                                                                             \
        PRIORITY,                                                                                                      \
        IDENTIFIER,                                                                                                    \
        RET_TYPE,                                                                                                      \
        __VA_ARGS__                                                                                                    \
    ))

/**
 * @brief Register a hook for a typed instance function.
 * @param DEF_TYPE The name of the hook definition.
 * @param PRIORITY Mortis::HookPriority The priority of the hook.
 * @param TYPE The type which the function belongs to.
 * @param IDENTIFIER The identifier of the hook. It can be a function pointer, symbol, address or a signature.
 * @param RET_TYPE The return type of the hook.
 * @param ... The parameters of the hook.
 *
 * @note register or unregister by calling DEF_TYPE::hook() and DEF_TYPE::unhook().
 */
#define MORTIS_TYPE_INSTANCE_HOOK(DEF_TYPE, PRIORITY, TYPE, IDENTIFIER, RET_TYPE, ...)                                 \
    MORTIS_VA_EXPAND(MORTIS_INSTANCE_HOOK_IMPL(DEF_TYPE, TYPE, PRIORITY, IDENTIFIER, RET_TYPE, __VA_ARGS__))

/**
 * @brief Register a hook for a instance function.
 * @param DEF_TYPE The name of the hook definition.
 * @param PRIORITY Mortis::HookPriority The priority of the hook.
 * @param IDENTIFIER The identifier of the hook. It can be a function pointer, symbol, address or a signature.
 * @param RET_TYPE The return type of the hook.
 * @param ... The parameters of the hook.
 *
 * @note register or unregister by calling DEF_TYPE::hook() and DEF_TYPE::unhook().
 */
#define MORTIS_INSTANCE_HOOK(DEF_TYPE, PRIORITY, IDENTIFIER, RET_TYPE, ...)                                            \
    MORTIS_VA_EXPAND(MORTIS_INSTANCE_HOOK_IMPL(                                                                        \
        DEF_TYPE,                                                                                                      \
        ::Mortis::Detail::EmptyHookTarget,                                                                             \
        PRIORITY,                                                                                                      \
        IDENTIFIER,                                                                                                    \
        RET_TYPE,                                                                                                      \
        __VA_ARGS__                                                                                                    \
    ))

/**
 * @brief Register a hook for a typed instance function.
 * @details The hook will be automatically registered and unregistered.
 * @see MORTIS_TYPE_INSTANCE_HOOK for usage.
 */
#define MORTIS_AUTO_TYPE_INSTANCE_HOOK(DEF_TYPE, PRIORITY, TYPE, IDENTIFIER, RET_TYPE, ...)                            \
    MORTIS_VA_EXPAND(MORTIS_AUTO_INSTANCE_HOOK_IMPL(DEF_TYPE, TYPE, PRIORITY, IDENTIFIER, RET_TYPE, __VA_ARGS__))

/**
 * @brief Register a hook for a instance function.
 * @details The hook will be automatically registered and unregistered.
 * @see MORTIS_INSTANCE_HOOK for usage.
 */
#define MORTIS_AUTO_INSTANCE_HOOK(DEF_TYPE, PRIORITY, IDENTIFIER, RET_TYPE, ...)                                       \
    MORTIS_VA_EXPAND(MORTIS_AUTO_INSTANCE_HOOK_IMPL(                                                                   \
        DEF_TYPE,                                                                                                      \
        ::Mortis::Detail::EmptyHookTarget,                                                                             \
        PRIORITY,                                                                                                      \
        IDENTIFIER,                                                                                                    \
        RET_TYPE,                                                                                                      \
        __VA_ARGS__                                                                                                    \
    ))
