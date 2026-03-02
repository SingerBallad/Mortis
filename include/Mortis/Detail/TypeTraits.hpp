#pragma once

#include <tuple>
#include <type_traits>

namespace Mortis {

// FunctionTraits
/// @brief Primary template (unspecialized — causes hard error for non-function types).
template <typename T>
struct FunctionTraits;

/// @brief Decompose a free-function signature into return type, args, and pointer.
template <typename R, typename... Args>
struct FunctionTraits<R(Args...)> {
    using ReturnType                               = R;
    using ArgsTuple                                = std::tuple<Args...>;
    using Pointer                                  = R (*)(Args...);
    static constexpr std::size_t kArity            = sizeof...(Args);
    static constexpr bool        kIsMemberFunction = false;
};

/// @brief Decompose a noexcept free-function signature.
template <typename R, typename... Args>
struct FunctionTraits<R(Args...) noexcept> : FunctionTraits<R(Args...)> {};

/// @brief Decompose a non-const member function pointer.
template <typename R, typename C, typename... Args>
struct FunctionTraits<R (C::*)(Args...)> {
    using ReturnType                               = R;
    using ClassType                                = C;
    using ArgsTuple                                = std::tuple<Args...>;
    using Pointer                                  = R (*)(C*, Args...);
    static constexpr std::size_t kArity            = sizeof...(Args);
    static constexpr bool        kIsMemberFunction = true;
};

/// @brief Decompose a const member function pointer.
template <typename R, typename C, typename... Args>
struct FunctionTraits<R (C::*)(Args...) const> {
    using ReturnType                               = R;
    using ClassType                                = C;
    using ArgsTuple                                = std::tuple<Args...>;
    using Pointer                                  = R (*)(const C*, Args...);
    static constexpr std::size_t kArity            = sizeof...(Args);
    static constexpr bool        kIsMemberFunction = true;
};

/// @brief Decompose a noexcept non-const member function pointer.
template <typename R, typename C, typename... Args>
struct FunctionTraits<R (C::*)(Args...) noexcept> : FunctionTraits<R (C::*)(Args...)> {};

/// @brief Decompose a const noexcept member function pointer.
template <typename R, typename C, typename... Args>
struct FunctionTraits<R (C::*)(Args...) const noexcept> : FunctionTraits<R (C::*)(Args...) const> {};

/// @brief SFINAE helper: true if FunctionTraits<T> is valid.
template <typename T, typename = void>
inline constexpr bool HasFunctionTraits = false;

template <typename T>
inline constexpr bool HasFunctionTraits<T, std::void_t<typename FunctionTraits<T>::ReturnType>> = true;

// Concepts
/// @brief Satisfied when Sig is a free-function signature (e.g., int(int,int)).
template <typename Sig>
concept FunctionSignature = HasFunctionTraits<Sig> && !FunctionTraits<Sig>::kIsMemberFunction;

/// @brief Satisfied when T is a pointer-to-member-function.
template <typename T>
concept MemberFunctionPointer = std::is_member_function_pointer_v<T>;

/// @brief Satisfied when T is a plain function pointer.
template <typename T>
concept FreeFunctionPointer = std::is_pointer_v<T> && std::is_function_v<std::remove_pointer_t<T>>;

// OriginalFunction wrapper
namespace Detail {

/// @brief Callable wrapper that forwards to the saved original function.
/// @tparam Sig Function signature.
template <typename Sig>
class OriginalFunction;

template <typename R, typename... Args>
class OriginalFunction<R(Args...)> {
public:
    using Pointer = R (*)(Args...);

    explicit OriginalFunction(Pointer* slot) noexcept : slot_(slot) {}

    auto operator()(Args... args) const -> R { return (*slot_)(std::forward<Args>(args)...); }

private:
    Pointer* slot_;
};

// MemberToFreeSig
/// @brief Convert a member-function-pointer type to a free-function signature
///        with an explicit this-pointer as the first argument.
template <typename MemFnPtr>
struct MemberToFreeSig;

template <typename R, typename C, typename... Args>
struct MemberToFreeSig<R (C::*)(Args...)> {
    using Type = R(C*, Args...);
};

template <typename R, typename C, typename... Args>
struct MemberToFreeSig<R (C::*)(Args...) const> {
    using Type = R(const C*, Args...);
};

template <typename R, typename C, typename... Args>
struct MemberToFreeSig<R (C::*)(Args...) noexcept> {
    using Type = R(C*, Args...);
};

template <typename R, typename C, typename... Args>
struct MemberToFreeSig<R (C::*)(Args...) const noexcept> {
    using Type = R(const C*, Args...);
};

/// @brief Extract the canonical (non-noexcept) function signature from a function pointer type.
/// e.g. int(*)(int, int) noexcept → int(int, int).
template <typename FnPtr>
using DeducedSignature = std::remove_pointer_t<typename FunctionTraits<std::remove_pointer_t<FnPtr>>::Pointer>;

// Auto-deduction from detour lambdas
/// @brief Probe type for extracting function signature from a generic detour lambda.
struct DetourProbe {
    /// Sentinel return type — convertible to any type for unevaluated context support.
    struct AnyReturn {
        template <typename T>
        operator T() const noexcept; // NOLINT — declaration-only
    };
    /// Accept any call (declaration only — never instantiated).
    template <typename... Args>
    auto operator()(Args&&...) const noexcept -> AnyReturn; // NOLINT — declaration-only
};

/// @brief Extract R(Args...) from a callable, dropping the first parameter.
template <typename>
struct DetourSigExtract;

// Member function pointer specializations (lambda / functor operator()).
template <typename R, typename C, typename First, typename... Args>
struct DetourSigExtract<R (C::*)(First, Args...) const> {
    using Type = R(Args...);
};
template <typename R, typename C, typename First, typename... Args>
struct DetourSigExtract<R (C::*)(First, Args...)> {
    using Type = R(Args...);
};
template <typename R, typename C, typename First, typename... Args>
struct DetourSigExtract<R (C::*)(First, Args...) const noexcept> {
    using Type = R(Args...);
};
template <typename R, typename C, typename First, typename... Args>
struct DetourSigExtract<R (C::*)(First, Args...) noexcept> {
    using Type = R(Args...);
};

// Plain function signature specializations (detour function pointers).
template <typename R, typename First, typename... Args>
struct DetourSigExtract<R(First, Args...)> {
    using Type = R(Args...);
};
template <typename R, typename First, typename... Args>
struct DetourSigExtract<R(First, Args...) noexcept> {
    using Type = R(Args...);
};

/// @brief SFINAE helper: true when T is an lvalue reference to OriginalFunction<Sig>.
template <typename T>
inline constexpr bool IsOriginalFunctionRef = false;

template <typename Sig>
inline constexpr bool IsOriginalFunctionRef<OriginalFunction<Sig>&> = true;

/// @brief SFINAE helper: true when T has a non-template operator().
template <typename T, typename = void>
inline constexpr bool HasConcreteCallOp = false;
template <typename T>
inline constexpr bool HasConcreteCallOp<T, std::void_t<decltype(&T::operator())>> = true;

/// @brief Deduce the hooked function signature from a detour callable.
template <typename Detour>
consteval auto DeduceDetourSig() {
    using D = std::remove_cvref_t<Detour>;
    if constexpr (std::is_class_v<D>) {
        // Lambda / functor path.
        if constexpr (HasConcreteCallOp<D>) {
            return static_cast<DetourSigExtract<decltype(&D::operator())>::Type*>(nullptr);
        } else {
            return static_cast<DetourSigExtract<decltype(&D::template operator()<DetourProbe>)>::Type*>(nullptr);
        }
    } else if constexpr (std::is_pointer_v<D> && std::is_function_v<std::remove_pointer_t<D>>) {
        // Detour function pointer path: R(*)(OriginalFunction<Sig>&, Args...)
        using FnSig  = std::remove_pointer_t<D>;
        using Traits = FunctionTraits<FnSig>;
        if constexpr (Traits::kArity > 0) {
            using FirstArg = std::tuple_element_t<0, typename Traits::ArgsTuple>;
            if constexpr (IsOriginalFunctionRef<FirstArg>) {
                return static_cast<DetourSigExtract<FnSig>::Type*>(nullptr);
            } else {
                return static_cast<void*>(nullptr);
            }
        } else {
            return static_cast<void*>(nullptr);
        }
    } else {
        return static_cast<void*>(nullptr);
    }
}

/// @brief The hooked function signature deduced from a detour callable.
/// @see DeduceDetourSig
template <typename Detour>
using DetourSignature = std::remove_pointer_t<decltype(DeduceDetourSig<Detour>())>;

} // namespace Detail

// Public alias so users can write Mortis::OriginalFunction<Sig> in detour function signatures.
template <typename Sig>
using OriginalFunction = Detail::OriginalFunction<Sig>;

// AutoDeducibleDetour concept
/// @brief Satisfied when signature is auto-deducible from a detour callable.
template <typename Detour>
concept AutoDeducibleDetour =
    requires { typename Detail::DetourSignature<Detour>; } && FunctionSignature<Detail::DetourSignature<Detour>>;

// DetourCallable concept
namespace Detail {

/// @brief Helper: true when Detour can be called as (OriginalFunction<Sig>&, Args...) -> R.
template <typename Detour, typename Sig, typename = void>
inline constexpr bool IsDetourInvocable = false;

template <typename Detour, typename R, typename... Args>
inline constexpr bool IsDetourInvocable<
    Detour,
    R(Args...),
    std::void_t<
        decltype(std::declval<Detour>()(std::declval<OriginalFunction<R(Args...)>&>(), std::declval<Args>()...))>> =
    std::is_invocable_r_v<R, Detour, OriginalFunction<R(Args...)>&, Args...>;

} // namespace Detail

/// @brief Satisfied when Detour is invocable as (OriginalFunction<Sig>&, Args...) → R.
template <typename Detour, typename Sig>
concept DetourCallable = FunctionSignature<Sig> && Detail::IsDetourInvocable<Detour, Sig>;

// Compile-time diagnostics
/// @brief Static-assert diagnostics for detour signature mismatches.
/// @tparam Sig Expected function signature.
/// @tparam Detour User-provided detour callable.
template <typename Sig, typename Detour>
struct DetourDiagnostics {
    using Traits = FunctionTraits<Sig>;
    using R      = Traits::ReturnType;

    static constexpr bool kIsValid = Detail::IsDetourInvocable<Detour, Sig>;

    static constexpr void Validate() {
        static_assert(
            kIsValid,
            "Detour callable signature mismatch: the detour must be invocable as "
            "(OriginalFunction<Sig>&, Args...) -> ReturnType, where Args and "
            "ReturnType match the hooked function signature."
        );
    }
};

} // namespace Mortis
