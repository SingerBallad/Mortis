#pragma once

#include <cstdint>
#include <type_traits>

#if !defined(MORTIS_ARCH_X64) && !defined(MORTIS_ARCH_ARM64)
#error "MORTIS_ARCH_X64 or MORTIS_ARCH_ARM64 must be defined (set by CMake)."
#endif

#if !defined(MORTIS_OS_WINDOWS) && !defined(MORTIS_OS_LINUX)
#error "MORTIS_OS_WINDOWS or MORTIS_OS_LINUX must be defined (set by CMake)."
#endif

#ifdef MORTIS_COMPILER_MSVC
#define MORTIS_NOINLINE __declspec(noinline)
#else
#define MORTIS_NOINLINE __attribute__((noinline))
#endif

namespace Mortis {

#ifdef MORTIS_OS_WINDOWS
inline constexpr bool kIsWindows = true;
inline constexpr bool kIsLinux   = false;
#else
inline constexpr bool kIsWindows = false;
inline constexpr bool kIsLinux   = true;
#endif

#ifdef MORTIS_ARCH_X64
inline constexpr bool kIsX64   = true;
inline constexpr bool kIsArm64 = false;
#else
inline constexpr bool kIsX64   = false;
inline constexpr bool kIsArm64 = true;
#endif

#ifdef MORTIS_COMPILER_MSVC
inline constexpr bool kIsMSVC  = true;
inline constexpr bool kIsGCC   = false;
inline constexpr bool kIsClang = false;
#elif defined(MORTIS_COMPILER_GCC)
inline constexpr bool kIsMSVC  = false;
inline constexpr bool kIsGCC   = true;
inline constexpr bool kIsClang = false;
#elif defined(MORTIS_COMPILER_CLANG)
inline constexpr bool kIsMSVC  = false;
inline constexpr bool kIsGCC   = false;
inline constexpr bool kIsClang = true;
#else
inline constexpr bool kIsMSVC  = false;
inline constexpr bool kIsGCC   = false;
inline constexpr bool kIsClang = false;
#endif

/// @brief Unsigned integer type capable of holding a pointer value.
using Address = std::uintptr_t;

/// @brief Default maximum number of concurrent hook slots per signature.
inline constexpr int kDefaultMaxHookSlots = 64;

/// @brief Get the address of a free function pointer.
template <typename Fn>
    requires std::is_function_v<std::remove_pointer_t<Fn>>
constexpr auto AddressOf(Fn fn) -> Address {
    return reinterpret_cast<Address>(fn);
}

/// @brief Deleted overload preventing non-function-pointer arguments.
template <typename T>
    requires(!std::is_function_v<std::remove_pointer_t<T>>)
auto AddressOf(T) -> Address = delete;

} // namespace Mortis
