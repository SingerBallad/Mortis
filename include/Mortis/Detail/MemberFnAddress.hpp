#pragma once

#include <Mortis/Config.hpp>

#include <bit>
#include <type_traits>

namespace Mortis::Detail {

/// @brief Get the code address from a member function pointer.
template <typename MemFnPtr>
    requires std::is_member_function_pointer_v<MemFnPtr>
auto MemberFnAddress(MemFnPtr fn) -> Address {
    if constexpr (sizeof(MemFnPtr) == sizeof(void*)) {
        // MSVC ABI: member function pointer is a plain code pointer.
        return std::bit_cast<Address>(fn);
    } else if constexpr (sizeof(MemFnPtr) == 2 * sizeof(void*)) {
        // Itanium ABI: {uintptr_t ptr; ptrdiff_t adj}
        struct Repr {
            std::uintptr_t ptr;
            std::ptrdiff_t adj;
        };
        auto repr = std::bit_cast<Repr>(fn);
        // LSB == 1 indicates a virtual function (vtable offset); not yet supported.
        if (repr.ptr & 1) return Address{0};
        return static_cast<Address>(repr.ptr);
    } else {
        static_assert(sizeof(MemFnPtr) == 0, "Unsupported member function pointer layout");
        return Address{0};
    }
}

} // namespace Mortis::Detail
