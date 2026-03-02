#pragma once

#include <Mortis/Mortis.hpp>

// Target functions with volatile intermediates to guarantee minimum code size
// on ARM64 (requires >= 12 bytes / 3 instructions for trampoline).
// Defined in TestHelpers.cpp to ensure a single translation unit controls
// code generation — inline definitions may be optimized below hookable size.

MORTIS_NOINLINE int  Add(int a, int b);
MORTIS_NOINLINE int  Multiply(int a, int b);
MORTIS_NOINLINE int  Subtract(int a, int b);
MORTIS_NOINLINE void TraceFunction(int x);

class Calculator {
public:
    MORTIS_NOINLINE int Compute(int x, int y);
};

/// Indirect call through a volatile function pointer to prevent IAT caching.
template <typename R, typename... Args>
auto IndirectCall(R (*fn)(Args...), Args... args) -> R {
    R (*volatile p)(Args...) = fn;
    return p(args...);
}
