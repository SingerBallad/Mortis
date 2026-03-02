#include "TestHelpers.hpp"

// Disable optimisation on MSVC to guarantee hookable code size.
#ifdef MORTIS_COMPILER_MSVC
#pragma optimize("", off)
#endif

MORTIS_NOINLINE int Add(int a, int b) {
    volatile int x = a;
    volatile int y = b;
    volatile int result = x + y;
    return result;
}

MORTIS_NOINLINE int Multiply(int a, int b) {
    volatile int x = a;
    volatile int y = b;
    volatile int result = x * y;
    return result;
}

MORTIS_NOINLINE int Subtract(int a, int b) {
    volatile int x = a;
    volatile int y = b;
    volatile int result = x - y;
    return result;
}

MORTIS_NOINLINE void TraceFunction(int x) {
    volatile int a = x;
    volatile int b = a + 1;
    volatile int c = b + 1;
    (void)c;
}

MORTIS_NOINLINE int Calculator::Compute(int x, int y) {
    volatile int a = x;
    volatile int b = y;
    volatile int result = a * 2 + b;
    return result;
}

#ifdef MORTIS_COMPILER_MSVC
#pragma optimize("", on)
#endif
