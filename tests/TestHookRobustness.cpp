#include "TestHelpers.hpp"
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <mutex>
#include <numeric>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#ifdef MORTIS_OS_WINDOWS
#include <Windows.h>
#endif

using namespace Mortis;

//  Additional target functions for robustness testing
//  (defined at bottom with #pragma optimize off to guarantee hookable size)

// Large struct passed by value
struct LargeStruct {
    std::array<std::uint8_t, 128> data{};
    int tag = 0;

    bool operator==(const LargeStruct& other) const {
        return data == other.data && tag == other.tag;
    }
};

// Varied calling patterns — defined later with optimizations off
MORTIS_NOINLINE int RecursiveFactorial(int n);
MORTIS_NOINLINE double FloatingPointAdd(double a, double b);
MORTIS_NOINLINE LargeStruct MakeLargeStruct(int tag);
MORTIS_NOINLINE int ManyParams(int a, int b, int c, int d, int e, int f);
MORTIS_NOINLINE int ThrowingFunction(int x);
MORTIS_NOINLINE int TightLoop(int n);
MORTIS_NOINLINE int ConditionalBranching(int x);
MORTIS_NOINLINE std::int64_t Int64Operation(std::int64_t a, std::int64_t b);
MORTIS_NOINLINE int VolatileHeavy(int x);
MORTIS_NOINLINE int SmallFunction(int x);

//  1. Recursion & Reentrancy

TEST(HookRobustness, RecursiveFunction) {
    // Hook a recursive function — the detour calls original, which re-enters
    EXPECT_EQ(IndirectCall(RecursiveFactorial, 5), 120);

    std::atomic<int> hookCallCount{0};
    auto hook = InlineHook::Create(
        &RecursiveFactorial,
        [&hookCallCount](auto& original, int n) -> int {
            hookCallCount.fetch_add(1, std::memory_order_relaxed);
            return original(n);
        }
    );
    ASSERT_TRUE(hook) << hook.error();

    int result = IndirectCall(RecursiveFactorial, 5);
    EXPECT_EQ(result, 120);
    // The hook should be called for each recursive invocation
    EXPECT_GE(hookCallCount.load(), 1);
}

TEST(HookRobustness, DetourCallsOriginalMultipleTimes) {
    auto hook = InlineHook::Create(
        &Add,
        [](auto& original, int a, int b) -> int {
            int r1 = original(a, b);
            int r2 = original(a, b);
            return r1 + r2;
        }
    );
    ASSERT_TRUE(hook) << hook.error();
    EXPECT_EQ(IndirectCall(Add, 3, 4), 14);  // (3+4) + (3+4)
}

//  2. Floating Point Arguments & Return Values

TEST(HookRobustness, FloatingPointFunction) {
    EXPECT_DOUBLE_EQ(IndirectCall(FloatingPointAdd, 1.5, 2.5), 4.0);

    auto hook = InlineHook::Create(
        &FloatingPointAdd,
        [](auto& original, double a, double b) -> double {
            return original(a, b) * 2.0;
        }
    );
    ASSERT_TRUE(hook) << hook.error();
    EXPECT_DOUBLE_EQ(IndirectCall(FloatingPointAdd, 1.5, 2.5), 8.0);

    ASSERT_TRUE(hook->disable());
    EXPECT_DOUBLE_EQ(IndirectCall(FloatingPointAdd, 1.5, 2.5), 4.0);
}

//  3. Large Struct By Value (tests register spilling / stack layout)

TEST(HookRobustness, LargeStructReturnValue) {
    auto result = IndirectCall(MakeLargeStruct, 42);
    EXPECT_EQ(result.tag, 42);
    EXPECT_EQ(result.data[0], 42);

    auto hook = InlineHook::Create(
        &MakeLargeStruct,
        [](auto& original, int tag) -> LargeStruct {
            auto s = original(tag);
            s.tag += 1000;
            return s;
        }
    );
    ASSERT_TRUE(hook) << hook.error();

    auto hooked = IndirectCall(MakeLargeStruct, 42);
    EXPECT_EQ(hooked.tag, 1042);
    EXPECT_EQ(hooked.data[0], 42);
}

//  4. Many Parameters (some on stack on x64)

TEST(HookRobustness, ManyParameters) {
    // x64 Windows: first 4 in RCX,RDX,R8,R9, rest on stack
    EXPECT_EQ(IndirectCall(ManyParams, 1, 2, 3, 4, 5, 6), 21);

    auto hook = InlineHook::Create(
        &ManyParams,
        [](auto& original, int a, int b, int c, int d, int e, int f) -> int {
            return original(a, b, c, d, e, f) + 100;
        }
    );
    ASSERT_TRUE(hook) << hook.error();
    EXPECT_EQ(IndirectCall(ManyParams, 1, 2, 3, 4, 5, 6), 121);
}

//  5. 64-bit Integer Arguments

TEST(HookRobustness, Int64Arguments) {
    std::int64_t a = 0x100000000LL;
    std::int64_t b = 0x200000000LL;
    EXPECT_EQ(IndirectCall(Int64Operation, a, b), a + b);

    auto hook = InlineHook::Create(
        &Int64Operation,
        [](auto& original, std::int64_t x, std::int64_t y) -> std::int64_t {
            return original(x, y) * 2;
        }
    );
    ASSERT_TRUE(hook) << hook.error();
    EXPECT_EQ(IndirectCall(Int64Operation, a, b), (a + b) * 2);
}

//  6. Exception Safety

TEST(HookRobustness, ExceptionInDetour) {
    auto hook = InlineHook::Create(
        &Add,
        [](auto& original, int a, int b) -> int {
            if (a < 0) throw std::runtime_error("negative a");
            return original(a, b);
        }
    );
    ASSERT_TRUE(hook) << hook.error();

    // Normal call should work
    EXPECT_EQ(IndirectCall(Add, 3, 4), 7);

    // Exception should propagate cleanly
    EXPECT_THROW(IndirectCall(Add, -1, 4), std::runtime_error);

    // Hook should still work after exception
    EXPECT_EQ(IndirectCall(Add, 5, 6), 11);
}

TEST(HookRobustness, ExceptionInOriginal) {
    // Hook ThrowingFunction which throws when x < 0
    auto hook = InlineHook::Create(
        &ThrowingFunction,
        [](auto& original, int x) -> int {
            return original(x) + 100;
        }
    );
    ASSERT_TRUE(hook) << hook.error();

    EXPECT_EQ(IndirectCall(ThrowingFunction, 10), 110);
    EXPECT_THROW(IndirectCall(ThrowingFunction, -1), std::runtime_error);

    // Verify hook still works after exception through original
    EXPECT_EQ(IndirectCall(ThrowingFunction, 20), 120);
}

//  7. Multi-threaded Concurrent Calling

TEST(HookRobustness, ConcurrentCalls) {
    std::atomic<int> totalCalls{0};

    auto hook = InlineHook::Create(
        &Add,
        [&totalCalls](auto& original, int a, int b) -> int {
            totalCalls.fetch_add(1, std::memory_order_relaxed);
            return original(a, b);
        }
    );
    ASSERT_TRUE(hook) << hook.error();

    constexpr int kThreads = 8;
    constexpr int kCallsPerThread = 1000;

    std::vector<std::thread> threads;
    std::atomic<bool> go{false};

    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&go, t] {
            while (!go.load(std::memory_order_acquire)) { /* spin */ }
            for (int i = 0; i < kCallsPerThread; ++i) {
                int result = IndirectCall(Add, t, i);
                EXPECT_EQ(result, t + i);
            }
        });
    }

    go.store(true, std::memory_order_release);
    for (auto& t : threads) t.join();

    EXPECT_EQ(totalCalls.load(), kThreads * kCallsPerThread);
}

TEST(HookRobustness, ConcurrentCallsMultipleFunctions) {
    std::atomic<int> addCalls{0}, mulCalls{0}, subCalls{0};

    auto hookAdd = InlineHook::Create(&Add,
        [&addCalls](auto& original, int a, int b) -> int {
            addCalls.fetch_add(1, std::memory_order_relaxed);
            return original(a, b);
        });
    auto hookMul = InlineHook::Create(&Multiply,
        [&mulCalls](auto& original, int a, int b) -> int {
            mulCalls.fetch_add(1, std::memory_order_relaxed);
            return original(a, b);
        });
    auto hookSub = InlineHook::Create(&Subtract,
        [&subCalls](auto& original, int a, int b) -> int {
            subCalls.fetch_add(1, std::memory_order_relaxed);
            return original(a, b);
        });
    ASSERT_TRUE(hookAdd) << hookAdd.error();
    ASSERT_TRUE(hookMul) << hookMul.error();
    ASSERT_TRUE(hookSub) << hookSub.error();

    constexpr int kThreads = 4;
    constexpr int kIter = 500;
    std::vector<std::thread> threads;
    std::atomic<bool> go{false};

    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&go] {
            while (!go.load(std::memory_order_acquire)) {}
            for (int i = 0; i < kIter; ++i) {
                EXPECT_EQ(IndirectCall(Add, 2, 3), 5);
                EXPECT_EQ(IndirectCall(Multiply, 2, 3), 6);
                EXPECT_EQ(IndirectCall(Subtract, 5, 2), 3);
            }
        });
    }

    go.store(true, std::memory_order_release);
    for (auto& t : threads) t.join();

    EXPECT_EQ(addCalls.load(), kThreads * kIter);
    EXPECT_EQ(mulCalls.load(), kThreads * kIter);
    EXPECT_EQ(subCalls.load(), kThreads * kIter);
}

//  8. Rapid Enable/Disable Toggling

TEST(HookRobustness, RapidToggle) {
    auto hook = InlineHook::Create(
        &Add,
        [](auto& original, int a, int b) -> int {
            return original(a, b) + 1;
        }
    );
    ASSERT_TRUE(hook) << hook.error();

    for (int i = 0; i < 100; ++i) {
        EXPECT_EQ(IndirectCall(Add, 1, 1), 3);  // hooked: 2+1
        ASSERT_TRUE(hook->disable());
        EXPECT_EQ(IndirectCall(Add, 1, 1), 2);  // original
        ASSERT_TRUE(hook->enable());
    }
}

TEST(HookRobustness, ToggleUnderConcurrentCalls) {
    // Test that toggling hooks between batches of concurrent calls is safe.
    // Note: Toggling while threads are mid-call through the prologue is
    // inherently unsafe without ThreadFreezer (which Install/Remove use).
    // This test verifies correctness of the synchronization in the
    // enable/disable + call boundary.

    auto hook = InlineHook::Create(
        &Multiply,
        [](auto& original, int a, int b) -> int {
            return original(a, b) + 1;
        }
    );
    ASSERT_TRUE(hook) << hook.error();

    for (int cycle = 0; cycle < 20; ++cycle) {
        // Ensure hook is enabled, then launch threads
        ASSERT_TRUE(hook->enable());

        constexpr int kWorkers = 4;
        constexpr int kCallsPerWorker = 100;
        std::atomic<int> errors{0};
        std::vector<std::thread> workers;
        std::atomic<bool> go{false};

        for (int i = 0; i < kWorkers; ++i) {
            workers.emplace_back([&go, &errors] {
                while (!go.load(std::memory_order_acquire)) {}
                for (int j = 0; j < kCallsPerWorker; ++j) {
                    int result = IndirectCall(Multiply, 3, 4);
                    if (result != 13) {  // hooked: 12+1
                        errors.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            });
        }
        go.store(true, std::memory_order_release);
        for (auto& w : workers) w.join();
        EXPECT_EQ(errors.load(), 0) << "cycle " << cycle;

        // Now disable safely (no concurrent callers)
        ASSERT_TRUE(hook->disable());
        EXPECT_EQ(IndirectCall(Multiply, 3, 4), 12);
    }
}

//  9. Chain Hooking (sequential hooks on same function)

TEST(HookRobustness, SequentialHookUnhook) {
    // Hook, unhook, then hook again — prologue must be fully restored
    for (int iteration = 0; iteration < 10; ++iteration) {
        auto hook = InlineHook::Create(
            &Add,
            [iteration](auto& original, int a, int b) -> int {
                return original(a, b) + iteration;
            }
        );
        ASSERT_TRUE(hook) << "iteration " << iteration << ": " << hook.error();
        EXPECT_EQ(IndirectCall(Add, 1, 1), 2 + iteration)
            << "iteration " << iteration;
    }
    // After all hooks are destroyed, original should work
    EXPECT_EQ(IndirectCall(Add, 1, 1), 2);
}

TEST(HookRobustness, DifferentDetoursOnSameFunction) {
    // First hook
    {
        auto hook = InlineHook::Create(
            &Subtract,
            [](auto& original, int a, int b) -> int {
                return original(a, b) * 10;
            }
        );
        ASSERT_TRUE(hook) << hook.error();
        EXPECT_EQ(IndirectCall(Subtract, 5, 2), 30);  // (5-2) * 10
    }
    EXPECT_EQ(IndirectCall(Subtract, 5, 2), 3);

    // Second hook with different behavior
    {
        auto hook = InlineHook::Create(
            &Subtract,
            [](auto& original, int a, int b) -> int {
                return original(a, b) + 500;
            }
        );
        ASSERT_TRUE(hook) << hook.error();
        EXPECT_EQ(IndirectCall(Subtract, 5, 2), 503);  // (5-2) + 500
    }
    EXPECT_EQ(IndirectCall(Subtract, 5, 2), 3);
}

//  10. Functions with Varied Prologue Patterns

TEST(HookRobustness, HookTightLoopFunction) {
    // TightLoop has a loop in its body — tests that prologue analysis
    // correctly identifies instruction boundaries
    EXPECT_EQ(IndirectCall(TightLoop, 5), 15);  // 1+2+3+4+5

    auto hook = InlineHook::Create(
        &TightLoop,
        [](auto& original, int n) -> int {
            return original(n) + 1000;
        }
    );
    ASSERT_TRUE(hook) << hook.error();
    EXPECT_EQ(IndirectCall(TightLoop, 5), 1015);
}

TEST(HookRobustness, HookConditionalBranchingFunction) {
    EXPECT_EQ(IndirectCall(ConditionalBranching, 10), 100);
    EXPECT_EQ(IndirectCall(ConditionalBranching, -5), 25);

    auto hook = InlineHook::Create(
        &ConditionalBranching,
        [](auto& original, int x) -> int {
            return original(x) + 1;
        }
    );
    ASSERT_TRUE(hook) << hook.error();
    EXPECT_EQ(IndirectCall(ConditionalBranching, 10), 101);
    EXPECT_EQ(IndirectCall(ConditionalBranching, -5), 26);
}

TEST(HookRobustness, HookVolatileHeavyFunction) {
    EXPECT_EQ(IndirectCall(VolatileHeavy, 10), 40);

    auto hook = InlineHook::Create(
        &VolatileHeavy,
        [](auto& original, int x) -> int {
            return original(x) * 2;
        }
    );
    ASSERT_TRUE(hook) << hook.error();
    EXPECT_EQ(IndirectCall(VolatileHeavy, 10), 80);
}

//  11. Detour State (captured data correctness)

TEST(HookRobustness, DetourWithCapturedState) {
    int capturedCounter = 0;
    std::string capturedLog;

    auto hook = InlineHook::Create(
        &Add,
        [&capturedCounter, &capturedLog](auto& original, int a, int b) -> int {
            ++capturedCounter;
            capturedLog += "call;";
            return original(a, b);
        }
    );
    ASSERT_TRUE(hook) << hook.error();

    for (int i = 0; i < 5; ++i) {
        EXPECT_EQ(IndirectCall(Add, 1, 2), 3);
    }
    EXPECT_EQ(capturedCounter, 5);
    EXPECT_EQ(capturedLog, "call;call;call;call;call;");
}

TEST(HookRobustness, DetourWithMutex) {
    std::mutex mtx;
    std::vector<int> log;

    auto hook = InlineHook::Create(
        &Add,
        [&mtx, &log](auto& original, int a, int b) -> int {
            std::lock_guard lock(mtx);
            log.push_back(a + b);
            return original(a, b);
        }
    );
    ASSERT_TRUE(hook) << hook.error();

    constexpr int kThreads = 4;
    constexpr int kCalls = 100;
    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&] {
            for (int i = 0; i < kCalls; ++i) {
                IndirectCall(Add, 1, 2);
            }
        });
    }
    for (auto& t : threads) t.join();

    EXPECT_EQ(log.size(), static_cast<std::size_t>(kThreads * kCalls));
    for (int v : log) EXPECT_EQ(v, 3);
}

//  12. Correctness Under Different Optimization Levels
//      (these tests exercise patterns that behave differently in
//       debug vs release: inlining, register allocation, etc.)

TEST(HookRobustness, SideEffectPreservation) {
    // Ensure detour side effects are visible across optimization levels
    volatile int sideEffect = 0;

    auto hook = InlineHook::Create(
        &Add,
        [&sideEffect](auto& original, int a, int b) -> int {
            sideEffect = a * b;
            return original(a, b);
        }
    );
    ASSERT_TRUE(hook) << hook.error();

    EXPECT_EQ(IndirectCall(Add, 7, 8), 15);
    EXPECT_EQ(sideEffect, 56);
}

TEST(HookRobustness, OriginalReturnValueIntegrity) {
    // Even in release mode with aggressive optimization, the original
    // function's return value should be faithfully relayed
    auto hook = InlineHook::Create(
        &Multiply,
        [](auto& original, int a, int b) -> int {
            int result = original(a, b);
            // Do NOT modify result — just pass through
            return result;
        }
    );
    ASSERT_TRUE(hook) << hook.error();

    // Test with values that stress the register allocator
    for (int i = 1; i <= 20; ++i) {
        EXPECT_EQ(IndirectCall(Multiply, i, i + 1), i * (i + 1));
    }
}

//  13. Back-to-back Hook Lifecycle

TEST(HookRobustness, BackToBackHookCreateDestroy) {
    // Stress test: create and destroy hooks rapidly
    for (int i = 0; i < 50; ++i) {
        auto hook = InlineHook::Create(
            &Add,
            [i](auto& original, int a, int b) -> int {
                return original(a, b) + i;
            }
        );
        ASSERT_TRUE(hook) << "iteration " << i << ": " << hook.error();
        EXPECT_EQ(IndirectCall(Add, 1, 1), 2 + i);
    }
    EXPECT_EQ(IndirectCall(Add, 1, 1), 2);
}

TEST(HookRobustness, MultipleHookHandleLifetimes) {
    // Create multiple hooks on different functions, destroy in varied order
    // Using optional to allow explicit destruction ordering
    std::optional<InlineHookHandle<int(int, int)>> hookAdd;
    std::optional<InlineHookHandle<int(int, int)>> hookMul;
    std::optional<InlineHookHandle<int(int, int)>> hookSub;

    auto rAdd = InlineHook::Create(&Add,
        [](auto& orig, int a, int b) -> int { return orig(a, b) + 10; });
    auto rMul = InlineHook::Create(&Multiply,
        [](auto& orig, int a, int b) -> int { return orig(a, b) + 20; });
    auto rSub = InlineHook::Create(&Subtract,
        [](auto& orig, int a, int b) -> int { return orig(a, b) + 30; });

    ASSERT_TRUE(rAdd) << rAdd.error();
    ASSERT_TRUE(rMul) << rMul.error();
    ASSERT_TRUE(rSub) << rSub.error();

    hookAdd.emplace(std::move(*rAdd));
    hookMul.emplace(std::move(*rMul));
    hookSub.emplace(std::move(*rSub));

    EXPECT_EQ(IndirectCall(Add, 1, 1), 12);
    EXPECT_EQ(IndirectCall(Multiply, 2, 3), 26);
    EXPECT_EQ(IndirectCall(Subtract, 5, 2), 33);

    // Destroy in middle-first order
    hookMul.reset();
    EXPECT_EQ(IndirectCall(Add, 1, 1), 12);
    EXPECT_EQ(IndirectCall(Multiply, 2, 3), 6);  // restored
    EXPECT_EQ(IndirectCall(Subtract, 5, 2), 33);

    hookAdd.reset();
    EXPECT_EQ(IndirectCall(Add, 1, 1), 2);  // restored
    EXPECT_EQ(IndirectCall(Subtract, 5, 2), 33);

    hookSub.reset();
    EXPECT_EQ(IndirectCall(Subtract, 5, 2), 3);  // restored
}

//  14. Member Function Hook Edge Cases

TEST(HookRobustness, MemberFunctionConcurrentCalls) {
    Calculator calc;
    int (Calculator::*volatile computePtr)(int, int) = &Calculator::Compute;
    auto callCompute = [&](int x, int y) { return (calc.*computePtr)(x, y); };

    std::atomic<int> hookCalls{0};
    auto hook = InlineHook::CreateMember<&Calculator::Compute>(
        [&hookCalls](auto& original, Calculator* self, int x, int y) -> int {
            hookCalls.fetch_add(1, std::memory_order_relaxed);
            return original(self, x, y);
        }
    );
    ASSERT_TRUE(hook) << hook.error();

    constexpr int kThreads = 4;
    constexpr int kCalls = 200;
    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&] {
            Calculator localCalc;
            for (int i = 0; i < kCalls; ++i) {
                int result = (localCalc.*computePtr)(i, i + 1);
                EXPECT_EQ(result, i * 2 + (i + 1));
            }
        });
    }
    for (auto& t : threads) t.join();
    EXPECT_EQ(hookCalls.load(), kThreads * kCalls);
}

TEST(HookRobustness, MemberFunctionDisableEnable) {
    Calculator calc;
    int (Calculator::*volatile computePtr)(int, int) = &Calculator::Compute;
    auto callCompute = [&](int x, int y) { return (calc.*computePtr)(x, y); };

    auto hook = InlineHook::CreateMember<&Calculator::Compute>(
        [](auto& original, Calculator* self, int x, int y) -> int {
            return original(self, x, y) + 999;
        }
    );
    ASSERT_TRUE(hook) << hook.error();

    for (int i = 0; i < 10; ++i) {
        EXPECT_EQ(callCompute(3, 4), 1009);
        ASSERT_TRUE(hook->disable());
        EXPECT_EQ(callCompute(3, 4), 10);
        ASSERT_TRUE(hook->enable());
    }
}

//  15. Import Hook Robustness (Windows only)

#ifdef MORTIS_OS_WINDOWS

MORTIS_NOINLINE static DWORD CallGetCurrentProcessId_Robust() {
    return GetCurrentProcessId();
}

TEST(HookRobustness, ImportHookConcurrentCalls) {
    DWORD realPid = CallGetCurrentProcessId_Robust();

    auto hook = ImportHook::Create<DWORD()>(
        "", "kernel32.dll", "GetCurrentProcessId",
        [](auto& original) -> DWORD {
            return original() + 1;
        }
    );
    ASSERT_TRUE(hook) << hook.error();

    constexpr int kThreads = 4;
    constexpr int kCalls = 200;
    std::atomic<int> errors{0};
    std::vector<std::thread> threads;

    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&] {
            for (int i = 0; i < kCalls; ++i) {
                DWORD pid = CallGetCurrentProcessId_Robust();
                if (pid != realPid + 1) {
                    errors.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }
    for (auto& t : threads) t.join();
    EXPECT_EQ(errors.load(), 0);
}

TEST(HookRobustness, ImportHookRapidToggle) {
    DWORD realPid = CallGetCurrentProcessId_Robust();

    auto hook = ImportHook::Create<DWORD()>(
        "", "kernel32.dll", "GetCurrentProcessId",
        [](auto& original) -> DWORD { return original() + 42; }
    );
    ASSERT_TRUE(hook) << hook.error();

    for (int i = 0; i < 50; ++i) {
        EXPECT_EQ(CallGetCurrentProcessId_Robust(), realPid + 42);
        ASSERT_TRUE(hook->disable());
        EXPECT_EQ(CallGetCurrentProcessId_Robust(), realPid);
        ASSERT_TRUE(hook->enable());
    }
}

TEST(HookRobustness, ImportHookBackToBack) {
    DWORD realPid = CallGetCurrentProcessId_Robust();

    for (int i = 0; i < 20; ++i) {
        auto hook = ImportHook::Create<DWORD()>(
            "", "kernel32.dll", "GetCurrentProcessId",
            [i](auto& original) -> DWORD { return original() + static_cast<DWORD>(i); }
        );
        ASSERT_TRUE(hook) << "iteration " << i << ": " << hook.error();
        EXPECT_EQ(CallGetCurrentProcessId_Robust(), realPid + static_cast<DWORD>(i));
    }
    EXPECT_EQ(CallGetCurrentProcessId_Robust(), realPid);
}

#endif  // MORTIS_OS_WINDOWS

//  16. Double-disable / Double-enable Idempotency

TEST(HookRobustness, DoubleDisableIsIdempotent) {
    auto hook = InlineHook::Create(
        &Add,
        [](auto& original, int a, int b) -> int {
            return original(a, b) + 1;
        }
    );
    ASSERT_TRUE(hook) << hook.error();

    ASSERT_TRUE(hook->disable());
    ASSERT_TRUE(hook->disable());  // second disable should be no-op
    EXPECT_EQ(IndirectCall(Add, 1, 1), 2);

    ASSERT_TRUE(hook->enable());
    ASSERT_TRUE(hook->enable());  // second enable should be no-op
    EXPECT_EQ(IndirectCall(Add, 1, 1), 3);
}

//  17. Hook Function Pointer Detour Robustness

namespace {

int RobustDetourMul(OriginalFunction<int(int, int)>& original, int a, int b) {
    return original(a, b) * 100;
}
}  // namespace

TEST(HookRobustness, FunctionPointerDetourToggle) {
    auto hook = InlineHook::Create(&Multiply, &RobustDetourMul);
    ASSERT_TRUE(hook) << hook.error();

    EXPECT_EQ(IndirectCall(Multiply, 3, 4), 1200);  // 12 * 100

    ASSERT_TRUE(hook->disable());
    EXPECT_EQ(IndirectCall(Multiply, 3, 4), 12);

    ASSERT_TRUE(hook->enable());
    EXPECT_EQ(IndirectCall(Multiply, 3, 4), 1200);
}

//  18. Stress Test — Many Hooks Simultaneously

TEST(HookRobustness, ManyConcurrentHooks) {
    // Hook multiple distinct functions simultaneously
    auto h1 = InlineHook::Create(&Add,
        [](auto& orig, int a, int b) -> int { return orig(a, b) + 1; });
    auto h2 = InlineHook::Create(&Multiply,
        [](auto& orig, int a, int b) -> int { return orig(a, b) + 2; });
    auto h3 = InlineHook::Create(&Subtract,
        [](auto& orig, int a, int b) -> int { return orig(a, b) + 3; });
    auto h4 = InlineHook::Create(&FloatingPointAdd,
        [](auto& orig, double a, double b) -> double { return orig(a, b) + 100.0; });
    auto h5 = InlineHook::Create(&TightLoop,
        [](auto& orig, int n) -> int { return orig(n) + 10; });

    ASSERT_TRUE(h1) << h1.error();
    ASSERT_TRUE(h2) << h2.error();
    ASSERT_TRUE(h3) << h3.error();
    ASSERT_TRUE(h4) << h4.error();
    ASSERT_TRUE(h5) << h5.error();

    EXPECT_EQ(IndirectCall(Add, 1, 2), 4);       // 3+1
    EXPECT_EQ(IndirectCall(Multiply, 2, 3), 8);   // 6+2
    EXPECT_EQ(IndirectCall(Subtract, 5, 1), 7);   // 4+3
    EXPECT_DOUBLE_EQ(IndirectCall(FloatingPointAdd, 1.0, 2.0), 103.0);
    EXPECT_EQ(IndirectCall(TightLoop, 3), 16);     // 6+10

    // Disable all
    ASSERT_TRUE(h1->disable());
    ASSERT_TRUE(h2->disable());
    ASSERT_TRUE(h3->disable());
    ASSERT_TRUE(h4->disable());
    ASSERT_TRUE(h5->disable());

    EXPECT_EQ(IndirectCall(Add, 1, 2), 3);
    EXPECT_EQ(IndirectCall(Multiply, 2, 3), 6);
    EXPECT_EQ(IndirectCall(Subtract, 5, 1), 4);
    EXPECT_DOUBLE_EQ(IndirectCall(FloatingPointAdd, 1.0, 2.0), 3.0);
    EXPECT_EQ(IndirectCall(TightLoop, 3), 6);
}

TEST(HookRobustness, ReuseFreedMiddleTrampolineSlotSafely) {
    // Install three hooks so trampolines are allocated back-to-back.
    auto h1 = InlineHook::Create(&Add,
        [](auto& orig, int a, int b) -> int { return orig(a, b) + 1; });
    auto h2 = InlineHook::Create(&Multiply,
        [](auto& orig, int a, int b) -> int { return orig(a, b) + 2; });
    auto h3 = InlineHook::Create(&Subtract,
        [](auto& orig, int a, int b) -> int { return orig(a, b) + 3; });

    ASSERT_TRUE(h1) << h1.error();
    ASSERT_TRUE(h2) << h2.error();
    ASSERT_TRUE(h3) << h3.error();

    EXPECT_EQ(IndirectCall(Add, 1, 2), 4);
    EXPECT_EQ(IndirectCall(Multiply, 2, 3), 8);
    EXPECT_EQ(IndirectCall(Subtract, 7, 4), 6);

    // Free the middle hook first.
    ASSERT_TRUE(h2->disable());
    EXPECT_EQ(IndirectCall(Multiply, 2, 3), 6);

    // Install another hook. If freed-slot bookkeeping is wrong,
    // this can alias an in-use trampoline and corrupt h3/h1 behavior.
    auto h4 = InlineHook::Create(&FloatingPointAdd,
        [](auto& orig, double a, double b) -> double { return orig(a, b) + 10.0; });
    ASSERT_TRUE(h4) << h4.error();

    EXPECT_EQ(IndirectCall(Add, 1, 2), 4);
    EXPECT_EQ(IndirectCall(Subtract, 7, 4), 6);
    EXPECT_DOUBLE_EQ(IndirectCall(FloatingPointAdd, 1.0, 2.0), 13.0);
}

//                   Hook Chain — Priority-ordered chaining

/// @brief Two hooks on the same function, different priorities.
TEST(HookChain, TwoHooksPriorityOrder) {
    // Hook A (priority 10): adds 1000
    auto hookA = InlineHook::Create(
        &SmallFunction,
        [](auto& original, int x) -> int {
            return original(x) + 1000;
        },
        10);
    ASSERT_TRUE(hookA) << hookA.error();

    // Hook B (priority 0, higher priority): multiplies result by 2
    auto hookB = InlineHook::Create(
        &SmallFunction,
        [](auto& original, int x) -> int {
            return original(x) * 2;
        },
        0);
    ASSERT_TRUE(hookB) << hookB.error();

    // Execution order: SmallFunction(5) = 6
    //   hookB (prio 0) called first: calls original → hookA (prio 10)
    //   hookA: calls original → real SmallFunction(5) = 6 → 6 + 1000 = 1006
    //   hookB: gets 1006 from its original() → 1006 * 2 = 2012
    EXPECT_EQ(IndirectCall(SmallFunction, 5), 2012);
}

/// @brief Three hooks with distinct priorities.
TEST(HookChain, ThreeHooksPriorityOrder) {
    // Priority 5: add 100
    auto h1 = InlineHook::Create(
        &SmallFunction,
        [](auto& original, int x) -> int { return original(x) + 100; },
        5);
    // Priority 0: multiply by 3 (highest priority, called first)
    auto h2 = InlineHook::Create(
        &SmallFunction,
        [](auto& original, int x) -> int { return original(x) * 3; },
        0);
    // Priority 10: add 10 (lowest priority, called last before real fn)
    auto h3 = InlineHook::Create(
        &SmallFunction,
        [](auto& original, int x) -> int { return original(x) + 10; },
        10);

    ASSERT_TRUE(h1) << h1.error();
    ASSERT_TRUE(h2) << h2.error();
    ASSERT_TRUE(h3) << h3.error();

    // Chain order: h2 (p0) → h1 (p5) → h3 (p10) → real
    // real SmallFunction(1) = 2
    // h3: original(1) = 2 → 2 + 10 = 12
    // h1: original(1) = 12 → 12 + 100 = 112
    // h2: original(1) = 112 → 112 * 3 = 336
    EXPECT_EQ(IndirectCall(SmallFunction, 1), 336);
}

/// @brief Same-priority hooks execute in FIFO order.
TEST(HookChain, SamePriorityFIFO) {
    std::vector<int> callOrder;

    auto h1 = InlineHook::Create(
        &SmallFunction,
        [&callOrder](auto& original, int x) -> int {
            callOrder.push_back(1);
            return original(x);
        },
        0);
    auto h2 = InlineHook::Create(
        &SmallFunction,
        [&callOrder](auto& original, int x) -> int {
            callOrder.push_back(2);
            return original(x);
        },
        0);
    auto h3 = InlineHook::Create(
        &SmallFunction,
        [&callOrder](auto& original, int x) -> int {
            callOrder.push_back(3);
            return original(x);
        },
        0);

    ASSERT_TRUE(h1) << h1.error();
    ASSERT_TRUE(h2) << h2.error();
    ASSERT_TRUE(h3) << h3.error();

    IndirectCall(SmallFunction, 1);

    ASSERT_EQ(callOrder.size(), 3u);
    EXPECT_EQ(callOrder[0], 1);  // First installed, called first
    EXPECT_EQ(callOrder[1], 2);
    EXPECT_EQ(callOrder[2], 3);
}

/// @brief Removing a middle hook rewires the chain correctly.
TEST(HookChain, RemoveMiddleHook) {
    // h1 prio 0: +1000
    auto h1 = InlineHook::Create(
        &SmallFunction,
        [](auto& original, int x) -> int { return original(x) + 1000; },
        0);
    // h2 prio 5: +100
    auto h2 = InlineHook::Create(
        &SmallFunction,
        [](auto& original, int x) -> int { return original(x) + 100; },
        5);
    // h3 prio 10: +10
    auto h3 = InlineHook::Create(
        &SmallFunction,
        [](auto& original, int x) -> int { return original(x) + 10; },
        10);

    ASSERT_TRUE(h1) << h1.error();
    ASSERT_TRUE(h2) << h2.error();
    ASSERT_TRUE(h3) << h3.error();

    // Chain: h1 → h2 → h3 → real
    // SmallFunction(1)=2, h3: 2+10=12, h2: 12+100=112, h1: 112+1000=1112
    EXPECT_EQ(IndirectCall(SmallFunction, 1), 1112);

    // Remove h2 (middle)
    ASSERT_TRUE(h2->disable());

    // Chain: h1 → h3 → real
    // h3: 2+10=12, h1: 12+1000=1012
    EXPECT_EQ(IndirectCall(SmallFunction, 1), 1012);
}

/// @brief Removing first (highest priority) hook.
TEST(HookChain, RemoveFirstHook) {
    auto h1 = InlineHook::Create(
        &SmallFunction,
        [](auto& original, int x) -> int { return original(x) + 1000; },
        0);
    auto h2 = InlineHook::Create(
        &SmallFunction,
        [](auto& original, int x) -> int { return original(x) + 100; },
        5);

    ASSERT_TRUE(h1) << h1.error();
    ASSERT_TRUE(h2) << h2.error();

    // Chain: h1 → h2 → real.  SmallFunction(1)=2, h2:102, h1:1102
    EXPECT_EQ(IndirectCall(SmallFunction, 1), 1102);

    // Remove h1 (first/highest priority)
    ASSERT_TRUE(h1->disable());

    // Chain: h2 → real.  SmallFunction(1)=2, h2:102
    EXPECT_EQ(IndirectCall(SmallFunction, 1), 102);
}

/// @brief Removing last (lowest priority) hook.
TEST(HookChain, RemoveLastHook) {
    auto h1 = InlineHook::Create(
        &SmallFunction,
        [](auto& original, int x) -> int { return original(x) + 1000; },
        0);
    auto h2 = InlineHook::Create(
        &SmallFunction,
        [](auto& original, int x) -> int { return original(x) + 100; },
        5);

    ASSERT_TRUE(h1) << h1.error();
    ASSERT_TRUE(h2) << h2.error();

    EXPECT_EQ(IndirectCall(SmallFunction, 1), 1102);

    // Remove h2 (last/lowest priority)
    ASSERT_TRUE(h2->disable());

    // Chain: h1 → real.  SmallFunction(1)=2, h1:1002
    EXPECT_EQ(IndirectCall(SmallFunction, 1), 1002);
}

/// @brief Re-enable a disabled hook back into the chain.
TEST(HookChain, ReenableHook) {
    auto h1 = InlineHook::Create(
        &SmallFunction,
        [](auto& original, int x) -> int { return original(x) + 1000; },
        0);
    auto h2 = InlineHook::Create(
        &SmallFunction,
        [](auto& original, int x) -> int { return original(x) + 100; },
        5);

    ASSERT_TRUE(h1) << h1.error();
    ASSERT_TRUE(h2) << h2.error();

    EXPECT_EQ(IndirectCall(SmallFunction, 1), 1102);

    ASSERT_TRUE(h1->disable());
    EXPECT_EQ(IndirectCall(SmallFunction, 1), 102);

    ASSERT_TRUE(h1->enable());
    EXPECT_EQ(IndirectCall(SmallFunction, 1), 1102);
}

/// @brief Destroy a handle mid-chain (via scope exit).
TEST(HookChain, HandleDestructionMidChain) {
    auto h1 = InlineHook::Create(
        &SmallFunction,
        [](auto& original, int x) -> int { return original(x) + 1000; },
        0);
    ASSERT_TRUE(h1) << h1.error();

    {
        auto h2 = InlineHook::Create(
            &SmallFunction,
            [](auto& original, int x) -> int { return original(x) + 100; },
            5);
        ASSERT_TRUE(h2) << h2.error();
        EXPECT_EQ(IndirectCall(SmallFunction, 1), 1102);
    }
    // h2 destroyed — chain should be just h1 → real
    EXPECT_EQ(IndirectCall(SmallFunction, 1), 1002);
}

/// @brief All handles destroyed — function fully restored.
TEST(HookChain, AllHandlesDestroyed) {
    {
        auto h1 = InlineHook::Create(
            &SmallFunction,
            [](auto& original, int x) -> int { return original(x) * 10; },
            0);
        auto h2 = InlineHook::Create(
            &SmallFunction,
            [](auto& original, int x) -> int { return original(x) + 1; },
            5);
        ASSERT_TRUE(h1) << h1.error();
        ASSERT_TRUE(h2) << h2.error();
        EXPECT_NE(IndirectCall(SmallFunction, 5), 6); // modified
    }
    // Both destroyed — original behavior restored
    EXPECT_EQ(IndirectCall(SmallFunction, 5), 6);
}

/// @brief Chain with concurrent callers.
TEST(HookChain, ConcurrentCallsOnChain) {
    auto h1 = InlineHook::Create(
        &SmallFunction,
        [](auto& original, int x) -> int { return original(x) + 1000; },
        0);
    auto h2 = InlineHook::Create(
        &SmallFunction,
        [](auto& original, int x) -> int { return original(x) + 100; },
        5);
    ASSERT_TRUE(h1) << h1.error();
    ASSERT_TRUE(h2) << h2.error();

    std::atomic<int> failures{0};
    constexpr int kThreads = 8;
    constexpr int kCalls = 1000;

    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&failures] {
            for (int c = 0; c < kCalls; ++c) {
                // SmallFunction(1)=2, h2:102, h1:1102
                if (IndirectCall(SmallFunction, 1) != 1102) {
                    ++failures;
                }
            }
        });
    }
    for (auto& t : threads) t.join();
    EXPECT_EQ(failures.load(), 0);
}

/// @brief Stress test: many hooks on one function.
TEST(HookChain, ManyHooksOnSameFunction) {
    std::vector<std::optional<InlineHookHandle<int(int)>>> hooks;
    hooks.reserve(10);

    for (int i = 0; i < 10; ++i) {
        auto h = InlineHook::Create(
            &SmallFunction,
            [i](auto& original, int x) -> int { return original(x) + (i + 1); },
            i * 10);
        ASSERT_TRUE(h) << "Hook " << i << " failed: " << h.error();
        hooks.emplace_back(std::move(h.value()));
    }

    // Each hook adds (i+1) to the result.
    // Total addition = 1+2+3+...+10 = 55
    // SmallFunction(0)=1, plus 55 = 56
    EXPECT_EQ(IndirectCall(SmallFunction, 0), 56);

    // Remove hooks from high priority to low
    for (int i = 0; i < 10; ++i) {
        hooks[i].reset();
    }
    EXPECT_EQ(IndirectCall(SmallFunction, 0), 1);
}

/// @brief Default priority (0) for all Create overloads.
TEST(HookChain, DefaultPriorityBackwardCompat) {
    // Existing code without priority parameter should still work
    auto h1 = InlineHook::Create(
        &Add,
        [](auto& original, int a, int b) -> int { return original(a, b) + 100; });
    ASSERT_TRUE(h1) << h1.error();
    EXPECT_EQ(IndirectCall(Add, 1, 2), 103);
}

//  Target function definitions (optimizations disabled for hookable size)

#ifdef MORTIS_COMPILER_MSVC
#pragma optimize("", off)
#endif

MORTIS_NOINLINE int RecursiveFactorial(int n) {
    volatile int vn = n;
    if (vn <= 1) return 1;
    volatile int sub = vn - 1;
    return vn * RecursiveFactorial(sub);
}

MORTIS_NOINLINE double FloatingPointAdd(double a, double b) {
    volatile double va = a;
    volatile double vb = b;
    volatile double result = va + vb;
    return result;
}

MORTIS_NOINLINE LargeStruct MakeLargeStruct(int tag) {
    LargeStruct s;
    volatile int vtag = tag;
    s.tag = vtag;
    s.data[0] = static_cast<std::uint8_t>(vtag);
    s.data[1] = static_cast<std::uint8_t>(vtag + 1);
    return s;
}

MORTIS_NOINLINE int ManyParams(int a, int b, int c, int d, int e, int f) {
    volatile int va = a;
    volatile int vb = b;
    volatile int vc = c;
    volatile int vd = d;
    volatile int ve = e;
    volatile int vf = f;
    return va + vb + vc + vd + ve + vf;
}

MORTIS_NOINLINE int ThrowingFunction(int x) {
    volatile int vx = x;
    if (vx < 0) throw std::runtime_error("negative input");
    volatile int result = vx;
    return result;
}

MORTIS_NOINLINE int TightLoop(int n) {
    volatile int sum = 0;
    volatile int i = 1;
    while (i <= n) {
        sum = sum + i;
        i = i + 1;
    }
    return sum;
}

MORTIS_NOINLINE int ConditionalBranching(int x) {
    volatile int vx = x;
    volatile int result = 0;
    if (vx > 0) {
        result = vx * vx;
    } else {
        result = (-vx) * (-vx);
    }
    return result;
}

MORTIS_NOINLINE std::int64_t Int64Operation(std::int64_t a, std::int64_t b) {
    volatile std::int64_t va = a;
    volatile std::int64_t vb = b;
    volatile std::int64_t result = va + vb;
    return result;
}

MORTIS_NOINLINE int VolatileHeavy(int x) {
    volatile int a = x;
    volatile int b = a + x;
    volatile int c = b + x;
    volatile int d = c + x;
    return d;
}

MORTIS_NOINLINE int SmallFunction(int x) {
    volatile int v = x;
    volatile int r = v + 1;
    return r;
}

#ifdef MORTIS_COMPILER_MSVC
#pragma optimize("", on)
#endif
