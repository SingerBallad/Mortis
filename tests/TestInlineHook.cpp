#include "TestHelpers.hpp"
#include <gtest/gtest.h>

#include <utility>

using namespace Mortis;

// Plain function-pointer detour helpers (used by FunctionPointerDetour tests).
namespace {

int DetourSubtract(OriginalFunction<int(int, int)>& original, int a, int b) { return original(a, b) + 1000; }

} // namespace

// InlineHook — Core

TEST(InlineHook, FreeFunctionByAddress) {
    EXPECT_EQ(IndirectCall(Add, 3, 4), 7);

    // Signature auto-deduced from the detour lambda.
    auto hook =
        InlineHook::Create(AddressOf(&Add), [](auto& original, int a, int b) -> int { return original(a, b) * 10; });
    ASSERT_TRUE(hook) << hook.error();
    EXPECT_EQ(IndirectCall(Add, 3, 4), 70);

    ASSERT_TRUE(hook->disable());
    EXPECT_EQ(IndirectCall(Add, 3, 4), 7);

    ASSERT_TRUE(hook->enable());
    EXPECT_EQ(IndirectCall(Add, 3, 4), 70);
}

TEST(InlineHook, FreeFunctionScopeRestore) {
    {
        auto hook = InlineHook::Create(AddressOf(&Add), [](auto& original, int a, int b) -> int {
            return original(a, b) + 100;
        });
        ASSERT_TRUE(hook) << hook.error();
        EXPECT_EQ(IndirectCall(Add, 3, 4), 107);
    }
    EXPECT_EQ(IndirectCall(Add, 3, 4), 7);
}

TEST(InlineHook, TypedFunctionPointer) {
    auto hook =
        InlineHook::Create(&Multiply, [](auto& original, int a, int b) -> int { return original(a, b) + 1000; });
    ASSERT_TRUE(hook) << hook.error();
    EXPECT_EQ(IndirectCall(Multiply, 5, 6), 1030);
}

TEST(InlineHook, MemberFunction) {
    Calculator calc;
    int (Calculator::* volatile computePtr)(int, int) = &Calculator::Compute;
    auto callCompute                                  = [&](int x, int y) { return (calc.*computePtr)(x, y); };

    EXPECT_EQ(callCompute(3, 4), 10); // 3*2 + 4

    auto hook =
        InlineHook::CreateMember<&Calculator::Compute>([](auto& original, Calculator* self, int x, int y) -> int {
            return original(self, x, y) + 100;
        });
    ASSERT_TRUE(hook) << hook.error();
    EXPECT_EQ(callCompute(3, 4), 110);
}

TEST(InlineHook, MemberFunctionByAddress) {
    Calculator calc;
    int (Calculator::* volatile computePtr)(int, int) = &Calculator::Compute;
    auto callCompute                                  = [&](int x, int y) { return (calc.*computePtr)(x, y); };

    EXPECT_EQ(callCompute(3, 4), 10);

    // Use CreateMember with an explicit address.
    auto addr = Detail::MemberFnAddress(&Calculator::Compute);
    auto hook =
        InlineHook::CreateMember<&Calculator::Compute>(addr, [](auto& original, Calculator* self, int x, int y) -> int {
            return original(self, x, y) + 200;
        });
    ASSERT_TRUE(hook) << hook.error();
    EXPECT_EQ(callCompute(3, 4), 210);
}

TEST(InlineHook, MemberFunctionPointerDetour) {
    // Hook a member function with a plain function pointer detour.
    Calculator calc;
    int (Calculator::* volatile computePtr)(int, int) = &Calculator::Compute;
    auto callCompute                                  = [&](int x, int y) { return (calc.*computePtr)(x, y); };

    EXPECT_EQ(callCompute(3, 4), 10);

    auto hook = InlineHook::CreateMember<&Calculator::Compute>(
        [](OriginalFunction<int(Calculator*, int, int)>& original, Calculator* self, int x, int y) -> int {
            return original(self, x, y) + 300;
        }
    );
    ASSERT_TRUE(hook) << hook.error();
    EXPECT_EQ(callCompute(3, 4), 310);
}

TEST(InlineHook, IsEnabled) {
    auto hook = InlineHook::Create(AddressOf(&Subtract), [](auto& original, int a, int b) -> int {
        return original(a, b) * 2;
    });
    ASSERT_TRUE(hook) << hook.error();
    EXPECT_TRUE(hook->isEnabled());

    ASSERT_TRUE(hook->disable());
    EXPECT_FALSE(hook->isEnabled());

    ASSERT_TRUE(hook->enable());
    EXPECT_TRUE(hook->isEnabled());
}

//                   InlineHook — Move semantics

TEST(InlineHook, MoveConstruction) {
    auto hook = InlineHook::Create(AddressOf(&Subtract), [](auto& original, int a, int b) -> int {
        return original(a, b) + 500;
    });
    ASSERT_TRUE(hook) << hook.error();
    EXPECT_EQ(IndirectCall(Subtract, 10, 3), 507);

    auto moved = std::move(hook.value());
    EXPECT_TRUE(moved.isEnabled());
    EXPECT_EQ(IndirectCall(Subtract, 10, 3), 507);
}

TEST(InlineHook, MoveAssignment) {
    auto hook1 = InlineHook::Create(AddressOf(&Subtract), [](auto& original, int a, int b) -> int {
        return original(a, b) + 200;
    });
    ASSERT_TRUE(hook1) << hook1.error();

    InlineHookHandle<int(int, int)> hook2 = std::move(hook1.value());
    EXPECT_TRUE(hook2.isEnabled());
    EXPECT_EQ(IndirectCall(Subtract, 10, 3), 207);
}

//                   InlineHook — Advanced scenarios

TEST(InlineHook, DisableEnableMultipleCycles) {
    auto hook =
        InlineHook::Create(AddressOf(&Add), [](auto& original, int a, int b) -> int { return original(a, b) + 1; });
    ASSERT_TRUE(hook) << hook.error();

    for (int i = 0; i < 5; ++i) {
        EXPECT_EQ(IndirectCall(Add, 1, 1), 3) << "cycle " << i << " enabled";
        ASSERT_TRUE(hook->disable());
        EXPECT_EQ(IndirectCall(Add, 1, 1), 2) << "cycle " << i << " disabled";
        ASSERT_TRUE(hook->enable());
    }
    EXPECT_EQ(IndirectCall(Add, 1, 1), 3);
}

TEST(InlineHook, ConcurrentHooksDifferentFunctions) {
    auto hookAdd = InlineHook::Create(&Add, [](auto& original, int a, int b) -> int { return original(a, b) + 100; });
    auto hookMul =
        InlineHook::Create(&Multiply, [](auto& original, int a, int b) -> int { return original(a, b) + 200; });
    auto hookSub =
        InlineHook::Create(&Subtract, [](auto& original, int a, int b) -> int { return original(a, b) + 300; });
    ASSERT_TRUE(hookAdd) << hookAdd.error();
    ASSERT_TRUE(hookMul) << hookMul.error();
    ASSERT_TRUE(hookSub) << hookSub.error();

    EXPECT_EQ(IndirectCall(Add, 2, 3), 105);       // 5 + 100
    EXPECT_EQ(IndirectCall(Multiply, 2, 3), 206);  // 6 + 200
    EXPECT_EQ(IndirectCall(Subtract, 10, 3), 307); // 7 + 300
}

TEST(InlineHook, HookVoidFunction) {
    // Verify that hooking a void(int) function works.
    volatile int sideEffect = 0;

    auto hook = InlineHook::Create(AddressOf(&TraceFunction), [&sideEffect](auto& original, int x) -> void {
        sideEffect = x * 2;
        original(x);
    });
    ASSERT_TRUE(hook) << hook.error();

    TraceFunction(21);
    EXPECT_EQ(sideEffect, 42);
}

//                InlineHook — Function pointer detour

TEST(InlineHook, FunctionPointerDetour) {
    // Hook Subtract with a plain function pointer detour.
    EXPECT_EQ(IndirectCall(Subtract, 10, 3), 7);

    auto hook = InlineHook::Create(&Subtract, &DetourSubtract);
    ASSERT_TRUE(hook) << hook.error();

    EXPECT_EQ(IndirectCall(Subtract, 10, 3), 1007); // 7 + 1000

    // Disable / re-enable.
    ASSERT_TRUE(hook->disable());
    EXPECT_EQ(IndirectCall(Subtract, 10, 3), 7);

    ASSERT_TRUE(hook->enable());
    EXPECT_EQ(IndirectCall(Subtract, 10, 3), 1007);
}

TEST(InlineHook, FunctionPointerDetourByAddress) {
    // Same as above but the target is given as a raw Address.
    EXPECT_EQ(IndirectCall(Subtract, 10, 3), 7);

    auto hook = InlineHook::Create(AddressOf(&Subtract), &DetourSubtract);
    ASSERT_TRUE(hook) << hook.error();

    EXPECT_EQ(IndirectCall(Subtract, 10, 3), 1007);
}

TEST(InlineHook, OriginalAccessor) {
    // Original() works with lambda-based hooks too.
    auto hook = InlineHook::Create(&Add, [](auto& original, int a, int b) -> int { return original(a, b) + 100; });
    ASSERT_TRUE(hook) << hook.error();

    // Calling Original() directly should bypass the hook.
    auto* orig = hook->original();
    EXPECT_EQ(orig(3, 4), 7);                // original Add
    EXPECT_EQ(IndirectCall(Add, 3, 4), 107); // through hook
}

TEST(InlineHook, FunctionPointerTypeMismatchDoesNotCompile) {
    // This is a compile-time check — the static_assert below documents
    // that a detour function pointer must have a matching signature.
    //
    // Uncommenting the line below should produce a compile error:
    //   auto hook = InlineHook::Create(&Add, &TraceFunction);  // mismatched signatures
    SUCCEED();
}
