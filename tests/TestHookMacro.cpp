#include "TestHelpers.hpp"
#include <Mortis/Mortis.hpp>
#include <gtest/gtest.h>

using namespace Mortis;

// Dummy target functions for tests
namespace {
int StaticTargetAdd(int a, int b) { return a + b; }
int AutoStaticTargetAdd(int a, int b) { return a + b; }

class TestTargetClass {
public:
    int value = 10;
    int Multiply(int factor) { return value * factor; }
};

class DerivedTargetClass : public TestTargetClass {
public:
    int AddAndMultiply(int a, int factor) { return (value + a) * factor; }
};
} // namespace

// Manual Static Hook

MORTIS_STATIC_HOOK(MyStaticHook, Mortis::HookPriority::Normal, (void*)&StaticTargetAdd, int, int a, int b) {
    // Modify arguments and call original
    return origin(a * 2, b * 2);
}

TEST(HookMacro, ManualStaticHook) {
    EXPECT_EQ(StaticTargetAdd(2, 3), 5);

    auto res = MyStaticHook::hook();
    ASSERT_TRUE(res);

    EXPECT_EQ(StaticTargetAdd(2, 3), 10);

    auto res2 = MyStaticHook::unhook();
    ASSERT_TRUE(res2);

    EXPECT_EQ(StaticTargetAdd(2, 3), 5);
}

// Manual Instance Hook

MORTIS_TYPE_INSTANCE_HOOK(
    MyInstanceHook,
    Mortis::HookPriority::Normal,
    TestTargetClass,
    &TestTargetClass::Multiply,
    int,
    int factor
) {

    // Access `this` transparently
    return origin(factor) + this->value;
}

TEST(HookMacro, ManualInstanceHook) {
    TestTargetClass obj;
    EXPECT_EQ(obj.Multiply(3), 30);

    auto res = MyInstanceHook::hook();
    ASSERT_TRUE(res);

    EXPECT_EQ(obj.Multiply(3), 40); // 30 + 10

    auto res2 = MyInstanceHook::unhook();
    ASSERT_TRUE(res2);

    EXPECT_EQ(obj.Multiply(3), 30);
}

// AUTO Static Hook

MORTIS_AUTO_STATIC_HOOK(
    MyAutoStaticHook,
    Mortis::HookPriority::Normal,
    (void*)&AutoStaticTargetAdd,
    int,
    int a,
    int b
) {
    return origin(a, b) + 100;
}

TEST(HookMacro, AutoStaticHookAlreadyActive) {
    // When the test runs, the AUTO registrar is already initialized globally.
    // AutoStaticTargetAdd should ALREADY be hooked here.
    EXPECT_EQ(AutoStaticTargetAdd(2, 3), 105);

    // Unhooking via manual call
    auto res = MyAutoStaticHook::unhook();
    ASSERT_TRUE(res);

    EXPECT_EQ(AutoStaticTargetAdd(2, 3), 5);

    // Re-hook for clean state (auto registrar destructor will handle it safely if left hooked,
    // but just to be symmetrical)
    res = MyAutoStaticHook::hook();
    ASSERT_TRUE(res);
}

// AUTO Instance Hook

MORTIS_AUTO_TYPE_INSTANCE_HOOK(
    MyAutoInstanceHook,
    Mortis::HookPriority::Normal,
    DerivedTargetClass,
    &DerivedTargetClass::AddAndMultiply,
    int,
    int a,
    int factor
) {

    int originalRes = origin(a, factor);
    // Uses thisFor to cast parent type if needed or just use this
    return originalRes * 2;
}

TEST(HookMacro, AutoInstanceHookAlreadyActive) {
    DerivedTargetClass obj;
    // (10 + 2) * 3 = 36 * 2 (hook) = 72
    EXPECT_EQ(obj.AddAndMultiply(2, 3), 72);

    auto res = MyAutoInstanceHook::unhook();
    ASSERT_TRUE(res);

    EXPECT_EQ(obj.AddAndMultiply(2, 3), 36);

    res = MyAutoInstanceHook::hook();
    ASSERT_TRUE(res);
}
