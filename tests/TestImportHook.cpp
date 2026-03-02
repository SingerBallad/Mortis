#include "TestHelpers.hpp"
#include <gtest/gtest.h>

#include <Windows.h>
#include <utility>

using namespace Mortis;

// NOINLINE wrapper to force a fresh IAT dereference each call, preventing
// the optimizer from hoisting the IAT load out of the call-site.

MORTIS_NOINLINE static DWORD CallGetCurrentProcessId() {
    return GetCurrentProcessId();
}

// ImportHook — Core

TEST(ImportHook, HookKernel32Function) {
    DWORD realPid = CallGetCurrentProcessId();
    EXPECT_NE(realPid, 0u);

    auto hook = ImportHook::Create<DWORD()>(
        "",                  // main executable
        "kernel32.dll",
        "GetCurrentProcessId",
        [](auto& original) -> DWORD {
            return original() + 1;
        }
    );
    ASSERT_TRUE(hook) << hook.error();
    EXPECT_TRUE(hook->isEnabled());

    DWORD hookedPid = CallGetCurrentProcessId();
    EXPECT_EQ(hookedPid, realPid + 1);

    ASSERT_TRUE(hook->disable());
    EXPECT_FALSE(hook->isEnabled());
    EXPECT_EQ(CallGetCurrentProcessId(), realPid);

    ASSERT_TRUE(hook->enable());
    EXPECT_TRUE(hook->isEnabled());
    EXPECT_EQ(CallGetCurrentProcessId(), realPid + 1);
}

TEST(ImportHook, ScopeRestore) {
    DWORD realPid = CallGetCurrentProcessId();
    {
        auto hook = ImportHook::Create<DWORD()>(
            "", "kernel32.dll", "GetCurrentProcessId",
            [](auto& original) -> DWORD { return original() + 999; }
        );
        ASSERT_TRUE(hook) << hook.error();
        EXPECT_EQ(CallGetCurrentProcessId(), realPid + 999);
    }
    EXPECT_EQ(CallGetCurrentProcessId(), realPid);
}

TEST(ImportHook, MoveConstruction) {
    DWORD realPid = CallGetCurrentProcessId();
    auto hook = ImportHook::Create<DWORD()>(
        "", "kernel32.dll", "GetCurrentProcessId",
        [](auto& original) -> DWORD { return original() + 42; }
    );
    ASSERT_TRUE(hook) << hook.error();
    EXPECT_EQ(CallGetCurrentProcessId(), realPid + 42);

    auto moved = std::move(hook.value());
    EXPECT_TRUE(moved.isEnabled());
    EXPECT_EQ(CallGetCurrentProcessId(), realPid + 42);
}

TEST(ImportHook, NonexistentFunction) {
    auto hook = ImportHook::Create<void()>(
        "", "kernel32.dll", "ThisFunctionDoesNotExist_XYZ",
        [](auto& original) { original(); }
    );
    EXPECT_FALSE(hook);
    EXPECT_EQ(hook.code(), ErrorCode::ImportNotFound);
}

TEST(ImportHook, NonexistentModule) {
    auto hook = ImportHook::Create<void()>(
        "", "nonexistent_module_xyz.dll", "SomeFunction",
        [](auto& original) { original(); }
    );
    EXPECT_FALSE(hook);
}
