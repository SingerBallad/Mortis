/// @file TestCore.cpp
/// @brief Tests for Config, Result, ErrorCode, and MemoryProtection.

#include "TestHelpers.hpp"
#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

using namespace Mortis;

// Config.hpp

TEST(Config, PlatformConstants) {
#ifdef MORTIS_OS_WINDOWS
    EXPECT_TRUE(kIsWindows);
    EXPECT_FALSE(kIsLinux);
#elif defined(MORTIS_OS_LINUX)
    EXPECT_FALSE(kIsWindows);
    EXPECT_TRUE(kIsLinux);
#endif
}

TEST(Config, ArchitectureConstants) {
#ifdef MORTIS_ARCH_X64
    EXPECT_TRUE(kIsX64);
    EXPECT_FALSE(kIsArm64);
#elif defined(MORTIS_ARCH_ARM64)
    EXPECT_FALSE(kIsX64);
    EXPECT_TRUE(kIsArm64);
#endif
}

TEST(Config, DefaultMaxHookSlots) { EXPECT_EQ(kDefaultMaxHookSlots, 64); }

TEST(Config, CompilerConstants) {
#ifdef MORTIS_COMPILER_MSVC
    EXPECT_TRUE(kIsMSVC);
#elif defined(MORTIS_COMPILER_GCC)
    EXPECT_TRUE(kIsGCC);
#elif defined(MORTIS_COMPILER_CLANG)
    EXPECT_TRUE(kIsClang);
#endif
}

TEST(Config, AddressOf) {
    auto addr = AddressOf(&Add);
    EXPECT_NE(addr, 0u);
    EXPECT_EQ(addr, reinterpret_cast<Address>(&Add));
}

TEST(Config, PlatformAndArchMutuallyExclusive) {
    // Exactly one platform and one arch must be true.
    EXPECT_EQ(static_cast<int>(kIsWindows) + static_cast<int>(kIsLinux), 1);
    EXPECT_EQ(static_cast<int>(kIsX64) + static_cast<int>(kIsArm64), 1);
}

// Result.hpp

TEST(Result, OkValue) {
    auto r = Result<int>::Ok(42);
    ASSERT_TRUE(r);
    EXPECT_EQ(r.value(), 42);
}

TEST(Result, ErrValue) {
    auto r = Result<int>::Err("something failed");
    EXPECT_FALSE(r);
    EXPECT_EQ(r.error(), "something failed");
}

TEST(Result, ArrowOperator) {
    auto r = Result<std::string>::Ok("hello");
    ASSERT_TRUE(r);
    EXPECT_EQ(r->size(), 5u);

    const auto& cr = r;
    EXPECT_EQ(cr->size(), 5u);
}

TEST(Result, ValueRvalueRef) {
    auto r = Result<std::string>::Ok("movable");
    ASSERT_TRUE(r);
    std::string moved = std::move(r).value();
    EXPECT_EQ(moved, "movable");
}

TEST(Result, ConstValueRef) {
    const auto r = Result<int>::Ok(99);
    ASSERT_TRUE(r);
    EXPECT_EQ(r.value(), 99);
}

TEST(ResultVoid, Ok) {
    auto r = Result<void>::Ok();
    EXPECT_TRUE(r);
    EXPECT_TRUE(r.error().empty());
}

TEST(ResultVoid, Err) {
    auto r = Result<void>::Err("void error");
    EXPECT_FALSE(r);
    EXPECT_EQ(r.error(), "void error");
}

// ErrorCode

TEST(Result, ErrorCodeDefault) {
    auto r = Result<int>::Err("legacy error");
    EXPECT_EQ(r.code(), ErrorCode::Unknown);
}

TEST(Result, ErrorCodeStructured) {
    auto r = Result<int>::Err(ErrorCode::NoFreeSlots, "pool full");
    EXPECT_FALSE(r);
    EXPECT_EQ(r.code(), ErrorCode::NoFreeSlots);
    EXPECT_EQ(r.error(), "pool full");
}

TEST(Result, OkHasUnknownCode) {
    auto r = Result<int>::Ok(42);
    EXPECT_TRUE(r);
    EXPECT_EQ(r.code(), ErrorCode::Unknown);
}

TEST(ResultVoid, ErrorCodeStructured) {
    auto r = Result<void>::Err(ErrorCode::MemoryNotReadable, "bad addr");
    EXPECT_FALSE(r);
    EXPECT_EQ(r.code(), ErrorCode::MemoryNotReadable);
    EXPECT_EQ(r.error(), "bad addr");
}

TEST(ResultVoid, OkHasUnknownCode) {
    auto r = Result<void>::Ok();
    EXPECT_TRUE(r);
    EXPECT_EQ(r.code(), ErrorCode::Unknown);
}

TEST(Result, AllErrorCodesDistinct) {
    // Verify that all error codes have distinct underlying values.
    std::vector codes{
        static_cast<int>(ErrorCode::Unknown),
        static_cast<int>(ErrorCode::HookInstallFailed),
        static_cast<int>(ErrorCode::HookRemoveFailed),
        static_cast<int>(ErrorCode::ProtectionFailed),
        static_cast<int>(ErrorCode::MemoryNotReadable),
        static_cast<int>(ErrorCode::MemoryNotWritable),
        static_cast<int>(ErrorCode::NoFreeSlots),
        static_cast<int>(ErrorCode::ImportNotFound),
        static_cast<int>(ErrorCode::ModuleNotFound),
        static_cast<int>(ErrorCode::InvalidArgument),
    };
    std::sort(codes.begin(), codes.end());
    auto it = std::unique(codes.begin(), codes.end());
    EXPECT_EQ(it, codes.end()) << "Duplicate ErrorCode underlying values found";
}

// MemoryProtection

TEST(MemoryProtection, BitwiseOr) {
    auto combined = MemoryProtection::Read | MemoryProtection::Write;
    EXPECT_EQ(combined, MemoryProtection::ReadWrite);
}

TEST(MemoryProtection, BitwiseAnd) {
    auto masked = MemoryProtection::ReadWriteExec & MemoryProtection::Write;
    EXPECT_EQ(masked, MemoryProtection::Write);
}

TEST(MemoryProtection, HasFlag) {
    EXPECT_TRUE(HasFlag(MemoryProtection::ReadWriteExec, MemoryProtection::Read));
    EXPECT_TRUE(HasFlag(MemoryProtection::ReadWriteExec, MemoryProtection::Write));
    EXPECT_TRUE(HasFlag(MemoryProtection::ReadWriteExec, MemoryProtection::Execute));
    EXPECT_FALSE(HasFlag(MemoryProtection::Read, MemoryProtection::Write));
    EXPECT_FALSE(HasFlag(MemoryProtection::None, MemoryProtection::Read));
}

TEST(MemoryProtection, NoneHasNoFlags) {
    EXPECT_FALSE(HasFlag(MemoryProtection::None, MemoryProtection::Read));
    EXPECT_FALSE(HasFlag(MemoryProtection::None, MemoryProtection::Write));
    EXPECT_FALSE(HasFlag(MemoryProtection::None, MemoryProtection::Execute));
}
