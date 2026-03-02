#include "TestHelpers.hpp"
#include <gtest/gtest.h>

#include <cstdint>

using namespace Mortis;

// Process / Module introspection

TEST(Process, Singleton) {
    auto& p1 = Process::Self();
    auto& p2 = Process::Self();
    EXPECT_EQ(&p1, &p2);
}

TEST(Process, FindMainModule) {
    auto& process    = Process::Self();
    auto  mainModule = process.FindModule();
    ASSERT_TRUE(mainModule.has_value());
    EXPECT_FALSE(mainModule->name().empty());
    EXPECT_NE(mainModule->base(), 0u);
    EXPECT_GT(mainModule->size(), 0u);
}

TEST(Process, FindModuleNonexistent) {
    auto& process = Process::Self();
    auto  mod     = process.FindModule("this_module_does_not_exist_12345.dll");
    EXPECT_FALSE(mod.has_value());
}

TEST(Process, EnumerateModules) {
    auto& process = Process::Self();
    auto  modules = process.EnumerateModules();
    EXPECT_GT(modules.size(), 0u);

    // At least one module should contain the Add function
    auto addAddr = AddressOf(&Add);
    bool found   = false;
    for (auto& mod : modules) {
        if (mod.contains(addAddr)) {
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found);
}

TEST(Process, ModuleContainsAddress) {
    auto& process    = Process::Self();
    auto  mainModule = process.FindModule();
    ASSERT_TRUE(mainModule.has_value());
    auto addAddr = AddressOf(&Add);
    EXPECT_TRUE(mainModule->contains(addAddr));
    EXPECT_FALSE(mainModule->contains(0u));
}

TEST(Process, ReadMemory) {
    int  value  = 0xBEEF;
    int  dest   = 0;
    auto result = Process::ReadMemory(&dest, reinterpret_cast<Address>(&value), sizeof(int));
    ASSERT_TRUE(result) << result.error();
    EXPECT_EQ(dest, 0xBEEF);
}

TEST(Process, WriteMemory) {
    int  value  = 42;
    int  source = 99;
    auto result = Process::WriteMemory(reinterpret_cast<Address>(&value), &source, sizeof(int));
    ASSERT_TRUE(result) << result.error();
    EXPECT_EQ(value, 99);
}

TEST(Process, ReadTyped) {
    int  value  = 12345;
    auto result = Process::Read<int>(reinterpret_cast<Address>(&value));
    ASSERT_TRUE(result) << result.error();
    EXPECT_EQ(result.value(), 12345);
}

TEST(Process, WriteTyped) {
    int  value  = 0;
    auto result = Process::Write<int>(reinterpret_cast<Address>(&value), 67890);
    ASSERT_TRUE(result) << result.error();
    EXPECT_EQ(value, 67890);
}

TEST(Process, SetAndQueryProtection) {
    auto addAddr  = AddressOf(&Add);
    auto origProt = Process::QueryProtection(addAddr);
    ASSERT_TRUE(origProt) << origProt.error();

    auto oldProt = Process::SetProtection(addAddr, 64, MemoryProtection::ReadWriteExec);
    ASSERT_TRUE(oldProt) << oldProt.error();

    auto newProt = Process::QueryProtection(addAddr);
    ASSERT_TRUE(newProt);
    EXPECT_TRUE(HasFlag(newProt.value(), MemoryProtection::Write));

    // Restore
    auto restored = Process::SetProtection(addAddr, 64, oldProt.value());
    ASSERT_TRUE(restored);
}

TEST(Process, IsReadableWritable) {
    int local = 0;
    EXPECT_TRUE(Process::IsReadable(reinterpret_cast<Address>(&local)));
    EXPECT_TRUE(Process::IsWritable(reinterpret_cast<Address>(&local)));
    EXPECT_FALSE(Process::IsReadable(0u));
    EXPECT_FALSE(Process::IsWritable(0u));
}

//             Module

TEST(Module, ConstructorAndAccessors) {
    Module mod("test.dll", 0x1000, 0x2000);
    EXPECT_EQ(mod.name(), "test.dll");
    EXPECT_EQ(mod.base(), 0x1000u);
    EXPECT_EQ(mod.size(), 0x2000u);
}

TEST(Module, ContainsBoundary) {
    Module mod("test.dll", 0x1000, 0x2000);
    EXPECT_TRUE(mod.contains(0x1000));  // base (inclusive)
    EXPECT_TRUE(mod.contains(0x2FFF));  // base + size - 1
    EXPECT_FALSE(mod.contains(0x3000)); // base + size (exclusive)
    EXPECT_FALSE(mod.contains(0x0FFF)); // below base
}

TEST(Module, FindTextSection) {
    auto& process    = Process::Self();
    auto  mainModule = process.FindModule();
    ASSERT_TRUE(mainModule.has_value());

    auto textSection = mainModule->findSection(".text");
    ASSERT_TRUE(textSection.has_value());
    auto [secBase, secSize] = *textSection;
    EXPECT_NE(secBase, 0u);
    EXPECT_GT(secSize, 0u);
}

TEST(Module, FindSectionNonexistent) {
    auto& process    = Process::Self();
    auto  mainModule = process.FindModule();
    ASSERT_TRUE(mainModule.has_value());

    auto noSection = mainModule->findSection(".doesnotexist");
    EXPECT_FALSE(noSection.has_value());
}

TEST(Module, FindExport) {
    auto& process = Process::Self();
    if constexpr (kIsWindows) {
        auto kernel32 = process.FindModule("kernel32");
        ASSERT_TRUE(kernel32.has_value());

        auto addr = kernel32->findExport("GetCurrentProcessId");
        ASSERT_TRUE(addr.has_value());
        EXPECT_NE(*addr, 0u);
    } else {
        auto libc = process.FindModule("libc");
        ASSERT_TRUE(libc.has_value());

        auto addr = libc->findExport("malloc");
        ASSERT_TRUE(addr.has_value());
        EXPECT_NE(*addr, 0u);
    }
}

TEST(Module, FindExportNonexistent) {
    auto& process = Process::Self();
    if constexpr (kIsWindows) {
        auto kernel32 = process.FindModule("kernel32");
        ASSERT_TRUE(kernel32.has_value());
        auto addr = kernel32->findExport("ThisFunctionDoesNotExist_12345");
        EXPECT_FALSE(addr.has_value());
    } else {
        auto libc = process.FindModule("libc");
        ASSERT_TRUE(libc.has_value());
        auto addr = libc->findExport("ThisFunctionDoesNotExist_12345");
        EXPECT_FALSE(addr.has_value());
    }
}

TEST(Module, EnumerateExports) {
    auto& process = Process::Self();
    if constexpr (kIsWindows) {
        auto kernel32 = process.FindModule("kernel32");
        ASSERT_TRUE(kernel32.has_value());
        auto exports = kernel32->enumerateExports();
        EXPECT_GT(exports.size(), 0u);
        EXPECT_NE(exports.find("GetCurrentProcessId"), exports.end());
    } else {
        auto libc = process.FindModule("libc");
        ASSERT_TRUE(libc.has_value());
        auto exports = libc->enumerateExports();
        EXPECT_GT(exports.size(), 0u);
        EXPECT_NE(exports.find("malloc"), exports.end());
    }
}
