#include "TestHelpers.hpp"
#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <utility>

using namespace Mortis;

// Pointer

TEST(Pointer, ConstructFromAddress) {
    Pointer ptr(static_cast<Address>(0x1234));
    EXPECT_EQ(ptr.getAddress(), 0x1234u);
}

TEST(Pointer, ConstructFromVoidPtr) {
    int value = 0;
    Pointer ptr(&value);
    EXPECT_EQ(ptr.getAddress(), reinterpret_cast<Address>(&value));
}

TEST(Pointer, ReadWriteTyped) {
    int testValue = 42;
    auto ptr = Pointer(&testValue);

    auto readResult = ptr.read<int>();
    ASSERT_TRUE(readResult);
    EXPECT_EQ(readResult.value(), 42);

    auto writeResult = ptr.write<int>(99);
    ASSERT_TRUE(writeResult);
    EXPECT_EQ(testValue, 99);
}

TEST(Pointer, ReadBytes) {
    std::uint32_t testValue = 0x04030201;
    auto ptr = Pointer(&testValue);
    auto bytesResult = ptr.readBytes(sizeof(testValue));
    ASSERT_TRUE(bytesResult);
    auto& bytes = bytesResult.value();
    EXPECT_EQ(bytes.size(), sizeof(testValue));
    EXPECT_EQ(bytes[0], 0x01);
    EXPECT_EQ(bytes[1], 0x02);
    EXPECT_EQ(bytes[2], 0x03);
    EXPECT_EQ(bytes[3], 0x04);
}

TEST(Pointer, WriteBytes) {
    std::uint32_t testValue = 0;
    auto ptr = Pointer(&testValue);
    auto result = ptr.writeBytes({0xAA, 0xBB, 0xCC, 0xDD});
    ASSERT_TRUE(result) << result.error();
    EXPECT_EQ(testValue, 0xDDCCBBAA);
}

TEST(Pointer, Deref) {
    int value = 42;
    int* pValue = &value;
    auto ptr = Pointer(&pValue);
    auto derefResult = ptr.deref();
    ASSERT_TRUE(derefResult) << derefResult.error();
    EXPECT_EQ(derefResult.value().getAddress(), reinterpret_cast<Address>(&value));

    auto readResult = derefResult.value().read<int>();
    ASSERT_TRUE(readResult);
    EXPECT_EQ(readResult.value(), 42);
}

TEST(Pointer, DerefChain) {
    int value = 123;
    int* p = &value;
    int** pp = &p;

    auto ptr = Pointer(&pp);
    auto result = ptr.deref({0, 0});
    ASSERT_TRUE(result) << result.error();
    EXPECT_EQ(result.value().getAddress(), reinterpret_cast<Address>(&value));
}

TEST(Pointer, AddSub) {
    auto ptr = Pointer(static_cast<Address>(0x1000));
    auto added = ptr.add(0x100);
    EXPECT_EQ(added.getAddress(), 0x1100u);

    auto subtracted = ptr.sub(0x100);
    EXPECT_EQ(subtracted.getAddress(), 0x0F00u);

    EXPECT_EQ(ptr.add(50).sub(50).getAddress(), ptr.getAddress());
}

TEST(Pointer, IsReadableWritable) {
    int testValue = 42;
    auto ptr = Pointer(&testValue);
    EXPECT_TRUE(ptr.isReadable());
    EXPECT_TRUE(ptr.isWritable());

    auto nullPtr = Pointer(static_cast<Address>(0));
    EXPECT_FALSE(nullPtr.isReadable());
    EXPECT_FALSE(nullPtr.isWritable());
}

TEST(Pointer, OwnerModule) {
    auto owner = Pointer(reinterpret_cast<void*>(&Add)).ownerModule();
    ASSERT_TRUE(owner.has_value());
    EXPECT_FALSE(owner->name().empty());
}

TEST(Pointer, OwnerModuleNull) {
    auto owner = Pointer(static_cast<Address>(0)).ownerModule();
    EXPECT_FALSE(owner.has_value());
}

// ScopedProtect

TEST(ScopedProtect, ProtectsAndRestores) {
    auto addAddr = AddressOf(&Add);
    auto origProt = Process::QueryProtection(addAddr);
    ASSERT_TRUE(origProt);

    {
        auto guard = ScopedProtect::Create(
            addAddr, 64, MemoryProtection::ReadWriteExec);
        ASSERT_TRUE(guard) << guard.error();

        auto prot = Process::QueryProtection(addAddr);
        ASSERT_TRUE(prot);
        EXPECT_TRUE(HasFlag(prot.value(), MemoryProtection::Write));
    }

    auto restoredProt = Process::QueryProtection(addAddr);
    ASSERT_TRUE(restoredProt);
    EXPECT_EQ(restoredProt.value(), origProt.value());
}

TEST(ScopedProtect, MoveConstruction) {
    auto addAddr = AddressOf(&Add);
    auto origProt = Process::QueryProtection(addAddr);
    ASSERT_TRUE(origProt);

    {
        auto guard = ScopedProtect::Create(
            addAddr, 64, MemoryProtection::ReadWriteExec);
        ASSERT_TRUE(guard) << guard.error();

        ScopedProtect moved = std::move(guard.value());

        auto prot = Process::QueryProtection(addAddr);
        ASSERT_TRUE(prot);
        EXPECT_TRUE(HasFlag(prot.value(), MemoryProtection::Write));
    }
    auto restoredProt = Process::QueryProtection(addAddr);
    ASSERT_TRUE(restoredProt);
    EXPECT_EQ(restoredProt.value(), origProt.value());
}

TEST(ScopedProtect, MoveAssignment) {
    auto addAddr = AddressOf(&Add);
    auto origProt = Process::QueryProtection(addAddr);
    ASSERT_TRUE(origProt);

    {
        auto guard1 = ScopedProtect::Create(
            addAddr, 64, MemoryProtection::ReadWriteExec);
        ASSERT_TRUE(guard1) << guard1.error();

        // Create a second guard on a different address, then move-assign.
        int dummy = 0;
        auto guard2 = ScopedProtect::Create(
            reinterpret_cast<Address>(&dummy), 4, MemoryProtection::ReadWrite);
        ASSERT_TRUE(guard2) << guard2.error();

        guard2.value() = std::move(guard1.value());

        // Protection should still be RWX (guard1 moved to guard2)
        auto prot = Process::QueryProtection(addAddr);
        ASSERT_TRUE(prot);
        EXPECT_TRUE(HasFlag(prot.value(), MemoryProtection::Write));
    }
    auto restoredProt = Process::QueryProtection(addAddr);
    ASSERT_TRUE(restoredProt);
    EXPECT_EQ(restoredProt.value(), origProt.value());
}

//  MemoryPatch

TEST(MemoryPatch, PatchAndRestore) {
    int patchTarget = 0xDEAD;
    auto patchAddr = reinterpret_cast<Address>(&patchTarget);
    auto patch = MemoryPatch::Create(patchAddr, {0x42, 0x42, 0x42, 0x42});
    ASSERT_TRUE(patch) << patch.error();

    EXPECT_EQ(patchTarget, 0x42424242);
    EXPECT_TRUE(patch->isApplied());

    ASSERT_TRUE(patch->restore());
    EXPECT_EQ(patchTarget, 0xDEAD);
    EXPECT_FALSE(patch->isApplied());

    ASSERT_TRUE(patch->apply());
    EXPECT_EQ(patchTarget, 0x42424242);
}

TEST(MemoryPatch, RaiiAutoRestore) {
    int patchTarget = 0xCAFE;
    auto patchAddr = reinterpret_cast<Address>(&patchTarget);
    {
        auto patch = MemoryPatch::Create(patchAddr, {0x11, 0x22, 0x33, 0x44});
        ASSERT_TRUE(patch) << patch.error();
        EXPECT_NE(patchTarget, 0xCAFE);
    }
    EXPECT_EQ(patchTarget, 0xCAFE);
}

TEST(MemoryPatch, CreateNop) {
    std::array<std::uint8_t, 16> buffer{};
    auto patchAddr = reinterpret_cast<Address>(buffer.data());
    auto patch = MemoryPatch::CreateNop(patchAddr, 8);
    ASSERT_TRUE(patch) << patch.error();

    if constexpr (kIsX64) {
        for (int i = 0; i < 8; ++i) {
            EXPECT_EQ(buffer[i], 0x90) << "byte " << i;
        }
    } else if constexpr (kIsArm64) {
        // ARM64 NOP = 0xD503201F (little-endian), 2 instructions for 8 bytes.
        EXPECT_EQ(buffer[0], 0x1F);
        EXPECT_EQ(buffer[1], 0x20);
        EXPECT_EQ(buffer[2], 0x03);
        EXPECT_EQ(buffer[3], 0xD5);
        EXPECT_EQ(buffer[4], 0x1F);
        EXPECT_EQ(buffer[5], 0x20);
        EXPECT_EQ(buffer[6], 0x03);
        EXPECT_EQ(buffer[7], 0xD5);
    }
}

TEST(MemoryPatch, MoveConstruction) {
    int patchTarget = 0xAAAA;
    auto patchAddr = reinterpret_cast<Address>(&patchTarget);
    auto patch = MemoryPatch::Create(patchAddr, {0xBB, 0xBB, 0xBB, 0xBB});
    ASSERT_TRUE(patch) << patch.error();

    MemoryPatch moved = std::move(patch.value());
    EXPECT_TRUE(moved.isApplied());
    EXPECT_EQ(patchTarget, static_cast<int>(0xBBBBBBBB));

    ASSERT_TRUE(moved.restore());
    EXPECT_EQ(patchTarget, 0xAAAA);
}

TEST(MemoryPatch, MoveAssignment) {
    int target1 = 0x1111;
    int target2 = 0x2222;
    auto patch1 = MemoryPatch::Create(
        reinterpret_cast<Address>(&target1), {0xAA, 0xAA, 0xAA, 0xAA});
    auto patch2 = MemoryPatch::Create(
        reinterpret_cast<Address>(&target2), {0xBB, 0xBB, 0xBB, 0xBB});
    ASSERT_TRUE(patch1) << patch1.error();
    ASSERT_TRUE(patch2) << patch2.error();

    EXPECT_EQ(target1, static_cast<int>(0xAAAAAAAA));
    EXPECT_EQ(target2, static_cast<int>(0xBBBBBBBB));

    // Move-assign patch1 into patch2 — patch2 should restore target2, then own target1.
    patch2.value() = std::move(patch1.value());

    EXPECT_EQ(target2, 0x2222); // target2 restored by old patch2
    EXPECT_EQ(target1, static_cast<int>(0xAAAAAAAA)); // target1 still patched via moved patch

    ASSERT_TRUE(patch2->restore());
    EXPECT_EQ(target1, 0x1111);
}

TEST(MemoryPatch, DoubleApplyRestoreIdempotent) {
    int patchTarget = 0x1234;
    auto patchAddr = reinterpret_cast<Address>(&patchTarget);
    auto patch = MemoryPatch::Create(patchAddr, {0x56, 0x78, 0x9A, 0xBC});
    ASSERT_TRUE(patch) << patch.error();

    ASSERT_TRUE(patch->apply());
    EXPECT_TRUE(patch->isApplied());

    ASSERT_TRUE(patch->restore());
    ASSERT_TRUE(patch->restore());
    EXPECT_FALSE(patch->isApplied());
    EXPECT_EQ(patchTarget, 0x1234);
}
