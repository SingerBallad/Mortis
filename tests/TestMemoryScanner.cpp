#include "TestHelpers.hpp"
#include <Mortis/Process.hpp>
#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>

using namespace Mortis;

// Known byte sequence kept in the test binary for deterministic scans.
// volatile prevents the optimizer from folding, deduplicating, or
// eliminating this array in Release builds.
static volatile const std::uint8_t kScanNeedle[] = {0x13, 0x37, 0xC0, 0xDE, 0x42, 0x99, 0xAA, 0x55};

// SignatureElement

TEST(SignatureElement, ByteFactory) {
    auto e = SignatureElement::Byte(std::byte{0xAB});
    EXPECT_TRUE(e.isConcrete());
    EXPECT_FALSE(e.isWildcard());
    EXPECT_TRUE(e.matches(std::byte{0xAB}));
    EXPECT_FALSE(e.matches(std::byte{0x00}));
}

TEST(SignatureElement, WildcardFactory) {
    auto e = SignatureElement::Wildcard();
    EXPECT_TRUE(e.isWildcard());
    EXPECT_FALSE(e.isConcrete());
    EXPECT_TRUE(e.matches(std::byte{0x00}));
    EXPECT_TRUE(e.matches(std::byte{0xFF}));
}

TEST(SignatureElement, PartialMask) {
    SignatureElement e{std::byte{0xA0}, std::byte{0xF0}};
    EXPECT_FALSE(e.isWildcard());
    EXPECT_FALSE(e.isConcrete());
    EXPECT_TRUE(e.matches(std::byte{0xAB}));
    EXPECT_TRUE(e.matches(std::byte{0xA0}));
    EXPECT_FALSE(e.matches(std::byte{0xB0}));
}

// Signature

TEST(Signature, DefaultIsEmpty) {
    Signature sig;
    EXPECT_TRUE(sig.empty());
    EXPECT_EQ(sig.size(), 0u);
}

TEST(Signature, ConstructFromElements) {
    std::vector<SignatureElement> elems = {
        SignatureElement::Byte(std::byte{0x48}),
        SignatureElement::Wildcard(),
        SignatureElement::Byte(std::byte{0xCC}),
    };
    Signature sig(std::move(elems));
    EXPECT_EQ(sig.size(), 3u);
    EXPECT_TRUE(sig[0].isConcrete());
    EXPECT_TRUE(sig[1].isWildcard());
    EXPECT_TRUE(sig[2].isConcrete());
}

TEST(Signature, ToStringRoundTrip) {
    auto sig = MemoryScanner::ParseSignature("48 8B ? CC");
    ASSERT_TRUE(sig.has_value());
    auto str = sig->toString();
    EXPECT_EQ(str, "48 8B ? CC");
}

TEST(Signature, ImplicitConversionToView) {
    auto sig = MemoryScanner::ParseSignature("AA BB");
    ASSERT_TRUE(sig.has_value());
    // Should compile — Signature implicitly converts to SignatureView.
    SignatureView view = *sig;
    EXPECT_EQ(view.size(), 2u);
}

// ParseSignature

TEST(MemoryScanner, ParseSignatureValid) {
    auto sig = MemoryScanner::ParseSignature("48 8B ? CC");
    ASSERT_TRUE(sig.has_value());
    EXPECT_EQ(sig->size(), 4u);
}

TEST(MemoryScanner, ParseSignatureEmpty) { EXPECT_FALSE(MemoryScanner::ParseSignature("").has_value()); }

TEST(MemoryScanner, ParseSignatureWildcardVariants) {
    auto s1 = MemoryScanner::ParseSignature("AA ? BB");
    auto s2 = MemoryScanner::ParseSignature("AA ?? BB");
    ASSERT_TRUE(s1.has_value());
    ASSERT_TRUE(s2.has_value());
    EXPECT_EQ(s1->size(), 3u);
    EXPECT_EQ(s2->size(), 3u);
}

//  String-pattern FindFirst / FindAll

TEST(MemoryScanner, FindFirstStringPattern) {
    (void)kScanNeedle[0];
    auto result = MemoryScanner::FindFirst("", "13 37 C0 DE 42 99 AA 55");
    ASSERT_TRUE(result.hasResult());
    EXPECT_NE(result.get(), 0u);
}

TEST(MemoryScanner, FindFirstStringPatternNoMatch) {
    auto result = MemoryScanner::FindFirst("", "FE FE FE FE FE FE FE FE FE FE FE FE FE FE FE FE");
    EXPECT_FALSE(result.hasResult());
}

TEST(MemoryScanner, FindAllStringPattern) {
    (void)kScanNeedle[0];
    auto results = MemoryScanner::FindAll("", "13 37 C0 DE 42 99 AA 55");
    EXPECT_GT(results.size(), 0u);
    for (auto& r : results) {
        EXPECT_TRUE(r.hasResult());
    }
}

TEST(MemoryScanner, FindAllStringPatternNoMatch) {
    auto results = MemoryScanner::FindAll("", "FE FE FE FE FE FE FE FE FE FE FE FE FE FE FE FE");
    EXPECT_TRUE(results.empty());
}

TEST(MemoryScanner, FindFirstStringWildcard) {
    (void)kScanNeedle[0];
    auto result = MemoryScanner::FindFirst("", "13 37 ?? DE 42 ?? AA 55");
    ASSERT_TRUE(result.hasResult());
    EXPECT_NE(result.get(), 0u);
}

TEST(MemoryScanner, FindFirstNonexistentModule) {
    auto result = MemoryScanner::FindFirst("this_module_does_not_exist_12345.so", "13 37 C0 DE");
    EXPECT_FALSE(result.hasResult());
}

TEST(MemoryScanner, FindFirstInvalidPattern) {
    auto result = MemoryScanner::FindFirst("", "");
    EXPECT_FALSE(result.hasResult());
}

//  Pre-parsed signature scanning

TEST(MemoryScanner, FindFirstSignatureView) {
    (void)kScanNeedle[0];
    auto sig = MemoryScanner::ParseSignature("13 37 C0 DE 42 99 AA 55");
    ASSERT_TRUE(sig.has_value());
    auto result = MemoryScanner::FindFirst("", *sig);
    ASSERT_TRUE(result.hasResult());
    EXPECT_NE(result.get(), 0u);
}

TEST(MemoryScanner, FindAllSignatureView) {
    (void)kScanNeedle[0];
    auto sig = MemoryScanner::ParseSignature("13 37 C0 DE 42 99 AA 55");
    ASSERT_TRUE(sig.has_value());
    auto results = MemoryScanner::FindAll("", *sig);
    EXPECT_GT(results.size(), 0u);
}

// Module-based scanning

TEST(MemoryScanner, FindFirstWithModule) {
    (void)kScanNeedle[0];
    auto mod = Process::FindModule("");
    ASSERT_TRUE(mod.has_value());
    auto result = MemoryScanner::FindFirst(*mod, "13 37 C0 DE 42 99 AA 55");
    ASSERT_TRUE(result.hasResult());
    EXPECT_NE(result.get(), 0u);
}

TEST(MemoryScanner, FindAllWithModule) {
    (void)kScanNeedle[0];
    auto mod = Process::FindModule("");
    ASSERT_TRUE(mod.has_value());
    auto sig = MemoryScanner::ParseSignature("13 37 C0 DE 42 99 AA 55");
    ASSERT_TRUE(sig.has_value());
    auto results = MemoryScanner::FindAll(*mod, *sig);
    EXPECT_GT(results.size(), 0u);
}

// ScanResult

TEST(ScanResult, DefaultIsEmpty) {
    ScanResult r;
    EXPECT_FALSE(r.hasResult());
    EXPECT_FALSE(static_cast<bool>(r));
    EXPECT_EQ(r.get(), 0u);
    EXPECT_EQ(r.getRaw(), nullptr);
}

TEST(ScanResult, ConstructFromPointer) {
    const std::byte b{0x42};
    ScanResult      r{&b};
    EXPECT_TRUE(r.hasResult());
    EXPECT_EQ(r.getRaw(), &b);
    EXPECT_EQ(r.get(), reinterpret_cast<Address>(&b));
}

TEST(ScanResult, ReadInteger) {
    alignas(8) const std::uint8_t data[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    ScanResult                    r{reinterpret_cast<const std::byte*>(data)};
    EXPECT_EQ(r.read<std::uint8_t>(0), 0x01u);
    EXPECT_EQ(r.read<std::uint8_t>(3), 0x04u);
    EXPECT_EQ(r.read<std::uint16_t>(0), 0x0201u);
    EXPECT_EQ(r.read<std::uint32_t>(0), 0x04030201u);
}

TEST(ScanResult, Rel) {
    alignas(8) const std::uint8_t data[] = {
        0xAA,
        0xBB,
        0x10,
        0x00,
        0x00,
        0x00, // rel32 = +16
        0xCC
    };
    ScanResult r{reinterpret_cast<const std::byte*>(data)};
    auto       resolved = r.rel(2);
    auto       expected = reinterpret_cast<Address>(data + 6) + 16;
    EXPECT_EQ(resolved, expected);
}

TEST(ScanResult, RelWithRemaining) {
    alignas(8) const std::uint8_t data[] = {
        0xAA,
        0xBB,
        0x10,
        0x00,
        0x00,
        0x00,
        0xFF, // extra operand byte
        0xCC
    };
    ScanResult r{reinterpret_cast<const std::byte*>(data)};
    auto       resolved = r.rel(2, 1);
    auto       expected = reinterpret_cast<Address>(data + 7) + 16;
    EXPECT_EQ(resolved, expected);
}

TEST(ScanResult, ToPointer) {
    const std::byte dummy{0x42};
    ScanResult      r{&dummy};
    auto            ptr = r.toPointer();
    EXPECT_EQ(ptr.getAddress(), reinterpret_cast<Address>(&dummy));
}

// ScanOptions

TEST(MemoryScanner, FindFirstWithOptions) {
    (void)kScanNeedle[0];
    ScanOptions opts{ScanAlignment::X1, ScanHint::None};
    auto        result = MemoryScanner::FindFirst("", "13 37 C0 DE 42 99 AA 55", opts);
    ASSERT_TRUE(result.hasResult());
}

//  Section-based scanning

TEST(MemoryScanner, FindInSectionSmoke) {
    auto sig = MemoryScanner::ParseSignature("13 37 C0 DE 42 99 AA 55");
    ASSERT_TRUE(sig.has_value());
    auto result = MemoryScanner::FindInSection("", ".text", *sig);
    (void)result;
}

TEST(MemoryScanner, FindAllInSectionSmoke) {
    auto sig = MemoryScanner::ParseSignature("13 37 C0 DE 42 99 AA 55");
    ASSERT_TRUE(sig.has_value());
    auto results = MemoryScanner::FindAllInSection("", ".text", *sig);
    (void)results;
}

TEST(MemoryScanner, FindInSectionWithModule) {
    auto mod = Process::FindModule("");
    ASSERT_TRUE(mod.has_value());
    auto sig = MemoryScanner::ParseSignature("13 37 C0 DE 42 99 AA 55");
    ASSERT_TRUE(sig.has_value());
    // Module-based section scanning uses Module::FindSection().
    auto result = MemoryScanner::FindInSection(*mod, ".text", *sig);
    (void)result;
}

// Raw buffer scanning

TEST(MemoryScanner, ScanBufferMatch) {
    const std::array buf = {
        std::byte{0xAA},
        std::byte{0xBB},
        std::byte{0xCC},
        std::byte{0xDD},
        std::byte{0x11},
        std::byte{0x22},
        std::byte{0x33},
        std::byte{0x44},
        std::byte{0x55},
        std::byte{0x66},
        std::byte{0x77},
        std::byte{0x88},
        std::byte{0x99},
        std::byte{0x00},
        std::byte{0xFF},
        std::byte{0xEE},
    };
    auto sig = MemoryScanner::ParseSignature("11 22 33 44");
    ASSERT_TRUE(sig.has_value());
    auto result = MemoryScanner::ScanBuffer(buf, *sig);
    ASSERT_TRUE(result.hasResult());
    EXPECT_EQ(result.getRaw(), &buf[4]);
}

TEST(MemoryScanner, ScanBufferNoMatch) {
    const std::array<std::byte, 8> buf{};
    auto                           sig = MemoryScanner::ParseSignature("FF FF FF FF");
    ASSERT_TRUE(sig.has_value());
    EXPECT_FALSE(MemoryScanner::ScanBuffer(buf, *sig).hasResult());
}

TEST(MemoryScanner, ScanBufferAllMultiple) {
    const std::array buf = {
        std::byte{0xAA},
        std::byte{0xBB},
        std::byte{0x00},
        std::byte{0x00},
        std::byte{0xAA},
        std::byte{0xBB},
        std::byte{0x00},
        std::byte{0x00},
        std::byte{0xAA},
        std::byte{0xBB},
        std::byte{0x00},
        std::byte{0x00},
    };
    auto sig = MemoryScanner::ParseSignature("AA BB");
    ASSERT_TRUE(sig.has_value());
    auto results = MemoryScanner::ScanBufferAll(buf, *sig);
    EXPECT_EQ(results.size(), 3u);
}

TEST(MemoryScanner, ScanBufferWildcard) {
    const std::array buf = {
        std::byte{0x10},
        std::byte{0x20},
        std::byte{0xFF},
        std::byte{0x30},
        std::byte{0x40},
        std::byte{0x50},
        std::byte{0x60},
        std::byte{0x70},
    };
    auto sig = MemoryScanner::ParseSignature("10 ? FF 30");
    ASSERT_TRUE(sig.has_value());
    auto result = MemoryScanner::ScanBuffer(buf, *sig);
    ASSERT_TRUE(result.hasResult());
    EXPECT_EQ(result.getRaw(), &buf[0]);
}
