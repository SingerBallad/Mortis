#pragma once

#include <Mortis/Config.hpp>

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace Mortis {

class Module;
class Pointer;

/// @brief A single element of a byte pattern.
struct SignatureElement {
    std::byte value{}; ///< Byte value (only bits with mask set are significant).
    std::byte mask{};  ///< Bitmask — 0xFF = exact match, 0x00 = wildcard.

    /// @brief Create a concrete byte element.
    [[nodiscard]] static constexpr auto Byte(const std::byte v) noexcept -> SignatureElement {
        return {v, std::byte{0xFF}};
    }

    /// @brief Create a wildcard element.
    [[nodiscard]] static constexpr auto Wildcard() noexcept -> SignatureElement { return {std::byte{0}, std::byte{0}}; }

    /// @brief True if this element matches any byte.
    [[nodiscard]] constexpr auto isWildcard() const noexcept -> bool { return mask == std::byte{0}; }

    /// @brief True if this element matches exactly one byte value.
    [[nodiscard]] constexpr auto isConcrete() const noexcept -> bool { return mask == std::byte{0xFF}; }

    /// @brief Test whether a given byte matches this element.
    [[nodiscard]] constexpr auto matches(const std::byte b) const noexcept -> bool { return (b & mask) == value; }

    [[nodiscard]] constexpr auto operator==(const SignatureElement&) const noexcept -> bool = default;
};

/// @brief Owned parsed pattern signature, convertible to SignatureView.
class Signature {
public:
    Signature() = default;

    explicit Signature(std::vector<SignatureElement> elements) noexcept : elements_(std::move(elements)) {}

    [[nodiscard]] auto size() const noexcept -> std::size_t { return elements_.size(); }
    [[nodiscard]] auto empty() const noexcept -> bool { return elements_.empty(); }

    [[nodiscard]] auto data() const noexcept -> const SignatureElement* { return elements_.data(); }
    [[nodiscard]] auto begin() const noexcept -> const SignatureElement* { return elements_.data(); }
    [[nodiscard]] auto end() const noexcept -> const SignatureElement* { return elements_.data() + elements_.size(); }

    [[nodiscard]] auto operator[](std::size_t i) const noexcept -> const SignatureElement& { return elements_[i]; }

    /// @brief Implicit conversion to a non-owning view.
    // NOLINTNEXTLINE(google-explicit-constructor)
    operator std::span<const SignatureElement>() const noexcept { return {elements_.data(), elements_.size()}; }

    /// @brief Convert to an IDA-style hex string (e.g., "48 8B ? CC").
    [[nodiscard]] auto toString() const -> std::string;

private:
    std::vector<SignatureElement> elements_;
};

/// @brief Non-owning view into a parsed signature.
using SignatureView = std::span<const SignatureElement>;

/// @brief Memory scan alignment options.
enum class ScanAlignment : std::uint8_t {
    X1  = 1,  ///< Byte-aligned (default).
    X16 = 16, ///< 16-byte-aligned (faster).
};

/// @brief Bitmask hints for scanner optimizations.
enum class ScanHint : std::uint64_t {
    None   = 0,
    X86_64 = 1 << 0, ///< x86_64 code heuristics.
    Pair0  = 1 << 1, ///< Byte-pair scan from signature start.
};

constexpr auto operator|(const ScanHint a, const ScanHint b) noexcept -> ScanHint {
    return static_cast<ScanHint>(std::to_underlying(a) | std::to_underlying(b));
}
constexpr auto operator&(const ScanHint a, const ScanHint b) noexcept -> ScanHint {
    return static_cast<ScanHint>(std::to_underlying(a) & std::to_underlying(b));
}
constexpr auto operator|=(ScanHint& a, ScanHint b) noexcept -> ScanHint& { return a = a | b; }
constexpr auto operator&=(ScanHint& a, ScanHint b) noexcept -> ScanHint& { return a = a & b; }

/// @brief Options bundle for scan calls.
struct ScanOptions {
    ScanAlignment alignment = ScanAlignment::X1;
    ScanHint      hints     = ScanHint::None;
};

/// @brief Result of a pattern scan wrapping a pointer to matched bytes.
class ScanResult {
public:
    constexpr ScanResult() noexcept = default;
    explicit constexpr ScanResult(const std::byte* ptr) noexcept : result_(ptr) {}

    /// @brief Check whether the scan produced a match.
    [[nodiscard]] constexpr auto hasResult() const noexcept -> bool { return result_ != nullptr; }

    explicit constexpr operator bool() const noexcept { return hasResult(); }

    /// @brief Get the matched address.
    [[nodiscard]] auto get() const noexcept -> Address { return reinterpret_cast<Address>(result_); }

    /// @brief Get the underlying byte pointer.
    [[nodiscard]] constexpr auto getRaw() const noexcept -> const std::byte* { return result_; }

    /// @brief Read an integral value at @p offset bytes from the match.
    template <std::integral Int>
    [[nodiscard]] auto read(std::size_t offset) const noexcept -> Int {
        Int value{};
        std::memcpy(&value, result_ + offset, sizeof(Int));
        return value;
    }

    /// @brief Resolve a RIP-relative address at @p offset (x86-64 only).
    /// @param offset Byte offset from the match to the disp32 field.
    /// @param remaining Extra bytes after the disp32 before the next instruction.
    [[nodiscard]] auto rel(const std::size_t offset, const std::size_t remaining = 0) const noexcept -> Address {
        const auto disp = this->read<std::int32_t>(offset);
        return reinterpret_cast<Address>(result_ + offset + sizeof(std::int32_t) + remaining)
             + static_cast<Address>(disp);
    }

    /// @brief Convert to a Pointer.
    [[nodiscard]] auto toPointer() const noexcept -> Pointer;

private:
    const std::byte* result_ = nullptr;
};

/// @brief Static utility for pattern scanning.
struct MemoryScanner {
    MemoryScanner() = delete;

    /// @brief Parse an IDA-style pattern string into a reusable Signature.
    [[nodiscard]] static auto ParseSignature(std::string_view pattern) -> std::optional<Signature>;

    /// @brief Find the first match in a module (string pattern).
    [[nodiscard]] static auto FindFirst(std::string_view moduleName, std::string_view pattern, ScanOptions opts = {})
        -> ScanResult;

    /// @brief Find the first match in a Module (string pattern).
    [[nodiscard]] static auto FindFirst(const Module& module, std::string_view pattern, ScanOptions opts = {})
        -> ScanResult;

    /// @brief Find all matches in a module (string pattern).
    [[nodiscard]] static auto FindAll(std::string_view moduleName, std::string_view pattern, ScanOptions opts = {})
        -> std::vector<ScanResult>;

    /// @brief Find all matches in a Module (string pattern).
    [[nodiscard]] static auto FindAll(const Module& module, std::string_view pattern, ScanOptions opts = {})
        -> std::vector<ScanResult>;

    /// @brief Find the first match using a pre-parsed signature.
    [[nodiscard]] static auto FindFirst(std::string_view moduleName, SignatureView signature, ScanOptions opts = {})
        -> ScanResult;

    /// @brief Find the first match in a Module using a pre-parsed signature.
    [[nodiscard]] static auto FindFirst(const Module& module, SignatureView signature, ScanOptions opts = {})
        -> ScanResult;

    /// @brief Find all matches using a pre-parsed signature.
    [[nodiscard]] static auto FindAll(std::string_view moduleName, SignatureView signature, ScanOptions opts = {})
        -> std::vector<ScanResult>;

    /// @brief Find all matches in a Module using a pre-parsed signature.
    [[nodiscard]] static auto FindAll(const Module& module, SignatureView signature, ScanOptions opts = {})
        -> std::vector<ScanResult>;

    /// @brief Scan a specific section within a module.
    [[nodiscard]] static auto FindInSection(
        std::string_view moduleName,
        std::string_view sectionName,
        SignatureView    signature,
        ScanOptions      opts = {}
    ) -> ScanResult;

    /// @brief Scan a specific section within a Module.
    [[nodiscard]] static auto
    FindInSection(const Module& module, std::string_view sectionName, SignatureView signature, ScanOptions opts = {})
        -> ScanResult;

    /// @brief Find all matches in a section.
    [[nodiscard]] static auto FindAllInSection(
        std::string_view moduleName,
        std::string_view sectionName,
        SignatureView    signature,
        ScanOptions      opts = {}
    ) -> std::vector<ScanResult>;

    /// @brief Find all matches in a section within a Module.
    [[nodiscard]] static auto
    FindAllInSection(const Module& module, std::string_view sectionName, SignatureView signature, ScanOptions opts = {})
        -> std::vector<ScanResult>;

    /// @brief Scan a raw byte buffer for the first match.
    [[nodiscard]] static auto
    ScanBuffer(std::span<const std::byte> buffer, SignatureView signature, ScanOptions opts = {}) -> ScanResult;

    /// @brief Scan a raw byte buffer for all matches.
    [[nodiscard]] static auto
    ScanBufferAll(std::span<const std::byte> buffer, SignatureView signature, ScanOptions opts = {})
        -> std::vector<ScanResult>;
};

} // namespace Mortis
