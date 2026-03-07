#pragma once

#include <Mortis/MemoryScanner.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace Mortis {

template <std::size_t N>
struct FixedString {
    char value[N + 1]{};

    constexpr FixedString(const char (&str)[N + 1]) { // NOLINT(google-explicit-constructor)
        std::copy_n(str, N + 1, value);
    }

    [[nodiscard]] constexpr auto data() const noexcept -> const char* { return value; }
    [[nodiscard]] constexpr auto size() const noexcept -> std::size_t { return N; }
    [[nodiscard]] constexpr auto view() const noexcept -> std::string_view { return {value, N}; }
};

template <std::size_t N>
FixedString(const char (&)[N]) -> FixedString<N - 1>;

template <std::size_t N>
using FixedSignature = std::array<SignatureElement, N>;


namespace detail {

consteval auto HexDigit(const char c) noexcept -> std::uint8_t {
    if (c >= '0' && c <= '9') return static_cast<std::uint8_t>(c - '0');
    if (c >= 'A' && c <= 'F') return static_cast<std::uint8_t>(c - 'A' + 10);
    if (c >= 'a' && c <= 'f') return static_cast<std::uint8_t>(c - 'a' + 10);
    return 0xFF; // invalid
}

consteval auto CountTokens(const std::string_view str) noexcept -> std::size_t {
    std::size_t count   = 0;
    bool        inToken = false;
    for (const char c : str) {
        if (c == ' ') {
            inToken = false;
        } else if (!inToken) {
            inToken = true;
            ++count;
        }
    }
    return count;
}

template <std::size_t MaxN>
consteval auto ParseSignatureCompileTime(const std::string_view str)
    -> std::pair<std::array<SignatureElement, MaxN>, std::size_t> {
    std::array<SignatureElement, MaxN> result{};
    std::size_t                        count = 0;

    std::size_t i = 0;
    while (i < str.size()) {
        // Skip spaces.
        if (str[i] == ' ') {
            ++i;
            continue;
        }

        std::size_t tokenStart = i;
        while (i < str.size() && str[i] != ' ') ++i;
        const std::size_t tokenLen = i - tokenStart;

        if (tokenLen == 1) {
            if (str[tokenStart] != '?') {
                throw "Invalid single-character token in signature (expected '?')";
            }
            result[count++] = SignatureElement::Wildcard();
        } else if (tokenLen == 2) {
            const char hi = str[tokenStart];

            if (const char lo = str[tokenStart + 1]; hi == '?' && lo == '?') {
                // "??" → wildcard.
                result[count++] = SignatureElement::Wildcard();
            } else if (hi == '?') {
                // "?B" → low nibble known.
                const auto loVal = HexDigit(lo);
                if (loVal == 0xFF) throw "Invalid hex digit in signature";
                result[count++] = {std::byte{loVal}, std::byte{0x0F}};
            } else if (lo == '?') {
                // "A?" → high nibble known.
                const auto hiVal = HexDigit(hi);
                if (hiVal == 0xFF) throw "Invalid hex digit in signature";
                result[count++] = {static_cast<std::byte>(hiVal << 4), std::byte{0xF0}};
            } else {
                // "AB" → exact byte.
                const auto hiVal = HexDigit(hi);
                const auto loVal = HexDigit(lo);
                if (hiVal == 0xFF || loVal == 0xFF) throw "Invalid hex digit in signature";
                result[count++] = SignatureElement::Byte(static_cast<std::byte>((hiVal << 4) | loVal));
            }
        } else {
            throw "Invalid token length in signature (expected 1 or 2 characters per token)";
        }
    }

    if (count == 0) throw "Empty signature";
    bool foundConcrete = false;
    for (std::size_t k = 0; k < count; ++k) {
        if (result[k].mask != std::byte{0x00}) { // not a wildcard
            if (result[k].mask != std::byte{0xFF}) {
                throw "First non-wildcard byte must be fully specified (no partial mask), "
                      "e.g. use 'AA 4? ...' instead of '4? ...'";
            }
            foundConcrete = true;
            break;
        }
    }
    if (!foundConcrete) throw "Signature must contain at least one concrete (non-wildcard) byte";

    return {result, count};
}

} // namespace detail

template <FixedString Str>
consteval auto CompileSignature() {
    constexpr auto maxN = detail::CountTokens(Str.view());
    constexpr auto pair = detail::ParseSignatureCompileTime<maxN>(Str.view());
    constexpr auto size = pair.second;

    FixedSignature<size> out{};
    for (std::size_t i = 0; i < size; ++i) {
        out[i] = pair.first[i];
    }
    return out;
}

inline namespace literals {
inline namespace signature_literals {

/// @brief Compile-time signature literal.
/// Usage: `auto sig = "48 8B ? CC"_sig;`
/// Returns a `std::array<SignatureElement, N>`.
template <FixedString Str>
consteval auto operator""_sig() noexcept {
    return CompileSignature<Str>();
}

/// @brief Compile-time signature literal that returns a SignatureView.
/// The underlying storage has static storage duration.
/// Usage: `SignatureView sv = "48 8B ? CC"_sigv;`
template <FixedString Str>
constexpr auto operator""_sigv() noexcept {
    static constexpr auto sig = CompileSignature<Str>();
    return SignatureView{sig};
}

} // namespace signature_literals
} // namespace literals

} // namespace Mortis
