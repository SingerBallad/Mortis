#pragma once

#include <cstdint>
#include <expected>
#include <string>
#include <utility>

namespace Mortis {

/// @brief Structured error codes for common failure modes.
enum class ErrorCode : std::uint8_t {
    Unknown = 0,       ///< Unspecified / legacy string-only error.
    MemoryNotReadable, ///< Target memory is not readable.
    MemoryNotWritable, ///< Target memory is not writable.
    ProtectionFailed,  ///< Failed to change memory protection.
    HookInstallFailed, ///< Hook backend could not install the hook.
    HookRemoveFailed,  ///< Hook backend could not remove the hook.
    NoFreeSlots,       ///< SlotPool is full.
    ImportNotFound,    ///< Import entry not found in module.
    ModuleNotFound,    ///< Module not found.
    InvalidArgument,   ///< Invalid argument passed to API.
};

/// @brief Structured error payload: code + human-readable message.
struct ErrorInfo {
    ErrorCode   code = ErrorCode::Unknown;
    std::string message;
};

/// @brief Result type: value OR error, backed by std::expected.
///
/// @tparam T Value type on success.
template <typename T>
class Result : public std::expected<T, ErrorInfo> {
    using Base = std::expected<T, ErrorInfo>;

public:
    using Base::Base;
    using Base::operator=;

    /// @brief Construct a successful result.
    [[nodiscard]] static auto Ok(T value) -> Result { return Result(std::in_place, std::move(value)); }

    /// @brief Construct an error result (legacy string-only).
    [[nodiscard]] static auto Err(std::string msg) -> Result {
        return Result(std::unexpected(ErrorInfo{ErrorCode::Unknown, std::move(msg)}));
    }

    /// @brief Construct an error result with code and message.
    [[nodiscard]] static auto Err(ErrorCode code, std::string msg) -> Result {
        return Result(std::unexpected(ErrorInfo{code, std::move(msg)}));
    }

    // Accessors

    /// @return Reference to the contained value, forwarding value category.
    [[nodiscard]] auto value() & -> T& { return **this; }
    [[nodiscard]] auto value() const & -> const T& { return **this; }
    [[nodiscard]] auto value() && -> T&& { return std::move(**this); }
    [[nodiscard]] auto value() const && -> const T&& { return std::move(**this); }

    /// @return The error message. Empty string if result holds a value.
    [[nodiscard]] auto error() const -> const std::string& {
        static const std::string kEmpty;
        return this->has_value() ? kEmpty : Base::error().message;
    }

    /// @return The structured error code (ErrorCode::Unknown if success or legacy).
    [[nodiscard]] auto code() const -> ErrorCode {
        return this->has_value() ? ErrorCode::Unknown : Base::error().code;
    }
};

/// @brief Specialization of Result for void (success carries no payload).
template <>
class Result<void> : public std::expected<void, ErrorInfo> {
    using Base = std::expected<void, ErrorInfo>;

public:
    using Base::Base;
    using Base::operator=;

    /// @brief Construct a successful void result.
    [[nodiscard]] static auto Ok() -> Result { return {}; }

    /// @brief Construct an error void result.
    [[nodiscard]] static auto Err(std::string msg) -> Result {
        return Result(std::unexpected(ErrorInfo{ErrorCode::Unknown, std::move(msg)}));
    }

    /// @brief Construct an error void result with code and message.
    [[nodiscard]] static auto Err(const ErrorCode code, std::string msg) -> Result {
        return Result(std::unexpected(ErrorInfo{code, std::move(msg)}));
    }

    /// @return The error message. Empty string if result is a success.
    [[nodiscard]] auto error() const -> const std::string& {
        static const std::string kEmpty;
        return this->has_value() ? kEmpty : Base::error().message;
    }

    /// @return The structured error code.
    [[nodiscard]] auto code() const -> ErrorCode {
        return this->has_value() ? ErrorCode::Unknown : Base::error().code;
    }
};

} // namespace Mortis
