#pragma once

#include <Mortis/Config.hpp>
#include <Mortis/Result.hpp>

#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace Mortis {

/// @brief Portable memory protection flags (bitmask).
enum class MemoryProtection : std::uint32_t {
    None          = 0,
    Read          = 1 << 0,
    Write         = 1 << 1,
    Execute       = 1 << 2,
    ReadWrite     = Read | Write,
    ReadExec      = Read | Execute,
    ReadWriteExec = Read | Write | Execute,
};

/// @brief Bitwise OR for MemoryProtection.
constexpr auto operator|(const MemoryProtection a, const MemoryProtection b) -> MemoryProtection {
    return static_cast<MemoryProtection>(std::to_underlying(a) | std::to_underlying(b));
}

/// @brief Bitwise AND for MemoryProtection.
constexpr auto operator&(const MemoryProtection a, const MemoryProtection b) -> MemoryProtection {
    return static_cast<MemoryProtection>(std::to_underlying(a) & std::to_underlying(b));
}

/// @brief Check whether a flag is set in a protection bitmask.
constexpr auto HasFlag(const MemoryProtection value, const MemoryProtection flag) -> bool {
    return (value & flag) == flag;
}

/// @brief Represents a loaded module (DLL / shared object).
class Module {
public:
    /// @param name Module file path or name.
    /// @param base Base address of the module in memory.
    /// @param size Size of the module image in bytes.
    Module(std::string name, const Address base, const std::size_t size)
    : name_(std::move(name)),
      base_(base),
      size_(size) {}

    /// @return Module name or path.
    [[nodiscard]] auto name() const -> const std::string& { return name_; }

    /// @return Module base address.
    [[nodiscard]] auto base() const noexcept -> Address { return base_; }

    /// @return Module image size in bytes.
    [[nodiscard]] auto size() const noexcept -> std::size_t { return size_; }

    /// @brief Check if an address falls within this module.
    [[nodiscard]] auto contains(const Address addr) const noexcept -> bool { return addr >= base_ && addr < base_ + size_; }

    /// @brief Find a named export symbol.
    /// @param symbolName Export name.
    /// @return Address of the export, or nullopt.
    [[nodiscard]] auto findExport(std::string_view symbolName) const -> std::optional<Address>;

    /// @brief Enumerate all named exports.
    /// @return Map of export name to address.
    [[nodiscard]] auto enumerateExports() const -> std::unordered_map<std::string, Address>;

    /// @brief Find a section by name (e.g., ".text").
    /// @param sectionName Section name (max 8 chars).
    /// @return Pair of (section base, section size), or nullopt.
    [[nodiscard]] auto findSection(std::string_view sectionName) const
        -> std::optional<std::pair<Address, std::size_t>>;

private:
    friend class Process;
    std::string name_;
    Address     base_;
    std::size_t size_;
};

/// @brief Singleton for current-process introspection and memory operations.
class Process {
public:
    /// @return The singleton Process instance.
    static auto Self() -> Process&;

    /// @brief Find a loaded module by name.
    /// @param moduleName Substring of the module name (empty = main executable).
    /// @return The found Module, or nullopt.
    [[nodiscard]] static auto FindModule(std::string_view moduleName = "") -> std::optional<Module>;

    /// @brief List all loaded modules.
    [[nodiscard]] static auto EnumerateModules() -> std::vector<Module>;

    /// @brief Read raw bytes from process memory.
    /// @param dest Destination buffer.
    /// @param source Address to read from.
    /// @param size Number of bytes to read.
    static auto ReadMemory(void* dest, Address source, std::size_t size) -> Result<void>;

    /// @brief Write raw bytes to process memory.
    /// @param dest Address to write to.
    /// @param source Source buffer.
    /// @param size Number of bytes to write.
    static auto WriteMemory(Address dest, const void* source, std::size_t size) -> Result<void>;

    /// @brief Read a typed value from memory.
    /// @tparam T Trivially-copyable type.
    /// @param address Address to read from.
    /// @return The value, or error.
    template <typename T>
        requires std::is_trivially_copyable_v<T>
    [[nodiscard]] static auto Read(const Address address) -> Result<T> {
        T    value{};
        auto result = ReadMemory(&value, address, sizeof(T));
        if (!result) return Result<T>::Err(result.error());
        return Result<T>::Ok(std::move(value));
    }

    /// @brief Write a typed value to memory.
    /// @tparam T Trivially-copyable type.
    /// @param address Address to write to.
    /// @param value Value to write.
    /// @return Success or error.
    template <typename T>
        requires std::is_trivially_copyable_v<T>
    static auto Write(const Address address, const T& value) -> Result<void> {
        return WriteMemory(address, &value, sizeof(T));
    }

    /// @brief Change memory protection for a region.
    /// @param address Start address.
    /// @param size Region size in bytes.
    /// @param newProtection Desired protection flags.
    /// @return The previous protection, or error.
    static auto SetProtection(Address address, std::size_t size, MemoryProtection newProtection)
        -> Result<MemoryProtection>;

    /// @brief Change memory protection for a region without querying current protection.
    /// @param address Start address.
    /// @param size Region size in bytes.
    /// @param newProtection Desired protection flags.
    /// @return Success or error.
    static auto SetProtectionRaw(Address address, std::size_t size, MemoryProtection newProtection)
        -> Result<void>;

    /// @brief Query the current protection of a memory address.
    static auto QueryProtection(Address address) -> Result<MemoryProtection>;

    /// @brief Test whether an address is readable.
    static auto IsReadable(Address address, std::size_t size = 1) -> bool;

    /// @brief Test whether an address is writable.
    static auto IsWritable(Address address, std::size_t size = 1) -> bool;

private:
    Process() = default;
};

/// @brief A guard that changes memory protection on construction and restores it on destruction.
class ScopedProtect {
public:
    ScopedProtect(const ScopedProtect&)                    = delete;
    auto operator=(const ScopedProtect&) -> ScopedProtect& = delete;
    ScopedProtect(ScopedProtect&& other) noexcept;
    auto operator=(ScopedProtect&& other) noexcept -> ScopedProtect&;
    ~ScopedProtect();

    /// @brief Create a scoped protection change.
    /// @param address Start address.
    /// @param size Region size.
    /// @param newProtection Desired protection.
    /// @return ScopedProtect that restores old protection on destruction, or error.
    [[nodiscard]] static auto Create(Address address, std::size_t size, MemoryProtection newProtection)
        -> Result<ScopedProtect>;

private:
    ScopedProtect(Address address, std::size_t size, MemoryProtection oldProtection) noexcept;

    Address          address_;
    std::size_t      size_;
    MemoryProtection oldProtection_;
    bool             active_;
};

/// @brief Reversible byte-level memory patch with RAII restore.
class MemoryPatch {
public:
    MemoryPatch(const MemoryPatch&)                    = delete;
    auto operator=(const MemoryPatch&) -> MemoryPatch& = delete;
    MemoryPatch(MemoryPatch&& other) noexcept;
    auto operator=(MemoryPatch&& other) noexcept -> MemoryPatch&;
    ~MemoryPatch();

    /// @brief Create and immediately apply a memory patch.
    /// @param address Target address.
    /// @param newBytes Bytes to write.
    /// @return MemoryPatch handle, or error.
    [[nodiscard]] static auto Create(Address address, std::vector<std::uint8_t> newBytes) -> Result<MemoryPatch>;

    /// @brief Create a NOP-fill patch (0x90 on x64, D503201F on ARM64).
    /// @param address Target address.
    /// @param count Number of NOP bytes (x64) or byte count rounded to instructions (ARM64).
    [[nodiscard]] static auto CreateNop(Address address, std::size_t count) -> Result<MemoryPatch>;

    /// @brief Re-apply the patch bytes.
    [[nodiscard]] auto apply() -> Result<void>;

    /// @brief Restore original bytes.
    [[nodiscard]] auto restore() -> Result<void>;

    /// @return True if patch bytes are currently written.
    [[nodiscard]] auto isApplied() const noexcept -> bool { return applied_; }

private:
    MemoryPatch() = default;

    Address                   address_ = 0;
    std::vector<std::uint8_t> oldBytes_;
    std::vector<std::uint8_t> newBytes_;
    bool                      applied_ = false;
};

/// @brief Fluent wrapper around a raw memory address.
class Pointer {
public:
    /// @brief Construct from a raw address.
    explicit Pointer(Address address) noexcept : address_(address) {}

    /// @brief Construct from any pointer.
    explicit Pointer(void* ptr) noexcept : address_(reinterpret_cast<Address>(ptr)) {}

    /// @brief True if the address is non-zero.
    [[nodiscard]] explicit operator bool() const noexcept { return address_ != 0; }

    /// @return The raw address value.
    [[nodiscard]] auto getAddress() const noexcept -> Address { return address_; }

    /// @brief Read a typed value at this address.
    template <typename T>
        requires std::is_trivially_copyable_v<T>
    [[nodiscard]] auto read() const -> Result<T> {
        return Process::Read<T>(address_);
    }

    /// @brief Write a typed value at this address.
    template <typename T>
        requires std::is_trivially_copyable_v<T>
    auto write(const T& value) const -> Result<void> {
        return Process::Write<T>(address_, value);
    }

    /// @brief Read raw bytes.
    /// @param count Number of bytes to read.
    [[nodiscard]] auto readBytes(std::size_t count) const -> Result<std::vector<std::uint8_t>>;

    /// @brief Write raw bytes.
    [[nodiscard]] auto writeBytes(const std::vector<std::uint8_t>& bytes) const -> Result<void>;

    /// @brief Dereference one level of pointer indirection.
    [[nodiscard]] auto deref() const -> Result<Pointer>;

    /// @brief Follow a chain of pointer offsets.
    /// @param offsets Offset to add before each dereference.
    [[nodiscard]] auto deref(std::initializer_list<std::ptrdiff_t> offsets) const -> Result<Pointer>;

    /// @brief Create a new Pointer offset from this one.
    [[nodiscard]] auto add(std::ptrdiff_t offset) const noexcept -> Pointer {
        return Pointer(static_cast<Address>(static_cast<std::ptrdiff_t>(address_) + offset));
    }

    /// @brief Create a new Pointer at a negative offset.
    [[nodiscard]] auto sub(std::ptrdiff_t offset) const noexcept -> Pointer {
        return add(-offset);
    }

    /// @brief Test readability of this address.
    [[nodiscard]] auto isReadable() const -> bool { return Process::IsReadable(address_); }

    /// @brief Test writability of this address.
    [[nodiscard]] auto isWritable() const -> bool { return Process::IsWritable(address_); }

    /// @brief Find the module containing this address.
    [[nodiscard]] auto ownerModule() const -> std::optional<Module>;

private:
    Address address_;
};

} // namespace Mortis
