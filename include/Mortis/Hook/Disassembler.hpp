#pragma once

#include <Mortis/Result.hpp>

#include <capstone/capstone.h>

#include <utility>
#include <vector>

namespace Mortis::HookEngine {

/// @brief A single decoded instruction.
struct DecodedInsn {
    std::uint64_t             address = 0;        ///< Virtual address.
    std::vector<std::uint8_t> bytes;              ///< Raw bytes.
    cs_insn                   detail{};           ///< Capstone instruction detail (value copy only).
    int                       ripDispOffset = -1; ///< (x64) disp32 offset for RIP-relative ops; -1 if none.
};

/// @brief Result of prologue analysis.
struct PrologueInfo {
    std::vector<DecodedInsn> instructions;   ///< Decoded instructions covering the prologue.
    std::size_t              totalBytes = 0; ///< Total byte count of all instructions.
};

/// @brief Wrapper around the Capstone disassembly engine.
class Disassembler {
public:
    /// @brief Factory: initialise Capstone and return a ready Disassembler.
    [[nodiscard]] static auto Create() -> Result<Disassembler>;

    ~Disassembler();

    Disassembler(const Disassembler&)                    = delete;
    auto operator=(const Disassembler&) -> Disassembler& = delete;

    Disassembler(Disassembler&& other) noexcept : handle_(std::exchange(other.handle_, 0)) {}
    auto operator=(Disassembler&& other) noexcept -> Disassembler& {
        if (this != &other) {
            if (handle_) cs_close(&handle_);
            handle_ = std::exchange(other.handle_, 0);
        }
        return *this;
    }

    /// @brief Disassemble a function's prologue for relocation.
    [[nodiscard]] auto analyzePrologue(void* target, std::size_t minBytes, std::size_t maxBytes = 64) const
        -> Result<PrologueInfo>;

    /// @brief Follow jump stubs to the real function entry.
    [[nodiscard]] static auto SkipJumpStubs(void* code) -> void*;

    /// @brief True if instruction terminates a function.
    [[nodiscard]] static auto IsTerminating(const cs_insn& insn) -> bool;

    /// @brief Count filler bytes (NOP/int3/padding) at address.
    [[nodiscard]] static auto IsCodeFiller(const std::uint8_t* code, std::size_t remaining) -> std::size_t;

    /// @brief Access the raw Capstone handle (for relocators).
    [[nodiscard]] auto handle() const noexcept -> csh { return handle_; }

private:
    Disassembler() = default;
    csh handle_ = 0;
};

} // namespace Mortis::HookEngine
