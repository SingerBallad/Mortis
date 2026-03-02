#pragma once

#include <Mortis/Detail/ImportHookImpl.hpp>
#include <Mortis/Detail/SlotPool.hpp>
#include <Mortis/Detail/TypeTraits.hpp>
#include <Mortis/Result.hpp>

#include <string>
#include <string_view>
#include <utility>

namespace Mortis {

/// @brief Handle for an active import hook.
/// @tparam Sig Function signature of the hooked import (e.g., int(int)).
template <FunctionSignature Sig>
class ImportHookHandle {
    using Traits  = FunctionTraits<Sig>;
    using FnPtr   = Traits::Pointer;
    using SlotMgr = Detail::SlotPool<Sig>;

public:
    ImportHookHandle(const ImportHookHandle&)                    = delete;
    auto operator=(const ImportHookHandle&) -> ImportHookHandle& = delete;

    ImportHookHandle(ImportHookHandle&& other) noexcept
    : moduleName_(std::move(other.moduleName_)),
      importModule_(std::move(other.importModule_)),
      functionName_(std::move(other.functionName_)),
      originalFn_(std::exchange(other.originalFn_, nullptr)),
      detourRawFn_(std::exchange(other.detourRawFn_, nullptr)),
      slotIndex_(std::exchange(other.slotIndex_, -1)),
      enabled_(std::exchange(other.enabled_, false)) {}

    auto operator=(ImportHookHandle&& other) noexcept -> ImportHookHandle& {
        if (this != &other) {
            if (enabled_) (void)disable();
            Destroy();
            moduleName_   = std::move(other.moduleName_);
            importModule_ = std::move(other.importModule_);
            functionName_ = std::move(other.functionName_);
            originalFn_   = std::exchange(other.originalFn_, nullptr);
            detourRawFn_  = std::exchange(other.detourRawFn_, nullptr);
            slotIndex_    = std::exchange(other.slotIndex_, -1);
            enabled_      = std::exchange(other.enabled_, false);
        }
        return *this;
    }

    ~ImportHookHandle() {
        if (enabled_) {
            if (const auto result = disable(); !result) {
                if (slotIndex_ >= 0) slotIndex_ = -1;
                return;
            }
        }
        Destroy();
    }

    /// @brief Disable the hook (restore original import entry).
    /// @return Success or error.
    [[nodiscard]] auto disable() -> Result<void> {
        if (!enabled_) return Result<void>::Ok();
        auto result = ImportHookImpl::UnpatchImportEntry(
            moduleName_,
            importModule_,
            functionName_,
            reinterpret_cast<void*>(originalFn_)
        );
        if (!result) return result;
        enabled_ = false;
        return Result<void>::Ok();
    }

    /// @brief Re-enable a previously disabled hook.
    /// @return Success or error.
    [[nodiscard]] auto enable() -> Result<void> {
        if (enabled_) return Result<void>::Ok();
        void* prev   = nullptr;
        auto  result = ImportHookImpl::PatchImportEntry(
            moduleName_,
            importModule_,
            functionName_,
            reinterpret_cast<void*>(detourRawFn_),
            &prev
        );
        if (!result) return result;
        enabled_ = true;
        return Result<void>::Ok();
    }

    /// @return Whether the hook is currently active.
    [[nodiscard]] auto isEnabled() const noexcept -> bool { return enabled_; }

private:
    friend struct ImportHook;

    ImportHookHandle() = default;

    ImportHookHandle(
        std::string moduleName,
        std::string importModule,
        std::string functionName,
        FnPtr       originalFn,
        FnPtr       detourRawFn,
        int         slotIndex
    )
    : moduleName_(std::move(moduleName)),
      importModule_(std::move(importModule)),
      functionName_(std::move(functionName)),
      originalFn_(originalFn),
      detourRawFn_(detourRawFn),
      slotIndex_(slotIndex),
      enabled_(true) {}

    void Destroy() {
        if (slotIndex_ >= 0) {
            SlotMgr::Instance().release(slotIndex_);
            slotIndex_ = -1;
        }
    }

    std::string moduleName_;
    std::string importModule_;
    std::string functionName_;
    FnPtr       originalFn_  = nullptr;
    FnPtr       detourRawFn_ = nullptr;
    int         slotIndex_   = -1;
    bool        enabled_     = false;
};

/// @brief Factory for creating import hooks (IAT on Windows, GOT on Linux).
struct ImportHook {
    ImportHook() = delete;

    /// @brief Create an import hook with a lambda detour.
    template <FunctionSignature Sig, DetourCallable<Sig> Detour>
    [[nodiscard]] static auto
    Create(std::string_view moduleName, std::string_view importModule, std::string_view functionName, Detour&& detour)
        -> Result<ImportHookHandle<Sig>> {
        DetourDiagnostics<Sig, Detour>::Validate();

        using Traits  = FunctionTraits<Sig>;
        using FnPtr   = Traits::Pointer;
        using SlotMgr = Detail::SlotPool<Sig>;

        auto& pool  = SlotMgr::Instance();
        auto  alloc = pool.allocate(std::forward<Detour>(detour));
        if (!alloc) return Result<ImportHookHandle<Sig>>::Err(ErrorCode::NoFreeSlots, "No free import-hook slots");

        auto [slotIndex, rawFn] = *alloc;

        void* originalRaw = nullptr;
        auto  patchResult = ImportHookImpl::PatchImportEntry(
            moduleName,
            importModule,
            functionName,
            reinterpret_cast<void*>(rawFn),
            &originalRaw
        );

        if (!patchResult) {
            pool.release(slotIndex);
            return Result<ImportHookHandle<Sig>>::Err(patchResult.code(), patchResult.error());
        }

        auto originalFn = reinterpret_cast<FnPtr>(originalRaw);
        pool.setOriginal(slotIndex, originalFn);

        return Result<ImportHookHandle<Sig>>::Ok(
            ImportHookHandle<Sig>(
                std::string(moduleName),
                std::string(importModule),
                std::string(functionName),
                originalFn,
                rawFn,
                slotIndex
            )
        );
    }
};

} // namespace Mortis
