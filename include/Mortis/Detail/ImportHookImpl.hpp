#pragma once

#include <Mortis/Result.hpp>

#include <string_view>

namespace Mortis::ImportHookImpl {

/// @brief Patch an import entry to redirect to a new function.
auto PatchImportEntry(
    std::string_view moduleName,
    std::string_view importModule,
    std::string_view functionName,
    void*            newFunction,
    void**           originalFunction
) -> Result<void>;

/// @brief Restore a previously patched import entry.
auto UnpatchImportEntry(
    std::string_view moduleName,
    std::string_view importModule,
    std::string_view functionName,
    void*            originalFunction
) -> Result<void>;

} // namespace Mortis::ImportHookImpl
