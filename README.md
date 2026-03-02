# Mortis

Modern C++23 cross-platform reverse engineering framework.

Inline hooks, import hooks, memory patching, pattern scanning, and process introspection — all with zero-boilerplate type safety, RAII resource management, and `std::expected`-based error handling.

**Supported platforms:** Windows / Linux × x64 / ARM64

---

## Features at a Glance

| Feature                        | Description                                                                                        |
|--------------------------------|----------------------------------------------------------------------------------------------------|
| **InlineHook**                 | Detour free functions, member functions, and raw addresses with lambda or function pointer detours |
| **ImportHook**                 | Redirect IAT (Windows) / GOT (Linux) entries                                                       |
| **MemoryPatch**                | Reversible byte patches and NOP fills with RAII rollback                                           |
| **ScopedProtect**              | RAII memory protection guard                                                                       |
| **MemoryScanner**              | IDA-style pattern scanning with wildcard support                                                   |
| **Process / Module / Pointer** | Process introspection, module enumeration, typed memory R/W, pointer chain traversal               |
| **Result\<T\>**                | `std::expected`-based result type with structured error codes                                      |

---

## Quick Start

### Requirements

- C++23 compiler (MSVC 19.36+, Clang 17+, GCC 13+)
- CMake 3.20+
- Dependencies fetched automatically via `FetchContent`:
  - [Capstone v5](https://github.com/capstone-engine/capstone) — disassembly engine
  - [Google Test v1.15](https://github.com/google/googletest) — tests (optional)

### Build

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

| CMake Option            | Default | Description                               |
|-------------------------|---------|-------------------------------------------|
| `MORTIS_BUILD_TESTS`    | `ON`    | Build unit tests                          |
| `MORTIS_BUILD_EXAMPLES` | `ON`    | Build example programs                    |
| `MORTIS_USE_LIBHAT`     | `OFF`   | Use libhat for optimized pattern scanning |

### Integrate into Your Project

**CMake FetchContent (recommended):**

```cmake
FetchContent_Declare(
    Mortis
    GIT_REPOSITORY https://github.com/YourOrg/Mortis.git
    GIT_TAG        main
)
FetchContent_MakeAvailable(Mortis)

target_link_libraries(YourTarget PRIVATE Mortis)
```

**Single include:**

```cpp
#include <Mortis/Mortis.hpp>   // umbrella header — pulls in everything
using namespace Mortis;
```

---

## API Overview

### Inline Hook — Lambda Detour

The signature is **automatically deduced** from the lambda's parameter list. No manual `<int(int,int)>` template arguments needed.

```cpp
int Add(int a, int b) { return a + b; }

auto hook = InlineHook::Create(&Add, [](auto& original, int a, int b) -> int {
    return original(a, b) * 2;   // call original, double the result
});
// Add(3, 4) now returns 14

// RAII — hook is removed when `hook` goes out of scope
```

<details>
<summary>Compare: typical C hooking library</summary>

```cpp
// Traditional approach — verbose, unsafe, manual cleanup
typedef int (*AddFn)(int, int);
AddFn g_originalAdd = nullptr;

int __stdcall HookedAdd(int a, int b) {
    return g_originalAdd(a, b) * 2;
}

// Must manually specify signature, manage global state, remember to unhook
MH_CreateHook(&Add, &HookedAdd, (LPVOID*)&g_originalAdd);
MH_EnableHook(&Add);
// ... don't forget MH_DisableHook + MH_RemoveHook ...
```

</details>

### Inline Hook — Function Pointer Detour

When lambda capture isn't needed, pass a function pointer whose first parameter is `OriginalFunction<Sig>&` — the original function is injected automatically, just like lambdas:

```cpp
int HookedAdd(OriginalFunction<int(int, int)>& original, int a, int b) {
    return original(a, b) + 100;
}

auto hook = InlineHook::Create(&Add, &HookedAdd);
```

### Inline Hook — Member Function

Hook a C++ class method. The detour receives `(original, this_ptr, args...)`:

```cpp
auto hook = InlineHook::CreateMember<&Player::TakeDamage>(
    [](auto& original, Player* self, int damage) -> int {
        return original(self, 1);  // god mode: only take 1 damage
    }
);
```

### Inline Hook — Raw Address + Explicit Signature

For addresses obtained from pattern scanning or manual analysis:

```cpp
Address addr = scanner.FindFirst("", "48 89 5C 24 08")->value();
auto hook = InlineHook::Create<int(int, int)>(addr, [](auto& original, int a, int b) -> int {
    return original(a, b);
});
```

### Import Hook (IAT / GOT)

Redirect an imported function at the module's import table:

```cpp
auto hook = ImportHook::Create<DWORD()>(
    "",                       // empty = main executable
    "kernel32.dll",
    "GetCurrentProcessId",
    [](auto& original) -> DWORD {
        return original() + 1000;  // fake PID
    }
);
```

### Memory Patch

Write and restore arbitrary bytes with RAII:

```cpp
auto patch = MemoryPatch::Create(address, {0x90, 0x90, 0x90});  // 3× NOP
// patch->IsApplied() == true
patch->Restore();   // original bytes restored
patch->Apply();     // re-apply

auto nops = MemoryPatch::CreateNop(address, 16);  // platform-aware NOP fill
// destructor restores original bytes automatically
```

### Scoped Memory Protection

RAII guard that restores original protection on scope exit:

```cpp
{
    auto guard = ScopedProtect::Create(addr, size, MemoryProtection::ReadWriteExec);
    // memory is now RWX — safe to write code
    Process::Write<uint8_t>(addr, 0xCC);
}
// protection automatically restored
```

### Memory Scanner

IDA-style pattern scanning with `?` wildcards:

```cpp
auto results = MemoryScanner::FindPattern("", "48 8B ? CC ?? 00");
auto first   = MemoryScanner::FindFirst("game.dll", "E8 ? ? ? ? 48 8D");
auto info    = MemoryScanner::GetModuleInfo("game.dll");  // {base, size}
```

### Process Introspection

```cpp
auto& proc    = Process::Self();
auto  modules = proc.EnumerateModules();
auto  mod     = proc.FindModule("ntdll");

// Module API
mod->Name();        // "C:\Windows\System32\ntdll.dll"
mod->Base();        // 0x7FFE12340000
mod->Size();        // 0x1A3000
mod->Contains(addr);
mod->FindExport("RtlAllocateHeap");
mod->FindSection(".text");
mod->EnumerateExports();
```

### Pointer — Fluent Memory Access

```cpp
Pointer ptr(some_address);

auto val = ptr.Read<int>();              // typed read
ptr.Write<int>(42);                      // typed write
ptr.ReadBytes(16);                       // raw bytes
ptr.Add(0x10).Deref();                   // offset then dereference
ptr.Deref({0x20, 0x08, 0x00});           // multi-level pointer chain
ptr.IsReadable();                        // protection query
ptr.OwnerModule();                       // which module contains this?
```

### Result\<T\> — Error Handling

Built on `std::expected` — supports monadic operations, boolean conversion, and structured error codes:

```cpp
auto result = InlineHook::Create(&Add, detour);

if (result) {                           // boolean check
    auto& hook = result.Value();        // access value
}

if (!result) {
    ErrorCode code = result.Code();     // structured error code
    std::string msg = result.Error();   // human-readable message
}

// Monadic chaining
result.and_then([](auto& hook) { return hook.Disable(); })
      .or_else([](auto& err)  { log(err.message); });
```

---

## Design Highlights

### Zero-Boilerplate Type Safety

Mortis uses C++23 concepts and template argument deduction to eliminate boilerplate. The detour's parameter types **are** the hook's type specification:

```cpp
// The signature int(int, int) is deduced from the lambda — not repeated anywhere
auto hook = InlineHook::Create(&Add, [](auto& original, int a, int b) -> int {
    return original(a, b);
});
```

Mismatched types produce clear compile-time diagnostics thanks to `static_assert`-based `DetourDiagnostics`, not pages of template instantiation errors.

### Uniform RAII Semantics

Every resource — hooks, patches, protection changes — is an RAII handle. No `Init`/`Shutdown`, no cleanup callbacks, no `Uninitialize()`:

```cpp
{
    auto hook  = InlineHook::Create(...);
    auto patch = MemoryPatch::Create(...);
    auto guard = ScopedProtect::Create(...);
    // all active
}
// all automatically cleaned up — in reverse order
```

### Cross-Platform by Design

One API surface, two architectures (x64 / ARM64), two operating systems (Windows / Linux). Architecture-specific details (NOP encoding, instruction relocation, trampoline generation) are fully abstracted:

```
include/Mortis/        ← public headers (platform-neutral)
src/Arch/X64/          ← x64 instruction handling
src/Arch/ARM64/        ← ARM64 instruction handling
src/Platform/Win32/    ← Windows system calls
src/Platform/Linux/    ← Linux system calls
```

### No Global State

No `MH_Initialize()` / `MH_Uninitialize()`. No global hook lists. Each hook handle is self-contained and independently movable.

---

## Examples

Seven example programs are included under [`examples/`](examples/), covering the entire public API:

| Example                                                                     | Covers                                                           |
|-----------------------------------------------------------------------------|------------------------------------------------------------------|
| [`01_InlineHookLambda`](examples/01_InlineHookLambda.cpp)                   | Auto-deduced, typed pointer, and explicit-signature lambda hooks |
| [`02_InlineHookFunctionPointer`](examples/02_InlineHookFunctionPointer.cpp) | Function pointer detours, `Original()` accessor                  |
| [`03_MemberFunctionHook`](examples/03_MemberFunctionHook.cpp)               | `CreateMember<&Class::Method>`                                   |
| [`04_ImportHook`](examples/04_ImportHook.cpp)                               | IAT patching, Disable / Enable / RAII                            |
| [`05_MemoryPatchAndProtect`](examples/05_MemoryPatchAndProtect.cpp)         | `MemoryPatch`, `ScopedProtect`, `Process::Read/Write`            |
| [`06_MemoryScanner`](examples/06_MemoryScanner.cpp)                         | `FindFirst`, `FindPattern`, wildcard patterns                    |
| [`07_ProcessIntrospection`](examples/07_ProcessIntrospection.cpp)           | `Process`, `Module`, `Pointer`, `AddressOf`                      |

Build with `MORTIS_BUILD_EXAMPLES=ON` (default).

---

## Project Structure

```
Mortis/
├── include/Mortis/           # Public API headers
│   ├── Mortis.hpp            # Umbrella header
│   ├── Config.hpp            # Platform/arch detection, Address type
│   ├── Result.hpp            # std::expected-based Result<T>
│   ├── Process.hpp           # Process, Module, Pointer, ScopedProtect, MemoryPatch
│   ├── InlineHook.hpp        # InlineHook + InlineHookHandle
│   ├── ImportHook.hpp        # ImportHook + ImportHookHandle
│   ├── MemoryScanner.hpp     # Pattern scanning
│   └── Detail/               # Internal implementation details
├── src/
│   ├── Core/                 # Platform-neutral core logic
│   ├── Hook/                 # Hook backend (Capstone-based)
│   ├── Arch/{X64,ARM64}/     # Architecture-specific relocators
│   └── Platform/{Win32,Linux}/ # OS-specific implementations
├── tests/                    # Google Test suite (86 tests)
├── examples/                 # 7 example programs
└── CMakeLists.txt
```

---

## License

[TODO: Add license]
