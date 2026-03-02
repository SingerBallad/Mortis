# Mortis

Modern C++23 cross-platform hooking and reverse engineering library.

Inline hooks, import hooks, memory patching, pattern scanning, and process introspection — zero-boilerplate type safety, RAII resource management, `std::expected`-based error handling.

**Platforms:** Windows / Linux &nbsp;&times;&nbsp; x64 / ARM64

---

## Getting Started

### Requirements

- C++23 compiler (MSVC 19.36+, Clang 17+, GCC 13+)
- CMake 3.20+

All dependencies are fetched automatically via CMake `FetchContent`:

| Dependency | Version | Purpose |
|------------|---------|---------|
| [Capstone](https://github.com/capstone-engine/capstone) | v6 | Disassembly engine |
| [libhat](https://github.com/BasedInc/libhat) | v0.9.0 | Optimized pattern scanning |
| [Google Test](https://github.com/google/googletest) | v1.15.2 | Unit tests (optional) |

### Build

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

| CMake Option              | Default | Description               |
|---------------------------|---------|---------------------------|
| `MORTIS_BUILD_TESTS`      | `ON`    | Build unit tests          |
| `MORTIS_ENABLE_SANITIZERS`| `OFF`   | Enable ASan + UBSan       |

### Add to Your Project

**CMake FetchContent (recommended):**

```cmake
include(FetchContent)
FetchContent_Declare(
    Mortis
    GIT_REPOSITORY https://github.com/QwQNT/Mortis.git
    GIT_TAG        main
)
FetchContent_MakeAvailable(Mortis)

target_link_libraries(YourTarget PRIVATE Mortis)
```

**Umbrella header — one include, full API:**

```cpp
#include <Mortis/Mortis.hpp>
using namespace Mortis;
```

---

## Usage

### Inline Hook — Lambda

Signature is **automatically deduced** from the lambda. No manual template arguments needed.

```cpp
int Add(int a, int b) { return a + b; }

auto hook = InlineHook::Create(&Add, [](auto& original, int a, int b) -> int {
    return original(a, b) * 2;   // call original, double the result
});
// Add(3, 4) now returns 14
// RAII — hook removed when `hook` goes out of scope
```

### Inline Hook — Function Pointer

```cpp
int HookedAdd(OriginalFunction<int(int, int)>& original, int a, int b) {
    return original(a, b) + 100;
}

auto hook = InlineHook::Create(&Add, &HookedAdd);
```

### Inline Hook — Member Function

Detour receives `(original, this_ptr, args...)`:

```cpp
auto hook = InlineHook::CreateMember<&Player::TakeDamage>(
    [](auto& original, Player* self, int damage) -> int {
        return original(self, 1);  // god mode
    }
);
```

### Inline Hook — Raw Address

For addresses from pattern scanning or manual analysis:

```cpp
Address addr = scanner.FindFirst("", "48 89 5C 24 08")->value();
auto hook = InlineHook::Create<int(int, int)>(addr, [](auto& original, int a, int b) -> int {
    return original(a, b);
});
```

### Import Hook (IAT / GOT)

```cpp
auto hook = ImportHook::Create<DWORD()>(
    "",                       // empty = main executable
    "kernel32.dll",
    "GetCurrentProcessId",
    [](auto& original) -> DWORD {
        return original() + 1000;
    }
);
```

### Memory Patch

```cpp
auto patch = MemoryPatch::Create(address, {0x90, 0x90, 0x90});
patch->Restore();   // original bytes restored
patch->Apply();     // re-apply

auto nops = MemoryPatch::CreateNop(address, 16);  // platform-aware NOP fill
// destructor restores original bytes automatically
```

### Scoped Memory Protection

```cpp
{
    auto guard = ScopedProtect::Create(addr, size, MemoryProtection::ReadWriteExec);
    Process::Write<uint8_t>(addr, 0xCC);
}
// protection automatically restored
```

### Memory Scanner

IDA-style pattern scanning with `?` wildcards:

```cpp
auto results = MemoryScanner::FindPattern("", "48 8B ? CC ?? 00");
auto first   = MemoryScanner::FindFirst("game.dll", "E8 ? ? ? ? 48 8D");
auto info    = MemoryScanner::GetModuleInfo("game.dll");
```

### Process Introspection

```cpp
auto& proc = Process::Self();
auto  mod  = proc.FindModule("ntdll");

mod->Base();
mod->Size();
mod->FindExport("RtlAllocateHeap");
mod->FindSection(".text");
mod->EnumerateExports();
```

### Pointer

```cpp
Pointer ptr(some_address);

ptr.Read<int>();
ptr.Write<int>(42);
ptr.Add(0x10).Deref();
ptr.Deref({0x20, 0x08, 0x00});          // multi-level pointer chain
ptr.IsReadable();
```

### Result\<T\>

Built on `std::expected`:

```cpp
auto result = InlineHook::Create(&Add, detour);

if (result) {
    auto& hook = result.Value();
}
if (!result) {
    ErrorCode code = result.Code();
    std::string msg = result.Error();
}

// Monadic chaining
result.and_then([](auto& hook) { return hook.Disable(); })
      .or_else([](auto& err)  { log(err.message); });
```

---

## Project Structure

```
Mortis/
├── include/Mortis/             # Public API headers
│   ├── Mortis.hpp              #   Umbrella header
│   ├── Config.hpp              #   Platform/arch detection
│   ├── Result.hpp              #   std::expected-based Result<T>
│   ├── Process.hpp             #   Process, Module, Pointer, ScopedProtect, MemoryPatch
│   ├── InlineHook.hpp          #   InlineHook
│   ├── ImportHook.hpp          #   ImportHook
│   ├── MemoryScanner.hpp       #   Pattern scanning
│   └── Detail/                 #   Internal implementation details
├── src/
│   ├── Core/                   # Platform-neutral core logic
│   ├── Hook/                   # Hook backend (Capstone-based)
│   ├── Arch/{X64,ARM64}/       # Architecture-specific relocators
│   └── Platform/{Win32,Linux}/ # OS-specific implementations
├── tests/                      # Google Test suite
└── CMakeLists.txt
```

---

## License

This project is licensed under the [MIT License](LICENSE).
