#include <Mortis/Config.hpp>
#include <Mortis/Detail/ImportHookImpl.hpp>

#include <cstdio>
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <optional>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <unistd.h>

namespace Mortis::ImportHookImpl {

namespace {

struct GotEntry {
    Address* slot;
    Address  base;
};

auto FindGotEntry(const std::string_view moduleName, const std::string_view symbolName) -> std::optional<GotEntry> {
    void* handle = moduleName.empty() ? dlopen(nullptr, RTLD_NOW)
                                      : dlopen(std::string(moduleName).c_str(), RTLD_NOLOAD | RTLD_NOW);
    if (!handle) return std::nullopt;

    link_map* lm = nullptr;
    if (dlinfo(handle, RTLD_DI_LINKMAP, &lm) != 0 || !lm) {
        dlclose(handle);
        return std::nullopt;
    }

    const auto base = lm->l_addr;

    const ElfW(Dyn)* dynSym      = nullptr;
    const ElfW(Dyn)* dynStr      = nullptr;
    const ElfW(Dyn)* dynJmprel   = nullptr;
    const ElfW(Dyn)* dynPltrelsz = nullptr;
    const ElfW(Dyn)* dynRela     = nullptr;
    const ElfW(Dyn)* dynRelasz   = nullptr;

    for (const auto* dyn = lm->l_ld; dyn->d_tag != DT_NULL; ++dyn) {
        switch (dyn->d_tag) {
        case DT_SYMTAB:
            dynSym = dyn;
            break;
        case DT_STRTAB:
            dynStr = dyn;
            break;
        case DT_JMPREL:
            dynJmprel = dyn;
            break;
        case DT_PLTRELSZ:
            dynPltrelsz = dyn;
            break;
        case DT_RELA:
            dynRela = dyn;
            break;
        case DT_RELASZ:
            dynRelasz = dyn;
            break;
        default:
            break;
        }
    }

    if (!dynSym || !dynStr) {
        dlclose(handle);
        return std::nullopt;
    }

    auto* symtab = reinterpret_cast<const ElfW(Sym)*>(dynSym->d_un.d_ptr);
    auto* strtab = reinterpret_cast<const char*>(dynStr->d_un.d_ptr);

    auto searchRela = [&](const Address relaAddr, const std::size_t relaSize) -> std::optional<GotEntry> {
        auto*      rela  = reinterpret_cast<const ElfW(Rela)*>(relaAddr);
        const auto count = relaSize / sizeof(ElfW(Rela));
        for (std::size_t i = 0; i < count; ++i) {
            const auto symIdx = ELF64_R_SYM(rela[i].r_info);
            if (const char* name = strtab + symtab[symIdx].st_name; std::string_view(name) == symbolName) {
                auto* slot = reinterpret_cast<Address*>(base + rela[i].r_offset);
                return GotEntry{slot, base};
            }
        }
        return std::nullopt;
    };

    if (dynJmprel && dynPltrelsz) {
        if (auto r = searchRela(dynJmprel->d_un.d_ptr, dynPltrelsz->d_un.d_val)) {
            dlclose(handle);
            return r;
        }
    }
    if (dynRela && dynRelasz) {
        if (auto r = searchRela(dynRela->d_un.d_ptr, dynRelasz->d_un.d_val)) {
            dlclose(handle);
            return r;
        }
    }

    dlclose(handle);
    return std::nullopt;
}

/// Query the current PROT_* flags for the page containing @p addr by
/// parsing /proc/self/maps.  Returns PROT_READ | PROT_WRITE as a safe
/// fallback if the lookup fails (GOT pages are normally RW).
int QueryPageProtection(const void* addr) {
    auto* f = std::fopen("/proc/self/maps", "r");
    if (!f) return PROT_READ | PROT_WRITE;

    const auto target = reinterpret_cast<unsigned long>(addr);
    unsigned long start, end;
    char perms[5];
    int  prot = PROT_READ | PROT_WRITE; // fallback
    while (std::fscanf(f, "%lx-%lx %4s%*[^\n]\n", &start, &end, perms) == 3) {
        if (target >= start && target < end) {
            prot = 0;
            if (perms[0] == 'r') prot |= PROT_READ;
            if (perms[1] == 'w') prot |= PROT_WRITE;
            if (perms[2] == 'x') prot |= PROT_EXEC;
            break;
        }
    }
    std::fclose(f);
    return prot;
}

/// mprotect helper: temporarily adds PROT_WRITE, writes @p value to
/// @p slot, then restores the original page protection.
Result<void> WriteGotSlot(Address* slot, Address value) {
    const auto pageSize = static_cast<std::size_t>(sysconf(_SC_PAGESIZE));
    const auto slotAddr = reinterpret_cast<Address>(slot);
    const auto aligned  = slotAddr & ~(pageSize - 1);
    auto* const page    = reinterpret_cast<void*>(aligned);

    const int origProt = QueryPageProtection(slot);

    if (mprotect(page, pageSize, origProt | PROT_WRITE) != 0)
        return Result<void>::Err(ErrorCode::ProtectionFailed, "Failed to make GOT writable");

    *slot = value;

    mprotect(page, pageSize, origProt);
    return Result<void>::Ok();
}

} // anonymous namespace

auto PatchImportEntry(
    const std::string_view moduleName,
    std::string_view,
    const std::string_view functionName,
    void*                  newFunction,
    void**                 originalFunction
) -> Result<void> {
    auto entry = FindGotEntry(moduleName, functionName);
    if (!entry) return Result<void>::Err(ErrorCode::ImportNotFound, "GOT entry not found");

    *originalFunction = reinterpret_cast<void*>(*entry->slot);
    return WriteGotSlot(entry->slot, reinterpret_cast<Address>(newFunction));
}

auto UnpatchImportEntry(
    const std::string_view moduleName,
    std::string_view,
    const std::string_view functionName,
    void*                  originalFunction
) -> Result<void> {
    auto entry = FindGotEntry(moduleName, functionName);
    if (!entry) return Result<void>::Err(ErrorCode::ImportNotFound, "GOT entry not found");

    return WriteGotSlot(entry->slot, reinterpret_cast<Address>(originalFunction));
}

} // namespace Mortis::ImportHookImpl
