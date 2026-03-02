#include <Mortis/Process.hpp>

#include <Mortis/Platform/LinuxUtils.hpp>

#include <algorithm>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <unistd.h>

namespace Mortis {

auto Process::Self() -> Process& {
    static Process instance;
    return instance;
}

namespace {

using LinuxDetail::ComputeLoadRange;

struct FindModuleCtx {
    std::string_view      targetName;
    std::optional<Module> result;
};

int FindModuleCallback(dl_phdr_info* info, size_t, void* data) {
    auto*                  ctx = static_cast<FindModuleCtx*>(data);
    const std::string_view objName(info->dlpi_name);

    if (!ctx->targetName.empty()) {
        if (objName.find(ctx->targetName) == std::string_view::npos) return 0;
    } else {
        if (!objName.empty()) return 0;
    }

    if (auto range = ComputeLoadRange(info)) {
        auto [base, size] = *range;
        std::string name(objName);
        if (name.empty()) name = "main";
        ctx->result.emplace(std::move(name), base, size);
    }
    return 1;
}

struct EnumerateModulesCtx {
    std::vector<Module> modules;
};

int EnumerateModulesCallback(dl_phdr_info* info, size_t, void* data) {
    auto* ctx = static_cast<EnumerateModulesCtx*>(data);

    if (auto range = ComputeLoadRange(info)) {
        auto [base, size] = *range;
        std::string name(info->dlpi_name);
        if (name.empty()) name = "main";
        ctx->modules.emplace_back(std::move(name), base, size);
    }
    return 0;
}

} // anonymous namespace

auto Process::FindModule(const std::string_view moduleName) -> std::optional<Module> {
    FindModuleCtx ctx{moduleName, std::nullopt};
    dl_iterate_phdr(FindModuleCallback, &ctx);
    return ctx.result;
}

auto Process::EnumerateModules() -> std::vector<Module> {
    EnumerateModulesCtx ctx;
    dl_iterate_phdr(EnumerateModulesCallback, &ctx);
    return ctx.modules;
}

auto Process::ReadMemory(void* dest, const Address source, const std::size_t size) -> Result<void> {
    if (!IsReadable(source, size))
        return Result<void>::Err(ErrorCode::MemoryNotReadable, "Memory at address is not readable");
    auto* src = reinterpret_cast<const std::uint8_t*>(source);
    std::copy_n(src, size, static_cast<std::uint8_t*>(dest));
    return Result<void>::Ok();
}

auto Process::WriteMemory(const Address dest, const void* source, const std::size_t size) -> Result<void> {
    if (IsWritable(dest, size)) {
        auto* src = static_cast<const std::uint8_t*>(source);
        std::copy_n(src, size, reinterpret_cast<std::uint8_t*>(dest));
        return Result<void>::Ok();
    }

    const auto pageSize  = static_cast<std::size_t>(sysconf(_SC_PAGESIZE));
    const auto aligned   = dest & ~(pageSize - 1);
    auto       totalSize = (dest + size) - aligned;
    if (totalSize < pageSize) totalSize = pageSize;

    if (mprotect(reinterpret_cast<void*>(aligned), totalSize, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
        return Result<void>::Err(ErrorCode::ProtectionFailed, "Failed to change memory protection for write");

    auto* src = static_cast<const std::uint8_t*>(source);
    std::copy_n(src, size, reinterpret_cast<std::uint8_t*>(dest));
    mprotect(reinterpret_cast<void*>(aligned), totalSize, PROT_READ | PROT_EXEC);
    return Result<void>::Ok();
}

namespace {

auto QueryProtectionFromMaps(const Address address) -> std::optional<std::pair<MemoryProtection, std::size_t>> {
    std::optional<std::pair<MemoryProtection, std::size_t>> result;
    LinuxDetail::ForEachProcMapEntry([&](const LinuxDetail::ProcMapEntry& entry) {
        if (address < entry.start || address >= entry.end) return true;
        auto prot = MemoryProtection::None;
        if (entry.read) prot = prot | MemoryProtection::Read;
        if (entry.write) prot = prot | MemoryProtection::Write;
        if (entry.exec) prot = prot | MemoryProtection::Execute;
        result = std::pair{prot, (entry.end - address)};
        return false;
    });
    return result;
}

} // anonymous namespace

auto Process::SetProtection(const Address address, const std::size_t size, const MemoryProtection newProtection)
    -> Result<MemoryProtection> {
    auto oldProt = QueryProtection(address);
    if (!oldProt) return Result<MemoryProtection>::Err(oldProt.error());

    const auto pageSize  = static_cast<std::size_t>(sysconf(_SC_PAGESIZE));
    const auto aligned   = address & ~(pageSize - 1);
    auto       totalSize = (address + size) - aligned;
    if (totalSize < pageSize) totalSize = pageSize;

    if (mprotect(reinterpret_cast<void*>(aligned), totalSize, LinuxDetail::ToNativeProtection(newProtection)) != 0)
        return Result<MemoryProtection>::Err(ErrorCode::ProtectionFailed, "mprotect failed");

    return Result<MemoryProtection>::Ok(oldProt.value());
}

auto Process::SetProtectionRaw(const Address address, const std::size_t size, const MemoryProtection newProtection)
    -> Result<void> {
    const auto pageSize  = static_cast<std::size_t>(sysconf(_SC_PAGESIZE));
    const auto aligned   = address & ~(pageSize - 1);
    auto       totalSize = (address + size) - aligned;
    if (totalSize < pageSize) totalSize = pageSize;

    if (mprotect(reinterpret_cast<void*>(aligned), totalSize, LinuxDetail::ToNativeProtection(newProtection)) != 0)
        return Result<void>::Err(ErrorCode::ProtectionFailed, "mprotect failed");

    return Result<void>::Ok();
}

auto Process::QueryProtection(const Address address) -> Result<MemoryProtection> {
    const auto result = QueryProtectionFromMaps(address);
    if (!result) return Result<MemoryProtection>::Err(ErrorCode::ProtectionFailed, "Failed to query memory protection");
    return Result<MemoryProtection>::Ok(result->first);
}

auto Process::IsReadable(const Address address, std::size_t size) -> bool {
    if (size == 0) size = 1;
    const auto prot = QueryProtectionFromMaps(address);
    if (!prot || !HasFlag(prot->first, MemoryProtection::Read)) return false;
    auto          regionEnd = address + prot->second;
    const Address endAddr   = address + size;
    if (endAddr <= address) return false; // overflow
    while (endAddr > regionEnd) {
        const auto nextProt = QueryProtectionFromMaps(regionEnd);
        if (!nextProt || !HasFlag(nextProt->first, MemoryProtection::Read)) return false;
        regionEnd = regionEnd + nextProt->second;
    }
    return true;
}

auto Process::IsWritable(const Address address, std::size_t size) -> bool {
    if (size == 0) size = 1;
    const auto prot = QueryProtectionFromMaps(address);
    if (!prot || !HasFlag(prot->first, MemoryProtection::Write)) return false;
    auto          regionEnd = address + prot->second;
    const Address endAddr   = address + size;
    if (endAddr <= address) return false;
    while (endAddr > regionEnd) {
        const auto nextProt = QueryProtectionFromMaps(regionEnd);
        if (!nextProt || !HasFlag(nextProt->first, MemoryProtection::Write)) return false;
        regionEnd = regionEnd + nextProt->second;
    }
    return true;
}

auto Module::findExport(std::string_view symbolName) const -> std::optional<Address> {
    void* handle = dlopen(name_.c_str(), RTLD_NOLOAD | RTLD_NOW);
    if (!handle) handle = dlopen(nullptr, RTLD_NOW);
    if (!handle) return std::nullopt;

    auto* sym = dlsym(handle, std::string(symbolName).c_str());
    dlclose(handle);
    return sym ? std::optional{reinterpret_cast<Address>(sym)} : std::nullopt;
}

auto Module::enumerateExports() const -> std::unordered_map<std::string, Address> {
    std::unordered_map<std::string, Address> result;

    // Parse ELF headers from module base address.
    auto* ehdr = reinterpret_cast<const ElfW(Ehdr)*>(base_);
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 || ehdr->e_ident[EI_MAG1] != ELFMAG1 || ehdr->e_ident[EI_MAG2] != ELFMAG2
        || ehdr->e_ident[EI_MAG3] != ELFMAG3)
        return result;

    // Walk program headers to find PT_DYNAMIC.
    auto* phdr                  = reinterpret_cast<const ElfW(Phdr)*>(base_ + ehdr->e_phoff);
    const ElfW(Dyn)* dynSection = nullptr;
    for (int i = 0; i < ehdr->e_phnum; ++i) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dynSection = reinterpret_cast<const ElfW(Dyn)*>(base_ + phdr[i].p_vaddr);
            break;
        }
    }
    if (!dynSection) return result;

    // Extract .dynsym, .dynstr, and hash table info from dynamic section.
    const ElfW(Sym)* symtab      = nullptr;
    const char* strtab           = nullptr;
    ElfW(Word) nchain            = 0; // DT_HASH → number of symbols
    const ElfW(Word)* gnuBuckets = nullptr;
    ElfW(Word) gnuNbuckets       = 0;
    const ElfW(Word)* gnuChain   = nullptr;
    ElfW(Word) gnuSymndx         = 0; // GNU_HASH → first symbol index in chain

    for (auto* dyn = dynSection; dyn->d_tag != DT_NULL; ++dyn) {
        switch (dyn->d_tag) {
        case DT_SYMTAB:
            symtab = reinterpret_cast<const ElfW(Sym)*>(dyn->d_un.d_ptr);
            break;
        case DT_STRTAB:
            strtab = reinterpret_cast<const char*>(dyn->d_un.d_ptr);
            break;
        case DT_HASH: {
            auto* hash = reinterpret_cast<const ElfW(Word)*>(dyn->d_un.d_ptr);
            nchain     = hash[1]; // hash[0]=nbucket, hash[1]=nchain (=nsymbols)
            break;
        }
        case DT_GNU_HASH: {
            auto* gnu            = reinterpret_cast<const ElfW(Word)*>(dyn->d_un.d_ptr);
            gnuNbuckets          = gnu[0];
            gnuSymndx            = gnu[1];
            const auto bloomSize = gnu[2];
            // Skip: gnu[3] = bloom shift
            // Bloom filter starts at gnu+4, each element is Addr-sized
            auto* bloom = reinterpret_cast<const ElfW(Addr)*>(&gnu[4]);
            gnuBuckets  = reinterpret_cast<const ElfW(Word)*>(bloom + bloomSize);
            gnuChain    = gnuBuckets + gnuNbuckets;
            break;
        }
        default:
            break;
        }
    }

    if (!symtab || !strtab) return result;

    // Determine number of dynamic symbols.
    std::size_t nsyms = 0;
    if (nchain > 0) {
        // DT_HASH provides direct symbol count.
        nsyms = nchain;
    } else if (gnuBuckets && gnuChain) {
        // GNU_HASH: find the max symbol index from the hash buckets + chains.
        ElfW(Word) maxSym = 0;
        for (ElfW(Word) b = 0; b < gnuNbuckets; ++b) {
            if (gnuBuckets[b] > maxSym) maxSym = gnuBuckets[b];
        }
        if (maxSym >= gnuSymndx) {
            // Walk the chain from maxSym to find the end.
            ElfW(Word) idx = maxSym;
            while (!(gnuChain[idx - gnuSymndx] & 1)) ++idx;
            nsyms = idx + 1;
        }
    }

    for (std::size_t i = 0; i < nsyms; ++i) {
        const auto& sym = symtab[i];
        if (sym.st_name == 0 || sym.st_shndx == SHN_UNDEF) continue;
        const auto type = ELF64_ST_TYPE(sym.st_info);
        if (type != STT_FUNC && type != STT_OBJECT && type != STT_GNU_IFUNC) continue;

        const char* name = strtab + sym.st_name;
        auto        addr = static_cast<Address>(sym.st_value);
        // If the address looks relative (below base), it's a vaddr offset.
        if (addr < base_) addr += base_;
        result.emplace(std::string(name), addr);
    }
    return result;
}

auto Module::findSection(std::string_view sectionName) const -> std::optional<std::pair<Address, std::size_t>> {
    std::string path = name_;
    if (path.empty() || path == "main") {
        path = "/proc/self/exe";
    }

    const int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return std::nullopt;

    ElfW(Ehdr) ehdr{};
    if (const auto readHdr = pread(fd, &ehdr, sizeof(ehdr), 0); readHdr != static_cast<ssize_t>(sizeof(ehdr))) {
        close(fd);
        return std::nullopt;
    }

    if (ehdr.e_ident[EI_MAG0] != ELFMAG0 || ehdr.e_ident[EI_MAG1] != ELFMAG1 || ehdr.e_ident[EI_MAG2] != ELFMAG2
        || ehdr.e_ident[EI_MAG3] != ELFMAG3) {
        close(fd);
        return std::nullopt;
    }

    if (ehdr.e_shoff == 0 || ehdr.e_shnum == 0 || ehdr.e_shentsize == 0) {
        close(fd);
        return std::nullopt;
    }

    if (ehdr.e_shentsize != sizeof(ElfW(Shdr))) {
        close(fd);
        return std::nullopt;
    }

    std::vector<ElfW(Shdr)> shdrs(ehdr.e_shnum);
    const auto              shdrBytes = static_cast<std::size_t>(ehdr.e_shnum) * ehdr.e_shentsize;
    if (const auto readShdrs = pread(fd, shdrs.data(), shdrBytes, static_cast<off_t>(ehdr.e_shoff));
        readShdrs != static_cast<ssize_t>(shdrBytes)) {
        close(fd);
        return std::nullopt;
    }

    if (ehdr.e_shstrndx >= ehdr.e_shnum) {
        close(fd);
        return std::nullopt;
    }

    const auto& shstrtab = shdrs[ehdr.e_shstrndx];
    if (shstrtab.sh_size == 0) {
        close(fd);
        return std::nullopt;
    }

    std::vector<char> nameTable(shstrtab.sh_size);
    const auto        readNames = pread(fd, nameTable.data(), nameTable.size(), static_cast<off_t>(shstrtab.sh_offset));
    close(fd);
    if (readNames != static_cast<ssize_t>(nameTable.size())) return std::nullopt;

    for (const auto& sh : shdrs) {
        if (sh.sh_name >= nameTable.size()) continue;
        if (const std::string_view secName(nameTable.data() + sh.sh_name); secName == sectionName) {
            auto secAddr = base_ + sh.sh_addr;
            return std::pair{secAddr, static_cast<std::size_t>(sh.sh_size)};
        }
    }

    return std::nullopt;
}

} // namespace Mortis
