#include <Mortis/MemoryScanner.hpp>
#include <Mortis/Process.hpp>

#ifdef MORTIS_OS_LINUX
#include <Mortis/Platform/LinuxUtils.hpp>
#endif

#include <libhat/process.hpp>
#include <libhat/scanner.hpp>
#include <libhat/signature.hpp>

#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#ifdef MORTIS_OS_LINUX
#include <bit>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace Mortis {

namespace {

/// Convert Mortis ScanAlignment to libhat.
auto ToHatAlignment(ScanAlignment a) noexcept -> hat::scan_alignment {
    return static_cast<hat::scan_alignment>(static_cast<std::uint8_t>(a));
}

/// Convert Mortis ScanHint to libhat.
auto ToHatHint(ScanHint h) noexcept -> hat::scan_hint {
    return static_cast<hat::scan_hint>(static_cast<std::uint64_t>(h));
}

/// Convert SignatureView to a libhat signature.
auto ToHatSignature(SignatureView sig) -> hat::signature {
    hat::signature result;
    result.reserve(sig.size());
    for (const auto& [value, mask] : sig) {
        result.emplace_back(value, mask);
    }
    return result;
}

/// Convert a libhat signature to Signature.
auto FromHatSignature(const hat::signature& hatSig) -> Signature {
    std::vector<SignatureElement> elements;
    elements.reserve(hatSig.size());
    for (auto& e : hatSig) {
        elements.push_back({e.value(), e.mask()});
    }
    return Signature(std::move(elements));
}

/// Resolve a libhat module by name.
auto ResolveModule(const std::string_view moduleName) -> std::optional<hat::process::module> {
    if (moduleName.empty()) {
        return hat::process::get_process_module();
    }
    return hat::process::get_module(moduleName);
}

auto FindFirstInRange(std::span<const std::byte> data, const hat::signature& hatSig, const ScanOptions opts)
    -> ScanResult {
    const auto result =
        hat::find_pattern(data.begin(), data.end(), hatSig, ToHatAlignment(opts.alignment), ToHatHint(opts.hints));
    if (!result.has_result()) return {};
    return ScanResult{result.get()};
}

void AppendAllInRange(
    std::vector<ScanResult>&         out,
    const std::span<const std::byte> data,
    const hat::signature&            hatSig,
    const ScanOptions                opts
) {
    const auto hatResults =
        hat::find_all_pattern(data.begin(), data.end(), hatSig, ToHatAlignment(opts.alignment), ToHatHint(opts.hints));
    out.reserve(out.size() + hatResults.size());
    for (const auto& r : hatResults) {
        out.emplace_back(r.get());
    }
}

auto FindAllInRange(const std::span<const std::byte> data, const hat::signature& hatSig, const ScanOptions opts)
    -> std::vector<ScanResult> {
    std::vector<ScanResult> results;
    AppendAllInRange(results, data, hatSig, opts);
    return results;
}

} // anonymous namespace

auto Signature::toString() const -> std::string {
    constexpr std::string_view hex{"0123456789ABCDEF"};
    std::string                result;
    result.reserve(elements_.size() * 3);
    for (auto& e : elements_) {
        if (e.isWildcard()) {
            result += "? ";
        } else if (e.isConcrete()) {
            const auto v  = static_cast<std::uint8_t>(e.value);
            result       += hex[(v >> 4) & 0xFu];
            result       += hex[v & 0xFu];
            result       += ' ';
        } else {
            const auto v  = static_cast<std::uint8_t>(e.value);
            const auto m  = static_cast<std::uint8_t>(e.mask);
            result       += (m & 0xF0) ? hex[(v >> 4) & 0xFu] : '?';
            result       += (m & 0x0F) ? hex[v & 0xFu] : '?';
            result       += ' ';
        }
    }
    if (!result.empty()) result.pop_back();
    return result;
}

auto ScanResult::toPointer() const noexcept -> Pointer { return Pointer(get()); }

auto MemoryScanner::ParseSignature(const std::string_view pattern) -> std::optional<Signature> {
    const auto result = hat::parse_signature(pattern);
    if (!result.has_value()) return std::nullopt;
    return FromHatSignature(result.value());
}


auto MemoryScanner::FindFirst(const std::string_view moduleName, const std::string_view pattern, const ScanOptions opts)
    -> ScanResult {
    const auto parsed = ParseSignature(pattern);
    if (!parsed) return {};
    return FindFirst(moduleName, SignatureView{*parsed}, opts);
}

auto MemoryScanner::FindFirst(const Module& module, const std::string_view pattern, const ScanOptions opts)
    -> ScanResult {
    const auto parsed = ParseSignature(pattern);
    if (!parsed) return {};
    return FindFirst(module, SignatureView{*parsed}, opts);
}

auto MemoryScanner::FindAll(const std::string_view moduleName, const std::string_view pattern, const ScanOptions opts)
    -> std::vector<ScanResult> {
    const auto parsed = ParseSignature(pattern);
    if (!parsed) return {};
    return FindAll(moduleName, SignatureView{*parsed}, opts);
}

auto MemoryScanner::FindAll(const Module& module, const std::string_view pattern, const ScanOptions opts)
    -> std::vector<ScanResult> {
    const auto parsed = ParseSignature(pattern);
    if (!parsed) return {};
    return FindAll(module, SignatureView{*parsed}, opts);
}

auto MemoryScanner::FindFirst(const std::string_view moduleName, const SignatureView signature, const ScanOptions opts)
    -> ScanResult {
    const auto mod = ResolveModule(moduleName);
    if (!mod) return {};

    const auto hatSig = ToHatSignature(signature);
    ScanResult found;
    mod->for_each_segment([&](const std::span<std::byte> data, hat::protection) -> bool {
        found = FindFirstInRange(data, hatSig, opts);
        if (found.hasResult()) {
            return false;
        }
        return true;
    });
    return found;
}

auto MemoryScanner::FindFirst(const Module& module, const SignatureView signature, const ScanOptions opts)
    -> ScanResult {
    const auto hatSig = ToHatSignature(signature);
#ifdef MORTIS_OS_LINUX
    for (const auto ranges = LinuxDetail::GetReadableMappedRanges(module.base(), module.size());
         const auto& [start, size] : ranges) {
        const auto data = std::span{reinterpret_cast<const std::byte*>(start), size};
        if (auto result = FindFirstInRange(data, hatSig, opts); result.hasResult()) return result;
    }
    return {};
#else
    const auto data = std::span{reinterpret_cast<const std::byte*>(module.base()), module.size()};
    return FindFirstInRange(data, hatSig, opts);
#endif
}

auto MemoryScanner::FindAll(const std::string_view moduleName, const SignatureView signature, const ScanOptions opts)
    -> std::vector<ScanResult> {
    const auto mod = ResolveModule(moduleName);
    if (!mod) return {};

    const auto              hatSig = ToHatSignature(signature);
    std::vector<ScanResult> results;
    mod->for_each_segment([&](std::span<std::byte> data, hat::protection) -> bool {
        AppendAllInRange(results, data, hatSig, opts);
        return true;
    });
    return results;
}

auto MemoryScanner::FindAll(const Module& module, const SignatureView signature, const ScanOptions opts)
    -> std::vector<ScanResult> {
    const auto hatSig = ToHatSignature(signature);
#ifdef MORTIS_OS_LINUX
    std::vector<ScanResult> results;
    for (const auto ranges = LinuxDetail::GetReadableMappedRanges(module.base(), module.size());
         const auto& [start, size] : ranges) {
        const auto data = std::span{reinterpret_cast<const std::byte*>(start), size};
        AppendAllInRange(results, data, hatSig, opts);
    }
    return results;
#else
    const auto data = std::span{reinterpret_cast<const std::byte*>(module.base()), module.size()};
    return FindAllInRange(data, hatSig, opts);
#endif
}

#ifdef MORTIS_OS_LINUX
namespace {

/// Locate a section's runtime data by reading ELF section headers from disk.
auto GetElfSectionData(const hat::process::module& mod, const std::string_view sectionName) -> std::span<std::byte> {

    std::string filePath;
    const auto  baseAddr = mod.address();

    if (baseAddr == hat::process::get_process_module().address()) {
        filePath = "/proc/self/exe";
    } else {
        auto ctx = std::pair{baseAddr, &filePath};
        dl_iterate_phdr(
            [](dl_phdr_info* info, size_t, void* data) -> int {
                if (const auto* c = static_cast<std::pair<uintptr_t, std::string*>*>(data);
                    std::bit_cast<uintptr_t>(info->dlpi_addr) == c->first) {
                    *c->second = info->dlpi_name;
                    return 1;
                }
                return 0;
            },
            &ctx
        );
    }
    if (filePath.empty()) return {};

    const int fd = open(filePath.c_str(), O_RDONLY);
    if (fd < 0) return {};

    struct stat st{};
    if (fstat(fd, &st) != 0 || st.st_size < static_cast<off_t>(sizeof(Elf64_Ehdr))) {
        close(fd);
        return {};
    }

    auto* mapped = static_cast<const char*>(mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0));
    close(fd);
    if (mapped == MAP_FAILED) return {};

    const auto* ehdr = reinterpret_cast<const Elf64_Ehdr*>(mapped);
    if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0 || ehdr->e_shstrndx == SHN_UNDEF) {
        munmap(const_cast<char*>(mapped), st.st_size);
        return {};
    }

    const auto* shdr = reinterpret_cast<const Elf64_Shdr*>(mapped + ehdr->e_shoff);

    if (shdr[ehdr->e_shstrndx].sh_offset >= static_cast<size_t>(st.st_size)) {
        munmap(const_cast<char*>(mapped), st.st_size);
        return {};
    }
    const char* strtab = mapped + shdr[ehdr->e_shstrndx].sh_offset;

    std::span<std::byte> result;
    for (Elf64_Half i = 0; i < ehdr->e_shnum; ++i) {
        if (const char* name = strtab + shdr[i].sh_name;
            sectionName == name && shdr[i].sh_addr != 0 && shdr[i].sh_size != 0) {
            result = {reinterpret_cast<std::byte*>(baseAddr + shdr[i].sh_addr), shdr[i].sh_size};
            break;
        }
    }

    munmap(const_cast<char*>(mapped), st.st_size);
    return result;
}

} // anonymous namespace
#endif

auto MemoryScanner::FindInSection(
    const std::string_view moduleName,
    const std::string_view sectionName,
    const SignatureView    signature,
    const ScanOptions      opts
) -> ScanResult {
    const auto hatSig = ToHatSignature(signature);
    const auto mod    = ResolveModule(moduleName);
    if (!mod) return {};

#ifdef MORTIS_OS_WINDOWS
    auto data = mod->get_section_data(sectionName);
#else
    const auto data = GetElfSectionData(*mod, sectionName);
#endif
    if (data.empty()) return {};
    return FindFirstInRange(data, hatSig, opts);
}

auto MemoryScanner::FindInSection(
    const Module&          module,
    const std::string_view sectionName,
    const SignatureView    signature,
    const ScanOptions      opts
) -> ScanResult {
    auto sectionInfo = module.findSection(sectionName);
    if (!sectionInfo) return {};
    auto [base, size] = *sectionInfo;
    const auto data   = std::span{reinterpret_cast<const std::byte*>(base), size};
    return ScanBuffer(data, signature, opts);
}

auto MemoryScanner::FindAllInSection(
    const std::string_view moduleName,
    const std::string_view sectionName,
    const SignatureView    signature,
    const ScanOptions      opts
) -> std::vector<ScanResult> {
    const auto hatSig = ToHatSignature(signature);
    const auto mod    = ResolveModule(moduleName);
    if (!mod) return {};

#ifdef MORTIS_OS_WINDOWS
    auto data = mod->get_section_data(sectionName);
#else
    const auto data = GetElfSectionData(*mod, sectionName);
#endif
    if (data.empty()) return {};
    return FindAllInRange(data, hatSig, opts);
}

auto MemoryScanner::FindAllInSection(
    const Module&          module,
    const std::string_view sectionName,
    const SignatureView    signature,
    const ScanOptions      opts
) -> std::vector<ScanResult> {
    auto sectionInfo = module.findSection(sectionName);
    if (!sectionInfo) return {};
    auto [base, size] = *sectionInfo;
    const auto data   = std::span{reinterpret_cast<const std::byte*>(base), size};
    return ScanBufferAll(data, signature, opts);
}


auto MemoryScanner::ScanBuffer(std::span<const std::byte> buffer, SignatureView signature, ScanOptions opts)
    -> ScanResult {
    const auto hatSig = ToHatSignature(signature);
    return FindFirstInRange(buffer, hatSig, opts);
}

auto MemoryScanner::ScanBufferAll(
    const std::span<const std::byte> buffer,
    const SignatureView              signature,
    const ScanOptions                opts
) -> std::vector<ScanResult> {
    const auto hatSig = ToHatSignature(signature);
    return FindAllInRange(buffer, hatSig, opts);
}

} // namespace Mortis
