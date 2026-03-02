#include <Mortis/Process.hpp>

#include <utility>

namespace Mortis {

// ScopedProtect
ScopedProtect::ScopedProtect(ScopedProtect&& other) noexcept
: address_(std::exchange(other.address_, 0)),
  size_(std::exchange(other.size_, 0)),
  oldProtection_(std::exchange(other.oldProtection_, MemoryProtection::None)),
  active_(std::exchange(other.active_, false)) {}

auto ScopedProtect::operator=(ScopedProtect&& other) noexcept -> ScopedProtect& {
    if (this != &other) {
        if (active_) {
            (void)Process::SetProtection(address_, size_, oldProtection_);
        }
        address_       = std::exchange(other.address_, 0);
        size_          = std::exchange(other.size_, 0);
        oldProtection_ = std::exchange(other.oldProtection_, MemoryProtection::None);
        active_        = std::exchange(other.active_, false);
    }
    return *this;
}

ScopedProtect::~ScopedProtect() {
    if (active_) {
        (void)Process::SetProtection(address_, size_, oldProtection_);
    }
}

auto ScopedProtect::Create(const Address address, const std::size_t size, const MemoryProtection newProtection)
    -> Result<ScopedProtect> {
    auto oldProt = Process::SetProtection(address, size, newProtection);
    if (!oldProt) return Result<ScopedProtect>::Err(oldProt.error());
    return Result<ScopedProtect>::Ok(ScopedProtect(address, size, oldProt.value()));
}

ScopedProtect::ScopedProtect(
    const Address          address,
    const std::size_t      size,
    const MemoryProtection oldProtection
) noexcept
: address_(address),
  size_(size),
  oldProtection_(oldProtection),
  active_(true) {}

// MemoryPatch
MemoryPatch::~MemoryPatch() {
    if (applied_) {
        (void)restore();
    }
}

MemoryPatch::MemoryPatch(MemoryPatch&& other) noexcept
: address_(std::exchange(other.address_, 0)),
  oldBytes_(std::move(other.oldBytes_)),
  newBytes_(std::move(other.newBytes_)),
  applied_(std::exchange(other.applied_, false)) {}

auto MemoryPatch::operator=(MemoryPatch&& other) noexcept -> MemoryPatch& {
    if (this != &other) {
        if (applied_) (void)restore();
        address_  = std::exchange(other.address_, 0);
        oldBytes_ = std::move(other.oldBytes_);
        newBytes_ = std::move(other.newBytes_);
        applied_  = std::exchange(other.applied_, false);
    }
    return *this;
}

auto MemoryPatch::Create(const Address address, std::vector<std::uint8_t> newBytes) -> Result<MemoryPatch> {
    MemoryPatch patch;
    patch.address_  = address;
    patch.newBytes_ = std::move(newBytes);
    patch.oldBytes_.resize(patch.newBytes_.size());

    if (const auto readResult = Process::ReadMemory(patch.oldBytes_.data(), address, patch.oldBytes_.size());
        !readResult) return Result<MemoryPatch>::Err(readResult.error());

    if (const auto writeResult = Process::WriteMemory(address, patch.newBytes_.data(), patch.newBytes_.size());
        !writeResult) return Result<MemoryPatch>::Err(writeResult.error());

    patch.applied_ = true;
    return Result<MemoryPatch>::Ok(std::move(patch));
}

auto MemoryPatch::CreateNop(const Address address, const std::size_t count) -> Result<MemoryPatch> {
    std::vector<std::uint8_t> nops;

#ifdef MORTIS_ARCH_X64
    nops.assign(count, 0x90);
#elif defined(MORTIS_ARCH_ARM64)
    auto nopCount = count / 4;
    if (nopCount == 0) nopCount = 1;
    nops.resize(nopCount * 4);
    // ARM64 NOP: 0xD503201F (little-endian)
    for (std::size_t i = 0; i < nopCount; ++i) {
        nops[i * 4 + 0] = 0x1F;
        nops[i * 4 + 1] = 0x20;
        nops[i * 4 + 2] = 0x03;
        nops[i * 4 + 3] = 0xD5;
    }
#endif

    return Create(address, std::move(nops));
}

auto MemoryPatch::apply() -> Result<void> {
    if (applied_) return Result<void>::Ok();
    if (auto result = Process::WriteMemory(address_, newBytes_.data(), newBytes_.size()); !result) return result;
    applied_ = true;
    return Result<void>::Ok();
}

auto MemoryPatch::restore() -> Result<void> {
    if (!applied_) return Result<void>::Ok();
    if (auto result = Process::WriteMemory(address_, oldBytes_.data(), oldBytes_.size()); !result) return result;
    applied_ = false;
    return Result<void>::Ok();
}

// Pointer
auto Pointer::readBytes(const std::size_t count) const -> Result<std::vector<std::uint8_t>> {
    std::vector<std::uint8_t> buffer(count);
    if (const auto result = Process::ReadMemory(buffer.data(), address_, count); !result)
        return Result<std::vector<std::uint8_t>>::Err(result.error());
    return Result<std::vector<std::uint8_t>>::Ok(std::move(buffer));
}

auto Pointer::writeBytes(const std::vector<std::uint8_t>& bytes) const -> Result<void> {
    return Process::WriteMemory(address_, bytes.data(), bytes.size());
}

auto Pointer::deref() const -> Result<Pointer> {
    auto addr = Process::Read<Address>(address_);
    if (!addr) return Result<Pointer>::Err(addr.error());
    return Result<Pointer>::Ok(Pointer(addr.value()));
}

auto Pointer::deref(const std::initializer_list<std::ptrdiff_t> offsets) const -> Result<Pointer> {
    Pointer current = *this;
    for (const auto offset : offsets) {
        auto next = current.add(offset).deref();
        if (!next) return next;
        current = next.value();
    }
    return Result<Pointer>::Ok(current);
}

auto Pointer::ownerModule() const -> std::optional<Module> {
    for (auto& mod : Process::EnumerateModules()) {
        if (mod.contains(address_)) return mod;
    }
    return std::nullopt;
}

} // namespace Mortis
