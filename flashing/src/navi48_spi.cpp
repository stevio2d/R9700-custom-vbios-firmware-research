#include "flashamd/navi48_spi.hpp"

#include <array>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#ifdef __linux__
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace flashamd {
namespace {

constexpr std::uint16_t kAmdVendorId = 0x1002U;
constexpr std::uint32_t kNavi48RomSize = 0x200000U;
constexpr std::size_t kRomIndexOffset = 0x5A390U;
constexpr std::size_t kRomDataOffset = 0x5A394U;
constexpr std::uint64_t kIoResourceMem = 0x00000200ULL;
constexpr std::uint64_t kIoResourcePrefetch = 0x00002000ULL;

bool has_valid_amd_option_rom(const std::vector<std::uint8_t>& image) {
    constexpr std::array<std::uint8_t, 10> kAmdBiosSignature{
        ' ', '7', '6', '1', '2', '9', '5', '5', '2', '0'};
    constexpr std::size_t kSignatureOffset = 0x30U;
    constexpr std::size_t kHeaderSize = kSignatureOffset + kAmdBiosSignature.size();
    constexpr std::size_t kOptionRomAlignment = 512U;

    if (image.size() < kHeaderSize) return false;
    for (std::size_t offset = 0; offset <= image.size() - kHeaderSize;
         offset += kOptionRomAlignment) {
        if (image[offset] != 0x55U || image[offset + 1U] != 0xAAU) continue;

        const auto image_size = static_cast<std::size_t>(image[offset + 2U]) << 9U;
        if (image_size < kHeaderSize || image_size > image.size() - offset) continue;

        bool signature_matches = true;
        for (std::size_t index = 0; index < kAmdBiosSignature.size(); ++index) {
            if (image[offset + kSignatureOffset + index] != kAmdBiosSignature[index]) {
                signature_matches = false;
                break;
            }
        }
        if (signature_matches) return true;
    }
    return false;
}

bool is_known_navi48_revision(const PciDevice& device) {
    switch (device.device_id) {
    case 0x746FU:
        switch (device.revision_id) {
        case 0xF0U:
        case 0xF1U:
        case 0xF2U:
        case 0xF3U:
        case 0xF5U:
        case 0xF6U:
        case 0x30U:
        case 0x31U:
        case 0x32U:
            return true;
        default:
            return false;
        }
    case 0x7550U:
        return device.revision_id == 0xC0U || device.revision_id == 0xC2U ||
               device.revision_id == 0xC3U;
    case 0x7551U:
        return device.revision_id == 0xC0U || device.revision_id == 0xC8U;
    default:
        return false;
    }
}

bool valid_bdf(const std::string& bdf) {
    if (bdf.size() != 12U || bdf[4] != ':' || bdf[7] != ':' || bdf[10] != '.') return false;
    for (std::size_t i = 0; i < bdf.size(); ++i) {
        if (i == 4U || i == 7U || i == 10U) continue;
        const char c = bdf[i];
        const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!hex) return false;
    }
    return bdf[11] >= '0' && bdf[11] <= '7';
}

struct RegisterBar {
    unsigned int index{};
    std::uint64_t start{};
    std::uint64_t size{};
};

RegisterBar find_register_bar(const std::filesystem::path& device_path) {
    std::ifstream resources(device_path / "resource");
    if (!resources) throw std::runtime_error("Cannot read PCI resources for " + device_path.filename().string());

    std::vector<RegisterBar> candidates;
    std::string line;
    unsigned int index = 0;
    while (index < 6U && std::getline(resources, line)) {
        std::istringstream fields(line);
        std::uint64_t start{};
        std::uint64_t end{};
        std::uint64_t flags{};
        if (!(fields >> std::hex >> start >> end >> flags)) {
            ++index;
            continue;
        }
        if ((flags & kIoResourceMem) != 0U && (flags & kIoResourcePrefetch) == 0U &&
            end >= start && end - start < std::numeric_limits<std::uint64_t>::max()) {
            const std::uint64_t size = end - start + 1U;
            if (size >= kRomDataOffset + sizeof(std::uint32_t)) {
                candidates.push_back(RegisterBar{index, start, size});
            }
        }
        ++index;
    }

    if (candidates.size() != 1U) {
        throw std::runtime_error("Could not identify one non-prefetchable Navi48 register BAR for " +
                                 device_path.filename().string());
    }
    return candidates.front();
}

#ifdef __linux__
volatile std::sig_atomic_t g_backup_interrupted = 0;

void backup_signal_handler(int) { g_backup_interrupted = 1; }

void throw_if_backup_interrupted() {
    if (g_backup_interrupted != 0) {
        throw std::runtime_error("Raw Navi48 ROM backup interrupted; restoring runtime power policy");
    }
}

class FileDescriptor {
public:
    explicit FileDescriptor(int value) : value_(value) {}
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
    ~FileDescriptor() {
        if (value_ >= 0) (void)::close(value_);
    }
    int get() const { return value_; }

private:
    int value_;
};

class SignalCancellationGuard {
public:
    SignalCancellationGuard() {
        g_backup_interrupted = 0;
        struct sigaction action {};
        action.sa_handler = backup_signal_handler;
        sigemptyset(&action.sa_mask);
        action.sa_flags = 0;

        for (; installed_ < signals_.size(); ++installed_) {
            if (::sigaction(signals_[installed_], &action, &previous_[installed_]) != 0) {
                const int error = errno;
                restore_handlers();
                throw std::runtime_error("Cannot install interrupt cleanup handler: " +
                                         std::error_code(error, std::generic_category()).message());
            }
        }
    }

    SignalCancellationGuard(const SignalCancellationGuard&) = delete;
    SignalCancellationGuard& operator=(const SignalCancellationGuard&) = delete;

    ~SignalCancellationGuard() { restore_handlers(); }

    void check() const { throw_if_backup_interrupted(); }

private:
    void restore_handlers() noexcept {
        while (installed_ > 0U) {
            --installed_;
            (void)::sigaction(signals_[installed_], &previous_[installed_], nullptr);
        }
    }

    static constexpr std::array<int, 4> signals_{SIGINT, SIGTERM, SIGHUP, SIGQUIT};
    std::array<struct sigaction, 4> previous_{};
    std::size_t installed_{};
};

constexpr std::array<int, 4> SignalCancellationGuard::signals_;

class MappedBar {
public:
    MappedBar(const std::filesystem::path& path, std::size_t size) : size_(size) {
        const int fd = ::open(path.c_str(), O_RDWR | O_SYNC | O_CLOEXEC);
        if (fd < 0) {
            throw std::runtime_error("Cannot open " + path.string() + " for MMIO: " +
                                     std::error_code(errno, std::generic_category()).message() +
                                     "; run R9700flash-dump with sufficient PCI resource permissions");
        }
        FileDescriptor descriptor(fd);
        mapping_ = ::mmap(nullptr, size_, PROT_READ | PROT_WRITE, MAP_SHARED, descriptor.get(), 0);
        if (mapping_ == MAP_FAILED) {
            mapping_ = nullptr;
            throw std::runtime_error("Cannot map " + path.string() + " for MMIO: " +
                                     std::error_code(errno, std::generic_category()).message());
        }
        words_ = static_cast<volatile std::uint32_t*>(mapping_);
    }
    MappedBar(const MappedBar&) = delete;
    MappedBar& operator=(const MappedBar&) = delete;
    ~MappedBar() {
        if (mapping_ != nullptr) (void)::munmap(mapping_, size_);
    }

    void write32(std::size_t offset, std::uint32_t value) {
        check_offset(offset);
        words_[offset / sizeof(std::uint32_t)] = value;
        std::atomic_thread_fence(std::memory_order_seq_cst);
    }

    std::uint32_t read32(std::size_t offset) const {
        check_offset(offset);
        std::atomic_thread_fence(std::memory_order_seq_cst);
        const auto value = words_[offset / sizeof(std::uint32_t)];
        std::atomic_thread_fence(std::memory_order_seq_cst);
        return value;
    }

private:
    void check_offset(std::size_t offset) const {
        if ((offset % sizeof(std::uint32_t)) != 0U || offset > size_ ||
            size_ - offset < sizeof(std::uint32_t)) {
            throw std::runtime_error("Navi48 MMIO register offset is outside the mapped BAR");
        }
    }

    std::size_t size_{};
    void* mapping_{};
    volatile std::uint32_t* words_{};
};

class DeviceLock {
public:
    explicit DeviceLock(const std::string& bdf) {
        // Keep the lock namespace stable so old and renamed binaries serialize access.
        const auto path = std::filesystem::path("/run/lock") / ("R9700flash-" + bdf + ".lock");
        const int fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd < 0) {
            throw std::runtime_error("Cannot create per-device ROM lock " + path.string() + ": " +
                                     std::error_code(errno, std::generic_category()).message());
        }
        descriptor_ = std::make_unique<FileDescriptor>(fd);

        struct stat info {};
        if (::fstat(fd, &info) != 0 || !S_ISREG(info.st_mode)) {
            throw std::runtime_error("Per-device ROM lock is not a regular file: " + path.string());
        }
        int result;
        do {
            result = ::flock(fd, LOCK_EX);
            if (result != 0 && errno == EINTR) throw_if_backup_interrupted();
        } while (result != 0 && errno == EINTR);
        if (result != 0) {
            throw std::runtime_error("Cannot lock Navi48 ROM access for " + bdf + ": " +
                                     std::error_code(errno, std::generic_category()).message());
        }
    }

    DeviceLock(const DeviceLock&) = delete;
    DeviceLock& operator=(const DeviceLock&) = delete;

private:
    std::unique_ptr<FileDescriptor> descriptor_;
};

std::string read_sysfs_token(const std::filesystem::path& path, const std::string& description) {
    std::ifstream input(path);
    std::string token;
    if (!(input >> token)) throw std::runtime_error("Cannot read " + description + " at " + path.string());
    return token;
}

void write_power_control(const std::filesystem::path& path, const std::string& value) {
    const int fd = ::open(path.c_str(), O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        throw std::runtime_error("Cannot update runtime power control at " + path.string() + ": " +
                                 std::error_code(errno, std::generic_category()).message());
    }
    FileDescriptor descriptor(fd);
    const std::string command = value + "\n";
    ssize_t result;
    do {
        result = ::write(fd, command.data(), command.size());
    } while (result < 0 && errno == EINTR);
    if (result != static_cast<ssize_t>(command.size())) {
        const int error = result < 0 ? errno : EIO;
        throw std::runtime_error("Cannot set runtime power control to " + value + " at " + path.string() +
                                 ": " + std::error_code(error, std::generic_category()).message());
    }
}

class RuntimePowerGuard {
public:
    explicit RuntimePowerGuard(const std::filesystem::path& device_path)
        : control_path_(device_path / "power/control"),
          status_path_(device_path / "power/runtime_status"),
          original_(read_sysfs_token(control_path_, "PCI runtime power policy")) {
        if (original_ != "auto" && original_ != "on") {
            throw std::runtime_error("Unexpected PCI runtime power policy '" + original_ + "' for " +
                                     device_path.filename().string());
        }
        if (original_ == "auto") {
            write_power_control(control_path_, "on");
            changed_ = true;
        }
        try {
            const auto status = read_sysfs_token(status_path_, "PCI runtime power status");
            if (status != "active" && status != "unsupported") {
                throw std::runtime_error("GPU did not become active for raw ROM access (runtime_status=" +
                                         status + ")");
            }
        } catch (...) {
            restore_noexcept();
            throw;
        }
    }

    RuntimePowerGuard(const RuntimePowerGuard&) = delete;
    RuntimePowerGuard& operator=(const RuntimePowerGuard&) = delete;

    ~RuntimePowerGuard() { restore_noexcept(); }

    void restore() {
        if (!changed_) return;
        write_power_control(control_path_, original_);
        changed_ = false;
    }

private:
    void restore_noexcept() noexcept {
        if (!changed_) return;
        try {
            write_power_control(control_path_, original_);
            changed_ = false;
        } catch (const std::exception& error) {
            std::cerr << "R9700flash-dump: warning: could not restore PCI runtime power policy: "
                      << error.what() << '\n';
        }
    }

    std::filesystem::path control_path_;
    std::filesystem::path status_path_;
    std::string original_;
    bool changed_{};
};
#endif

} // namespace

bool supports_navi48_spi_rom(const PciDevice& device) {
    return device.vendor_id == kAmdVendorId && device.family == "AMD_NAVI48" &&
           device.rom_size == kNavi48RomSize && is_known_navi48_revision(device);
}

std::vector<std::uint8_t> read_navi48_spi_rom(const PciDevice& device) {
    if (!supports_navi48_spi_rom(device)) {
        throw std::runtime_error("Raw SPI backup supports only known Navi48 PCI IDs and revisions; " +
                                 device.bdf + " is not in the supported set");
    }
#ifdef __linux__
    if (!valid_bdf(device.bdf)) throw std::runtime_error("Invalid PCI BDF for raw SPI backup");

    const auto device_path = std::filesystem::path("/sys/bus/pci/devices") / device.bdf;
    std::error_code link_error;
    const auto driver = std::filesystem::read_symlink(device_path / "driver", link_error);
    if (link_error || driver.filename() != "amdgpu") {
        throw std::runtime_error("Raw SPI backup requires the selected Navi48 device to be initialized by amdgpu");
    }

    SignalCancellationGuard interruption;
    DeviceLock device_lock(device.bdf);
    RuntimePowerGuard power(device_path);
    interruption.check();
    const auto bar = find_register_bar(device_path);
    if (bar.size > std::numeric_limits<std::size_t>::max()) {
        throw std::runtime_error("Navi48 register BAR is too large to map in this process");
    }
    MappedBar registers(device_path / ("resource" + std::to_string(bar.index)),
                        static_cast<std::size_t>(bar.size));

    // These are the Navi48 ROM_INDEX and ROM_DATA registers from the AMD ASIC metadata.
    // The kernel uses the same pair to read the VBIOS from the ROM address space.
    registers.write32(kRomIndexOffset, 0U);
    const std::uint32_t first_word = registers.read32(kRomDataOffset);
    registers.write32(kRomIndexOffset, sizeof(std::uint32_t));
    const std::uint32_t second_word = registers.read32(kRomDataOffset);
    if (first_word == 0xFFFFFFFFU || second_word == 0xFFFFFFFFU || second_word == first_word) {
        throw std::runtime_error("Navi48 ROM index did not return distinct readable data; refusing an unverified dump");
    }

    // Set the address for every word so the result does not depend on the ROM controller's
    // auto-increment setting or on another reader's cursor state.
    std::vector<std::uint8_t> bytes(kNavi48RomSize);
    for (std::size_t offset = 0; offset < bytes.size(); offset += sizeof(std::uint32_t)) {
        if ((offset & 0xFFFU) == 0U) interruption.check();
        registers.write32(kRomIndexOffset, static_cast<std::uint32_t>(offset));
        const std::uint32_t word = registers.read32(kRomDataOffset);
        bytes[offset] = static_cast<std::uint8_t>(word & 0xFFU);
        bytes[offset + 1U] = static_cast<std::uint8_t>((word >> 8U) & 0xFFU);
        bytes[offset + 2U] = static_cast<std::uint8_t>((word >> 16U) & 0xFFU);
        bytes[offset + 3U] = static_cast<std::uint8_t>((word >> 24U) & 0xFFU);
    }
    if (!has_valid_amd_option_rom(bytes)) {
        throw std::runtime_error("Navi48 SPI stream contains no complete AMD option-ROM image; refusing to save it");
    }
    registers.write32(kRomIndexOffset, 0U);
    if (registers.read32(kRomDataOffset) != first_word) {
        throw std::runtime_error("Navi48 ROM data changed during the raw ROM read; refusing to save it");
    }
    registers.write32(kRomIndexOffset, sizeof(std::uint32_t));
    if (registers.read32(kRomDataOffset) != second_word) {
        throw std::runtime_error("Navi48 ROM data changed during the raw ROM read; refusing to save it");
    }
    interruption.check();
    power.restore();
    return bytes;
#else
    (void)device;
    throw std::runtime_error("Navi48 raw SPI ROM access is available only on Linux");
#endif
}

} // namespace flashamd
