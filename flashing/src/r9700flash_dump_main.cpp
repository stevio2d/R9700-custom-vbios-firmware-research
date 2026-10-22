#include "flashamd/core.hpp"
#include "flashamd/navi48_spi.hpp"

#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#ifdef __linux__
#include <fcntl.h>
#include <unistd.h>
#endif

namespace {

struct Options {
    bool list{};
    bool backup{};
    bool help{};
    bool version{};
    std::optional<std::size_t> device;
    std::optional<std::filesystem::path> output;
};

constexpr std::string_view kVersion = "R9700flash-dump 0.1.0 (Navi48 read-only)";

void show_help() {
    std::cout << kVersion << "\n"
              << "Usage:\n"
              << "  R9700flash-dump --list\n"
              << "  R9700flash-dump --backup --device INDEX --output FILE\n"
              << "  R9700flash-dump --help | --version\n\n"
              << "--list shows AMD display devices and marks Navi48 devices supported for raw SPI backup.\n"
              << "--backup reads the complete 2 MiB Navi48 SPI ROM through ROM_INDEX/ROM_DATA.\n"
              << "This build has no flash erase or programming command.\n";
}

std::size_t parse_index(std::string_view value) {
    if (value.empty()) throw std::runtime_error("--device requires an index");
    std::size_t parsed = 0;
    for (const char ch : value) {
        if (ch < '0' || ch > '9') throw std::runtime_error("--device index must be a non-negative integer");
        const std::size_t digit = static_cast<std::size_t>(ch - '0');
        if (parsed > (static_cast<std::size_t>(-1) - digit) / 10U) {
            throw std::runtime_error("--device index is too large");
        }
        parsed = parsed * 10U + digit;
    }
    return parsed;
}

Options parse_arguments(int argc, char** argv) {
    Options options;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg(argv[i]);
        if (arg == "--list" || arg == "--show" || arg == "-l") {
            options.list = true;
        } else if (arg == "--backup" || arg == "--save") {
            options.backup = true;
        } else if (arg == "--help" || arg == "-h" || arg == "/?") {
            options.help = true;
        } else if (arg == "--version") {
            options.version = true;
        } else if (arg == "--device" || arg == "-i") {
            if (++i >= argc) throw std::runtime_error("--device requires an index");
            options.device = parse_index(argv[i]);
        } else if (arg == "--output" || arg == "-o") {
            if (++i >= argc || std::string_view(argv[i]).empty()) {
                throw std::runtime_error("--output requires a path");
            }
            options.output = std::filesystem::path(argv[i]);
        } else {
            throw std::runtime_error("Unknown option: " + std::string(arg));
        }
    }

    if (options.help || options.version) return options;
    if (options.list && options.backup) throw std::runtime_error("Choose either --list or --backup");
    if (!options.list && !options.backup) options.list = true;
    if (options.backup && !options.device) throw std::runtime_error("--backup requires --device INDEX");
    if (options.backup && !options.output) throw std::runtime_error("--backup requires --output FILE");
    if (options.list && (options.device || options.output)) {
        throw std::runtime_error("--device and --output are used with --backup");
    }
    return options;
}

std::filesystem::path data_directory(const char* argv0) {
    (void)argv0;
    for (const char* variable : {"R9700FLASH_DUMP_DATA_DIR", "R9700FLASH_DATA_DIR", "AMDVBFLASH_DATA_DIR"}) {
        if (const char* value = std::getenv(variable); value != nullptr && *value != '\0') return value;
    }

#ifdef __linux__
    std::error_code error;
    const auto executable = std::filesystem::read_symlink("/proc/self/exe", error);
    if (!error) {
        const auto installed = executable.parent_path().parent_path() / "share" / "flash-amd";
        if (std::filesystem::exists(installed / "asic_devices.csv")) return installed;
    }
#endif

#ifdef R9700FLASH_DUMP_SOURCE_DATA_DIR
    return R9700FLASH_DUMP_SOURCE_DATA_DIR;
#else
    return "data";
#endif
}

std::vector<flashamd::PciDevice> enumerate_devices(const char* argv0) {
    auto catalog = flashamd::load_asic_catalog(data_directory(argv0) / "asic_devices.csv");
    flashamd::LinuxBackend backend(std::move(catalog), "sysfs");
    return backend.enumerate();
}

void show_devices(const std::vector<flashamd::PciDevice>& devices) {
    if (devices.empty()) {
        std::cout << "No AMD GPU devices detected.\n";
        return;
    }
    for (const auto& device : devices) {
        std::cout << '[' << device.index << "] " << device.name << " (" << device.family << ")"
                  << " [" << device.bdf << "] Vendor=" << flashamd::hex_id(device.vendor_id)
                  << " Device=" << flashamd::hex_id(device.device_id)
                  << " Revision=" << flashamd::hex_id(device.revision_id)
                  << " Subsystem=" << flashamd::hex_id(device.subsystem_vendor_id) << '/'
                  << flashamd::hex_id(device.subsystem_device_id)
                  << " Raw SPI backup=" << (flashamd::supports_navi48_spi_rom(device) ? "supported" : "unsupported")
                  << '\n';
    }
}

#ifdef __linux__
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

void write_new_file(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (fd < 0) {
        if (errno == EEXIST) throw std::runtime_error("Output already exists; choose a new filename: " + path.string());
        throw std::runtime_error("Cannot create " + path.string() + ": " +
                                 std::error_code(errno, std::generic_category()).message());
    }
    FileDescriptor output(fd);
    std::size_t written = 0;
    try {
        while (written < bytes.size()) {
            const auto remaining = bytes.size() - written;
            const auto count = ::write(fd, bytes.data() + written, remaining);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) {
                throw std::runtime_error("Failed while writing " + path.string() + ": " +
                                         std::error_code(errno, std::generic_category()).message());
            }
            written += static_cast<std::size_t>(count);
        }
        if (::fsync(fd) != 0) {
            throw std::runtime_error("Could not sync " + path.string() + ": " +
                                     std::error_code(errno, std::generic_category()).message());
        }
    } catch (...) {
        (void)::unlink(path.c_str());
        throw;
    }
}
#else
void write_new_file(const std::filesystem::path&, const std::vector<std::uint8_t>&) {
    throw std::runtime_error("R9700flash-dump backups are available only on Linux");
}
#endif

int run(int argc, char** argv) {
    const auto options = parse_arguments(argc, argv);
    if (options.help) {
        show_help();
        return 0;
    }
    if (options.version) {
        std::cout << kVersion << '\n';
        return 0;
    }

    const auto devices = enumerate_devices(argc > 0 ? argv[0] : nullptr);
    if (options.list) {
        show_devices(devices);
        return 0;
    }

    if (*options.device >= devices.size()) throw std::runtime_error("Device index is out of range");
    const auto& device = devices[*options.device];
    if (!flashamd::supports_navi48_spi_rom(device)) {
        throw std::runtime_error("Selected device " + device.bdf + " is not a supported Navi48 revision");
    }
    const auto bytes = flashamd::read_navi48_spi_rom(device);
    write_new_file(*options.output, bytes);
    std::cout << "Saved raw SPI ROM (" << bytes.size() << " bytes) from " << device.bdf
              << " to " << options.output->string() << '\n';
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    try {
        return run(argc, argv);
    } catch (const std::exception& error) {
        std::cerr << "R9700flash-dump: " << error.what() << '\n';
        return 1;
    }
}
