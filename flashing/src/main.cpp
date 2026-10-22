#include "flashamd/core.hpp"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#ifdef __linux__
#include <unistd.h>
#endif

namespace {

using Values = std::map<std::string, std::vector<std::string>>;

struct Options {
    Values values;
    std::vector<std::string> positional;
    bool simulator{};
    std::string help_command;
    std::optional<std::size_t> legacy_device;
    std::optional<std::string> legacy_file;
    std::optional<std::size_t> save_device;
};

const std::set<std::string> flags = {
    "version", "show-progress", "silent", "accept-EULA", "show-EULA", "cls", "close", "flush",
    "advanced", "show", "vbios-info", "bios-file-info", "ifwi-version", "pspbl-version",
    "savefile-at-end", "save-flashed-bytes", "active", "inactive", "flash-both-partitions",
    "fa", "fp", "fv", "complete", "biosimage", "pa", "checkpn", "checkifwi",
    "skip-psp-check", "set-quad-mode", "skip-ssid-check", "calculate-bar-size",
    "debug-log-options", "no-workload-execution", "force-recovery-path", "flash", "save", "cr", "cf"
};

const std::set<std::string> value_options = {
    "help", "debug-log-status", "debug-log-filename", "debug-log-filepath", "debug-log-filesize",
    "debug-log-filepolicy", "exe", "open", "device", "hw-access-mechanism", "vbios-file",
    "config", "allocate-sys-mem", "padevid", "passid", "pasvid", "pavbpn", "merge-ifwi"
};

constexpr std::string_view version_banner =
    "AMD IFWI Flasher Tool Version 5.0.879.0-Moded_v2. Copyright© 2020-2025 Advanced Micro Devices, Inc. All rights reserved.";

void show_banner() {
    std::cout << version_banner << "\n\n";
}

std::string canonical(std::string name) {
    if (name == "h" || name == "?") return "help";
    if (name == "e") return "show-EULA";
    if (name == "i") return "device";
    if (name == "a") return "advanced";
    if (name == "s") return "save";
    if (name == "p") return "flash";
    if (name == "fs") return "skip-ssid-check";
    if (name == "flash_both_partition" || name == "flash_both_partitions") return "flash-both-partitions";
    return name;
}

bool looks_like_option(const std::string& token) {
    if (token.size() < 2 || token[0] != '-') return false;
    if (token.size() > 1 && std::isdigit(static_cast<unsigned char>(token[1])) != 0) return false;
    return true;
}

bool parse_index(std::string_view text, std::size_t& index) {
    if (text.empty() || text.front() == '-') return false;
    std::size_t parsed{};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), parsed);
    if (error != std::errc{} || end != text.data() + text.size()) return false;
    index = parsed;
    return true;
}

void add_value(Options& options, const std::string& name, std::string value) {
    options.values[name].push_back(std::move(value));
}

Options parse_arguments(int argc, char** argv) {
    Options options;
    for (int i = 1; i < argc; ++i) {
        std::string token(argv[i]);
        if (token == "--simulator") {
            options.simulator = true;
            continue;
        }
        if (token == "-ai") {
            add_value(options, "advanced", "true");
            if (i + 1 < argc && !looks_like_option(argv[i + 1])) add_value(options, "device", argv[++i]);
            continue;
        }
        if (!looks_like_option(token)) {
            options.positional.push_back(std::move(token));
            continue;
        }
        if (token == "/?" || token == "/h") {
            add_value(options, "help", "true");
            continue;
        }
        if (token.rfind("--", 0) == 0) token.erase(0, 2);
        else token.erase(0, 1);
        std::string value;
        const auto equal = token.find('=');
        const bool has_inline_value = equal != std::string::npos;
        if (has_inline_value) {
            value = token.substr(equal + 1);
            token.resize(equal);
        }
        const auto name = canonical(token);
        if (name == "simulator") {
            options.simulator = true;
            continue;
        }
        if (name == "help") {
            if (has_inline_value) options.help_command = value;
            else if (i + 1 < argc && !looks_like_option(argv[i + 1])) options.help_command = argv[++i];
            add_value(options, name, has_inline_value ? value : "true");
            continue;
        }
        const bool is_known = flags.contains(name) || value_options.contains(name);
        if (!is_known) throw std::runtime_error("Invalid command line option: --" + name);
        if (flags.contains(name)) {
            if (has_inline_value) {
                if (value != "true" && value != "false" && name != "debug-log-status") {
                    throw std::runtime_error("Option does not accept a value: --" + name);
                }
                if (name == "debug-log-status") add_value(options, name, value);
                else if (value == "true") add_value(options, name, "true");
                else if (value == "false") continue;
            } else {
                add_value(options, name, "true");
            }
            if ((name == "flash" || name == "save") && !has_inline_value && i + 1 < argc) {
                std::size_t idx{};
                if (parse_index(argv[i + 1], idx)) {
                    ++i;
                    if (name == "flash") options.legacy_device = idx;
                    else options.save_device = idx;
                    if (i + 1 < argc && !looks_like_option(argv[i + 1])) {
                        ++i;
                        if (name == "flash") options.legacy_file = argv[i];
                        else if (!options.values.contains("vbios-file")) add_value(options, "vbios-file", argv[i]);
                    }
                }
            }
            if (name == "cr" && !has_inline_value && i + 1 < argc) {
                std::size_t index{};
                if (parse_index(argv[i + 1], index)) {
                    options.legacy_device = index;
                    ++i;
                    for (unsigned n = 0; n < 2 && i + 1 < argc && !looks_like_option(argv[i + 1]); ++n) {
                        options.positional.emplace_back(argv[++i]);
                    }
                }
            }
            continue;
        }
        if (!has_inline_value && i + 1 < argc && !looks_like_option(argv[i + 1])) {
            const std::string next(argv[i + 1]);
            if (name == "device" || name == "debug-log-status" || name == "debug-log-filename" ||
                name == "debug-log-filepath" || name == "debug-log-filesize" || name == "debug-log-filepolicy" ||
                name == "exe" || name == "open" || name == "hw-access-mechanism" || name == "vbios-file" ||
                name == "config" || name == "allocate-sys-mem" || name == "padevid" || name == "passid" ||
                name == "pasvid" || name == "pavbpn") {
                value = argv[++i];
            } else if (name == "merge-ifwi") {
                std::vector<std::string> args;
                for (unsigned n = 0; n < 4 && i + 1 < argc && !looks_like_option(argv[i + 1]); ++n) args.emplace_back(argv[++i]);
                if (args.size() != 4) throw std::runtime_error("The number of arguments provided for --merge-ifwi is invalid; expected PSPFWID, BaseIFWI, FirmwareIFWI, and newIFWI.");
                for (auto& arg : args) add_value(options, name, std::move(arg));
                continue;
            }
        }
        if (name == "device" && value.empty()) value = "-1";
        if (name == "merge-ifwi" && value.empty()) throw std::runtime_error("The number of arguments provided for --merge-ifwi is invalid; expected four values.");
        add_value(options, name, std::move(value));
    }
    const bool file_command = options.values.contains("flash") || options.values.contains("cf") ||
        options.values.contains("checkpn") || options.values.contains("checkifwi") ||
        options.values.contains("pa") || options.values.contains("bios-file-info") ||
        options.values.contains("vbios-info");
    if (file_command && !options.positional.empty()) {
        if (!options.values.contains("vbios-file") && !options.legacy_file) {
            options.legacy_file = options.positional.front();
        }
    }
    return options;
}

bool has(const Options& options, const std::string& key) {
    const auto it = options.values.find(key);
    return it != options.values.end() && !it->second.empty();
}

std::string value(const Options& options, const std::string& key, std::string fallback = {}) {
    const auto it = options.values.find(key);
    if (it == options.values.end() || it->second.empty()) return fallback;
    return it->second.front();
}

std::vector<std::uint8_t> read_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("Cannot open file: " + path.string());
    input.seekg(0, std::ios::end);
    const auto end = input.tellg();
    if (end < 0 || static_cast<std::uint64_t>(end) > 64ULL * 1024ULL * 1024ULL) {
        throw std::runtime_error("File is larger than the supported 64 MiB limit or unreadable: " + path.string());
    }
    input.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(end));
    if (!bytes.empty()) input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!input && !bytes.empty()) throw std::runtime_error("Failed to read file: " + path.string());
    return bytes;
}

void write_file(const std::filesystem::path& path, std::span<const std::uint8_t> bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("Cannot create file: " + path.string());
    output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!output) throw std::runtime_error("Failed to write file: " + path.string());
}

std::uint64_t parse_unsigned(std::string text) {
    int base = 10;
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        text.erase(0, 2);
        base = 16;
    }
    std::uint64_t number{};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), number, base);
    if (error != std::errc{} || end != text.data() + text.size()) throw std::runtime_error("Invalid numeric value: " + text);
    return number;
}

std::vector<std::size_t> device_indices(const Options& options, std::size_t count) {
    std::vector<std::size_t> indices;
    std::string chosen;
    if (options.legacy_device && !has(options, "device")) chosen = std::to_string(*options.legacy_device);
    else chosen = value(options, "device", "-1");
    if (chosen.empty() || chosen == "-1") {
        for (std::size_t i = 0; i < count; ++i) indices.push_back(i);
        return indices;
    }
    std::istringstream list(chosen);
    std::string part;
    while (std::getline(list, part, ',')) {
        const auto parsed = parse_unsigned(part);
        if (parsed >= count) throw std::runtime_error("Device index " + part + " is out of range; detected devices: " + std::to_string(count));
        const auto index = static_cast<std::size_t>(parsed);
        if (std::find(indices.begin(), indices.end(), index) == indices.end()) indices.push_back(index);
    }
    if (indices.empty()) throw std::runtime_error("No device index was selected");
    return indices;
}

std::string default_rom_filename(const flashamd::PciDevice& device) {
    std::string safe = device.name;
    std::replace_if(safe.begin(), safe.end(), [](unsigned char c) { return !std::isalnum(c) && c != '-' && c != '_'; }, '_');
    return safe + "_" + device.bdf + "_" + std::to_string(device.index) + ".rom";
}

void show_help(const std::filesystem::path& data, const std::string& command = {}) {
    if (command.empty() || command == "all" || command == "internal") {
        std::ifstream original_help(data / "original-help.txt");
        if (original_help) std::cout << original_help.rdbuf();
        else {
    std::cout << "AMDVBFlash 5.0.879.0 - Linux port\n"
                 "Usage: amdvbflash [options]\n\n"
                 "Common options:\n"
                 "  --help, -h, -?                     Show this help\n"
                 "  --version                         Show tool version\n"
                 "  --show-EULA, -e                   Show the embedded AMD FW Flash Tool EULA\n"
                 "  --accept-EULA                     Accept the EULA for this version\n"
                 "  --show                            Display information selected by other options\n"
                 "  --device, -i [N[,N...]]           Select zero-based device index; -1 or omitted means all\n"
                 "  --advanced, -a                    Show advanced device/partition information\n"
                 "  --show-progress                   Show progress during long operations\n"
                 "  --silent                          Suppress progress output\n"
                 "\nVBIOS and IFWI options:\n"
                 "  --save, -s                        Save the selected device ROM\n"
                 "  --flash, -p [N FILE]              Flash an image to a selected device\n"
                 "  --vbios-file FILE                 Select the VBIOS/IFWI file\n"
                 "  --vbios-info                      Show VBIOS image details with --show\n"
                 "  --bios-file-info                  Show BIOS image details from a file\n"
                 "  --ifwi-version                    Query device IFWI version with --show\n"
                 "  --pspbl-version                   Query PSP boot loader version with --show\n"
                 "  --checkpn                         Compare PCI part/device identifiers\n"
                 "  --checkifwi                       Compare the selected ROM/partition with an image\n"
                 "  --cr                              Calculate a selected ROM 16-bit checksum\n"
                 "  --cf                              Calculate a file 16-bit checksum\n"
                 "  --complete                        Check the full ROM/file for --cr or --cf\n"
                 "  --biosimage                       Limit --cr to the VBIOS image\n"
                 "  --pa                              Flash all matching ASICs (simulator only)\n"
                 "  --padevid ID --pasvid ID --passid ID --pavbpn PART\n"
                 "                                    Filter --pa targets\n"
                 "  --active | --inactive             Select active/inactive partition for checks\n"
                 "  --merge-ifwi ID BASE FW OUTPUT    Merge an IFWI image (format not implemented)\n"
                 "\nLinux hardware access:\n"
                 "  --hw-access-mechanism=sysfs|devmem|devmem,sysfs\n"
                 "  Linux device discovery and PCI ROM backup are read-only.\n"
                 "  Pass --simulator to run erase/write/readback operations against synthetic devices.\n";
        }
    } else if (command == "cf") {
        std::cout << version_banner << "\n\nHelp for switch: cf\n"
                     "Calculate 16-bit checksum for file <File> and optionally compare the result.\n"
                     "Usage:\n    -cf <file> <sum>, or\n    --cf <file> <sum>\n";
    } else if (command == "cr") {
        std::cout << version_banner << "\n\nHelp for switch: cr\n"
                     "Calculate a 16-bit checksum for a device ROM.\n"
                     "Usage:\n    -cr <Num> <size> <sum>, or\n    --cr --device <Num> <size> <sum>\n";
    } else if (command == "flash" || command == "p") {
        std::cout << version_banner << "\n\nHelp for switch: flash\n"
                     "Write VBIOS image in file <file> to flash ROM in ASIC <Num>.\n"
                     "Usage:\n    -p <Num> <File>, or\n    --flash --device [Num] --vbios-file <File>\n";
    } else if (command == "save" || command == "s") {
        std::cout << version_banner << "\n\nHelp for switch: save\n"
                     "Save the selected device VBIOS image.\n"
                     "Usage:\n    -s <Num> [File], or\n    --save --device <Num> --vbios-file <File>\n";
    } else {
        std::ifstream original_help(data / "original-help.txt");
        if (original_help) std::cout << original_help.rdbuf();
        else std::cout << "Original help resource is unavailable. Use --help without an argument for the built-in summary.\n";
    }
    if (command == "internal") {
        std::cout << "\nRecovered hidden options:\n"
                     "  --flash-both-partitions (-fs) --skip-ssid-check --skip-psp-check\n"
                     "  --set-quad-mode --config FILE --allocate-sys-mem=BOOL\n"
                     "  --calculate-bar-size --force-recovery-path\n"
                     "  --debug-log-status=BOOL --debug-log-options --debug-log-filename=NAME\n"
                     "  --debug-log-filepath=PATH --debug-log-filesize=SIZE --debug-log-filepolicy=POLICY\n"
                     "  --exe FILE --open FILE --close --flush --cls --no-workload-execution\n";
    }
}

void show_image(const std::filesystem::path& path, const flashamd::ImageInfo& info) {
    std::cout << "BIOS image file: " << path.string() << '\n'
              << "Image size: 0x" << std::hex << std::uppercase << info.file_size << std::dec << " bytes\n"
              << "PCI ROM signature: " << (info.has_rom_signature ? "valid" : "not found") << '\n';
    if (info.has_pcir) {
        std::cout << "PCIR vendor/device: " << flashamd::hex_id(info.vendor_id) << '/'
                  << flashamd::hex_id(info.device_id) << '\n'
                  << "ATOM subsystem vendor/device: " << flashamd::hex_id(info.subsystem_vendor_id) << '/'
                  << flashamd::hex_id(info.subsystem_device_id) << '\n';
        if (info.declared_size != 0) std::cout << "Declared option ROM size: " << info.declared_size << " bytes\n";
    } else {
        std::cout << "PCIR signature: not found\n";
    }
    if (info.has_atom) std::cout << "ATOM BIOS table revision: " << (info.atom_version.empty() ? "present" : info.atom_version) << '\n';
    else std::cout << "ATOM BIOS signature: not found\n";
    std::cout << "PSP directory marker: " << (info.has_psp_marker ? "found" : "not found") << '\n'
              << "16-bit checksum: 0x" << std::hex << std::uppercase << info.checksum << std::dec << '\n'
              << "Option ROM 8-bit checksum: ";
    if (!info.checksum_applicable) std::cout << "not applicable\n";
    else {
        std::cout << (info.checksum_ok ? "valid" : "invalid");
        if (info.checksum_size != 0U && info.image_checksum_size != 0U &&
            info.checksum_size != info.image_checksum_size) {
            std::cout << " (initialization " << info.checksum_size << " bytes, PCIR image "
                      << info.image_checksum_size << " bytes)";
        } else if (info.checksum_size != 0U) {
            std::cout << " over " << info.checksum_size << " bytes";
        } else {
            std::cout << " over PCIR image " << info.image_checksum_size << " bytes";
        }
        std::cout << '\n';
    }
}

void show_devices(const std::vector<flashamd::PciDevice>& devices, bool advanced,
                  flashamd::DeviceBackend& backend, const Options& options) {
    if (devices.empty()) {
        std::cout << "No AMD GPU devices detected.\n";
        return;
    }
    const auto indices = device_indices(options, devices.size());
    for (const auto index : indices) {
        const auto& device = devices[index];
        std::cout << '[' << device.index << "] " << device.name << " (" << device.family << ")"
                  << " [" << device.bdf << "] Vendor=" << flashamd::hex_id(device.vendor_id)
                  << " Device=" << flashamd::hex_id(device.device_id)
                  << " Revision=" << flashamd::hex_id(device.revision_id)
                  << " Subsystem=" << flashamd::hex_id(device.subsystem_vendor_id) << '/'
                  << flashamd::hex_id(device.subsystem_device_id) << '\n';
        if (advanced) {
            std::cout << "    ROM capacity: 0x" << std::hex << std::uppercase << device.rom_size
                      << std::dec << " bytes; IFWI partitions: "
                      << (device.rom_size >= 4096U ? "A/B (simulated half-ROM layout)" : "not reported") << '\n';
            if (backend.supports_firmware_writes()) {
                std::cout << "    Simulated active partition: A; inactive partition: B\n";
            }
        }
    }
}

std::filesystem::path image_path(const Options& options) {
    if (has(options, "vbios-file")) return value(options, "vbios-file");
    if (options.legacy_file) return *options.legacy_file;
    if (!options.positional.empty()) return options.positional.front();
    throw std::runtime_error("VBIOS File Image not specified.");
}

bool needs_eula(const Options& options) {
    for (const auto& [key, entries] : options.values) {
        (void)entries;
        if (key != "version" && key != "help" && key != "show-EULA" && key != "accept-EULA") return true;
    }
    return options.simulator || !options.positional.empty();
}

std::filesystem::path eula_state_path() {
    if (const char* config = std::getenv("XDG_CONFIG_HOME")) {
        return std::filesystem::path(config) / "amdvbflash" / "accepted-5.0.879";
    }
    if (const char* home = std::getenv("HOME")) {
        return std::filesystem::path(home) / ".config" / "amdvbflash" / "accepted-5.0.879";
    }
    return std::filesystem::temp_directory_path() / "amdvbflash-accepted-5.0.879";
}

void store_eula_acceptance() {
    const auto path = eula_state_path();
    std::filesystem::create_directories(path.parent_path());
    std::ofstream out(path);
    if (!out) throw std::runtime_error("Cannot store EULA acceptance at " + path.string());
    out << "accepted\n";
}

bool eula_accepted() {
    std::ifstream in(eula_state_path());
    std::string value;
    in >> value;
    return value == "accepted";
}

bool maybe_accept_eula(const Options& options, const std::filesystem::path& data) {
    if (has(options, "accept-EULA")) {
        store_eula_acceptance();
        return true;
    }
    if (eula_accepted()) return true;
#ifdef __linux__
    const bool interactive = ::isatty(STDIN_FILENO) != 0;
#else
    const bool interactive = false;
#endif
    if (!interactive) {
        std::cout << "EULA not accepted. Use --accept-EULA to accept and continue.\n";
        return false;
    }
    std::ifstream eula(data / "EULA.txt");
    if (eula) std::cout << eula.rdbuf();
    std::cout << "\nType Y to accept the AMD FW Flash Tool EULA: ";
    std::string response;
    std::getline(std::cin, response);
    std::transform(response.begin(), response.end(), response.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (response == "y" || response == "yes") {
        store_eula_acceptance();
        return true;
    }
    std::cout << "Eula not accepted. Not doing anything else.\n";
    return false;
}

flashamd::FlashPolicy flash_policy(const Options& options) {
    flashamd::FlashPolicy policy;
    policy.force_same = has(options, "fa");
    policy.force_part_number = has(options, "fp");
    policy.force_version = has(options, "fv");
    policy.skip_ssid_check = has(options, "skip-ssid-check");
    policy.both_partitions = has(options, "flash-both-partitions");
    policy.force_recovery_path = has(options, "force-recovery-path");
    return policy;
}

void validate_option_combinations(const Options& options) {
    for (const auto* flag : {"fa", "fp", "fv", "skip-ssid-check", "flash-both-partitions", "save-flashed-bytes"}) {
        if (has(options, flag) && !has(options, "flash") && !has(options, "pa")) {
            throw std::runtime_error(std::string("--") + flag + " can only be used with --flash");
        }
    }
    if (has(options, "savefile-at-end") && !has(options, "save")) {
        throw std::runtime_error("--savefile-at-end can only be used with --save");
    }
    if (has(options, "active") && has(options, "inactive")) throw std::runtime_error("--active and --inactive cannot be used together");
    if (has(options, "complete") && !has(options, "cf") && !has(options, "cr")) {
        throw std::runtime_error("--complete can only be used with --cf or --cr");
    }
    if (has(options, "biosimage") && !has(options, "cr")) throw std::runtime_error("--biosimage can only be used with --cr");
    if ((has(options, "ifwi-version") || has(options, "pspbl-version")) && !has(options, "show")) {
        throw std::runtime_error("Version queries require --show");
    }
    if (has(options, "inactive") && !has(options, "advanced") && !has(options, "checkifwi")) {
        throw std::runtime_error("--inactive requires --advanced or --checkifwi");
    }
    if (has(options, "active") && !has(options, "advanced") && !has(options, "checkifwi")) {
        throw std::runtime_error("--active requires --advanced or --checkifwi");
    }
}

int run(int argc, char** argv) {
    Options options;
    try {
        options = parse_arguments(argc, argv);
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 12;
    }
    const auto data = flashamd::data_directory(argv[0]);
    if (has(options, "help")) {
        show_help(data, options.help_command);
        return 0;
    }
    if (has(options, "version")) {
        show_banner();
        show_banner();
        return 0;
    }
    if (has(options, "show-EULA")) {
        if (!has(options, "silent")) show_banner();
        std::ifstream eula(data / "EULA.txt");
        if (!eula) throw std::runtime_error("Embedded EULA text is unavailable");
        std::cout << eula.rdbuf();
        return 0;
    }
    if (!has(options, "silent")) show_banner();
    validate_option_combinations(options);
    if (has(options, "accept-EULA") && !needs_eula(options)) {
        store_eula_acceptance();
        return 0;
    }
    if (needs_eula(options) && !maybe_accept_eula(options, data)) return 0;

    if (has(options, "merge-ifwi")) {
        throw std::runtime_error("IFWI merge is recognized, but PSPFWID partition replacement is not implemented because the encrypted IFWI layout could not be validated.");
    }
    auto catalog = flashamd::load_asic_catalog(data / "asic_devices.csv");
    bool simulator = options.simulator;
    if (const char* backend = std::getenv("AMDVBFLASH_BACKEND")) {
        if (std::string_view(backend) == "sim") simulator = true;
    }
    if (has(options, "pavbpn")) {
        throw std::runtime_error("--pavbpn is recognized, but part-number filtering is unavailable until VBIOS part metadata is decoded");
    }
    if (has(options, "checkifwi") && !simulator) {
        throw std::runtime_error("--checkifwi requires decoded IFWI partition metadata and is available only with --simulator in this port");
    }
    const bool offline_action = has(options, "cf") || has(options, "bios-file-info") ||
        (has(options, "vbios-info") && !has(options, "show"));
    const bool explicit_device_action = has(options, "show") || has(options, "advanced") ||
        has(options, "save") || has(options, "flash") || has(options, "cr") ||
        has(options, "checkpn") || has(options, "checkifwi") || has(options, "ifwi-version") ||
        has(options, "pspbl-version") || has(options, "pa") || has(options, "set-quad-mode");
    const bool needs_devices = explicit_device_action || !offline_action;
    std::unique_ptr<flashamd::DeviceBackend> backend;
    std::vector<flashamd::PciDevice> devices;
    if (needs_devices) {
        backend = flashamd::make_backend(simulator, catalog, value(options, "hw-access-mechanism", "devmem,sysfs"));
        devices = backend->enumerate();
    }
    if (has(options, "open")) std::cout << "Session logging is not implemented in this port.\n";
    if (has(options, "cls")) std::cout << "\033[2J\033[H";
    if (has(options, "debug-log-options")) {
        std::cout << "Debug logging options: enabled by default; --debug-log-status=false disables logging.\n";
    }
    if (has(options, "exe")) throw std::runtime_error("DB32 macro execution is not implemented in this port");

    const bool wants_device_list = has(options, "show") || has(options, "advanced") ||
        (!has(options, "flash") && !has(options, "save") && !has(options, "vbios-info") &&
         !has(options, "bios-file-info") && !has(options, "cf") && !has(options, "cr") &&
         !has(options, "checkpn") && !has(options, "checkifwi") && !has(options, "pa") &&
         !has(options, "ifwi-version") && !has(options, "pspbl-version") && !has(options, "set-quad-mode"));
    if (wants_device_list) show_devices(devices, has(options, "advanced"), *backend, options);

    std::optional<std::vector<std::uint8_t>> image;
    std::optional<flashamd::ImageInfo> info;
    std::optional<std::filesystem::path> path;
    const bool needs_image_file = has(options, "bios-file-info") || has(options, "vbios-info") ||
        has(options, "flash") || has(options, "cf") || has(options, "checkpn") ||
        has(options, "checkifwi") || has(options, "pa");
    if (needs_image_file) {
        path = image_path(options);
        image = read_file(*path);
        info = flashamd::inspect_image(*image);
    }
    if (has(options, "bios-file-info") || (has(options, "show") && has(options, "vbios-info"))) {
        show_image(*path, *info);
    }
    if (has(options, "cf")) {
        const auto calculated = flashamd::checksum16(*image);
        std::cout << "Checksum of file " << path->string() << ": 0x" << std::hex << std::uppercase << calculated << std::dec << '\n';
        auto expected = value(options, "cf-expected");
        if (expected.empty()) {
            const std::size_t expected_index = options.legacy_file ? 1U : 0U;
            if (options.positional.size() > expected_index) expected = options.positional[expected_index];
        }
        if (!expected.empty()) {
            const auto number = parse_unsigned(expected);
            if (number > 0xffffU) throw std::runtime_error("Expected checksum must fit in 16 bits");
            const bool match = calculated == number;
            std::cout << (match ? "Checksum is also OK.\n" : "Checksum does not match expected value.\n");
            if (!match) return 1;
        }
    }
    if (has(options, "ifwi-version") || has(options, "pspbl-version")) {
        const auto indices = device_indices(options, devices.size());
        for (const auto index : indices) {
            if (has(options, "ifwi-version")) std::cout << '[' << index << "] IFWI version: unavailable (no IFWI metadata decoded)\n";
            if (has(options, "pspbl-version")) std::cout << '[' << index << "] PSP Boot Loader version: unavailable (not reported by generic PCI ROM access)\n";
        }
    }
    if (has(options, "checkpn")) {
        if (!info->has_pcir) throw std::runtime_error("Part number/device comparison requires a PCIR header");
        const auto indices = device_indices(options, devices.size());
        bool all_match = true;
        for (const auto index : indices) {
            const auto& device = devices[index];
            const bool match = info->vendor_id == device.vendor_id && info->device_id == device.device_id;
            std::cout << '[' << index << "] Image part/device IDs " << (match ? "match" : "do not match") << " device " << device.bdf << '\n';
            all_match = all_match && match;
        }
        if (!all_match && !has(options, "fp")) return 1;
    }
    if (has(options, "checkifwi")) {
        const auto indices = device_indices(options, devices.size());
        bool all_match = true;
        for (const auto index : indices) {
            const auto rom = backend->read_rom(index);
            const std::size_t offset = has(options, "inactive") ? rom.size() / 2U : 0U;
            if (offset + image->size() > rom.size()) throw std::runtime_error("IFWI image does not fit in the selected partition");
            const auto active = std::span<const std::uint8_t>(rom).subspan(offset, image->size());
            const bool match = std::equal(image->begin(), image->end(), active.begin());
            std::cout << '[' << index << "] IFWI partition SHA256 " << (has(options, "inactive") ? "inactive" : "active")
                      << ": image " << flashamd::sha256(*image) << ", device " << flashamd::sha256(active)
                      << " — " << (match ? "match" : "mismatch") << '\n';
            all_match = all_match && match;
        }
        if (!all_match) return 1;
    }
    if (has(options, "cr")) {
        const auto indices = device_indices(options, devices.size());
        for (const auto index : indices) {
            const auto rom = backend->read_rom(index);
            std::size_t count = rom.size();
            if (has(options, "biosimage")) {
                const auto rom_info = flashamd::inspect_image(rom);
                if (rom_info.declared_size != 0 && rom_info.declared_size <= rom.size()) count = rom_info.declared_size;
            } else if (!options.positional.empty()) {
                count = static_cast<std::size_t>(parse_unsigned(options.positional[0]));
                if (count > rom.size()) throw std::runtime_error("Requested checksum size exceeds ROM capacity");
            }
            const auto calculated = flashamd::checksum16(std::span<const std::uint8_t>(rom).first(count));
            std::cout << '[' << index << "] ROM checksum (" << count << " bytes): 0x"
                      << std::hex << std::uppercase << calculated << std::dec << '\n';
            const std::size_t expected_pos = 1U;
            if (options.positional.size() > expected_pos) {
                const auto expected = parse_unsigned(options.positional[expected_pos]);
                if (expected > 0xffffU) throw std::runtime_error("Expected checksum must fit in 16 bits");
                if (calculated != expected) return 1;
                std::cout << "Checksum is also OK.\n";
            }
        }
    }
    if (has(options, "save")) {
        if (devices.empty()) throw std::runtime_error("Devices not specified");
        std::vector<std::size_t> indices;
        if (options.save_device && !has(options, "device")) indices = {*options.save_device};
        else indices = device_indices(options, devices.size());
        if (has(options, "vbios-file") && indices.size() > 1U) {
            throw std::runtime_error("--vbios-file names one output file; select one device when saving to an explicit path");
        }
        for (const auto index : indices) {
            if (index >= devices.size()) throw std::runtime_error("Device index is out of range");
            const auto rom = backend->read_rom(index);
            const auto target = has(options, "vbios-file") ? std::filesystem::path(value(options, "vbios-file"))
                                                            : std::filesystem::path(default_rom_filename(devices[index]));
            write_file(target, rom);
            std::cout << "Saved " << rom.size() << " bytes from " << devices[index].bdf << " to " << target.string() << '\n';
        }
    }
    if (has(options, "flash") || has(options, "pa")) {
        if (!path || !image || !info) throw std::runtime_error("No VBIOS Image file specified for flashing.");
        if (!backend->supports_firmware_writes()) {
            throw std::runtime_error("Linux hardware firmware writes are disabled in this build. Firmware writes are available only with --simulator.");
        }
        const auto indices = device_indices(options, devices.size());
        std::size_t completed = 0;
        std::optional<std::size_t> completed_index;
        for (const auto index : indices) {
            const auto& device = devices[index];
            if (has(options, "pa")) {
                if (has(options, "padevid") && parse_unsigned(value(options, "padevid")) != device.device_id) continue;
                if (has(options, "pasvid") && parse_unsigned(value(options, "pasvid")) != device.subsystem_vendor_id) continue;
                if (has(options, "passid") && parse_unsigned(value(options, "passid")) != device.subsystem_device_id) continue;
            }
            const auto result = flashamd::flash_image(*backend, index, *image, *info, flash_policy(options));
            std::cout << "Flashed device " << device.bdf << ": " << result.bytes_written
                      << " bytes, " << result.attempts << " attempt(s), readback verification "
                      << (result.verified ? "passed" : "failed") << '\n';
            ++completed;
            completed_index = index;
        }
        if (completed == 0) std::cout << "No devices matched the bulk flash filters.\n";
        if (has(options, "save-flashed-bytes") && completed == 1 && completed_index) {
            const auto readback = backend->read_rom(*completed_index);
            write_file(path->string() + ".flashed", readback);
        }
    }
    if (has(options, "set-quad-mode")) {
        if (!backend->supports_firmware_writes()) throw std::runtime_error("Quad mode changes require a PSP command and are unavailable through the read-only Linux backend");
        std::cout << "Quad mode request acknowledged by simulator; no physical device was changed.\n";
    }
    if (has(options, "close")) std::cout << "Session log closed.\n";
    if (has(options, "flush")) std::cout << "Session log flushed.\n";
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    try {
        return run(argc, argv);
    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }
}
