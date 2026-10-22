#include "flashamd/core.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cctype>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <system_error>

#ifdef __linux__
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace flashamd {
namespace {

std::string trim(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

std::uint64_t parse_number(std::string_view text) {
    std::string value(text);
    int base = 10;
    if (value.size() > 2 && value[0] == '0' && (value[1] == 'x' || value[1] == 'X')) {
        value.erase(0, 2);
        base = 16;
    }
    std::uint64_t out{};
    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), out, base);
    if (error != std::errc{} || end != value.data() + value.size()) {
        throw std::runtime_error("Invalid number: " + std::string(text));
    }
    return out;
}

std::uint16_t u16(std::span<const std::uint8_t> bytes, std::size_t offset) {
    if (offset + 2 > bytes.size()) return 0;
    return static_cast<std::uint16_t>(bytes[offset]) |
           static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[offset + 1]) << 8U);
}

bool contains(std::span<const std::uint8_t> bytes, std::string_view needle) {
    return std::search(bytes.begin(), bytes.end(), needle.begin(), needle.end()) != bytes.end();
}

const AsicDefinition* definition_for(const std::vector<AsicDefinition>& catalog, std::uint16_t id) {
    for (const auto& definition : catalog) {
        if (std::find(definition.device_ids.begin(), definition.device_ids.end(), id) != definition.device_ids.end()) {
            return &definition;
        }
    }
    return nullptr;
}

std::vector<std::uint8_t> synthetic_rom(const PciDevice& device) {
    constexpr std::size_t image_size = 512;
    std::vector<std::uint8_t> rom(device.rom_size, 0xffU);
    if (rom.size() < image_size) return rom;
    rom[0] = 0x55U;
    rom[1] = 0xaaU;
    rom[2] = 1U;
    rom[0x18] = 0x20U;
    rom[0x19] = 0U;
    constexpr std::size_t pcir = 0x20;
    rom[pcir] = 'P'; rom[pcir + 1] = 'C'; rom[pcir + 2] = 'I'; rom[pcir + 3] = 'R';
    const auto put_u16 = [&rom](std::size_t offset, std::uint16_t value) {
        rom[offset] = static_cast<std::uint8_t>(value & 0xffU);
        rom[offset + 1U] = static_cast<std::uint8_t>(value >> 8U);
    };
    rom[pcir + 4] = 0x02U; rom[pcir + 5] = 0x10U;
    rom[pcir + 6] = static_cast<std::uint8_t>(device.device_id & 0xffU);
    rom[pcir + 7] = static_cast<std::uint8_t>(device.device_id >> 8U);
    put_u16(pcir + 0x08U, 0U);
    put_u16(pcir + 0x0aU, 0x18U);
    rom[pcir + 0x0cU] = 3U;
    rom[pcir + 0x0dU] = 0U;
    rom[pcir + 0x0eU] = 0U;
    rom[pcir + 0x0fU] = 0U;
    rom[pcir + 0x10] = 1U;
    rom[pcir + 0x11] = 0U;
    rom[pcir + 0x12] = 0U;
    rom[pcir + 0x13] = 0U;
    rom[pcir + 0x14] = 0U;
    rom[pcir + 0x15] = 0x80U;
    rom[pcir + 0x16] = 0x1cU;
    rom[pcir + 0x17] = 0U;
    constexpr std::size_t atom_header = 0x80U;
    put_u16(0x48U, static_cast<std::uint16_t>(atom_header));
    std::fill(rom.begin() + static_cast<std::ptrdiff_t>(atom_header),
              rom.begin() + static_cast<std::ptrdiff_t>(atom_header + 0x1cU), 0U);
    put_u16(atom_header, 0x1cU);
    rom[atom_header + 2U] = 2U;
    rom[atom_header + 3U] = 2U;
    rom[atom_header + 4U] = 'A';
    rom[atom_header + 5U] = 'T';
    rom[atom_header + 6U] = 'O';
    rom[atom_header + 7U] = 'M';
    put_u16(atom_header + 0x18U, device.subsystem_vendor_id);
    put_u16(atom_header + 0x1aU, device.subsystem_device_id);
    unsigned sum = 0;
    for (std::size_t i = 0; i < image_size; ++i) sum += rom[i];
    rom[image_size - 1] = static_cast<std::uint8_t>(rom[image_size - 1] - (sum & 0xffU));
    return rom;
}

void write_enable(const std::filesystem::path& path, bool enabled) {
    std::ofstream out(path);
    if (!out) throw std::runtime_error("Cannot change PCI ROM read state at " + path.string() +
                                       "; run as root or use the device's sysfs permissions.");
    out << (enabled ? "1\n" : "0\n");
    out.flush();
    if (!out) throw std::runtime_error("Failed to change PCI ROM read state at " + path.string());
}

struct RomReadGuard {
    std::filesystem::path path;
    ~RomReadGuard() {
        try { write_enable(path, false); } catch (...) { }
    }
};

#ifdef __linux__
bool probe_devmem_read_only(const std::filesystem::path& device_path) {
    std::ifstream resource(device_path / "resource");
    std::string first_line;
    if (!resource || !std::getline(resource, first_line)) return false;
    std::istringstream values(first_line);
    std::uint64_t start{}, end{}, flags{};
    values >> std::hex >> start >> end >> flags;
    if (!values || start == 0 || end < start || (flags & 0x200U) == 0U) return false;
    const long page_size_long = ::sysconf(_SC_PAGESIZE);
    if (page_size_long <= 0) return false;
    const auto page_size = static_cast<std::uint64_t>(page_size_long);
    const std::uint64_t aligned = start - (start % page_size);
    const std::size_t delta = static_cast<std::size_t>(start - aligned);
    const int fd = ::open("/dev/mem", O_RDONLY | O_SYNC | O_CLOEXEC);
    if (fd < 0) return false;
    void* mapping = ::mmap(nullptr, delta + sizeof(std::uint32_t), PROT_READ, MAP_SHARED,
                           fd, static_cast<off_t>(aligned));
    ::close(fd);
    if (mapping == MAP_FAILED) return false;
    volatile const std::uint32_t value = *reinterpret_cast<volatile const std::uint32_t*>(
        static_cast<const std::uint8_t*>(mapping) + delta);
    (void)value;
    const bool unmapped = ::munmap(mapping, delta + sizeof(std::uint32_t)) == 0;
    return unmapped;
}
#endif

constexpr std::array<std::uint32_t, 64> sha_k = {
    0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
    0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
    0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
    0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
    0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
    0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
    0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
    0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
};

std::uint32_t rotate_right(std::uint32_t x, unsigned count) {
    return (x >> count) | (x << (32U - count));
}

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

} // namespace

std::filesystem::path data_directory(const char* argv0) {
    if (const char* explicit_path = std::getenv("AMDVBFLASH_DATA_DIR")) {
        if (*explicit_path != '\0') return explicit_path;
    }
    std::filesystem::path executable_path;
#ifdef __linux__
    std::error_code link_error;
    executable_path = std::filesystem::read_symlink("/proc/self/exe", link_error);
    if (link_error) executable_path.clear();
#endif
    if (executable_path.empty()) {
        const std::filesystem::path argument(argv0 == nullptr ? "amdvbflash" : argv0);
        if (argument.has_parent_path()) {
            executable_path = std::filesystem::absolute(argument);
        } else if (const char* path_value = std::getenv("PATH")) {
            const std::string_view search_path(path_value);
            std::size_t begin = 0;
            while (begin <= search_path.size()) {
                const auto end = search_path.find(':', begin);
                const auto component = search_path.substr(begin,
                    end == std::string_view::npos ? search_path.size() - begin : end - begin);
                const auto directory = component.empty() ? std::filesystem::current_path()
                                                         : std::filesystem::path(component);
                const auto candidate = directory / argument;
                std::error_code file_error;
                if (std::filesystem::is_regular_file(candidate, file_error) && !file_error) {
                    executable_path = std::filesystem::absolute(candidate);
                    break;
                }
                if (end == std::string_view::npos) break;
                begin = end + 1U;
            }
        }
        if (executable_path.empty()) executable_path = std::filesystem::absolute(argument);
    }
    const auto executable = executable_path.parent_path();
    const auto installed = executable.parent_path() / "share" / "flash-amd";
    if (std::filesystem::exists(installed / "asic_devices.csv")) return installed;
#ifdef FLASHAMD_SOURCE_DATA_DIR
    return FLASHAMD_SOURCE_DATA_DIR;
#else
    return "data";
#endif
}

std::vector<AsicDefinition> load_asic_catalog(const std::filesystem::path& path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("Cannot open ASIC catalog: " + path.string());
    std::string line;
    if (!std::getline(in, line)) throw std::runtime_error("ASIC catalog is empty: " + path.string());
    std::vector<AsicDefinition> catalog;
    while (std::getline(in, line)) {
        if (trim(line).empty()) continue;
        std::array<std::string, 5> columns;
        std::size_t start = 0;
        for (std::size_t i = 0; i < 4; ++i) {
            const auto comma = line.find(',', start);
            if (comma == std::string::npos) throw std::runtime_error("Malformed ASIC catalog row");
            columns[i] = trim(line.substr(start, comma - start));
            start = comma + 1;
        }
        columns[4] = trim(line.substr(start));
        AsicDefinition definition;
        definition.family = columns[0];
        definition.name = columns[1];
        definition.rom_type = columns[2];
        const auto rom_size = parse_number(columns[3]);
        if (rom_size > std::numeric_limits<std::uint32_t>::max()) throw std::runtime_error("ASIC ROM size is out of range");
        definition.rom_size = static_cast<std::uint32_t>(rom_size);
        std::istringstream ids(columns[4]);
        std::string id;
        while (std::getline(ids, id, ';')) {
            const auto parsed = parse_number(trim(id));
            if (parsed > 0xffffU) throw std::runtime_error("ASIC PCI device ID is out of range");
            definition.device_ids.push_back(static_cast<std::uint16_t>(parsed));
        }
        if (definition.device_ids.empty()) throw std::runtime_error("ASIC catalog row has no PCI IDs");
        catalog.push_back(std::move(definition));
    }
    return catalog;
}

ImageInfo inspect_image(std::span<const std::uint8_t> bytes) {
    ImageInfo result;
    result.file_size = bytes.size();
    result.has_rom_signature = bytes.size() >= 2 && bytes[0] == 0x55U && bytes[1] == 0xaaU;
    result.has_psp_marker = contains(bytes, "$PSP") || contains(bytes, "PSP$");
    result.checksum = checksum16(bytes);

    if (result.has_rom_signature) {
        const std::size_t header_size = bytes.size() >= 3U
            ? static_cast<std::size_t>(bytes[2]) * 512U : 0U;
        std::size_t pcir_image_size = 0U;
        const std::size_t pcir_offset = u16(bytes, 0x18);
        if (pcir_offset <= bytes.size() && bytes.size() - pcir_offset >= 0x0cU &&
            bytes[pcir_offset] == 'P' && bytes[pcir_offset + 1] == 'C' &&
            bytes[pcir_offset + 2] == 'I' && bytes[pcir_offset + 3] == 'R') {
            const auto pcir_length = static_cast<std::size_t>(u16(bytes, pcir_offset + 0x0a));
            if (pcir_length >= 0x16U && pcir_length <= bytes.size() - pcir_offset) {
                result.has_pcir = true;
                result.vendor_id = u16(bytes, pcir_offset + 4);
                result.device_id = u16(bytes, pcir_offset + 6);
                pcir_image_size = static_cast<std::size_t>(u16(bytes, pcir_offset + 0x10)) * 512U;
                if (bytes[pcir_offset + 0x14U] == 0U) {
                    result.checksum_size = header_size;
                    result.image_checksum_size = pcir_image_size;
                    result.checksum_applicable = header_size != 0U || pcir_image_size != 0U;
                    result.declared_size = static_cast<std::uint32_t>(
                        std::max(header_size, pcir_image_size));
                } else {
                    result.declared_size = static_cast<std::uint32_t>(
                        pcir_image_size == 0U ? header_size : pcir_image_size);
                }
            }
        } else {
            result.declared_size = static_cast<std::uint32_t>(header_size);
        }
        if (!result.has_pcir && header_size != 0U) {
            result.checksum_size = header_size;
            result.checksum_applicable = true;
        }
        const auto scope_checksum_ok = [&bytes](std::size_t size) {
            return size != 0U && size <= bytes.size() &&
                std::accumulate(bytes.begin(),
                    bytes.begin() + static_cast<std::ptrdiff_t>(size), 0U,
                    [](unsigned value, std::uint8_t byte) { return (value + byte) & 0xffU; }) == 0U;
        };
        if (result.checksum_applicable) {
            result.checksum_ok = (result.checksum_size == 0U || scope_checksum_ok(result.checksum_size)) &&
                (result.image_checksum_size == 0U || scope_checksum_ok(result.image_checksum_size));
        }
    }
    const std::size_t scan_size = std::min<std::size_t>(bytes.size(), 1024U * 1024U);
    const auto scan_begin = bytes.begin();
    const auto scan_end = scan_begin + static_cast<std::ptrdiff_t>(scan_size);
    const auto atom = std::search(scan_begin, scan_end, "ATOM", "ATOM" + 4);
    result.has_atom = atom != scan_end;
    if (result.has_rom_signature && bytes.size() >= 0x4aU) {
        const std::size_t atom_header = u16(bytes, 0x48);
        if (atom_header <= bytes.size() && bytes.size() - atom_header >= 0x1cU &&
            bytes[atom_header + 4] == 'A' && bytes[atom_header + 5] == 'T' &&
            bytes[atom_header + 6] == 'O' && bytes[atom_header + 7] == 'M') {
            const std::size_t structure_size = u16(bytes, atom_header);
            if (structure_size >= 0x1cU && structure_size <= bytes.size() - atom_header) {
                result.subsystem_vendor_id = u16(bytes, atom_header + 0x18U);
                result.subsystem_device_id = u16(bytes, atom_header + 0x1aU);
                std::ostringstream version;
                version << static_cast<unsigned>(bytes[atom_header + 2U]) << '.'
                        << static_cast<unsigned>(bytes[atom_header + 3U]);
                result.atom_version = version.str();
            }
        }
    }
    return result;
}

std::uint16_t checksum16(std::span<const std::uint8_t> bytes) {
    std::uint32_t sum = 0;
    for (const auto byte : bytes) sum = (sum + byte) & 0xffffU;
    return static_cast<std::uint16_t>(sum);
}

std::string sha256(std::span<const std::uint8_t> bytes) {
    std::array<std::uint32_t, 8> hash = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
    };
    std::vector<std::uint8_t> message(bytes.begin(), bytes.end());
    const std::uint64_t bit_length = static_cast<std::uint64_t>(message.size()) * 8ULL;
    message.push_back(0x80U);
    while ((message.size() % 64U) != 56U) message.push_back(0U);
    for (int shift = 56; shift >= 0; shift -= 8) {
        message.push_back(static_cast<std::uint8_t>((bit_length >> static_cast<unsigned>(shift)) & 0xffULL));
    }
    for (std::size_t block = 0; block < message.size(); block += 64U) {
        std::array<std::uint32_t, 64> words{};
        for (std::size_t i = 0; i < 16; ++i) {
            const std::size_t p = block + i * 4U;
            words[i] = (static_cast<std::uint32_t>(message[p]) << 24U) |
                       (static_cast<std::uint32_t>(message[p + 1]) << 16U) |
                       (static_cast<std::uint32_t>(message[p + 2]) << 8U) |
                        static_cast<std::uint32_t>(message[p + 3]);
        }
        for (std::size_t i = 16; i < words.size(); ++i) {
            const auto s0 = rotate_right(words[i - 15], 7) ^ rotate_right(words[i - 15], 18) ^ (words[i - 15] >> 3U);
            const auto s1 = rotate_right(words[i - 2], 17) ^ rotate_right(words[i - 2], 19) ^ (words[i - 2] >> 10U);
            words[i] = words[i - 16] + s0 + words[i - 7] + s1;
        }
        auto a = hash[0]; auto b = hash[1]; auto c = hash[2]; auto d = hash[3];
        auto e = hash[4]; auto f = hash[5]; auto g = hash[6]; auto h = hash[7];
        for (std::size_t i = 0; i < words.size(); ++i) {
            const auto s1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
            const auto choice = (e & f) ^ ((~e) & g);
            const auto temp1 = h + s1 + choice + sha_k[i] + words[i];
            const auto s0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
            const auto majority = (a & b) ^ (a & c) ^ (b & c);
            const auto temp2 = s0 + majority;
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;
        }
        hash[0] += a; hash[1] += b; hash[2] += c; hash[3] += d;
        hash[4] += e; hash[5] += f; hash[6] += g; hash[7] += h;
    }
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (const auto word : hash) output << std::setw(8) << word;
    return output.str();
}

std::string hex_id(std::uint16_t value) {
    std::ostringstream output;
    output << "0x" << std::uppercase << std::hex << std::setw(4) << std::setfill('0') << value;
    return output.str();
}

SimulatorBackend::SimulatorBackend(std::vector<AsicDefinition> catalog) {
    std::size_t n = 0;
    for (const auto& definition : catalog) {
        if (definition.rom_size == 0U || definition.rom_size > 64U * 1024U * 1024U) continue;
        PciDevice device;
        device.index = n;
        std::ostringstream bdf;
        bdf << "0000:" << std::hex << std::setw(2) << std::setfill('0') << (n + 1U)
            << ":00.0";
        device.bdf = bdf.str();
        device.vendor_id = 0x1002U;
        device.device_id = definition.family == "AMD_NAVI48" &&
                           std::find(definition.device_ids.begin(), definition.device_ids.end(), 0x7550U) != definition.device_ids.end()
                               ? 0x7550U : definition.device_ids.front();
        device.subsystem_vendor_id = 0x1002U;
        device.subsystem_device_id = static_cast<std::uint16_t>(0x0001U + n);
        device.revision_id = 1U;
        device.family = definition.family;
        device.name = definition.name;
        device.rom_size = definition.rom_size;
        device.supported_device_ids = definition.device_ids;
        devices_.push_back({device, synthetic_rom(device)});
        ++n;
    }
}

std::vector<PciDevice> SimulatorBackend::enumerate() {
    std::vector<PciDevice> result;
    result.reserve(devices_.size());
    for (const auto& entry : devices_) result.push_back(entry.info);
    return result;
}

std::vector<std::uint8_t> SimulatorBackend::read_rom(std::size_t index) {
    if (index >= devices_.size()) throw std::runtime_error("Device index is out of range");
    return devices_[index].rom;
}

void SimulatorBackend::erase_rom(std::size_t index, std::size_t offset, std::size_t size) {
    if (erase_failures_remaining_ > 0U) {
        --erase_failures_remaining_;
        throw std::runtime_error("simulated transient erase failure");
    }
    if (index >= devices_.size()) throw std::runtime_error("Device index is out of range");
    auto& rom = devices_[index].rom;
    if (offset > rom.size() || size > rom.size() - offset) throw std::runtime_error("Erase range exceeds ROM size");
    std::fill(rom.begin() + static_cast<std::ptrdiff_t>(offset),
              rom.begin() + static_cast<std::ptrdiff_t>(offset + size), 0xffU);
}

void SimulatorBackend::program_rom(std::size_t index, std::size_t offset,
                                   std::span<const std::uint8_t> bytes) {
    if (index >= devices_.size()) throw std::runtime_error("Device index is out of range");
    auto& rom = devices_[index].rom;
    if (offset > rom.size() || bytes.size() > rom.size() - offset) throw std::runtime_error("Program range exceeds ROM size");
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if ((static_cast<unsigned>(~rom[offset + i]) & bytes[i]) != 0U) {
            throw std::runtime_error("SPI ROM programming attempted a zero-to-one bit transition without erase");
        }
        rom[offset + i] = static_cast<std::uint8_t>(rom[offset + i] & bytes[i]);
    }
}

LinuxBackend::LinuxBackend(std::vector<AsicDefinition> catalog, std::string mechanism)
    : catalog_(std::move(catalog)), mechanism_(lower(std::move(mechanism))) {
    mechanism_.erase(std::remove_if(mechanism_.begin(), mechanism_.end(), [](unsigned char c) {
        return std::isspace(c) != 0;
    }), mechanism_.end());
    if (mechanism_ != "sysfs" && mechanism_ != "devmem" && mechanism_ != "devmem,sysfs" &&
        mechanism_ != "sysfs,devmem") {
        throw std::runtime_error("Linux supports --hw-access-mechanism=sysfs, devmem, or devmem,sysfs; the Windows driver mode is unavailable");
    }
}

std::vector<PciDevice> LinuxBackend::enumerate() {
    if (enumerated_) return devices_;
    enumerated_ = true;
#ifdef __linux__
    const std::filesystem::path root("/sys/bus/pci/devices");
    if (!std::filesystem::exists(root)) return {};
    std::vector<std::filesystem::path> paths;
    for (const auto& entry : std::filesystem::directory_iterator(root)) paths.push_back(entry.path());
    std::sort(paths.begin(), paths.end());
    const auto read_attr = [](const std::filesystem::path& path) -> std::string {
        std::ifstream in(path);
        std::string value;
        if (in) in >> value;
        return value;
    };
    for (const auto& path : paths) {
        try {
            const auto vendor = static_cast<std::uint16_t>(parse_number(read_attr(path / "vendor")));
            if (vendor != 0x1002U) continue;
            const auto class_code = parse_number(read_attr(path / "class"));
            if ((class_code >> 16U) != 0x03U) continue;
            const auto id = static_cast<std::uint16_t>(parse_number(read_attr(path / "device")));
            const auto* definition = definition_for(catalog_, id);
            PciDevice device;
            device.index = devices_.size();
            device.bdf = path.filename().string();
            device.vendor_id = vendor;
            device.device_id = id;
            device.subsystem_vendor_id = static_cast<std::uint16_t>(parse_number(read_attr(path / "subsystem_vendor")));
            device.subsystem_device_id = static_cast<std::uint16_t>(parse_number(read_attr(path / "subsystem_device")));
            device.revision_id = static_cast<std::uint8_t>(parse_number(read_attr(path / "revision")));
            device.family = definition == nullptr ? "UNKNOWN" : definition->family;
            device.name = definition == nullptr ? "Unknown AMD device" : definition->name;
            device.rom_size = definition == nullptr ? 0U : definition->rom_size;
            device.supported_device_ids = definition == nullptr ? std::vector<std::uint16_t>{id} : definition->device_ids;
            devices_.push_back(std::move(device));
        } catch (const std::exception&) {
            continue;
        }
    }
#else
    (void)catalog_;
#endif
    return devices_;
}

std::vector<std::uint8_t> LinuxBackend::read_rom(std::size_t index) {
    auto devices = enumerate();
    if (index >= devices.size()) throw std::runtime_error("Device index is out of range");
#ifdef __linux__
    const auto path = std::filesystem::path("/sys/bus/pci/devices") / devices[index].bdf;
    if (mechanism_.find("devmem") != std::string::npos) {
        // Verify that /dev/mem access, when requested, is a read-only BAR mapping. ROM data
        // still comes from the kernel's explicit PCI ROM attribute, which has clear bounds.
        (void)probe_devmem_read_only(path);
    }
    const auto rom_path = path / "rom";
    write_enable(rom_path, true);
    RomReadGuard guard{rom_path};
    std::ifstream in(rom_path, std::ios::binary);
    if (!in) throw std::runtime_error("Cannot read " + rom_path.string() +
                                      "; check permissions and whether the kernel driver permits ROM access.");
    std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (bytes.empty()) throw std::runtime_error("PCI ROM read returned no data for " + devices[index].bdf);
    return bytes;
#else
    (void)index;
    throw std::runtime_error("Linux PCI ROM access is unavailable on this platform");
#endif
}

void LinuxBackend::erase_rom(std::size_t, std::size_t, std::size_t) {
    throw std::runtime_error("Linux hardware firmware writes are disabled; use --simulator to exercise flash flows");
}

void LinuxBackend::program_rom(std::size_t, std::size_t, std::span<const std::uint8_t>) {
    throw std::runtime_error("Linux hardware firmware writes are disabled; use --simulator to exercise flash flows");
}

std::unique_ptr<DeviceBackend> make_backend(bool simulator,
                                            std::vector<AsicDefinition> catalog,
                                            std::string mechanism) {
    if (simulator) return std::make_unique<SimulatorBackend>(std::move(catalog));
    return std::make_unique<LinuxBackend>(std::move(catalog), std::move(mechanism));
}

FlashResult flash_image(DeviceBackend& backend, std::size_t index,
                        std::span<const std::uint8_t> image,
                        const ImageInfo& image_info,
                        const FlashPolicy& policy) {
    if (!backend.supports_firmware_writes()) {
        throw std::runtime_error("Linux hardware firmware writes are disabled; use --simulator to exercise flash flows");
    }
    if (!image_info.has_rom_signature || !image_info.has_pcir) {
        throw std::runtime_error("Input image is not a valid PCI option ROM (missing 55 AA or PCIR signature)");
    }
    if (image.empty()) throw std::runtime_error("Input image is empty");
    if (image_info.declared_size != 0U && image_info.declared_size > image.size()) {
        throw std::runtime_error("Input image is truncated: declared option ROM size exceeds the file size");
    }
    if (image_info.checksum_applicable && !image_info.checksum_ok) {
        throw std::runtime_error("Input image has an invalid option ROM 8-bit checksum");
    }
    const auto devices = backend.enumerate();
    if (index >= devices.size()) throw std::runtime_error("Device index is out of range");
    const auto& device = devices[index];
    if (image_info.vendor_id != 0x1002U) {
        throw std::runtime_error("Input image vendor ID " + hex_id(image_info.vendor_id) + " is not AMD");
    }
    if (std::find(device.supported_device_ids.begin(), device.supported_device_ids.end(), image_info.device_id) == device.supported_device_ids.end()) {
        throw std::runtime_error("Input image device ID " + hex_id(image_info.device_id) +
                                 " does not match ASIC family " + device.name);
    }
    const bool has_subsystem = image_info.subsystem_vendor_id != 0U || image_info.subsystem_device_id != 0U;
    if (has_subsystem && !policy.skip_ssid_check &&
        (image_info.subsystem_vendor_id != device.subsystem_vendor_id ||
         image_info.subsystem_device_id != device.subsystem_device_id)) {
        throw std::runtime_error("Input image subsystem IDs do not match the selected device; use --skip-ssid-check only for a known compatible image");
    }
    const auto rom = backend.read_rom(index);
    if (image.size() > rom.size()) throw std::runtime_error("Input image is larger than the device ROM");
    const std::size_t half = rom.size() / 2U;
    if (policy.both_partitions && image.size() > half) {
        throw std::runtime_error("Image is too large to fit in both simulated partitions");
    }
    if (!policy.force_same && rom.size() >= image.size() &&
        std::equal(image.begin(), image.end(), rom.begin())) {
        throw std::runtime_error("Same IFWI image already flashed. Use --fa to force flash the same image.");
    }

    constexpr std::size_t erase_block = 4096U;
    constexpr std::size_t page_size = 256U;
    const std::array<std::size_t, 2> starts = {0U, half};
    const unsigned max_attempts = 3U;
    FlashResult result;
    std::string last_error;
    for (unsigned attempt = 1; attempt <= max_attempts; ++attempt) {
        try {
            for (unsigned partition = 0; partition < (policy.both_partitions ? 2U : 1U); ++partition) {
                const std::size_t start = starts[partition];
                const std::size_t erase_size = ((image.size() + erase_block - 1U) / erase_block) * erase_block;
                if (start + erase_size > rom.size()) throw std::runtime_error("Flash erase range exceeds ROM capacity");
                backend.erase_rom(index, start, erase_size);
                for (std::size_t offset = 0; offset < image.size(); offset += page_size) {
                    const std::size_t count = std::min(page_size, image.size() - offset);
                    backend.program_rom(index, start + offset, image.subspan(offset, count));
                }
            }
            const auto verification = backend.read_rom(index);
            bool matches = std::equal(image.begin(), image.end(), verification.begin());
            if (policy.both_partitions) {
                matches = matches && std::equal(image.begin(), image.end(), verification.begin() + static_cast<std::ptrdiff_t>(half));
            }
            result.attempts = attempt;
            if (matches) {
                result.bytes_written = image.size() * (policy.both_partitions ? 2U : 1U);
                result.verified = true;
                return result;
            }
            last_error = "readback did not match the programmed image";
        } catch (const std::exception& error) {
            result.attempts = attempt;
            last_error = error.what();
        }
    }
    throw std::runtime_error("SPI ROM write/verification failed after 3 attempts: " + last_error);
}

} // namespace flashamd
