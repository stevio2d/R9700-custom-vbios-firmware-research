#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace flashamd {

struct AsicDefinition {
    std::string family;
    std::string name;
    std::string rom_type;
    std::uint32_t rom_size{};
    std::vector<std::uint16_t> device_ids;
};

struct PciDevice {
    std::size_t index{};
    std::string bdf;
    std::uint16_t vendor_id{};
    std::uint16_t device_id{};
    std::uint16_t subsystem_vendor_id{};
    std::uint16_t subsystem_device_id{};
    std::uint8_t revision_id{};
    std::string family;
    std::string name;
    std::uint32_t rom_size{};
    std::vector<std::uint16_t> supported_device_ids;
};

struct ImageInfo {
    std::size_t file_size{};
    std::uint32_t declared_size{};
    std::size_t checksum_size{};
    std::size_t image_checksum_size{};
    bool has_rom_signature{};
    bool has_pcir{};
    bool has_atom{};
    bool has_psp_marker{};
    bool checksum_applicable{};
    bool checksum_ok{};
    std::uint16_t checksum{};
    std::uint16_t vendor_id{};
    std::uint16_t device_id{};
    std::uint16_t subsystem_vendor_id{};
    std::uint16_t subsystem_device_id{};
    std::string atom_version;
};

struct FlashPolicy {
    bool force_same{};
    bool force_part_number{};
    bool force_version{};
    bool skip_ssid_check{};
    bool both_partitions{};
    bool force_recovery_path{};
};

struct FlashResult {
    std::size_t bytes_written{};
    unsigned attempts{};
    bool verified{};
};

std::filesystem::path data_directory(const char* argv0);
std::vector<AsicDefinition> load_asic_catalog(const std::filesystem::path& path);
ImageInfo inspect_image(std::span<const std::uint8_t> bytes);
std::uint16_t checksum16(std::span<const std::uint8_t> bytes);
std::string sha256(std::span<const std::uint8_t> bytes);
std::string hex_id(std::uint16_t value);

class DeviceBackend {
public:
    virtual ~DeviceBackend() = default;
    virtual std::vector<PciDevice> enumerate() = 0;
    virtual std::vector<std::uint8_t> read_rom(std::size_t index) = 0;
    virtual bool supports_firmware_writes() const = 0;
    virtual void erase_rom(std::size_t index, std::size_t offset, std::size_t size) = 0;
    virtual void program_rom(std::size_t index, std::size_t offset,
                             std::span<const std::uint8_t> bytes) = 0;
};

class SimulatorBackend final : public DeviceBackend {
public:
    explicit SimulatorBackend(std::vector<AsicDefinition> catalog);
    std::vector<PciDevice> enumerate() override;
    std::vector<std::uint8_t> read_rom(std::size_t index) override;
    bool supports_firmware_writes() const override { return true; }
    void erase_rom(std::size_t index, std::size_t offset, std::size_t size) override;
    void program_rom(std::size_t index, std::size_t offset,
                     std::span<const std::uint8_t> bytes) override;
    void fail_next_erase_operations(unsigned count) { erase_failures_remaining_ = count; }
private:
    struct Entry {
        PciDevice info;
        std::vector<std::uint8_t> rom;
    };
    std::vector<Entry> devices_;
    unsigned erase_failures_remaining_{};
};

class LinuxBackend final : public DeviceBackend {
public:
    explicit LinuxBackend(std::vector<AsicDefinition> catalog, std::string mechanism);
    std::vector<PciDevice> enumerate() override;
    std::vector<std::uint8_t> read_rom(std::size_t index) override;
    bool supports_firmware_writes() const override { return false; }
    void erase_rom(std::size_t index, std::size_t offset, std::size_t size) override;
    void program_rom(std::size_t index, std::size_t offset,
                     std::span<const std::uint8_t> bytes) override;
private:
    std::vector<AsicDefinition> catalog_;
    std::string mechanism_;
    std::vector<PciDevice> devices_;
    bool enumerated_{};
};

std::unique_ptr<DeviceBackend> make_backend(bool simulator,
                                            std::vector<AsicDefinition> catalog,
                                            std::string mechanism);
FlashResult flash_image(DeviceBackend& backend, std::size_t index,
                        std::span<const std::uint8_t> image,
                        const ImageInfo& image_info,
                        const FlashPolicy& policy);

} // namespace flashamd
