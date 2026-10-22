#include "flashamd/core.hpp"
#include "flashamd/navi48_spi.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

std::vector<std::uint8_t> sample_image(std::uint16_t device_id,
                                       std::uint16_t subsystem_vendor = 0,
                                       std::uint16_t subsystem_device = 0,
                                       std::uint8_t code_type = 0U) {
    std::vector<std::uint8_t> image(512U, 0U);
    image[0] = 0x55U;
    image[1] = 0xaaU;
    image[2] = 1U;
    image[0x18] = 0x20U;
    constexpr std::size_t pcir = 0x20U;
    image[pcir] = 'P'; image[pcir + 1] = 'C'; image[pcir + 2] = 'I'; image[pcir + 3] = 'R';
    image[pcir + 4] = 0x02U; image[pcir + 5] = 0x10U;
    image[pcir + 6] = static_cast<std::uint8_t>(device_id & 0xffU);
    image[pcir + 7] = static_cast<std::uint8_t>(device_id >> 8U);
    image[pcir + 0x0a] = 0x18U;
    image[pcir + 0x0b] = 0x00U;
    image[pcir + 0x10] = 1U;
    image[pcir + 0x14] = code_type;
    image[pcir + 0x15] = 0x80U;
    image[pcir + 0x16] = 0x1cU;
    image[pcir + 0x1c] = 0xaaU;
    image[pcir + 0x1d] = 0xaaU;
    image[pcir + 0x1e] = 0xbbU;
    image[pcir + 0x1f] = 0xbbU;
    constexpr std::size_t atom = 0x80U;
    image[0x48] = static_cast<std::uint8_t>(atom & 0xffU);
    image[0x49] = static_cast<std::uint8_t>(atom >> 8U);
    image[atom] = 0x1cU;
    image[atom + 1U] = 0x00U;
    image[atom + 2U] = 2U;
    image[atom + 3U] = 2U;
    image[atom + 4U] = 'A'; image[atom + 5U] = 'T'; image[atom + 6U] = 'O'; image[atom + 7U] = 'M';
    image[atom + 0x18U] = static_cast<std::uint8_t>(subsystem_vendor & 0xffU);
    image[atom + 0x19U] = static_cast<std::uint8_t>(subsystem_vendor >> 8U);
    image[atom + 0x1aU] = static_cast<std::uint8_t>(subsystem_device & 0xffU);
    image[atom + 0x1bU] = static_cast<std::uint8_t>(subsystem_device >> 8U);
    unsigned sum = 0;
    for (const auto byte : image) sum = (sum + byte) & 0xffU;
    image.back() = static_cast<std::uint8_t>(image.back() - sum);
    return image;
}

} // namespace

int main() {
    try {
        const auto catalog = flashamd::load_asic_catalog(
            std::filesystem::path(FLASHAMD_TEST_DATA_DIR) / "asic_devices.csv");
        require(catalog.size() == 18U, "catalog should contain all 18 embedded ASIC configurations");
        const auto navi48 = std::find_if(catalog.begin(), catalog.end(), [](const auto& item) {
            return item.family == "AMD_NAVI48";
        });
        require(navi48 != catalog.end(), "Navi48 should be in the catalog");
        require(navi48->rom_size == 0x200000U, "Navi48 ROM size should match the embedded configuration");
        require(std::find(navi48->device_ids.begin(), navi48->device_ids.end(), 0x7550U) != navi48->device_ids.end(),
                "Navi48 should include the Radeon AI PRO R9700 device family ID");

        flashamd::PciDevice supported_navi48;
        supported_navi48.vendor_id = 0x1002U;
        supported_navi48.device_id = 0x7551U;
        supported_navi48.revision_id = 0xC0U;
        supported_navi48.family = "AMD_NAVI48";
        supported_navi48.rom_size = 0x200000U;
        require(flashamd::supports_navi48_spi_rom(supported_navi48),
                "known Navi48 R9700 revisions should be enabled for raw SPI backup");
        supported_navi48.revision_id = 0x00U;
        require(!flashamd::supports_navi48_spi_rom(supported_navi48),
                "unknown Navi48 revisions should fail closed for raw SPI backup");

        const std::string abc = "abc";
        const auto abc_bytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(abc.data()), abc.size());
        require(flashamd::sha256(abc_bytes) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                "SHA256 should match the standard abc test vector");
        require(flashamd::checksum16(std::array<std::uint8_t, 3>{1U, 2U, 3U}) == 6U,
                "16-bit checksum should sum bytes modulo 65536");

        const auto image = sample_image(0x7310U);
        const auto image_info = flashamd::inspect_image(image);
        require(image_info.has_rom_signature, "sample image should have 55 AA option ROM signature");
        require(image_info.has_pcir, "sample image should have a PCIR header");
        require(image_info.has_atom, "sample image should have an ATOM signature");
        require(image_info.atom_version == "2.2", "ATOM table revision should come from the pointed header");
        require(image_info.checksum_applicable && image_info.checksum_size == 512U &&
                    image_info.image_checksum_size == 512U,
                "legacy initialization and PCIR image checksum scopes should be decoded");
        require(image_info.checksum_ok, "sample image checksum should be valid");
        require(image_info.device_id == 0x7310U, "PCIR device ID should be decoded little endian");
        require(image_info.subsystem_vendor_id == 0U && image_info.subsystem_device_id == 0U,
                "subsystem IDs should not be read from bytes beyond the standard PCIR structure");

        auto padded_image = image;
        padded_image.push_back(0xffU);
        const auto padded_info = flashamd::inspect_image(padded_image);
        require(padded_info.checksum_ok && padded_info.checksum_size == 512U &&
                    padded_info.image_checksum_size == 512U,
                "trailing file padding should not extend the legacy option ROM checksum scope");
        flashamd::SimulatorBackend padded_simulator(catalog);
        require(flashamd::flash_image(padded_simulator, 0U, padded_image, padded_info, {}).verified,
                "valid legacy image should remain flashable when unrelated trailing bytes are present");

        auto canceled_checksum_image = image;
        canceled_checksum_image[100U] ^= 0x01U;
        canceled_checksum_image.push_back(0xffU);
        const auto canceled_checksum_info = flashamd::inspect_image(canceled_checksum_image);
        require(!canceled_checksum_info.checksum_ok,
                "trailing bytes must not cancel corruption inside the declared ROM image");
        require(flashamd::checksum16(canceled_checksum_image) % 256U == 0U &&
                    flashamd::checksum16(canceled_checksum_image) == flashamd::checksum16(image) + 256U,
                "whole-file checksum should see trailing bytes that cancel the corrupt ROM byte");
        bool canceled_checksum_blocked = false;
        try {
            flashamd::SimulatorBackend cancel_simulator(catalog);
            (void)flashamd::flash_image(cancel_simulator, 0U, canceled_checksum_image,
                                        canceled_checksum_info, {});
        } catch (const std::runtime_error& error) {
            canceled_checksum_blocked = std::string(error.what()).find("checksum") != std::string::npos;
        }
        require(canceled_checksum_blocked,
                "checksum corruption inside the declared ROM image should be rejected before erase");

        auto split_scope_image = image;
        split_scope_image.resize(1024U, 0U);
        split_scope_image[0x30U] = 2U;
        split_scope_image[512U] = 0xfeU;
        split_scope_image[100U] ^= 0x01U;
        const auto split_scope_info = flashamd::inspect_image(split_scope_image);
        require(split_scope_info.checksum_size == 512U && split_scope_info.image_checksum_size == 1024U,
                "initialization and PCIR image checksum scopes should remain distinct");
        require(flashamd::checksum16(split_scope_image) % 256U == 0U && !split_scope_info.checksum_ok,
                "a valid whole-image sum must not mask a bad initialization-region sum");
        bool split_scope_blocked = false;
        try {
            flashamd::SimulatorBackend split_scope_simulator(catalog);
            (void)flashamd::flash_image(split_scope_simulator, 0U, split_scope_image,
                                        split_scope_info, {});
        } catch (const std::runtime_error& error) {
            split_scope_blocked = std::string(error.what()).find("checksum") != std::string::npos;
        }
        require(split_scope_blocked,
                "corruption in the initialization region should be rejected even if PCIR image sum is zero");

        auto efi_image = sample_image(0x7310U, 0U, 0U, 3U);
        efi_image[100U] ^= 0x01U;
        const auto efi_info = flashamd::inspect_image(efi_image);
        require(!efi_info.checksum_applicable && flashamd::checksum16(efi_image) % 256U == 1U,
                "EFI option ROM images should not be reported as having a legacy checksum");
        flashamd::SimulatorBackend efi_simulator(catalog);
        require(flashamd::flash_image(efi_simulator, 0U, efi_image, efi_info, {}).verified,
                "absence of a legacy checksum should not block an EFI image");

        flashamd::SimulatorBackend simulator(catalog);
        const auto devices = simulator.enumerate();
        require(devices.size() == 18U, "simulator should expose every embedded ASIC family");
        require(devices[10].family == "AMD_NAVI48", "simulator Navi48 index should remain stable");
        const auto simulated_rom_info = flashamd::inspect_image(simulator.read_rom(10U));
        require(simulated_rom_info.has_pcir && simulated_rom_info.declared_size == 512U,
                "simulator ROM should contain a valid PCIR structure and declared image size");
        require(simulated_rom_info.subsystem_vendor_id == devices[10].subsystem_vendor_id &&
                    simulated_rom_info.subsystem_device_id == devices[10].subsystem_device_id,
                "simulator ROM ATOM header should carry its device subsystem IDs");
        require(simulated_rom_info.checksum_ok, "simulator ROM should have a valid option ROM checksum");
        require(simulated_rom_info.checksum_applicable && simulated_rom_info.checksum_size == 512U &&
                    simulated_rom_info.image_checksum_size == 512U,
                "simulator ROM checksum should be scoped to its declared ROM image");
        const auto result = flashamd::flash_image(simulator, 0U, image, image_info, {});
        require(result.verified && result.attempts == 1U, "simulated flash should write and verify on the first try");
        const auto rom = simulator.read_rom(0U);
        require(std::equal(image.begin(), image.end(), rom.begin()), "simulated flash should preserve programmed bytes");
        bool repeated_blocked = false;
        try { (void)flashamd::flash_image(simulator, 0U, image, image_info, {}); }
        catch (const std::runtime_error&) { repeated_blocked = true; }
        require(repeated_blocked, "same image should require --fa");
        flashamd::FlashPolicy force_same;
        force_same.force_same = true;
        require(flashamd::flash_image(simulator, 0U, image, image_info, force_same).verified,
                "--fa policy should permit writing the same image");

        const auto wrong_family_image = sample_image(0x7360U);
        bool incompatible_image_blocked = false;
        try {
            (void)flashamd::flash_image(simulator, 0U, wrong_family_image,
                                        flashamd::inspect_image(wrong_family_image), {});
        } catch (const std::runtime_error&) { incompatible_image_blocked = true; }
        require(incompatible_image_blocked, "image for a different ASIC family should be rejected");

        auto truncated_image = image;
        truncated_image.resize(64U);
        bool truncated_image_blocked = false;
        try {
            (void)flashamd::flash_image(simulator, 0U, truncated_image,
                                        flashamd::inspect_image(truncated_image), {});
        } catch (const std::runtime_error& error) {
            truncated_image_blocked = std::string(error.what()).find("truncated") != std::string::npos;
        }
        require(truncated_image_blocked, "an image shorter than its declared ROM length should be rejected");

        auto oversized_header_image = image;
        oversized_header_image[2U] = 2U;
        const auto oversized_header_info = flashamd::inspect_image(oversized_header_image);
        require(oversized_header_info.declared_size == 1024U,
                "legacy ROM header size should be included when it exceeds the PCIR image length");
        bool oversized_header_blocked = false;
        try {
            (void)flashamd::flash_image(simulator, 0U, oversized_header_image,
                                        oversized_header_info, force_same);
        } catch (const std::runtime_error& error) {
            oversized_header_blocked = std::string(error.what()).find("truncated") != std::string::npos;
        }
        require(oversized_header_blocked,
                "a ROM header length larger than the file should be rejected as truncated");

        auto bad_checksum_image = image;
        bad_checksum_image[100U] ^= 0x01U;
        bool bad_checksum_blocked = false;
        try {
            (void)flashamd::flash_image(simulator, 0U, bad_checksum_image,
                                        flashamd::inspect_image(bad_checksum_image), force_same);
        } catch (const std::runtime_error& error) {
            bad_checksum_blocked = std::string(error.what()).find("checksum") != std::string::npos;
        }
        require(bad_checksum_blocked, "a corrupt option ROM checksum should be rejected before erase");

        flashamd::SimulatorBackend ssid_device(catalog);
        const auto mismatched_ssid_image = sample_image(0x7310U, 0x1002U, 0x9999U);
        const auto mismatched_ssid_info = flashamd::inspect_image(mismatched_ssid_image);
        require(mismatched_ssid_info.subsystem_vendor_id == 0x1002U &&
                    mismatched_ssid_info.subsystem_device_id == 0x9999U,
                "subsystem IDs should be decoded from the ATOM ROM header");
        bool ssid_mismatch_blocked = false;
        try { (void)flashamd::flash_image(ssid_device, 0U, mismatched_ssid_image, mismatched_ssid_info, {}); }
        catch (const std::runtime_error&) { ssid_mismatch_blocked = true; }
        require(ssid_mismatch_blocked, "subsystem mismatch should be rejected unless bypassed");
        flashamd::FlashPolicy skip_ssid;
        skip_ssid.skip_ssid_check = true;
        require(flashamd::flash_image(ssid_device, 0U, mismatched_ssid_image, mismatched_ssid_info, skip_ssid).verified,
                "--skip-ssid-check should bypass only the subsystem ID gate");

        flashamd::SimulatorBackend retry_device(catalog);
        retry_device.fail_next_erase_operations(1U);
        const auto retried = flashamd::flash_image(retry_device, 0U, image, image_info, {});
        require(retried.verified && retried.attempts == 2U, "transient erase failure should retry and verify");

        flashamd::SimulatorBackend exhausted_device(catalog);
        exhausted_device.fail_next_erase_operations(3U);
        bool retries_exhausted = false;
        try { (void)flashamd::flash_image(exhausted_device, 0U, image, image_info, {}); }
        catch (const std::runtime_error& error) {
            retries_exhausted = std::string(error.what()).find("after 3 attempts") != std::string::npos;
        }
        require(retries_exhausted, "three transient erase failures should exhaust the retry limit");

        flashamd::SimulatorBackend all_families(catalog);
        const auto all_devices = all_families.enumerate();
        for (std::size_t index = 0; index < all_devices.size(); ++index) {
            const auto& device = all_devices[index];
            const auto family_image = sample_image(device.device_id);
            const auto family_info = flashamd::inspect_image(family_image);
            if (device.rom_size < family_image.size()) {
                bool unsupported_rom_blocked = false;
                try { (void)flashamd::flash_image(all_families, index, family_image, family_info, {}); }
                catch (const std::runtime_error&) { unsupported_rom_blocked = true; }
                require(unsupported_rom_blocked, "non-SPI ROM family should reject simulated flash");
            } else {
                const auto family_result = flashamd::flash_image(all_families, index, family_image, family_info, {});
                require(family_result.verified, "every supported ASIC family should complete simulated write and verify");
            }
        }

        flashamd::SimulatorBackend dual_partition(catalog);
        flashamd::FlashPolicy both;
        both.both_partitions = true;
        const auto dual_result = flashamd::flash_image(dual_partition, 0U, image, image_info, both);
        require(dual_result.verified && dual_result.bytes_written == image.size() * 2U,
                "both-partition simulation should write and verify both slots");

        const std::vector<std::uint8_t> malformed = {0x00U, 0x01U, 0x02U};
        require(!flashamd::inspect_image(malformed).has_rom_signature, "malformed image should be rejected by signature check");
        bool malformed_blocked = false;
        try { (void)flashamd::flash_image(simulator, 0U, malformed, flashamd::inspect_image(malformed), {}); }
        catch (const std::runtime_error&) { malformed_blocked = true; }
        require(malformed_blocked, "malformed image should never enter the flash sequence");

        bool nor_rule_checked = false;
        try {
            const std::array<std::uint8_t, 1> one_to_zero = {0x00U};
            simulator.program_rom(1U, 1000U, one_to_zero);
            const std::array<std::uint8_t, 1> zero_to_one = {0xffU};
            simulator.program_rom(1U, 1000U, zero_to_one);
        } catch (const std::runtime_error&) { nor_rule_checked = true; }
        require(nor_rule_checked, "simulator should enforce NOR flash erase-before-program semantics");

        std::cout << "core checks passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "core check failed: " << error.what() << '\n';
        return 1;
    }
}
