#pragma once

#include "flashamd/core.hpp"

namespace flashamd {

// Supports only Navi48 devices and returns the complete 2 MiB SPI ROM image.
bool supports_navi48_spi_rom(const PciDevice& device);
std::vector<std::uint8_t> read_navi48_spi_rom(const PciDevice& device);

} // namespace flashamd
