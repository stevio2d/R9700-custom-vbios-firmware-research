# AMDVBFlash Linux port

A C++20 command-line port of the recoverable offline and device-management behavior in the supplied AMDVBFlash 5.0.879 binary. The original executable is Windows x64. The port builds natively on Linux and keeps PCI discovery, ROM backup, image parsing, and simulated writes behind a device interface.

## Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

## Examples

```sh
./build/amdvbflash --version
./build/amdvbflash --help=all
./build/amdvbflash --show --device --accept-EULA
./build/amdvbflash --show --bios-file-info --vbios-file backup.rom --accept-EULA
./build/amdvbflash --cf --vbios-file backup.rom --accept-EULA
./build/amdvbflash --simulator --show --device 10 --accept-EULA
```

The focused Navi48 raw-backup utility is built as `R9700flash-dump`:

```sh
sudo ./build/R9700flash-dump --list
sudo ./build/R9700flash-dump --backup --device 0 --output R9700-03-00.0.spi.rom
```

`R9700flash-dump` marks supported Navi48 devices in the list. Backup reads its configured 2 MiB ROM address range through the Navi48 `ROM_INDEX`/`ROM_DATA` MMIO registers, checks indexed reads for stable data, and requires a complete AMD option-ROM image somewhere in the dump. The option-ROM image may begin at a nonzero address. The utility creates a new output file without replacing an existing file. It requires the device to be initialized by `amdgpu` and sufficient permission to map its PCI register BAR. It holds a per-device lock and temporarily prevents PCI runtime suspend during the read, then restores the previous power policy. `SIGINT`, `SIGTERM`, `SIGHUP`, and `SIGQUIT` request graceful cleanup; `SIGKILL` and process crashes cannot run cleanup. This command has no flash erase or programming operation. On the target Navi48 R9700 at `0000:03:00.0`, two consecutive 2 MiB reads were reported byte-identical. The retained [XFX capture](../bios/xfx-r9700-0000-03-00-0/original/stock-spi-capture.rom) has two byte-identical 117,248-byte PCIR chains at offsets `0x40000` and `0x120000`, each with a 58,880-byte legacy image and 58,368-byte EFI image; see its [triage report](../bios/xfx-r9700-0000-03-00-0/evidence/stock-spi-rom-triage.json). The 2 MiB range comes from the configured Navi48 address extent and has not been independently matched to the physical chip capacity, so this capture is not qualified as a full-chip recovery image.

For `amdvbflash`, `--accept-EULA` records acceptance for version 5.0.879 under the user configuration directory. Help, version, and EULA display do not require acceptance. `R9700flash-dump` is a separate focused utility and does not show or record the AMDVBFlash EULA.

`--simulator` creates one synthetic PCI device per each of the 18 embedded ASIC families. Use it for erase, write, compatibility, force-option, retry, and readback flows. The simulator does not access the host PCI bus.

Simulated flashing validates the declared ROM length and applicable legacy 8-bit checksums before erase. It checks both the initialization region and the PCIR image when those lengths differ; trailing file padding cannot cancel corruption in either scope. EFI ROMs have no applicable legacy checksum. Physical `--checkifwi` is refused because this port does not decode AMD's real partition table; `--pavbpn` is also refused until VBIOS part-number metadata can be decoded.

The Linux backend lists AMD PCI display-class functions (PCI class `0x03`) through sysfs and can save a device ROM through the kernel PCI ROM attribute. This keeps PCI bridges and audio functions out of the GPU list. Firmware writes are disabled on physical Linux devices. `--hw-access-mechanism=devmem` performs a read-only BAR mapping probe and still reads ROM bytes through sysfs; it does not emulate AMD's register-driven SPI programming protocol.

Run `sudo env R9700FLASH_DUMP_BIN="$PWD/build/R9700flash-dump" scripts/validate_r9700_readonly.sh [output-directory]` on an R9700 Linux host to create and check a raw 2 MiB SPI backup. The script never runs a flash command.

