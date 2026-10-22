# XFX Radeon AI PRO R9700 — device record

Status: one AMD SMI-identified R9700 function is recorded by its PCI BDF. Its unique ASIC identifier is redacted in this public copy. The exact retail SKU, board-label serial and PCB revision have not been observed. Two matching driver-loaded VBIOS reads and one 2 MiB GPU-mediated raw SPI address-space capture are preserved below. The capture contains complete option-ROM structures, but the fitted SPI capacity and full-chip recovery coverage remain unverified.

## Identity

| Field | Value / evidence |
|---|---|
| Card ID (matches folder and CSV) | `xfx-r9700-0000-03-00-0` |
| Board family | R9700; AMD SMI market name `AMD Radeon AI PRO R9700` |
| Vendor / exact model / SKU / package code | XFX Limited subsystem vendor; exact XFX retail SKU/package code unknown. Host reports Radeon AI PRO R9700. |
| PCB revision / silkscreen / hardware revision | PCB revision and silkscreen unknown. PCI revision register is `c0`; this is not a PCB revision. |
| Serial reference / batch or serial range | Unique AMD SMI ASIC ID redacted; this is not a board-label serial. Board serial unknown. |
| Intake date / operator / acquisition provenance | Physical intake date/operator unknown. Driver-loaded software capture recorded 2026-10-18 from `capture-host` over SSH; the physical card was not removed or photographed. |
| PCI BDF / slot | `0000:03:00.0`; physical slot label unknown. |
| PCI vendor / device ID | `1002:7551` |
| PCI subsystem vendor / device ID | `1eae:9801` (XFX Limited) |
| PCI revision register / observed silicon marking | PCI revision `c0`; package marking not observed. |
| Label, front and back photo paths | Unknown; no card photos retained. |

See the [host checks](../../inventory/host_checks.md) and [acquisition record](evidence/ACQUISITION.md) for the device association and its limits.

## Memory, power and cooling

| Field | Value / evidence |
|---|---|
| Reported capacity / bus / effective data rate | Host tools report 32,624 MiB GDDR6 and a 256-bit interface. Effective data rate was not measured. |
| DRAM manufacturer / complete part markings | AMD SMI reports Samsung; physical package markings are unknown. |
| Package count / placement / density / width / speed bin | Unknown; board not inspected. |
| Memory voltage / datasheet reference | Unknown. |
| GPU VRM controller / power-stage markings and ratings | Unknown; board not inspected. |
| GPU / SoC / memory phase topology; memory controller | Unknown. |
| Shunts / telemetry / overcurrent limits | Unknown. |
| Power connector / PSU / cable / thermal margin | Unknown; board and power cabling not inspected. |
| Cooler / fan controller / fan connector and tach/PWM map | Unknown; board not inspected. |
| Display connector layout / routing evidence | Unknown; display outputs were not inspected. |

## Flash and recovery

| Field | Value / evidence |
|---|---|
| SPI manufacturer / full marking / package | Unknown; no physical SPI device was inspected. |
| PCB reference designator / location / pin-1 photo | Unknown. |
| Exact datasheet / VCC and I/O requirements | Unknown. |
| Measured programmer rail and logic levels | Not measured; no programmer was connected. |
| JEDEC ID / physical capacity in bytes | Unknown; the GPU-mediated 2 MiB address-space capture does not identify the fitted chip or prove its capacity. |
| Write-protect state / dual-BIOS evidence | Unknown. |
| Programmer / adapter / clip or socket / software versions | No SPI programmer used. |
| Repeat-read group / comparison logs | Two identical driver-loaded software reads and two byte-identical raw 2 MiB reads are reported in the capture records; only one raw capture file is retained. See [acquisition evidence](evidence/ACQUISITION.md). The raw-read group is not independently reproduced here. |
| Software stock dump path / SHA-256 / bytes | [Read 1](original/stock-software-read1.rom) and [read 2](original/stock-software-read2.rom); each 58,880 bytes, SHA-256 `aad3d6957f284a0cce130f8e106ea7a1118ba9bf1bf86b26d86a28ca11d0bc8d`. |
| Raw SPI capture path / SHA-256 / bytes | [stock-spi-capture.rom](original/stock-spi-capture.rom); 2,097,152 bytes; SHA-256 `21aa437510552f5110edd26388e236b87cb47a96f86b4c17b4e20bf60b2ec876`. `R9700flash-dump` read its configured 2 MiB address range; physical chip capacity and recovery coverage are not verified. |
| Separate recovery copy location / verification date | None. The software VBIOS copies and raw address-space capture are not qualified recovery images. |
| Recovery demonstration / stock retest experiment | Not demonstrated. |

## Stock baseline and software

The driver reports ATOM BIOS identifier/version `113-48WD6SHD1-P02`; the captured bytes also contain `ATOMBIOSBK-AMD VER023.008.000.068.000001`. The host kernel log reports PMFW `104.74.0`, Linux `7.0.14-custom-nogpu`, and that the driver fetched VBIOS from ACPI VFCT. No clocks, temperatures, fan behavior, board power, workload, or performance baseline was measured. See [host checks](../../inventory/host_checks.md).

## Compatibility, unknowns and history

The [R9700flash-dump documentation](../../flashing/docs/r9700flash-dump.md)
describes the separate raw address-space read recorded above. It adds no
physical chip identity or recovery test, and its configured 2 MiB extent does
not establish the fitted flash capacity.

The sourced assessment of candidate XFX VBIOS benefits, runtime alternatives,
ROM-to-ROM differences and remaining gates is in the
[custom-VBIOS benefit assessment](evidence/CUSTOM_VBIOS_BENEFIT_ASSESSMENT.md).

The captured VBIOS is associated with the `0000:03:00.0` driver instance. The host has three other AMD SMI-identified R9700 functions with the same subsystem ID; this record does not generalize either capture to those cards or to another XFX board revision. The driver-loaded bytes came from `amdgpu_vbios` debugfs after the PCI sysfs ROM read returned `EIO`; the kernel logged VFCT as their source. The raw SPI address-space capture is retained separately, but the physical flash part and its capacity have not been identified. See the [XFX/ASUS comparison](evidence/XFX_ASUS_COMPARISON.md). No firmware was written, modified, boot-tested or rolled back.
