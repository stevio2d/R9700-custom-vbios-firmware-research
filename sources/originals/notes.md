
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
from hashlib import sha256
import re

FOLDER = "R9700_VBIOS_Research_Pack"

PACK = r"""@@ 00_README.md
# AMD Radeon AI PRO R9700 — VBIOS Research & Engineering Pack

Date: 2026-10-18
Status: Initial evidence-based engineering pack, not a completed firmware reverse-engineering report.

## Objective

Develop and validate a working custom VBIOS for AMD Radeon AI PRO R9700 cards, with an emphasis on:
- Performance and efficiency improvements.
- Fan, thermal, and power behavior.
- Potentially disabled features.
- Reproducible flashing and recovery.
- Compatibility across vendors and PCB revisions.

## Important distinction

A BIOS file that can be edited is not necessarily a BIOS that can boot.

The project must establish whether the R9700 verifies cryptographic
signatures over the regions we intend to modify.

Changing a checksum does not repair a cryptographic signature.

An external programmer may allow writing the SPI chip while the card is
powered off, but it cannot force the GPU to accept invalid firmware.

## Evidence categories

VERIFIED: Direct AMD or board-vendor documentation.
OBSERVED: Reproducible result from an actual card or firmware dump.
HYPOTHESIS: Technically plausible but not demonstrated on R9700.
UNKNOWN: No sufficient evidence yet.

Do not turn a hypothesis into a specification.

## Recommended first experiment

1. Obtain one R9700 card and identify its exact board revision.
2. Record PCI IDs, VBIOS version, clocks, temperatures and power behavior.
3. Read its VBIOS without modifying anything.
4. Identify the physical flash IC and verify a hardware recovery route.
5. Acquire another ROM from the same exact model, if available.
6. Compare the two images.
7. Establish which firmware regions are authenticated.
8. Only then consider a controlled modification.

## Contents

01 — Verified vendors, models and revisions.
02 — Hardware and memory specifications.
03 — VBIOS collection and binary comparison.
04 — SPI flash chip identification.
05 — Flashing, backup and recovery.
06 — Firmware security and protection.
07 — Engineering roadmap to a working custom VBIOS.
08 — Gated features and unlock hypotheses.
09 — Performance modification priorities.
10 — Laboratory validation and acceptance criteria.
11 — Sources and open questions.

The templates folder contains inventory and testing spreadsheets in CSV form.

## Not included

No vendor firmware binaries, patched images, signature bypasses or
claims of successful custom R9700 VBIOS booting are included.

Those require actual ROM dumps and hardware validation.

@@ 01_Vendors_and_Models.md
# R9700 Vendors, Models and PCB Revisions

## Confirmed product pages

### ASUS
Model: TURBO-AI-PRO-R9700-32G
Memory: 32GB GDDR6
Outputs: 3x DisplayPort 2.1a, 1x HDMI 2.1b
Default: 2350MHz game, up to 2920MHz boost
GPU Tweak III OC mode: 2370MHz game, up to 2940MHz boost

ASUS published BIOS update tool v1 on 2026-06-04.
The release notes describe a quieter fan curve.

This is evidence that ASUS distributes an R9700 firmware update.
It does not establish which bytes changed or whether third-party
modified firmware is accepted.

Sources:
https://www.asus.com/motherboards-components/graphics-cards/turbo/turbo-ai-pro-r9700-32g/techspec/
https://www.asus.com/us/motherboards-components/graphics-cards/turbo/turbo-ai-pro-r9700-32g/helpdesk_download?model2Name=TURBO-AI-PRO-R9700-32G

### ASRock
Model: Radeon AI PRO R9700 Creator 32GB
Memory: 32GB GDDR6 at 20Gbps
Clocks: 2350MHz game, up to 2920MHz boost
Outputs: 4x DisplayPort 2.1a
Power: 1x 12V-2x6
Cooling: Active, dual-slot

Source:
https://www.asrock.com/Graphics-Card/AMD/Radeon%20AI%20PRO%20R9700%20Creator%2032GB/

### Gigabyte
Model: Radeon AI PRO R9700 AI TOP 32G
Part number: GV-R9700AI TOP-32GD
Documented revisions: 1.0 and 1.1
Clocks: 2350MHz game, up to 2920MHz boost
Outputs: 3x DisplayPort 2.1a, 1x HDMI 2.1b
Cooling: Turbo/blower design

Both revisions must be treated as separate hardware records.
Published specifications alone cannot establish PCB or ROM identity.

Sources:
https://www.gigabyte.com/Graphics-Card/GV-R9700AI-TOP-32GD-rev-10/sp
https://www.gigabyte.com/au/Graphics-Card/GV-R9700AI-TOP-32GD-rev-11/sp

### PowerColor
Model: AI PRO R9700 32G-B
Memory: 32GB GDDR6, 20Gbps, 256-bit
Clocks: 2350MHz game, up to 2920MHz boost
Outputs: 4x DisplayPort 2.1a
Power: 12V-2x6

Source:
https://www.powercolor.com/product-detail258.htm

### Sapphire
Model: Radeon AI PRO R9700 32GB
SKU: 32358-01
Cooling: Active blower
Outputs: 4x DisplayPort 2.1a

Related but distinct product:
Radeon AI PRO R9700S 32GB Passive
SKU: 32361-01

Do not assume the passive R9700S ROM is safe to flash
onto the actively cooled R9700.

Sources:
https://www.sapphiretech.com/en/commercial/radeon-ai-pro-r9700
https://www.sapphiretech.com/en/commercial/radeon-ai-pro-r9700s

### XFX
Model: Radeon AI PRO R9700 32GB
Part number: RX-97XPROAIY
Memory: 32GB GDDR6, 20Gbps
Clocks: 2350MHz game, up to 2920MHz boost
Outputs: 4x DisplayPort 2.1a
Cooling: Blower

Note: The XFX product page contains an apparent R9070/R9700
naming inconsistency. Use its actual model number and confirm
the packaging before assigning ROM files.

Source:
https://helpdesk.xfxforce.com/shop/xfx-amd-radeon-ai-pro-r9700-32gb-gddr6-4xdp-amd-rdna-tm-4

## Manufacturer comparison requirements

For every physical card, collect:
- Brand and exact SKU.
- PCB revision and serial-number range.
- PCI vendor/device/subsystem IDs.
- VBIOS version and ROM SHA-256.
- Flash IC marking and JEDEC ID.
- Memory manufacturer and chip markings.
- VRM controller and power-stage markings.
- Display output configuration.
- Cooling system and fan controller.
- Stock clocks, power limits and temperatures.

## Are all vendors using different BIOS files?

UNKNOWN until actual ROM images are collected and hashed.

Different output layouts, cooling systems and board revisions
make firmware differences plausible, but they do not prove them.

@@ 02_GPU_Memory_and_Hardware.md
# GPU, Memory and Hardware Specifications

## AMD-verified reference specifications

GPU architecture: RDNA 4
Compute units: 64
Stream processors: 4096
AI accelerators: 128
Ray accelerators: 64
ROPs: 128
Transistors: 53.9 billion

Game clock: 2350MHz
Boost clock: Up to 2920MHz

Memory capacity: 32GB
Memory technology: GDDR6
Memory bus: 256-bit
Memory data rate: 20Gbps
Peak memory bandwidth: 640GB/s
Infinity Cache: 64MB

Total board power: 300W
External power: 12V-2x6
PCIe: 5.0 x16
Recommended PSU: 750W

Memory ECC: Supported on Linux according to AMD.
Display support: Up to four outputs, depending on partner design.
Video: H.264, H.265/HEVC and AV1 encode/decode.

Official sources:
https://www.amd.com/en/products/graphics/workstations/radeon-ai-pro/ai-9000-series/amd-radeon-ai-pro-r9700.html
https://www.amd.com/content/dam/amd/en/documents/partner-hub/radeon-pro/radeon-ai-pro-r9700-datasheet.pdf

## Memory chips: what is NOT yet established

The published 32GB capacity and 256-bit interface do not
identify the exact memory package arrangement.

Still required:
- DRAM manufacturer: Samsung, SK hynix, Micron or another supplier.
- Exact memory part number.
- Number of packages.
- Density and package width.
- Physical placement.
- Memory rail voltage.
- Supported timing and speed bins.
- Whether different board revisions use different DRAM.

Do not assume every R9700 has identical memory chips.

## GPU die

RDNA 4 is verified by AMD.

Some reporting identifies the silicon as Navi 48.
Treat the precise die identification as secondary-source information
until independently verified for the board being tested.

## Power delivery

Unknown per board:
- VRM controller.
- GPU power-stage count and current rating.
- Memory VRM design.
- Shunt values and telemetry configuration.
- Hardware overcurrent limits.
- PCB trace and connector thermal margins.

These must be inspected before proposing a higher power limit.

## Why these details matter

Memory vendor and VRM differences can make cross-flashing unsafe.

Even when two cards use the same GPU, a mismatched ROM could
configure the wrong fan, memory or voltage behavior.

@@ 03_VBIOS_Collection_and_Diff.md
# VBIOS Collection, Identification and Binary Comparison

## Goal

Create a verified database of stock R9700 firmware images.

Do not rely on filenames such as "R9700_original.bin".
Every image must be tied to an exact physical board.

## Collection sources

1. Read the installed card through a supported software interface.
2. Read the physical SPI chip using a compatible programmer.
3. Obtain official manufacturer update packages.
4. Obtain verified community dumps only as comparison material.

The ASUS BIOS update package is a particularly useful target
for static analysis because the vendor documents a fan-curve change.

Source:
https://www.asus.com/us/motherboards-components/graphics-cards/turbo/turbo-ai-pro-r9700-32g/helpdesk_download?model2Name=TURBO-AI-PRO-R9700-32G

## Required ROM metadata

- Manufacturer and exact SKU.
- Board and PCB revision.
- PCI device ID.
- Subsystem vendor and device IDs.
- ROM length in bytes.
- SHA-256 checksum.
- VBIOS version and build date.
- Acquisition method.
- Whether image came from the SPI chip or PCI ROM interface.
- Flash IC model and capacity.
- Whether dump was repeated and verified.

## Binary analysis workflow

1. Keep immutable copies of every original.
2. Compare exact sizes and SHA-256 hashes.
3. Identify PCI option-ROM headers and image boundaries.
4. Identify ATOM BIOS data structures where applicable.
5. Compare strings, version fields and board identifiers.
6. Compare changed byte ranges between firmware versions.
7. Determine whether differences are data, code or signatures.
8. Map candidate fan, power and clock fields.
9. Validate candidate fields against independent observations.
10. Do not write edited images until authentication is understood.

## Recommended tools

- sha256sum or hashlib.
- cmp, xxd and a hex editor.
- Python for binary parsing.
- UEFITool only where applicable to the actual image structure.
- Vendor utilities for firmware metadata.
- A reproducible diff tool such as VBinDiff or ImHex.

No parser should be trusted solely because it recognizes a header.

## Acceptance criterion

A proposed field mapping requires:
- A reproducible offset.
- A plausible type and unit.
- Cross-image evidence.
- A known relationship to observable behavior.
- Evidence that editing the field will not invalidate
  an enforced signature.

@@ 04_SPI_Flash_Identification.md
# SPI Flash Chip Identification and Physical Recovery

## Critical unknown

The exact SPI flash part number and location have NOT been
verified here for each R9700 board.

Do not assume the same flash IC is used by ASUS, ASRock,
Gigabyte, PowerColor, Sapphire and XFX.

## Board-specific inspection procedure

1. Photograph both sides of the unpowered PCB.
2. Record the exact PCB revision.
3. Locate likely SPI NOR flash packages.
4. Read the complete top marking under magnification.
5. Consult the exact manufacturer's datasheet.
6. Confirm package, pinout, capacity and supply voltage.
7. Read the JEDEC ID with a compatible programmer.
8. Compare the chip capacity with the full hardware dump.
9. Record coordinates relative to visible PCB landmarks.

Likely packages include small 8-pin SPI NOR devices, but this
is a search clue, not a confirmed R9700 component specification.

## Programmer options

- A properly voltage-compatible CH341A-based SPI programmer.
- A supported professional SPI programmer.
- flashrom with a compatible external programmer.
- A socket adapter if the chip must be desoldered.

## Voltage precautions

Check the flash IC datasheet before connecting any programmer.

Some chips require 1.8V; others use 3.3V.

Some inexpensive black CH341A boards can drive signals near
5V despite providing a nominal 3.3V supply.

Use a verified voltage-safe programmer and suitable level shifting.

Never assume that a clip or adapter provides the correct voltage.

## Clip versus desoldering

An in-circuit SOIC clip may work, but other PCB components can
interfere with SPI communication or be unintentionally powered.

If detection fails or repeated reads disagree:
- Stop.
- Recheck wiring and voltage.
- Consider controlled desoldering and socket programming.

Do not connect an external programmer while the GPU is
connected to an energized PSU.

## Evidence required before a write

- Exact flash chip identity.
- Correct programmer voltage.
- Stable JEDEC ID.
- Two matching full-chip reads.
- SHA-256 hashes recorded.
- Known-good recovery image.
- Confirmed ability to verify written contents.

Reference:
https://manpages.debian.org/trixie/flashrom/flashrom.8.en.html

@@ 05_Flashing_Backup_and_Recovery.md
# Flashing, Backup, Verification and Recovery

## Rule

No firmware write until a physical recovery path is verified.

## Step 1: Identify the card on Linux

Run:

    lspci -nn | grep -Ei 'VGA|Display'

Record the exact PCI address and IDs.

## Step 2: Optional PCI ROM read

The Linux kernel exposes a read-only PCI ROM resource when
the device and driver support it.

Example, replacing the address with your actual GPU:

    BDF=0000:03:00.0
    ROM="/sys/bus/pci/devices/$BDF/rom"
    echo 1 | sudo tee "$ROM" >/dev/null
    sudo dd if="$ROM" of=R9700_pci_rom.bin bs=64K
    echo 0 | sudo tee "$ROM" >/dev/null
    sha256sum R9700_pci_rom.bin

This is not guaranteed to return the complete physical SPI contents.

Kernel reference:
https://docs.kernel.org/PCI/sysfs-pci.html

## Step 3: External programmer read

Only after identifying the exact chip and verifying voltage:

    sudo flashrom -p ch341a_spi
    sudo flashrom -p ch341a_spi -r original_read1.bin
    sudo flashrom -p ch341a_spi -r original_read2.bin
    sha256sum original_read1.bin original_read2.bin
    cmp original_read1.bin original_read2.bin

The two full-chip reads must match byte-for-byte.

If they do not, do not continue.

## Step 4: Preserve originals

Store copies:
- On the lab computer.
- On separate removable storage.
- In a read-only archive with SHA-256 checksums.

Never overwrite the original dump.

## Step 5: Software flashing

AMDVBFlash/ATIFlash support for the R9700 must be verified
against the exact utility version and card firmware.

Do not assume an older flashing utility supports RDNA 4.

Vendor update tools may enforce model matching or
additional verification.

## Step 6: Recovery from a bad flash

If a card no longer initializes:
1. Power down and disconnect all power.
2. Confirm the flash chip and its voltage.
3. Connect the validated external programmer.
4. Re-read the chip if possible.
5. Compare against the known-good backup.
6. Write the original full-chip image using the correct programmer.
7. Verify the restored contents byte-for-byte.
8. Disconnect the programmer before powering the GPU.
9. Reinstall and test the card at stock settings.

Example flashrom commands, ONLY with a verified programmer setup:

    sudo flashrom -p ch341a_spi -w original_read1.bin
    sudo flashrom -p ch341a_spi -v original_read1.bin

A hardware programmer can restore bytes but cannot repair
damage caused by incorrect voltage, wiring or power delivery.

@@ 06_Firmware_Security_and_Protections.md
# Firmware Security, Signatures and Write Protections

## The central feasibility question

Can the R9700 boot an arbitrarily modified VBIOS?

This has NOT been established by the available evidence.

## Distinct mechanisms to investigate

1. PCI option-ROM checksums.
2. ATOM BIOS internal structure checks.
3. Cryptographic authentication of firmware regions.
4. GPU security processor or microcontroller validation.
5. Driver-level firmware validation.
6. Board and subsystem ID matching.
7. Software flasher model restrictions.
8. SPI status-register protection bits.
9. Hardware write-protect pin behavior.
10. Dual-BIOS support, if present on a specific PCB.

These are different mechanisms and require separate tests.

## Important limitations

A valid legacy checksum does not imply a valid signature.

A hardware SPI programmer may bypass a software write lock,
but it does not bypass a signature check performed at boot.

A ROM accepted by one board may be rejected by another because
of board ID, memory topology, display outputs or firmware policy.

## Research plan

- Compare original and official updated ASUS firmware.
- Identify every changed region.
- Search for authentication metadata and signature blocks.
- Compare behavior of signed and unsigned areas.
- Investigate AMD documentation and driver source code.
- Establish whether non-authenticated configuration data exists.
- Determine whether approved vendor firmware customization
  or runtime driver controls offer an alternative route.

## Stop condition

If the desired fields are covered by enforced signatures
and no legitimate signing route exists, do not claim that
a working arbitrary custom VBIOS is achievable.

Shift effort to supported tuning or vendor-provided firmware.

@@ 07_Custom_VBIOS_Engineering_Roadmap.md
# Engineering Roadmap to a Bootable Custom VBIOS

## Phase 0 — Define the target

Select one exact R9700 SKU and PCB revision.

Define the requested change:
- Better sustained clocks?
- Lower power at equal performance?
- Faster memory?
- Quieter fan behavior?
- A specific feature unlock?

Set measurable success criteria before modifying anything.

Gate: One reproducible stock benchmark and complete card inventory.

## Phase 1 — Establish recovery

Identify the SPI chip and obtain two matching hardware dumps.

Gate: Verified original image, programmer voltage and
recovery procedure.

## Phase 2 — Establish ROM provenance

Collect multiple stock ROMs from identical cards, if possible.

Compare:
- ROM sizes and hashes.
- BIOS versions.
- PCI IDs.
- Memory and VRM configurations.
- Fan and thermal behavior.

Gate: No unexplained board identity mismatch.

## Phase 3 — Analyze firmware layout

Identify option-ROM structure, configuration tables,
embedded firmware and potential signatures.

Gate: Evidence-based map of candidate fields and
authentication boundaries.

## Phase 4 — Non-writing proof of concept

Build a parser that reads the original ROM and produces
a report of known fields without changing the image.

Test against more than one independent ROM.

Gate: Parser produces consistent and explainable output.

## Phase 5 — Controlled modification feasibility

Determine whether a proposed field is:
- Mutable and not authenticated.
- Mutable but authenticated.
- Fixed by hardware.
- Managed by driver or runtime software.

Gate: A technically credible route to an accepted boot image.

## Phase 6 — First write experiment

Only with a sacrificial or recoverable card:
- Preserve all originals.
- Make one small, well-understood change.
- Verify image integrity.
- Use a confirmed compatible flashing method.
- Test initialization, display and driver loading.
- Restore stock firmware immediately if unstable.

Do not begin with a power-limit increase or a feature unlock.

## Phase 7 — Stability validation

Run short and long tests covering:
- Cold boot and warm reboot.
- Driver loading.
- PCIe link stability.
- Memory errors.
- AI inference.
- Graphics rendering.
- Thermals and fan control.
- Power and connector temperatures.

Gate: No regressions relative to stock.

## Phase 8 — Generalize across boards

Repeat the entire process for each exact SKU and PCB revision.

Never assume one working image is universal.

## Definition of success

A custom VBIOS is considered successful only when it:
1. Boots repeatedly.
2. Loads the expected drivers.
3. Preserves all required hardware functions.
4. Survives stress testing.
5. Produces a measurable benefit.
6. Has a verified rollback path.

@@ 08_Gated_Features_and_Unlocks.md
# Potentially Gated Features — R9700 Investigation

## Already officially supported

### ROCm
The R9700 is officially listed in AMD ROCm support documentation.

This is not a missing feature that requires a VBIOS unlock.

Support depends on the exact ROCm version, OS and framework.

Sources:
https://rocm.docs.amd.com/projects/radeon-ryzen/en/latest/docs/compatibility/compatibilityrad/native_linux/native_linux_compatibility.html
https://rocm.docs.amd.com/projects/radeon-ryzen/en/latest/docs/compatibility/compatibilityrad/windows/windows_compatibility.html

### ECC
AMD lists R9700 memory ECC support as "Yes (Linux Only)".

Question: Is the Windows limitation due to driver support,
firmware policy or another platform requirement?

No evidence currently establishes a VBIOS-based Windows unlock.

Source:
https://www.amd.com/en/products/graphics/workstations/radeon-ai-pro/ai-9000-series/amd-radeon-ai-pro-r9700.html

### AI acceleration and precision formats
RDNA 4 AI accelerators and supported FP8/FP16/INT8/INT4
capabilities are already advertised.

A custom VBIOS cannot create new physical compute units.

### Multi-GPU
AMD documents multi-GPU use for R9700 workloads.

Do not confuse multi-GPU compute support with SR-IOV
virtualization or pooled physical VRAM.

## Potentially software- or firmware-gated

### SR-IOV / virtual GPU partitioning
Status: UNVERIFIED for R9700.

Investigation:
- Check official AMD virtualization support matrices.
- Inspect PCI capabilities and relevant driver support.
- Compare with officially supported virtualization products.
- Determine whether firmware, driver, licensing and hardware
  capabilities are all present.

No basis yet for promising an SR-IOV unlock.

### Workstation application certifications
Status: Primarily a software/driver/vendor support issue.

A BIOS identity change does not confer official certification.

### Power and clock limits
Status: Potential tuning target.

Some limits may be configurable, while others are enforced
by signed firmware, driver policy or hardware protection.

### Fan control
Status: Proven manufacturer-level firmware change exists.

ASUS published an R9700 BIOS update for fan-curve behavior.

This does not prove unsigned fan-table editing is possible.

## Features unlikely to be unlocked through VBIOS alone

### More physical VRAM
Requires actual memory packages, routing and supported
memory initialization. Firmware cannot manufacture capacity.

### More compute units
May be limited by silicon design, defects, fuses or product
configuration. No evidence establishes disabled usable
compute units on the R9700.

### More display connectors
Requires physical connectors, routing and supporting hardware.

### Wider memory bus or more Infinity Cache
These are physical silicon and board characteristics.

### Features from Radeon PRO W7900 or Instinct products
Those products may use different architectures, dies,
memory subsystems and software stacks.

Higher price does not establish that an R9700 contains
the same disabled hardware.

## Unlock investigation decision tree

1. Does AMD list the feature for R9700 already?
   If yes, test driver/OS support before touching firmware.
2. Does the GPU physically contain the necessary hardware?
   If no, stop.
3. Is the feature exposed in PCI capabilities or driver code?
   If no, investigate further; do not assume firmware gating.
4. Is the restriction software, licensing or firmware based?
5. Does changing the relevant setting require signed firmware?
6. Can the change be validated without risking the card?
7. Is there a measurable benefit and a reliable rollback?

@@ 09_Performance_Modification_Priorities.md
# Performance, Efficiency and Thermal Modification Priorities

## Baseline first

Measure the stock card before proposing a BIOS change.

Capture:
- Sustained GPU clock.
- Memory clock.
- Board power.
- GPU temperature and hotspot temperature.
- Fan speed.
- Workload throughput.
- Error and crash rate.
- Ambient temperature.
- PCIe link width and speed.

## Priority 1 — Cooling and fan behavior

Potential benefit:
- Reduced thermal throttling.
- More consistent sustained clocks.
- Lower noise at equivalent performance.

Evidence:
ASUS has issued an R9700 firmware update affecting fan behavior.

Risks:
Excessive hotspot or VRM temperatures and reduced fan lifespan.

## Priority 2 — Efficiency tuning

Potential benefit:
- Lower power for equal throughput.
- Better multi-card density.
- Reduced cooling demand.

Start with supported runtime controls where available.

## Priority 3 — Sustained GPU clocks

Potential benefit:
Higher throughput in GPU-compute-bound workloads.

Risks:
Instability, additional power, thermal limits and diminishing returns.

The published boost clock is not a guaranteed sustained clock.

## Priority 4 — Memory performance

Potential benefit:
Higher throughput for memory-bandwidth-bound workloads.

Risks:
Silent calculation errors, memory instability and overheating.

Validate with workloads that detect incorrect results,
not only benchmarks that report speed.

## Priority 5 — Power limit

AMD specifies 300W TBP.

Increasing a limit is not automatically beneficial.

Before considering it, characterize:
- VRM capability.
- Cooling capacity.
- Connector and cable temperatures.
- PSU headroom.
- Actual workload bottlenecks.
- Whether firmware authentication permits changes.

## Experiment design

Change one variable at a time.

Compare:
- Tokens per second in the same AI model.
- Time per image or rendering task.
- Effective memory bandwidth.
- Performance per watt.
- Sustained performance over 30–60 minutes.
- Reproducibility across multiple runs.

A successful mod must beat the stock configuration
without unacceptable stability or thermal regressions.

@@ 10_Laboratory_Test_Plan.md
# Lab Procedures, Safety and Acceptance Criteria

## Equipment

- Test workstation with stable PSU.
- Known-good display and PCIe configuration.
- Second computer for recovery work.
- ESD-safe workspace.
- Camera or microscope for PCB identification.
- Voltage-safe SPI programmer and appropriate adapter.
- Thermal monitoring and logging tools.
- Optional power measurement equipment.

## Before every firmware experiment

Record:
- Date, operator and test purpose.
- Card manufacturer, SKU and PCB revision.
- PCI IDs.
- Original ROM SHA-256.
- Candidate ROM SHA-256.
- Exact modified bytes and intended effect.
- Programmer and software versions.
- Recovery image location.
- Baseline benchmark results.

## Minimum boot validation

- Cold boot succeeds.
- Warm reboot succeeds.
- GPU enumerates correctly.
- Expected driver loads.
- All intended display outputs work.
- No firmware-related system errors.
- Original memory capacity is reported.
- Idle temperatures and fan behavior are normal.

## Load validation

- 30-minute graphics stress test.
- 30-minute AI or compute workload.
- Extended workload representative of actual use.
- Memory correctness test where available.
- Power and thermal logging.
- Repeated reboots.

These are starting criteria, not proof of lifetime reliability.

## Stop conditions

Immediately stop and restore stock firmware for:
- Repeated initialization failure.
- Memory errors or incorrect computations.
- Unexpected voltage behavior.
- Fan failure.
- Thermal runaway.
- Unstable PCIe operation.
- Connector overheating.
- Significant performance regression.

## Acceptance

Approve a modification only if:
- The benefit is repeatable.
- No new errors appear.
- Temperatures and power remain within validated limits.
- The card survives reboot and sustained-load tests.
- Recovery remains available.

@@ 11_Sources_and_Research_Gaps.md
# Source Library and Outstanding Questions

## Primary sources

AMD R9700 product specifications:
https://www.amd.com/en/products/graphics/workstations/radeon-ai-pro/ai-9000-series/amd-radeon-ai-pro-r9700.html

AMD R9700 datasheet:
https://www.amd.com/content/dam/amd/en/documents/partner-hub/radeon-pro/radeon-ai-pro-r9700-datasheet.pdf

AMD R9700 announcement:
https://ir.amd.com/news-events/press-releases/detail/1253/amd-introduces-new-radeon-graphics-cards-and-ryzen-threadripper-processors-at-computex-2025

AMD Radeon AI PRO partners:
https://www.amd.com/en/products/graphics/workstations/radeon-ai-pro.html

ASUS specifications:
https://www.asus.com/motherboards-components/graphics-cards/turbo/turbo-ai-pro-r9700-32g/techspec/

ASUS firmware downloads:
https://www.asus.com/us/motherboards-components/graphics-cards/turbo/turbo-ai-pro-r9700-32g/helpdesk_download?model2Name=TURBO-AI-PRO-R9700-32G

ASRock Creator:
https://www.asrock.com/Graphics-Card/AMD/Radeon%20AI%20PRO%20R9700%20Creator%2032GB/

Gigabyte revision 1.0:
https://www.gigabyte.com/Graphics-Card/GV-R9700AI-TOP-32GD-rev-10/sp

Gigabyte revision 1.1:
https://www.gigabyte.com/au/Graphics-Card/GV-R9700AI-TOP-32GD-rev-11/sp

PowerColor:
https://www.powercolor.com/product-detail258.htm

Sapphire R9700:
https://www.sapphiretech.com/en/commercial/radeon-ai-pro-r9700

Sapphire R9700S:
https://www.sapphiretech.com/en/commercial/radeon-ai-pro-r9700s

XFX:
https://helpdesk.xfxforce.com/shop/xfx-amd-radeon-ai-pro-r9700-32gb-gddr6-4xdp-amd-rdna-tm-4

AMD ROCm Linux compatibility:
https://rocm.docs.amd.com/projects/radeon-ryzen/en/latest/docs/compatibility/compatibilityrad/native_linux/native_linux_compatibility.html

AMD ROCm Windows compatibility:
https://rocm.docs.amd.com/projects/radeon-ryzen/en/latest/docs/compatibility/compatibilityrad/windows/windows_compatibility.html

Linux PCI ROM documentation:
https://docs.kernel.org/PCI/sysfs-pci.html

flashrom manual:
https://manpages.debian.org/trixie/flashrom/flashrom.8.en.html

TechPowerUp VBIOS database:
https://www.techpowerup.com/vgabios/

## Important unresolved questions

1. Which exact SPI NOR flash IC does each board use?
2. Where is that chip located on each PCB revision?
3. What are the exact PCI device and subsystem IDs?
4. Which memory manufacturer and packages are installed?
5. Are vendor ROMs identical or different?
6. What changes in the ASUS fan-curve update?
7. Are clock, power and fan tables cryptographically signed?
8. Can any R9700 boot an unsigned modified ROM?
9. Which AMDVBFlash versions recognize R9700?
10. Does any R9700 model include dual-BIOS recovery?
11. Which power limits are driver-controlled versus firmware-controlled?
12. Is SR-IOV physically supported or officially enabled?
13. Why is ECC listed as Linux-only?
14. Which proposed changes provide measurable benefits?

## Research priorities

HIGH: Obtain original ROM dumps and physical flash-chip evidence.

HIGH: Analyze official ASUS firmware update and signature boundaries.

HIGH: Confirm hardware recovery before attempting modifications.

MEDIUM: Compare PCB revisions and memory manufacturers.

MEDIUM: Investigate driver-level tuning and feature restrictions.

LOW: Cross-flashing between unrelated models before compatibility
has been established.

@@ templates/card_inventory.csv
card_id,manufacturer,model,sku,pcb_revision,serial_reference,pci_vendor_id,pci_device_id,subsystem_vendor_id,subsystem_device_id,vbios_version,flash_chip_marking,flash_voltage,memory_marking,cooling,notes
CARD001,,,,,,,,,,,,,,,

@@ templates/rom_inventory.csv
rom_id,card_id,filename,source,acquisition_date,bytes,sha256,vbios_version,board_revision,read_1_matches_read_2,signature_status,notes
ROM001,,,,,,,,,,,

@@ templates/test_log.csv
test_id,date,card_id,rom_sha256,workload,duration_minutes,avg_gpu_clock_mhz,memory_rate_gbps,board_power_w,gpu_temp_c,hotspot_temp_c,fan_rpm,throughput,errors,result,notes
TEST001,,,,,,,,,,,,,,,
"""

def main():
    root = Path(FOLDER)
    root.mkdir(parents=True, exist_ok=True)

    parts = re.split(r"(?m)^@@ ([A-Za-z0-9_./-]+)\n", PACK)

    if parts[0].strip():
        raise ValueError("Unexpected text before first file marker.")

    created = []

    for index in range(1, len(parts), 2):
        relative_name = parts[index]
        content = parts[index + 1].strip() + "\n"

        destination = root / relative_name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
        created.append(destination)

    checksums = []

    for file in sorted(created):
        digest = sha256(file.read_bytes()).hexdigest()
        relative = file.relative_to(root)
        checksums.append(f"{digest}  {relative.as_posix()}")

    (root / "SHA256SUMS.txt").write_text(
        "\n".join(checksums) + "\n",
        encoding="utf-8"
    )

    zip_path = Path(f"{FOLDER}.zip")

    with ZipFile(zip_path, "w", ZIP_DEFLATED) as archive:
        for file in sorted(root.rglob("*")):
            if file.is_file():
                archive.write(
                    file,
                    arcname=file.relative_to(root.parent)
                )

    print()
    print("R9700 VBIOS RESEARCH PACK CREATED")
    print("--------------------------------")
    print(f"ZIP file: {zip_path.resolve()}")
    print(f"Documents and templates: {len(created)}")
    print("Includes SHA-256 manifest.")
    print()
    print("This is a research and engineering starter pack.")
    print("It does not contain a modified or flashable VBIOS.")

if __name__ == "__main__":
    main()