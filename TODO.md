# Research work queue


Card-specific research and hardware tasks remain pending. Completed research items are checked off with links to their retained evidence; inherited statements and example paths do not count as completed work. Record evidence before checking anything off.

## P0 — Identify, back up and establish recovery


- [ ] Complete physical identification for the selected XFX device: record its retail product number, PCB revision, board-label serial reference, photos and outputs. BDF `0000:03:00.0` now has a provisional device record with PCI identity; unique ASIC identifiers are redacted, and labels and exact board details remain unknown. [Card record](bios/xfx-r9700-0000-03-00-0/CARD.md), [chapter 1](docs/01_Vendors_and_Models.md) and [host record](inventory/host_checks.md)
- [ ] Record stock clocks, temperatures, fan behavior, power, drivers and reproducible workload baseline. [Chapters 2](docs/02_GPU_Memory_and_Hardware.md) and [10](docs/10_Laboratory_Test_Plan.md). [EXP-0001](experiments/EXP-0001.md) captures one default workload run and telemetry, but does not establish a reproducible baseline: there was no prior control run, ambient or fan reading, effective GDDR rate, or validated card-specific thermal/power limit. [EXP-0002](experiments/EXP-0002.md) adds matched three-repeat release measurements and fan telemetry; ambient, effective GDDR rate and exact-board limit qualification remain absent.
- [ ] Identify DRAM markings, population, VRM controller/power stages and board differences without assuming an RX 9070 BOM. [Chapter 2](docs/02_GPU_Memory_and_Hardware.md)
- [ ] Identify the exact SPI device, suffix, package, location, voltage, capacity and JEDEC ID; verify programmer rails and signal levels. No physical SPI device has been inspected. [Chapter 4](docs/04_SPI_Flash_Identification.md)
- [x] Collect two byte-identical software VBIOS reads for XFX device `0000:03:00.0`; archive both files, hashes and acquisition evidence. These are the AMDGPU driver's debugfs blob, and the host log says VBIOS came from ACPI VFCT, so equivalence to the physical SPI contents is unverified. [Card record](bios/xfx-r9700-0000-03-00-0/CARD.md) and [acquisition evidence](bios/xfx-r9700-0000-03-00-0/evidence/ACQUISITION.md)
- [ ] After identifying the SPI device, establish compatible programmer/card support and collect three identical full-chip reads; retain a separate recovery copy. One 2 MiB GPU-mediated address-space capture exists, but the SPI device and its capacity have not been identified, and the capture is not qualified for recovery. [Chapters 4](docs/04_SPI_Flash_Identification.md) and [5](docs/05_Flashing_Backup_and_Recovery.md)
- [ ] Demonstrate stock restoration and post-restore validation through the physical recovery route before an experimental firmware write. [Chapter 5](docs/05_Flashing_Backup_and_Recovery.md)
- [x] Implement and offline-test BDF-resolved Linux software capture, evidence planning, acquisition verification, bounded PE-resource extraction and the source-built reader's synthetic acquisition core. These tools do not perform a physical SPI read or firmware modification. See [Linux capture](tools/linux_spi_capture.py), [PE resources](tools/pe_resources.py) and the [native reader](ports/r9700-reader/README.md).
- [ ] Qualify a physical identification/read route, including chip identity and capacity, controller protocol, deployed-module provenance, cleanup and complete address coverage. The retained `R9700flash-dump` image covers a configured 2 MiB range; this does not establish fitted chip capacity or full-chip recovery coverage. Any live hardware operation needs separate explicit task authorization and a documented target, scope, cleanup, rollback and recovery plan. See [chapters 4](docs/04_SPI_Flash_Identification.md) and [5](docs/05_Flashing_Backup_and_Recovery.md).
- [ ] Complete target-applicable read-only inspection of EFI/PSP, live advanced information, firmware versions and partition status. Cached inventory and file inspection remain offline-only; they do not establish physical transport or live feature coverage. See the [native reader](ports/r9700-reader/README.md).

## P1 — Establish firmware provenance and feasibility


- [ ] Recover the remaining primary references behind unresolved source tokens and reconcile the source disagreements; selected vendor, AMD and software claims are now independently checked, while sample observations remain unresolved. [Chapter 11](docs/11_Sources_and_Research_Gaps.md)
- [x] Acquire and independently hash the ASUS official update package; statically extract and hash both payloads without executing the updater, preserving package-to-image provenance. The package size and digest match ASUS's listing. This does not establish association with a physical card. [Acquisition record](bios/vendor-packages/asus/ACQUISITION.md) and [chapter 3](docs/03_VBIOS_Collection_and_Diff.md)
- [ ] Collect same-board stock/vendor images before and after an official update. The ASUS AS04/AS07 package payloads now have a bounded diff and retained byte map, but neither is associated with a physical card. [ASUS analysis](bios/vendor-packages/asus/ASUS_ROM_ANALYSIS.md) and [chapter 3](docs/03_VBIOS_Collection_and_Diff.md)
- [x] Complete a read-only, revision-aware map of the existing ASUS package/payloads, XFX software-ROM sample and bounded XFX raw-SPI-to-ASUS PCIR comparison. Supported structures, GOP PE and legacy x86 code are statically analyzed; updater and GOP PE signer signatures plus signed PE digests are checked; every ASUS payload byte is classified, and unsupported bodies/runtime behavior remain explicitly unresolved. This does not establish ASUS card association, GPU-side VBIOS authentication, hardware behavior or compatibility. [ROM triage reporter](tools/rom_triage.py), [XFX/ASUS comparison](bios/xfx-r9700-0000-03-00-0/evidence/XFX_ASUS_COMPARISON.md), [ASUS analysis and Ghidra sidecars](bios/vendor-packages/asus/ASUS_ROM_ANALYSIS.md), [chapter 7](docs/07_Custom_VBIOS_Engineering_Roadmap.md)
- [ ] Establish which candidate regions are authenticated, which components enforce checks, and which are controlled by SMU/driver/hardware policy. [Chapter 6](docs/06_Firmware_Security_and_Protections.md)
- [ ] Test useful runtime controls before deciding whether a persistent firmware change offers a benefit. [Chapter 9](docs/09_Performance_Modification_Priorities.md)

## P2 — Controlled modification and validation


- [ ] Define one well-understood minimal modification, exact parent hash, byte diff, integrity checks and go/no-go criteria; do not start with a power increase or speculative feature unlock. [Chapter 7](docs/07_Custom_VBIOS_Engineering_Roadmap.md)
- [ ] Run a recoverable acceptance experiment and distinguish flasher refusal, initialization failure, accepted change and inconclusive result. [Chapter 6](docs/06_Firmware_Security_and_Protections.md)
- [ ] Validate cold/warm boot, both declared OS/driver stacks, all required functions, sustained compute, memory correctness, thermals and logs. [Chapter 10](docs/10_Laboratory_Test_Plan.md)
- [ ] Measure benefit against repeated stock runs; demonstrate rollback, stock retest and candidate revalidation. [Chapter 10](docs/10_Laboratory_Test_Plan.md)
- [ ] Repeat identification, recovery and validation for each additional physical card and PCB revision; do not generalize one success. [Chapter 7](docs/07_Custom_VBIOS_Engineering_Roadmap.md)

## P3 — Specific feature investigations


- [x] Record AMD's published ECC OS label, current ROCm support matrices and current published SR-IOV matrix, with access dates and limits. This does not establish card-specific behavior. [Chapters 8](docs/08_Gated_Features_and_Unlocks.md) and [11](docs/11_Sources_and_Research_Gaps.md)
- [x] Observe Linux ECC reporting and PCI virtualization exposure on four AMD SMI-identified Radeon AI PRO R9700 functions. The host kernel reports MEM ECC active, GECC disabled and SRAM ECC not presented; privileged PCI capability output lists no SR-IOV capability. This does not test ECC correction under workload or establish behavior for other XFX SKUs/PCB revisions. [Chapter 8](docs/08_Gated_Features_and_Unlocks.md) and [host record](inventory/host_checks.md)
- [ ] Trace one requested feature through hardware, firmware, subsystem policy, driver and application gates; stop if the necessary hardware is absent. [Chapter 8](docs/08_Gated_Features_and_Unlocks.md)
- [ ] Evaluate power or memory changes only after identifying the bottleneck, hardware limits, authentication route and recovery evidence. [Chapter 9](docs/09_Performance_Modification_Priorities.md)

- [x] Run scoped custom HIP compute-kernel trials against unchanged Radiance 1.9.0.
  [EXP-0003](experiments/EXP-0003.md) records exact kernel checks and three matched
  repeats for GDN and MoE. Both candidates stay experimental: full-model gains
  did not meet the promotion threshold. Production 1.6.0 was restored. This is
  runtime evidence and does not qualify firmware changes.
