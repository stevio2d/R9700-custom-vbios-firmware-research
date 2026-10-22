# Radeon AI PRO R9700 firmware research


This repository organizes three supplied research documents into a working plan for the modern AMD Radeon AI PRO R9700. The objective is to establish feasibility, then develop and validate a recoverable custom VBIOS with measurable benefits. See [GOAL.md](GOAL.md) for the acceptance criteria and [TODO.md](TODO.md) for the work queue.

## Repository map

| Path | Contents |
|---|---|
| `docs/` | Eleven ordered research chapters, linked below |
| `bios/` | Physical-card records, preserved images, vendor packages and the card template |
| `flashing/` and `ports/` | Capture utilities, read-only tooling and the native reader source |
| `inventory/` | Card, firmware, package, host-check and test records |
| `experiments/` | Experiment plans, findings and retained run evidence |
| `sources/originals/` | The three supplied source files, preserved byte-for-byte |
| `tools/` and `tests/` | Offline analysis helpers and repository checks |

Working records use generic labels for the capture host and operator, omit private network addresses, hardware UUIDs and local home paths, and preserve firmware image bytes. Experiment hash indexes refer to the redacted working copies. The supplied files under `sources/originals/` remain unchanged.

**Current state:** one XFX R9700 device record is tied to host BDF `0000:03:00.0`, with two byte-identical 58,880-byte driver-loaded software VBIOS reads and one 2 MiB GPU-mediated raw SPI address-space capture from `R9700flash-dump`. The software reads came from an ACPI VFCT-derived driver blob. The raw capture contains two duplicate option-ROM chains, but the fitted SPI capacity and full-chip recovery coverage remain unverified. The exact retail SKU, board-label serial and PCB revision remain unknown. No modified images, firmware writes, custom-image boots or firmware rollbacks have been recorded; runtime workload measurements are retained in [EXP-0001](experiments/EXP-0001.md), [EXP-0002](experiments/EXP-0002.md) and [EXP-0003](experiments/EXP-0003.md); no custom R9700 BIOS or flashing procedure has been validated. One official ASUS update ZIP and two ROM payloads extracted from it are retained under `bios/vendor-packages/asus/`, with measured hashes and extraction provenance in the [acquisition record](bios/vendor-packages/asus/ACQUISITION.md) and [vendor package catalog](inventory/vendor_packages.csv). Those vendor files remain unassociated with a physical card and are not identified as full-chip SPI images. See the [XFX device record](bios/xfx-r9700-0000-03-00-0/CARD.md), its [acquisition evidence](bios/xfx-r9700-0000-03-00-0/evidence/ACQUISITION.md), and the [read/write guide](flashing/README.md).

The [source-built native reader](ports/r9700-reader/README.md) provides cached inventory and bounded native file inspection, checksum and comparison commands alongside its separate synthetic acquisition core. Physical `identify` and `backup` commands remain disabled because controller protocol, exact build provenance and physical coverage are unqualified. The separately built `R9700flash-dump` produced the retained raw address-space capture; that capture does not qualify the reader or a full-chip recovery route.

No existing physical backup interface is qualified. The driver stays unchanged,
physical commands remain disabled, and no driver-extension fallback is selected.

R9700 is the primary target. The passive **R9700S is a separate board family**, included only as explicitly labelled comparison material. Neither is the ATI Radeon 9700 from 2002.

## Research chapters


1. [Vendors, models and revisions](docs/01_Vendors_and_Models.md)
2. [GPU, memory and hardware](docs/02_GPU_Memory_and_Hardware.md)
3. [VBIOS collection and binary comparison](docs/03_VBIOS_Collection_and_Diff.md)
4. [SPI flash identification](docs/04_SPI_Flash_Identification.md)
5. [Flashing, backup and recovery](docs/05_Flashing_Backup_and_Recovery.md)
6. [Firmware security and protections](docs/06_Firmware_Security_and_Protections.md)
7. [Custom VBIOS engineering roadmap](docs/07_Custom_VBIOS_Engineering_Roadmap.md)
8. [Gated features and unlock hypotheses](docs/08_Gated_Features_and_Unlocks.md)
9. [Performance modification priorities](docs/09_Performance_Modification_Priorities.md)
10. [Laboratory test plan](docs/10_Laboratory_Test_Plan.md)
11. [Sources, disagreements and research gaps](docs/11_Sources_and_Research_Gaps.md)

## Evidence and provenance


The [source index](sources/README.md) identifies the three byte-preserved originals, their hashes, and unavailable sandbox downloads. Initial setup did not include fresh external checks; a follow-up pass on 2026-10-18 independently checked selected vendor, AMD and software references, recorded in chapter 11. Citation/image tokens in the originals remain unresolved references unless a separate checked URL is recorded.

Use these labels for future evidence:

- **INHERITED:** a claim from a supplied source; even a source's “verified” label remains inherited here.
- **VERIFIED:** a primary reference actually inspected and recorded with URL, access date and relevant excerpt or archived evidence.
- **OBSERVED:** a reproducible measurement tied to a physical card, image hash, tool version and retained logs.
- **HYPOTHESIS / INFERRED:** an explanation or deduction requiring a test.
- **UNKNOWN:** evidence is missing or conflicting.

Writing flash bytes, passing a structural checksum, and passing cryptographic authentication are distinct. A programmer does not establish that the GPU will accept an edited image. Feasibility remains unknown.

## Read or write a VBIOS

The [Linux capture tool](tools/linux_spi_capture.py) provides offline
planning/verification and a bounded BDF-resolved software-dump interface. A
separate read-only `R9700flash-dump` capture is stored with the XFX card record;
its 2 MiB address extent does not establish fitted chip capacity or full-chip
recovery coverage. Any future live hardware operation requires separate explicit
task authorization and a documented target, scope, cleanup, rollback and recovery
plan.

The [flashing guide](flashing/README.md) distinguishes software VBIOS backups from full-chip SPI reads and describes the prerequisites for a future write. Its AMDVBFlash command forms are inherited examples, not verified R9700 instructions. Any firmware write is at your own risk and can leave a card unusable; follow the recovery and authentication gates in chapters 4–7.

## Add a physical GPU


For each newly inspected physical card, choose a stable lowercase ID, for example `r9700-asus-001`. That ASUS ID remains illustrative; the existing XFX device record uses its host and PCI BDF. Copy the [BIOS template](bios/_template/) for another card:

```sh
cp -R bios/_template bios/r9700-asus-001
```

Fill in `bios/r9700-asus-001/CARD.md` from that card's labels, PCI enumeration, photos and inspection. Add one matching `card_id` to [inventory/cards.csv](inventory/cards.csv). Keep unknown values explicit and distinguish reported specifications from observations. Create a new card ID for every physical card, including otherwise identical units; record PCB revisions separately.

## Add a BIOS image or vendor package


Follow [bios/README.md](bios/README.md). For an artifact tied to a physical card, preserve it in that card's `original/` or `official/` directory and derivatives in `modified/`; record it in both the card's `manifest.csv` and [inventory/roms.csv](inventory/roms.csv) with matching fields. For a vendor package not associated with a card, stage it under `bios/vendor-packages/<vendor>/` and record it in [inventory/vendor_packages.csv](inventory/vendor_packages.csv) without inventing a card ID. Record actual byte length, SHA-256, parent package hash for extracted payloads, and extraction details. Identify software dumps, full SPI images, packages, extracted payloads and modified images explicitly; they are not interchangeable.

Example paths for another card are `bios/r9700-asus-001/original/stock-software-read1.rom` and `bios/r9700-asus-001/original/stock-full-spi-read1.bin`. The existing XFX software reads are stored in its per-card `original/` directory. Hash files after acquisition; a filename or source-reported package hash is not a measurement of a local ROM.

## Add an experiment


Copy [templates/experiment.md](templates/experiment.md) to a new `experiments/EXP-NNNN.md`, assign an unused experiment ID, and complete the hypothesis, baseline, gates and rollback plan before testing. Follow [experiments/README.md](experiments/README.md) and chapter 10. Add actual test runs to [inventory/test_log.csv](inventory/test_log.csv), link raw evidence from the experiment, and record negative results. A plan is not a completed test.

## Repository conventions


The card and ROM inventories now include one evidence-backed XFX device record and its two matching software reads; the test log records actual runtime workload runs linked to their retained evidence. The vendor package catalog contains the unassociated ASUS package and its two extracted payloads. Empty template BIOS directories are retained by `.gitkeep`. BIOS binaries and vendor archives may be tracked; caches and temporary files are ignored by [.gitignore](.gitignore). Preserve acquisitions rather than overwriting them. Repository workflow is documented in [AGENTS.md](AGENTS.md).

The ASUS updater was not executed. A dependency-free read-only [ROM triage tool](tools/rom_triage.py) was run on both ASUS payloads, the XFX software capture and the retained XFX raw SPI address-space capture. Read-only checks on the capture host identified four AMD Radeon AI PRO R9700 functions with XFX subsystem ID `1eae:9801`; the [host check record](inventory/host_checks.md) preserves their BDFs and reported Samsung memory, ECC state, PCI capabilities, PCIe topology and kernel messages. The XFX raw capture agrees with the tool documentation's two duplicate ROM chains and differs from the driver-loaded legacy VBIOS at eight byte positions in each copy. Its complete-chip coverage remains unverified because the physical SPI capacity is unknown and no independent programmer read is retained. Physical board labels, exact XFX product numbers and PCB revisions remain unknown. No firmware write, custom-image boot or rollback has occurred. Further source research may still be needed for unresolved report citations and board-specific claims.
