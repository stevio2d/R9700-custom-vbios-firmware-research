# Firmware artifacts and per-card records


Two device-associated software VBIOS reads and one 2 MiB GPU-mediated raw SPI address-space capture are recorded for the XFX R9700 function at `0000:03:00.0`. The driver-loaded reads came from the AMDGPU debugfs blob; the host log says the driver fetched VBIOS from ACPI VFCT. The raw capture was made with `R9700flash-dump`; the fitted SPI capacity and full-chip recovery coverage remain unverified. See the [card record](xfx-r9700-0000-03-00-0/CARD.md) and [acquisition evidence](xfx-r9700-0000-03-00-0/evidence/ACQUISITION.md). The official ASUS update ZIP and two extracted ROM payloads remain unassociated under [`vendor-packages/asus/`](vendor-packages/asus/), with hashes and extraction details in its [acquisition record](vendor-packages/asus/ACQUISITION.md) and [`inventory/vendor_packages.csv`](../inventory/vendor_packages.csv); they are not identified as full-chip images. `_template/` is a form, not a physical GPU. Copy it for each additional card using the workflow in the [root README](../README.md).

## Layout


For the hypothetical card ID `r9700-asus-001`, the copy produces:

```text
bios/r9700-asus-001/
  CARD.md
  manifest.csv
  original/.gitkeep
  official/.gitkeep
  modified/.gitkeep
```

- `original/`: unmodified acquisitions from this physical card, including software ROM reads and full physical SPI reads. Preserve each independent read and its metadata.
- `official/`: untouched vendor packages and separately identified extracted payloads. Record source URL and acquisition details, and the package hash as the extracted payload's parent.
- `modified/`: derived candidate images; preserve the immediate parent image, exact changed offsets/bytes and experiment record.

Keep `.gitkeep` in empty directories. Photos and acquisition logs may be placed in a card's additional `evidence/` directory when real evidence exists. That directory is not pre-created. Record their paths in CARD.md and the acquisition notes.

## Unassociated vendor packages

Until a physical card can be associated, stage vendor downloads and extracted payloads under `bios/vendor-packages/<vendor>/`. Keep the package unchanged, put extracted payloads in a clearly named subdirectory such as `payloads/`, and record the package and every payload in [`inventory/vendor_packages.csv`](../inventory/vendor_packages.csv). Record source-page and direct-download URLs, acquisition date/method, actual byte count and SHA-256, vendor-published metadata and whether it matches, extraction tools/versions, and the package hash as each payload's parent. For nested formats, retain intermediate archive names and hashes in `extraction_details`. Do not add unassociated artifacts to per-card manifests or `inventory/roms.csv`, and do not label a vendor payload as full-chip recovery coverage without evidence.

## CSV conventions


All CSVs use UTF-8, a header row, comma delimiters and standard quoting for commas/newlines. Do not add comment lines or sample rows. IDs are globally unique; one physical card has one `card_id`. Blank values mean not yet recorded; use `unknown` in descriptive fields when inspected but unresolved. Numeric fields stay blank when unknown. Dates use ISO 8601, preferably UTC timestamps. SHA-256 values use 64 lowercase hexadecimal characters.

[manifest.csv](_template/manifest.csv) and [inventory/roms.csv](../inventory/roms.csv) share the same header and describe the same card-associated artifacts. Add one row per acquired or derived card artifact to both. Global ROM inventory is the union of per-card manifests; do not duplicate a `rom_id`. Identical bytes acquired twice remain separate acquisitions/rows with their own paths and IDs. A shared vendor package may be associated with multiple cards using separate rows/IDs only after that association is evidenced; before then, use the separate vendor package catalog.

| Field | Meaning |
|---|---|
| `rom_id`, `card_id` | Unique artifact acquisition/derivation ID; physical card ID matching CARD.md and cards.csv |
| `file_path` | Path from repository root, such as `bios/r9700-asus-001/original/stock-full-spi-read1.bin`; no absolute paths |
| `image_type` | `software_dump`, `raw_spi_capture`, `full_spi_image`, `vendor_package`, `extracted_payload`, or `modified_image`. Use `raw_spi_capture` when an address-space read exists but chip capacity or complete physical coverage has not been established. |
| `file_type` | Actual format: e.g. `pci_option_rom`, `raw_spi`, `zip`, `pe_executable`, or `unknown`; extension alone is insufficient |
| `source` | Physical card, vendor URL, or attributed community source; community images are comparison material until validated |
| `acquisition_date`, `acquisition_method` | When and how acquired; distinguish programmer read, software read, download, extraction and derivation |
| `tool`, `tool_version`, `acquisition_details` | Exact tools, adapter/BDF or JEDEC ID, setup/command and raw log path as applicable |
| `bytes`, `sha256` | Measured byte length and hash of this actual file; package and payload hashes are separate |
| `parent_sha256` | Immediate parent image hash for modifications; package hash for extraction; blank for direct acquisitions |
| `vbios_version`, `board_revision` | Actual parsed version and target board revision; record unknown rather than guessing from a source |
| `read_group`, `read_1_matches_read_2`, `repeat_read_status` | Group of independent reads; `yes`/`no` for the first pair, and e.g. `three_identical` or `mismatch` for full read evidence; blank if not applicable |
| `signature_status` | Evidence-based authentication status, normally `unknown`; a checksum or successful write is not proof of signature acceptance |
| `experiment_id`, `notes` | Derivation/validation experiment when applicable; explanatory evidence and limitations |

For the central vendor catalog, compare the local package hash with the vendor's published digest instead of copying it as a measurement. Do not call an extracted payload a complete SPI image without demonstrating its coverage and matching the identified chip capacity.

## Card and test inventory fields


[cards.csv](../inventory/cards.csv) retains the supplied identity fields and adds board-family, PCI revision, JEDEC/capacity, memory-population and VRM information. `serial_reference` can refer to a retained private label/photo rather than expose a full serial. `board_family` is `R9700` or explicitly `R9700S`; `flash_voltage` is volts and `flash_capacity_bytes` is bytes. `flash_voltage` must reflect the exact datasheet and verified setup, not a guess. `stock_rom_sha256` identifies the preserved baseline; CARD.md identifies whether it is software or full SPI. `card_record_path` points to the card's CARD.md.

[test_log.csv](../inventory/test_log.csv) contains one row per actual run, with a unique `test_id` and the experiment's `experiment_id`. Record `card_id` and the running image's `rom_sha256`, an optional `baseline_test_id`, environment, workload/version, duration, metrics, error evidence and result. Keep units explicit: effective memory data rate in Gbit/s, clocks in MHz, temperatures in °C, board power in W and fan in RPM. Record throughput units separately. `errors` may contain a count or a concise diagnosis; raw evidence belongs at `log_path`. Results are `pass`, `fail` or `inconclusive`; planned runs have no row yet. Use blank metrics for unavailable sensors and explain limitations in `notes`.

## Acquisition and modification rules


Follow [collection](../docs/03_VBIOS_Collection_and_Diff.md), [identification](../docs/04_SPI_Flash_Identification.md), [recovery](../docs/05_Flashing_Backup_and_Recovery.md) and [security](../docs/06_Firmware_Security_and_Protections.md) gates. A software dump may cover less than the physical chip. Keep immutable originals and a separate recovery copy. Source-reported IDs and hashes are research leads, not evidence that a file belongs to a physical card.
