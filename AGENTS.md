# Repository facts and workflow


## Scope and state


This is documentation and research scaffolding for the modern AMD Radeon AI PRO R9700. R9700S is a separate passive board family. One XFX R9700 device record is tied to host BDF `0000:03:00.0`, with two identical driver-loaded software VBIOS reads and one 2 MiB `R9700flash-dump` address-space capture. The kernel log says the software VBIOS came from ACPI VFCT; the raw capture's configured extent has not been verified against the fitted chip capacity and is not qualified as a recovery image. The exact retail SKU, board-label serial and PCB revision remain unknown; see `bios/xfx-r9700-0000-03-00-0/CARD.md` and `inventory/host_checks.md`. No successful firmware edits are recorded. Runtime workload measurements are retained in `experiments/EXP-0001.md`, `experiments/EXP-0002.md` and `experiments/EXP-0003.md`; they do not validate firmware changes. One official ASUS vendor package and two extracted ROM payloads remain unassociated under `bios/vendor-packages/asus/`. GOAL.md defines success; TODO.md tracks pending work.

## Sources and claims


- Keep the three supplied files under `sources/originals/` byte-identical to the inputs; edit working chapters under `docs/` instead.
- `notes.md` contains a generator and embedded chapters. Extract literal text only; do not execute or import it.
- Attribute inherited claims to N, R1 or R2 as defined in `sources/README.md`. Unresolved citation/image tokens are not verified references. Preserve disagreements as research questions in chapter 11.
- Keep external source leads distinguishable from references actually checked and measurements made in this project. Record URLs, dates, image hashes, tool versions and logs for new evidence.
- Do not imply successful flashing, working edits or validation without retained evidence. Hardware tasks stay unchecked until performed.

## Artifacts and records


- Copy `bios/_template/` to `bios/<gpu-id>/` for each physical card. Use the same ID as `card_id` in the inventories.
- Stage unassociated vendor downloads and extracted payloads under `bios/vendor-packages/<vendor>/`; record each package or payload in `inventory/vendor_packages.csv` with actual hashes, source, acquisition date, extraction details and parent package hash. Do not add these artifacts to card manifests or `inventory/roms.csv` until a physical card is identified and the association is evidenced.
- Preserve acquisitions in `original/` or `official/`; derivatives belong in `modified/`. Keep `.gitkeep` in otherwise empty directories.
- Distinguish software dumps, full SPI images, vendor packages, extracted payloads and modified images in metadata. A package or partial image is not a full-chip recovery image.
- Record every card-associated artifact in its per-card manifest and `inventory/roms.csv`; shared fields must agree and paths must be repository-relative. Record unassociated vendor packages and extracted payloads in `inventory/vendor_packages.csv` instead. Hash actual files, not filenames or copied source claims.
- Every derivative needs a parent-image SHA-256 (or package hash for an extracted payload) and a change/extraction record. Never overwrite the only original or recovery copy.
- Experiments use `templates/experiment.md`; actual test runs use `inventory/test_log.csv`. Every row must identify a real run and point to retained evidence. Do not add sample hardware or placeholder test rows.
- BIOS binaries and official archives may be tracked. Keep temporary output and caches ignored without broadly ignoring firmware extensions.

## Verification for documentation updates


Check all local Markdown links outside the immutable originals, exactly eleven chapters with README links, well-formed CSVs with consistent card manifest/ROM inventory headers, example paths against the template, and byte/SHA-256 preservation of originals. Keep card and ROM inventory rows synchronized with each physical-card record and per-card manifest. `test_log.csv` may contain actual runs with retained evidence, but no sample rows. `vendor_packages.csv` may contain sourced unassociated packages and extracted payloads. The template's three artifact directories must contain only `.gitkeep`.

For routine documentation maintenance, do not download new firmware, run source-embedded or documented firmware commands, flash hardware, or perform fresh external research unless the task explicitly calls for it. Static archive listing/extraction and the read-only ROM reporter are allowed for an explicit source-audit task. Hardware testing, flashing, commits and publication remain separate work. Firmware research must follow the recovery and authentication gates in chapters 4–7.

`tools/linux_spi_capture.py` provides offline `plan`/`verify` and a live software
VBIOS capture interface; its SPI capture mode is disabled. A separate
`R9700flash-dump` utility in `flashing/` has one retained 2 MiB address-space
read, without physical chip-capacity qualification. Any future live hardware
capture or identification requires separate explicit task authorization and a
documented target, scope, cleanup, rollback and recovery plan.
Run `python3 -m unittest discover -s tests -v` and
`python3 tools/check_repository.py` for offline verification.

The source-built reader core is under `ports/r9700-reader/`. Build only into a
fresh repository `.cache/` directory. The production native `identify`/`backup`
commands fail closed; the separately linked mock is synthetic and never belongs
in card manifests, ROM inventories or hardware test logs. Exact deployed-module
provenance, controller protocol and physical geometry/topology remain unqualified.

No physical backup interface is qualified. No driver-extension fallback is
selected; production physical commands remain disabled.
