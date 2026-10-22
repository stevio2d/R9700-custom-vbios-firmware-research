# Supplied sources and provenance


Three user-supplied files were copied unchanged into `sources/originals/` on 2026-10-18. The source author, model/session history and external references behind the reports have not been independently established. Preserve the supplied filenames and exact bytes; use `docs/` for corrections and consolidation. The supplied originals were not edited.

| ID | Preserved file | Bytes | SHA-256 of supplied bytes |
|---|---|---:|---|
| N | [notes.md](originals/notes.md) | 33239 | `45e68d173460e2339c3d9691e4f40bb2af03217ce6a438859a1858c631bd8a5b` |
| R1 | [deep-research-report.md](originals/deep-research-report.md) | 25511 | `0dd43835e1fe4422d11898e1c96e006401ebbb6f0fce04fadc4b327e744b9c30` |
| R2 | [deep-research-report (1).md](originals/deep-research-report%20%281%29.md) | 50625 | `87a08888fc655a8718427ef8788b93970b99573795d7862097d9832f72f6f443` |

- **N:** supplied generator text, with literal embedded chapters and CSV headers. Its embedded README calls the pack initial research rather than completed reverse engineering.
- **R1:** the custom VBIOS research report, with a stated 2026-10-18 research cut-off and active R9700 scope; includes reported ASRock/ASUS identifiers and comparison leads.
- **R2:** the development/modification/recovery report, including separately labelled passive R9700S material, package metadata and programming research.

## Extraction and consolidation


The working chapters began with the literal `PACK` sections between N's `@@` markers. The generator was **not executed or imported**. CSV headers were adapted into the empty working inventories and manifest; example `CARD001`, `ROM001` and `TEST001` rows were removed. Chapter text was then consolidated with R1/R2, keeping material disagreements and evidence limitations in [chapter 11](../docs/11_Sources_and_Research_Gaps.md). All eleven chapters link to the preserved originals.

All eleven chapters link these originals directly. A follow-up pass on 2026-10-18 checked selected vendor, AMD, ROCm and firmware-format references; URLs, dates and claim limits are recorded in chapter 11. The ASUS support ZIP was downloaded and its local size/hash match the page's published metadata. Two named ROM payloads were statically extracted and hashed; neither is associated with a physical card or identified as a full-chip image. The generic reporter and ASUS-specific bounded analysis are documented in chapter 3 and retained as [human-readable findings](../bios/vendor-packages/asus/ASUS_ROM_ANALYSIS.md) plus [structured data](../bios/vendor-packages/asus/ASUS_ROM_ANALYSIS.json). The ASUS updater was not executed, and no firmware write or hardware validation occurred. A later host investigation is recorded in the [host check log](../inventory/host_checks.md); it includes two matching driver-loaded software VBIOS reads for BDF `0000:03:00.0` and a separate 2 MiB GPU-mediated raw SPI address-space capture. The raw capture has not been matched to an identified physical chip capacity or an independent programmer read. N's remaining URLs and the old session-local citation tokens remain research leads unless a specific checked URL is recorded.

## Unavailable linked artifacts


R1 advertises `sandbox:/mnt/data/R9700_VBIOS_Research_Pack_2026-10-18.zip` and an 18-file pack, including diagrams, an annotated PCB figure, source JSON and hash manifest. R2 contains an inline recovery flowchart and workflow examples as report text, not separate acquired pack artifacts. That sandbox download and its advertised artifacts were not included in the three supplied files and are not available here. They have not been reconstructed or represented as acquired evidence.

The reports' citation and image tokens are session-local unresolved references. They are preserved verbatim only in the originals; no source artifact for the linked PCB photographs, ROMs, signature bypass or successful modified image was supplied. Some related public URLs were found and inspected, but no one-to-one mapping from an old token to a URL is recoverable. The ASUS package and extracted payloads now have local hashes and an acquisition record; those measurements do not establish card association or image acceptance. Use the [root README](../README.md) for evidence labels and contribution workflows.
