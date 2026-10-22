# XFX raw SPI capture compared with ASUS payloads

## Inputs and comparison scope

| Input | Size | SHA-256 | Status |
|---|---:|---|---|
| [XFX raw SPI capture](../original/stock-spi-capture.rom) | 2,097,152 bytes | `21aa437510552f5110edd26388e236b87cb47a96f86b4c17b4e20bf60b2ec876` | `R9700flash-dump` address-space read associated with XFX BDF `0000:03:00.0`; physical chip capacity and full-chip recovery coverage are unverified. |
| [ASUS AS04 payload](../../vendor-packages/asus/payloads/7551OG.23.8.0.68.AS04.rom) | 2,031,872 bytes | `0242ce25f406d61f7ff87c3e7be1324ad8f6e1066a2279e6b9ec03b736e60235` | ASUS updater payload, not a physical card read or established full-chip image. |
| [ASUS AS07 payload](../../vendor-packages/asus/payloads/7551OG.23.8.0.68.AS07.rom) | 2,031,872 bytes | `bee92e0a7092c9849b636bf0ec9eaf172c213cb3e34056bac40bc67c6150ecb4` | ASUS updater payload, not a physical card read or established full-chip image. |

The XFX capture and ASUS payloads have different acquisition coverage and lengths, so this report compares their matching PCIR option-ROM chains at the same raw/file offsets. It does not treat the ASUS files as full-chip images or draw a cross-flash compatibility conclusion.

## Structure and duplicate copies

The retained [ROM triage report](stock-spi-rom-triage.json), generated with `tools/rom_triage.py` SHA-256 `e386fa2d68a559452cb0ad466771e987c5e29a47e7358934c32e21e9362ae207` under Python 3.14.7, identifies two byte-identical option-ROM chains in the XFX address-space capture:

| Chain | Legacy PCIR image | EFI PCIR image | Total chain length |
|---|---|---|---:|
| 1 | `0x40000–0x4e600` (58,880 bytes) | `0x4e600–0x5ca00` (58,368 bytes) | 117,248 bytes |
| 2 | `0x120000–0x12e600` (58,880 bytes) | `0x12e600–0x13ca00` (58,368 bytes) | 117,248 bytes |

Both chains identify PCI vendor/device `1002:7551`; the legacy image checksum sums to zero modulo 256. The corresponding ASUS payloads have the same four PCIR boundaries and IDs, and each ASUS payload also repeats its two chains byte-for-byte. These repeated bytes do not establish a dual-BIOS switch or physical bank topology.

## Byte comparison

Each XFX chain is byte-identical to the other. Direct byte comparisons used equal-length slices at the PCIR offsets above with Python 3.14.7; the counts below are differing byte positions, without normalization. For either chain, the comparison found:

| Compared range | XFX vs AS04 | XFX vs AS07 | AS04 vs AS07 |
|---|---:|---:|---:|
| Legacy image (58,880 bytes) | 584 bytes differ | 588 bytes differ | 24 bytes differ |
| EFI image (58,368 bytes) | 5 bytes differ | 5 bytes differ | 4 bytes differ |
| Complete chain (117,248 bytes) | 589 bytes differ | 593 bytes differ | 28 bytes differ |

The XFX raw legacy image differs from the retained XFX driver-loaded software VBIOS at 8 byte positions in each duplicate copy. The software read came from the driver's VFCT-derived debugfs blob, so it is a separate firmware copy. Relative to the start of either legacy image, differences are at `0x21`, `0x2286`, `0x2384`, `0x239c`, and `0x23dc–0x23df`.

The XFX strings are `113-48WD6SHD1-P02` and `XFX_G2870200_XTW_32GB_APM107618`. The ASUS strings are `7551OG.23.8.0.68.AS04` / `7551OG.23.8.0.68.AS07` and `ASUS_G28702_XTW_32GB_PS_APM108117_300W`. All three images report `ATOMBIOSBK-AMD VER023.008.000.068.000001` and GOP revision `003.009.001.023.008`. Shared component version strings and near-matching EFI bytes do not establish that ASUS board settings are safe for the XFX card.

## Raw capture versus software VBIOS and aligned ATOM fields

The first 58,880-byte legacy chain at capture offset `0x40000` has the same length and bounded PCIR ID as the two retained driver-loaded software reads. The raw chain differs from either software read at eight byte positions: `0x21`, `0x2286`, `0x2384`, `0x239c` and `0x23dc–0x23df`, relative to the chain start. The second raw chain is byte-identical to the first. Both legacy images have valid zero-modulo-256 checksums. The software-ROM reporter warns that its PCIR last-image indicator is clear at end-of-file; that warning concerns chain completeness, not the checksum.

Five of the eight raw/software differences fall in two parsed ATOM records. Re-reading those records against the exact public v2.2/v3.5 definitions gives:

| Record and offset | Driver-loaded software VBIOS | Raw capture chain | Interpretation limit |
|---|---:|---:|---|
| `vram_usage_by_firmware` v2.2, `+0x0a` (`0x2286`) | Reserved `u16` is `0x0008` | Reserved `u16` is `0x0000` | Reserved bytes; no memory-capacity or timing meaning is assigned. |
| `firmware_info` v3.5, `+0x10` (`0x2384`) | `firmware_capability=0x00024001` | `firmware_capability=0x00024000` | The matched [public ATOM header](https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h) names `0x00000001` as `FIRMWARE_POSTED`; the raw and ASUS values clear that bit. This is a state/capability flag, not a performance control. |
| `firmware_info` v3.5, `+0x28` (`0x239c`) | `mc_baseaddr_high=0x00000080` | `mc_baseaddr_high=0x00000000` | A named memory-controller address field; no tuning implication is established. |
| `firmware_info` v3.5, `+0x68–0x6b` (`0x23dc–0x23df`) | `support_dev_in_objinfo=0x0688`; `display_phy_tuning_size=0x1618` | Both fields are zero | Public field names only; the difference does not establish a display capability or XFX runtime behavior. |
| Outside the parsed ATOM records (`0x21`) | `0xe7` | `0x2c` | Unmapped option-ROM byte. |

At matching image-relative offsets, the raw capture legacy chain differs from ASUS AS04 by 584 bytes and AS07 by 588 bytes. The driver-loaded software ROM differs by 591 and 595 bytes, respectively. The two XFX acquisition forms therefore do not produce interchangeable byte baselines.

The ATOM comparison of the raw chain against either ASUS payload has these same-revision record differences: `ATOM_ROM_HEADER` (8 bytes, with the header target shifted by eight bytes), `smc_dpm_info` v6.0 (6), `firmware_info` v3.5 (1), `unclassified_table_09` v3.3 (1), and `display_object_info` v1.5 (3). `firmware_info` differs only at the nonzero `pplib_pptable_id`: XFX `0x0000125b`, ASUS `0x00001296`. The raw chain's `firmware_capability=0x00024000`, `mc_baseaddr_high=0`, display-object support/PHY-size fields, and reserved VRAM value match ASUS; the software copy differs at those fields as listed above. UMC v4.0 and DCE v4.5 are byte-identical across the bounded legacy images; GFX_INFO v3.1 is also byte-identical but its body remains undecoded. Identical bytes do not establish common board wiring or image compatibility.

This comparison identifies no editable clock, voltage, general power-limit, memory-timing, fan-curve, ECC-enable, CU-enable, virtualization or physical-display field. The distinct XFX capture fields are either non-tuning metadata or reserved/unmapped bytes; board-specific SMC/DPM v6.0 remains opaque. The sourced benefit assessment is in [CUSTOM_VBIOS_BENEFIT_ASSESSMENT.md](CUSTOM_VBIOS_BENEFIT_ASSESSMENT.md).

## Limits

The ASUS payload files are 65,280 bytes shorter than the XFX 2 MiB capture, and the ASUS package was extracted from an updater archive. Only the bounded, corresponding PCIR chains were compared. No meaning is assigned here to the changed bytes beyond the version and board strings already identified in the existing [ASUS static analysis](../../vendor-packages/asus/ASUS_ROM_ANALYSIS.md). The changed ranges do not establish a fan-curve change, authentication coverage, GPU acceptance, board compatibility, or behavior.

The XFX file is a GPU-mediated read of the tool's configured 2 MiB address range. The fitted SPI part, JEDEC ID and physical capacity have not been inspected; there is no independent programmer read or retained second raw capture. It is not qualified as a standalone recovery image.
