# XFX VBIOS and raw SPI capture acquisitions

## Target and provenance

- **Acquired:** 2026-10-18.
- **Host:** `capture-host` (`REDACTED_HOST_IP`).
- **GPU function:** `0000:03:00.0`, PCI `1002:7551`, subsystem `1eae:9801` (XFX Limited), PCI revision `c0`.
- **AMD SMI ASIC ID:** redacted in this public copy; it is not the board-label serial.
- **Reported VBIOS identifier:** `113-48WD6SHD1-P02`.
- **OS/kernel:** Ubuntu 24.04.4 LTS, Linux `7.0.14-custom-nogpu`.
- **Acquisition type:** read-only software capture of the Linux AMDGPU driver's per-device `amdgpu_vbios` debugfs blob. The host boot log says the driver fetched VBIOS from ACPI VFCT.

The captured bytes are tied to this driver instance and BDF. The current evidence does not prove they are byte-for-byte identical to the physical card's SPI contents. This is a software VBIOS capture, not a full SPI image or a standalone brick-recovery backup.

## Capture and repeatability

The PCI sysfs ROM access at `/sys/bus/pci/devices/0000:03:00.0/rom` was attempted first. Reading it returned `EIO`; cleanup disabled the ROM resource. This changed transient sysfs resource-access state, not firmware contents. The retained stderr is an I/O traceback and does not preserve the exact control command sequence; it is available in [failed-sysfs-rom-read.stderr.log](failed-sysfs-rom-read.stderr.log). No bytes from that attempt were kept as an acquisition.

The driver-exposed blob was then read twice, in separate SSH commands, without unbinding or resetting the GPU:

```sh
ssh -o HostKeyAlias=REDACTED_HOST_IP REDACTED_HOST_IP \
  'sudo -n cat /sys/kernel/debug/dri/0000:03:00.0/amdgpu_vbios' \
  > bios/xfx-r9700-0000-03-00-0/original/stock-software-read1.rom

ssh -o HostKeyAlias=REDACTED_HOST_IP REDACTED_HOST_IP \
  'sudo -n cat /sys/kernel/debug/dri/0000:03:00.0/amdgpu_vbios' \
  > bios/xfx-r9700-0000-03-00-0/original/stock-software-read2.rom
```

| File | Bytes | SHA-256 |
|---|---:|---|
| [stock-software-read1.rom](../original/stock-software-read1.rom) | 58,880 | `aad3d6957f284a0cce130f8e106ea7a1118ba9bf1bf86b26d86a28ca11d0bc8d` |
| [stock-software-read2.rom](../original/stock-software-read2.rom) | 58,880 | `aad3d6957f284a0cce130f8e106ea7a1118ba9bf1bf86b26d86a28ca11d0bc8d` |

The two files compared byte-for-byte equal with `cmp`. The first two bytes are `55 aa`. The ROM contains `113-48WD6SHD1-P02` and `AMD ATOMBIOS` strings.

## Raw SPI address-space capture

- **Acquisition date:** 2026-10-19, based on the retained file's local filesystem creation/modification date; no command transcript with a timestamp was retained.
- **Host / target:** `capture-host`, PCI BDF `0000:03:00.0`, PCI `1002:7551`, subsystem `1eae:9801`.
- **Method:** read-only Navi48 `ROM_INDEX`/`ROM_DATA` MMIO address-space read through the PCI register BAR, using `R9700flash-dump` version `0.1.0` as described in the [tool documentation](../../../flashing/docs/r9700flash-dump.md).
- **Original staged path:** `flashing/XFX-R9700-03-00.0.spi.rom`; it has been placed in this card's `original/` directory without changing its bytes.
- **Retained file:** [stock-spi-capture.rom](../original/stock-spi-capture.rom), 2,097,152 bytes, SHA-256 `21aa437510552f5110edd26388e236b87cb47a96f86b4c17b4e20bf60b2ec876`.
- **Repeatability:** the tool documentation reports two consecutive 2 MiB reads from this BDF compared byte-identically. Only one raw capture file is retained here; the second file and exact command/output log are not present.

The retained [raw ROM triage report](stock-spi-rom-triage.json) identifies two byte-identical PCIR chains, each containing a 58,880-byte legacy image and a 58,368-byte EFI image. Their starts are `0x40000` and `0x120000`; both identify PCI `1002:7551`. The legacy image checksum sums to zero modulo 256. This structural result confirms the ROM contents are plausible and bounded; it does not prove the physical SPI part's size or full-chip coverage.

The capture is a GPU-mediated read of the tool's configured 2 MiB address range. No physical SPI marking, JEDEC ID, voltage or chip capacity has been observed, and no independent programmer read has been compared. Treat it as a raw SPI address-space capture, not a qualified full-chip recovery image. See the [XFX/ASUS comparison](XFX_ASUS_COMPARISON.md) for a bounded comparison with the ASUS updater payloads.

## Read-only structure report

The repository's `tools/rom_triage.py` was run against read 1 using local Python 3.14.7. Its [JSON report](rom-triage.json) records one length-bounded legacy PCIR image (vendor `1002`, device `7551`) of 58,880 bytes and 19 ATOM structures. Its legacy 8-bit checksum is zero modulo 256. The parser emitted one warning: the PCIR image indicator does not mark this image as last even though no bytes remain. The image's advertised length fits the file, but the warning leaves whole-chain completeness unresolved. The checksum is a structural check only; it does not establish authenticity, signature acceptance, or flash coverage.

- Analyzer: `tools/rom_triage.py`, SHA-256 `e386fa2d68a559452cb0ad466771e987c5e29a47e7358934c32e21e9362ae207`.
- Analyzer runtime: Python 3.14.7.
- Capture tools: Linux AMDGPU debugfs, GNU coreutils `cat` 9.4, and OpenSSH `10.2p1`.

## Limits

- The host boot log says VBIOS was fetched from ACPI VFCT. The debugfs bytes therefore document the image exposed by the initialized driver; they do not independently establish the bytes stored on the card's SPI NOR.
- No JEDEC ID, SPI voltage, physical flash capacity, partition layout, or write-protect state was obtained. One 2 MiB GPU-mediated raw address-space capture is now retained, but its extent has not been matched to an identified physical chip and it is not qualified as a full-chip recovery image.
- No firmware image was written. The unsuccessful PCI sysfs attempt only involved transient ROM-resource access state as described above. No updater, programmer, driver unbind, reset, or workload test was used for the successful debugfs capture; the later raw SPI address-space read is a separate read-only operation.
- Do not use either file as a full-chip recovery image or assume it is interchangeable with the ASUS vendor payloads.
