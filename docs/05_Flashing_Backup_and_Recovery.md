# Flashing, backup, verification and recovery


> This chapter contains inherited N/R1/R2 research claims and future-work proposals. Two identical driver-loaded software VBIOS reads and one 2 MiB GPU-mediated raw SPI address-space capture are recorded for one XFX R9700 device. The raw capture has not been matched to an identified physical chip capacity and is not qualified as a recovery image. No external recovery setup, stock restoration or rollback has been verified. See the [card record](../bios/xfx-r9700-0000-03-00-0/CARD.md), [source index](../sources/README.md) and [research gaps](11_Sources_and_Research_Gaps.md). Supplied originals: [N](../sources/originals/notes.md), [R1](../sources/originals/deep-research-report.md), [R2](../sources/originals/deep-research-report%20%281%29.md).

## Scope and gate


This chapter consolidates N/R1/R2 as a **future procedure outline**. The software reads are driver-loaded bytes and do not establish physical SPI coverage. A separate GPU-mediated raw read of the configured 2 MiB address range exists, but the physical chip capacity, full-chip coverage and recovery route remain unverified. No experimental candidate write is permitted before physical recovery has been demonstrated for the exact board.

The recovery demonstration is itself a controlled stock-image operation after identification, repeatable reads, independent backups and a validated electrical setup. It must not depend on the candidate firmware being functional. Record the restoration and stock retest as an experiment; owning a programmer or having matching reads alone is not a completed recovery demonstration.

## Identify and acquire before updates


Correlate PCI BDF, subsystem IDs, physical slot/serial reference and the utility's adapter index before every operation. An index of `0` in a source example does not identify the intended card in a real multi-GPU system.

N/R1/R2 describe software reads through a supported AMD/vendor utility; N also describes Linux's PCI ROM sysfs resource. Such reads may be unavailable, truncated, driver-dependent or different in size/hash from the complete physical SPI. A sysfs enable/read sequence changes device access state and needs a planned cleanup path. The attempt on XFX BDF `0000:03:00.0` returned `EIO`; cleanup disabled the ROM resource. Two reads from the AMDGPU debugfs `amdgpu_vbios` blob succeeded and matched, but the host log says the driver sourced VBIOS from ACPI VFCT. The files and acquisition limits are recorded in the [per-card evidence](../bios/xfx-r9700-0000-03-00-0/evidence/ACQUISITION.md); they are not verified physical SPI reads.

R1 cites a 2020 AMDVBFlash guide as syntax evidence; R2 describes a Windows-oriented ASUS package/user report. Neither proves that an arbitrary Windows/Linux/DOS/UEFI build supports RDNA 4 or this R9700. Verify source, exact version, help, target-card recognition and read/verify semantics before use. Do not download or run unofficial force-flashers as part of this setup.

Collect at least two byte-identical software dumps where supported, and, after [chip identification](04_SPI_Flash_Identification.md), **three byte-identical full physical SPI reads**. The existing 2 MiB `R9700flash-dump` capture has useful ROM structure but does not meet this gate: physical capacity is unknown, only one raw file is retained, and no independent programmer read exists. For each acquisition record method, tool/version, BDF or JEDEC identity, bytes, SHA-256 and logs in the [manifest](../bios/_template/manifest.csv). Check plausible content/structures and capacity; repeated identical all-blank reads are not proof of a valid backup.

## Preserve and verify

The [Linux capture CLI](../tools/linux_spi_capture.py) records software reads in
exclusively created acquisition directories, retaining partial bytes, failure
status, tool/evidence hashes, identity/mapping and acquisition times. Its offline
`verify` checks retained bytes and repeat records without opening the GPU. It
never promotes software/controller output to full-chip status and does not provide
a qualified SPI backend. Any future live hardware operation requires separate
explicit task authorization and a documented target, scope, cleanup, rollback and
recovery plan. Existing VFCT-derived ROMs retain their original metadata.

Separately, [`R9700flash-dump`](../flashing/docs/r9700flash-dump.md) produced the
retained 2 MiB XFX raw address-space capture. The tool documentation reports two
matching reads, but only one raw file is retained. The capture is not a verified
full-chip image until physical chip geometry and complete coverage are established.


Keep each independent read, a known-good full-chip stock image and its hash locally and on physically separate storage/read-only archive. Never overwrite originals. Preserve vendor packages separately; identify any extracted image's boundaries and coverage before calling it a recovery image. Software and physical dumps need not match each other's size/hash.

For a future `r9700-asus-001` card, example acquisition paths are:

```text
bios/r9700-asus-001/original/stock-software-read1.rom
bios/r9700-asus-001/original/stock-software-read2.rom
bios/r9700-asus-001/original/stock-full-spi-read1.bin
bios/r9700-asus-001/original/stock-full-spi-read2.bin
bios/r9700-asus-001/original/stock-full-spi-read3.bin
```

These files do not exist. They agree with the [template layout](../bios/README.md). Comparison of actual files uses both hashes and byte comparisons; record independent readback after any later write.

## Future programming and recovery ladder


1. Prefer an exact-model vendor/AMD programming path when confirmed compatible. Model/subsystem mismatch is diagnostic evidence; do not defeat it merely to proceed.
2. If a candidate fails but the card still enumerates, boot through an iGPU/second GPU, re-identify the target and use the exact original software image through the supported utility if possible.
3. If enumeration or software restoration fails, power down, disconnect all power and restore the **exact full-chip stock image** with the already validated external setup. Confirm voltage, chip identity, capacity and board provenance again.
4. If the clip cannot produce stable reads, stop and diagnose or use controlled isolation/desoldered programming. No reliable full image means no write.
5. Verify/read back the restored bytes against the known-good image. Disconnect the programmer before powering the card.
6. Perform complete AC-off boot and [stock validation](10_Laboratory_Test_Plan.md); preserve failure, restoration and retest logs.

R2 discusses status-register block protection and /WP reporting where supported; investigate protection state with the actual chip's datasheet/tool rather than cutting traces, lifting pins or forcing writes. Active/inactive mirrors and a dual-BIOS switch are unverified for the target board. Do not assume either provides recovery.

A hardware programmer restores bytes; it cannot undo electrical damage, guarantee a compatible donor image or bypass GPU/driver authentication. See [chapter 6](06_Firmware_Security_and_Protections.md).
