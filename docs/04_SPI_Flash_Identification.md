# SPI flash identification and physical recovery preparation


> This chapter contains inherited N/R1/R2 research claims and future-work proposals. No board-specific flash component has been identified and no external programmer operation has been performed. One 2 MiB GPU-mediated raw SPI address-space capture is retained for XFX BDF `0000:03:00.0`, but physical chip capacity and full-chip recovery coverage remain unknown. See the [source index](../sources/README.md) and [research gaps](11_Sources_and_Research_Gaps.md). Supplied originals: [N](../sources/originals/notes.md), [R1](../sources/originals/deep-research-report.md), [R2](../sources/originals/deep-research-report%20%281%29.md).

## Unknown hardware

The [retained `R9700flash-dump` capture](../flashing/docs/r9700flash-dump.md)
covers its configured 2 MiB GPU-mediated address range; this does not establish
the fitted chip's capacity or complete coverage. The
[software capture tool](../tools/linux_spi_capture.py) reads a driver-exposed
VBIOS and provides no physical SPI interface. Chip identity, geometry, backend
qualification and external-programmer evidence remain pending. The software
tool has no capacity override or generic SPI/register interface; physical
recovery research remains pending.


N/R1/R2 do not establish an exact SPI NOR part number, voltage, capacity, board location or common flash device across R9700 vendors/revisions. Small SOIC/SOP-8 or WSON-8 packages and 25-series families (`W25`, `MX25`, `GD25`, `IS25`) are search clues from R2, not an R9700 bill of materials. Other controllers/EEPROMs may look similar.

## Board-specific identification


1. Record labels and exact PCB revision; photograph both sides and preserve location/pin-1 evidence.
2. Disconnect mains/auxiliary power, remove the card from the slot where practical, discharge it and verify the target rail is unpowered.
3. Read the complete chip top marking and suffix. Retrieve that exact manufacturer's datasheet; confirm package, pinout, supply/I/O voltage and capacity.
4. Identify the PCB reference designator and landmarks; verify ground/pin orientation and harness continuity rather than relying on clip wire colors.
5. Confirm programmer support for that device and measure its actual supply and logic levels before connection. A nominal 3.3 V label or adapter does not establish safe signal voltage; N warns some CH341A boards can drive near 5 V.
6. Read the JEDEC ID using the validated setup. Check that the ID, marking, datasheet and full-image byte length agree.
7. Retain three independent, byte-identical full-chip reads with hashes and logs. The existing 2 MiB GPU-mediated address-space capture does not meet this gate because the physical chip capacity is unknown and no independent programmer reads are retained. Disagreement means stop and diagnose, not choose a favored dump.

N asks for two matching reads; R1/R2 ask for three. This project's future gate uses **three** full-chip reads and retains the disagreement in [chapter 11](11_Sources_and_Research_Gaps.md). No physical chip reads, identifications, or electrical checks have been performed here; the retained GPU-mediated address-space capture is described above.

## Generic eight-pin convention


R1/R2 provide this common serial-NOR mapping. It is **not an R9700 pinout**. The exact datasheet overrides it, including alternate reset/quad functions and pull-up requirements.

| Pin | Common flash function | Logical programmer connection |
|---|---|---|
| 1 | /CS | Chip select |
| 2 | DO / IO1 | MISO |
| 3 | /WP / IO2 | Device-specific handling |
| 4 | GND | Ground |
| 5 | DI / IO0 | MOSI |
| 6 | CLK | Clock |
| 7 | /HOLD, /RESET or IO3 | Device-specific handling |
| 8 | VCC | Exact device supply voltage |

Determine pin 1 from actual package/datasheet evidence. Do not attach a programmer based only on this generic table.

## Programmer and connection leads


R2 discusses professional SPI programmers (Dediprog SF class), universal programmers (XGecu T48/T56 class), verified-voltage CH341A setups and SBC SPI interfaces. These are inherited options, not current purchase recommendations or a claim that any model supports the unknown target chip. Confirm the exact device, voltage, adapter, software/backend and electrical behavior before selection.

A clip may fail because of bus loading, poor contact, another component holding a line or unintended back-powering. If repeat reads disagree or identification is unstable, stop, verify the setup, then consider controlled isolation/desoldering and socket programming. Do not repeatedly force an unstable in-circuit write.

Never energize the GPU normally while an ordinary external programmer drives the SPI supply/lines. R2 discourages powered hot-flashing because of donor-card, short-circuit and ESD risks. External programming cannot repair electrical damage or make an invalid signature acceptable.

## Evidence gate before writing


The [card record](../bios/_template/CARD.md) must contain chip/datasheet identity, voltage/logic measurements, stable JEDEC ID, capacity, orientation and setup photos, matching read hashes, independent stock archive and a verified write/readback route. The [recovery chapter](05_Flashing_Backup_and_Recovery.md) adds the demonstrated restoration requirement before candidate firmware experiments.
