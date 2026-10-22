# R9700flash-dump

`R9700flash-dump` is a read-only Navi48 PCI ROM utility. This build supports listing AMD display devices and backing up the raw 2 MiB ROM address space on known Navi48 revisions. It does not write, erase, or unlock flash.

## Use

```sh
sudo R9700flash-dump --list
sudo R9700flash-dump --backup --device 0 --output R9700-03-00.0.spi.rom
```

Device indexes follow the displayed list. `--output` must name a file that does not already exist; the utility refuses to replace an existing backup. `--show` is an alias for `--list`, and `--save` is an alias for `--backup`.

## Read path

Linux's PCI ROM attribute reads the expansion ROM BAR. That path is failing on the target host, while AMDGPU logs that it fetched the VBIOS from VFCT. `R9700flash-dump` therefore uses Navi48's `ROM_INDEX` and `ROM_DATA` MMIO registers on the PCI register BAR. The register offsets and 2 MiB capacity come from the Navi48 record recovered from the supplied AMD tool. Upstream AMDGPU uses the same register pair to read the VBIOS from ROM; the raw backup reads the full capacity recorded for Navi48.

The command requires a known Navi48 device revision, the `amdgpu` driver bound to that device, and permission to map the register BAR (normally root). It takes a per-device lock, temporarily sets PCI runtime power control to `on` so the GPU stays active, then restores the previous policy when the read finishes. It maps the non-prefetchable memory BAR and sets the ROM address before every dword read. It checks that indexed reads at offsets 0 and 4 are distinct and stable, then scans the configured 2 MiB address range at 512-byte boundaries for a complete option-ROM image with AMD's VBIOS signature. The option-ROM image can begin at a nonzero offset within the raw capture. On target device `0000:03:00.0`, two consecutive 2 MiB reads were reported byte-identical. Static triage of the retained [capture](../../bios/xfx-r9700-0000-03-00-0/original/stock-spi-capture.rom) finds two byte-identical 117,248-byte PCIR chains at raw offsets `0x40000` and `0x120000`; each contains a 58,880-byte legacy image followed by a 58,368-byte EFI image. The kernel's debugfs VBIOS came from ACPI VFCT and differs from each SPI legacy image at eight byte positions, so it is a separate firmware copy rather than a byte-for-byte reference. The 2 MiB length is the configured address extent; the fitted chip capacity and complete physical coverage have not been independently established. The tool refuses to create an output file if the read checks fail or no complete AMD VBIOS image is found. `SIGINT`, `SIGTERM`, `SIGHUP`, and `SIGQUIT` request graceful cancellation so normal cleanup can restore the power policy; `SIGKILL` or a process crash cannot run that cleanup. The operation does not issue SPI erase or program commands.

The two target-device reads were byte-identical, but the dump has not been compared against an independent hardware SPI programmer read. Coverage of the full address map is therefore supported by repeatability and the embedded VBIOS structure, not by an off-card comparison.
