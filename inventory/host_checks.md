# Read-only host checks

## Four-XFX host observation

- **Observation date:** 2026-10-18. Local clock times and network endpoint are omitted.
- **Host:** anonymized remote capture host.
- **OS/kernel:** Ubuntu 24.04.4 LTS, Linux `7.0.14-custom-nogpu`, x86-64.
- **PCI tool:** `lspci` 3.10.0.
- **AMD inventory tool:** AMD SMI `27.1.0+7da43026`, ROCm 10.1.0.
- **Scope:** read-only PCI, sysfs, and kernel-log inspection, followed by one driver-loaded VBIOS capture described below. No SPI contents or firmware image were written, and no firmware utility, stress test, or workload test was run. A failed PCI ROM sysfs attempt changed transient resource-access state before cleanup disabled the resource; see the per-card acquisition record. No bytes from that attempt were retained.
- **Evidence source:** command output from the SSH checks and kernel-journal excerpts supplied from the host. The relevant excerpts are transcribed here; the complete journal was not copied into the repository.

AMD SMI identifies all four functions as **AMD Radeon AI PRO R9700**. The PCI subsystem ID is XFX. The BDFs have not been mapped to physical labels or board serials, and the exact XFX product number/PCB revision remains unknown. `0000:03:00.0` now has a provisional device record and two matching driver-loaded software reads; the other three functions do not have card records.

### PCI identity and Linux device mapping

| BDF | Vendor/device | Subsystem | PCI revision | Kernel driver | IOMMU group |
|---|---|---|---|---|---:|
| `0000:03:00.0` | `1002:7551` | `1eae:9801` (XFX) | `c0` | `amdgpu` | 49 |
| `0000:06:00.0` | `1002:7551` | `1eae:9801` (XFX) | `c0` | `amdgpu` | 51 |
| `0000:83:00.0` | `1002:7551` | `1eae:9801` (XFX) | `c0` | `amdgpu` | 13 |
| `0000:86:00.0` | `1002:7551` | `1eae:9801` (XFX) | `c0` | `amdgpu` | 15 |

AMD SMI's GPU indices map as `0` → `03:00.0`, `1` → `06:00.0`, `2` → `83:00.0`, and `3` → `86:00.0`. It reports `MARKET_NAME: AMD Radeon AI PRO R9700`, target `gfx1201`, 64 compute units, PCI revision `c0`, chip revision `0x01`, and external revision `0x51` for all four. Its `ASIC_SERIAL` identifiers were:

| BDF | AMD SMI ASIC serial |
|---|---|
| `0000:03:00.0` | `REDACTED_ASIC_ID` |
| `0000:06:00.0` | redacted |
| `0000:83:00.0` | redacted |
| `0000:86:00.0` | redacted |

AMD SMI reported unique ASIC identifiers for these functions. They are redacted in this public copy and are not chassis or board-label serial numbers.

The DRM card numbers are not the PCI addresses: `card0` maps to `83:00.0`, `card2` to `86:00.0`, `card3` to `03:00.0`, and `card4` to `06:00.0`. `card1` maps to the onboard ASPEED device at `45:00.0`. Use BDFs to distinguish the four AMD functions.

PCI sysfs exposes no `physical_slot` value for the four GPU functions. Each reports `numa_node=-1` and `local_cpulist=0-63`; this does not map a BDF to a chassis slot or board label.

### PCI capabilities and topology

Privileged `lspci -Dnnvv` output for each GPU function showed:

- A GPU-to-downstream-switch link status of **32 GT/s x16** and a maximum link capability of 32 GT/s x16.
- Resizable BAR capability: BAR 0 currently 32 GiB (supported sizes 256 MiB–32 GiB); BAR 2 currently 256 MiB (supported sizes 2–256 MiB). BAR aperture size is not a VRAM-capacity measurement.
- PASID capability is present, with execution and privilege support; PASID is disabled in the reported control state. ACS is listed, but the reported ACS capability/control flags are all negative.
- No PCIe SR-IOV extended capability was listed for any of the four functions. The corresponding `sriov_totalvfs` and `sriov_numvfs` sysfs attributes were absent. This is a negative observation for these enumerated functions on this host, not a claim about every XFX/AMD card.

The kernel's boot-time PCI enumeration separately reported each end-to-end path as limited by a **16.0 GT/s x16 upstream link** at the indicated root port. It reported 252.048 Gb/s available versus 504.112 Gb/s if that link ran at 32.0 GT/s x16:

| GPU BDF | Upstream root port named by kernel | Boot-time path limit |
|---|---|---|
| `0000:03:00.0` | `0000:00:01.1` | 16.0 GT/s x16; 252.048 Gb/s available |
| `0000:06:00.0` | `0000:00:03.1` | 16.0 GT/s x16; 252.048 Gb/s available |
| `0000:83:00.0` | `0000:80:01.1` | 16.0 GT/s x16; 252.048 Gb/s available |
| `0000:86:00.0` | `0000:80:03.1` | 16.0 GT/s x16; 252.048 Gb/s available |

Thus the later `lspci` endpoint link status at 32 GT/s x16 does not establish a 32 GT/s end-to-end host path. AMD SMI reports a Gen5 x16 interface and 32 GT/s maximum for each GPU. Its `PCIE_LEVELS` list 2.5 GT/s and 16.0 GT/s levels; these were not interpreted as the live link state. Its board-level fields do not provide a product number: `MODEL_NUMBER`, `FRU_ID`, and `PRODUCT_NAME` are `N/A` for all four; the reported manufacturer is Advanced Micro Devices, Inc. [AMD/ATI]. The kernel's boot-time “capable of 504.112 Gb/s with 32.0 GT/s” parenthetical and the later sysfs root-port maximum of 16.0 GT/s are not reconciled; neither is a measured workload result.

A subsequent idle-state sysfs sample at 16:52:44 showed all four GPU functions runtime-suspended with endpoint links at 32.0 GT/s x16. Their root ports (`00:01.1`, `00:03.1`, `80:01.1`, `80:03.1`) and switch upstream ports reported 2.5 GT/s x16 at that sample, while switch downstream ports remained at 32.0 GT/s x16. The root ports' reported maximum is 16.0 GT/s x16. Most inspected bridges were runtime-suspended; one was `active` and two were `suspending` during the read. This idle snapshot differs from the boot-time 16.0 GT/s report and is not an under-load link measurement. A separate sysfs read showed `power/control=auto` for the GPU functions; no power-management control was changed.

### Driver-reported GPU and firmware information

The kernel log reports the following for all four BDFs during `amdgpu` initialization:

- IP blocks include `gfx_v12_0`, `gmc_v12_0`, `psp_v14_0`, and `smu_v14_0`.
- `active_cu_number 64` (64 active compute units).
- 32,624 MiB VRAM reported ready, with a 32,768 MiB BAR aperture; 256-bit GDDR6.
- `MEM ECC is active.`
- `SRAM ECC is not presented.`
- `GECC is disabled`; the log says enabling `amdgpu_ras_enable=1` would require a later boot cycle. No boot parameter was changed.
- RAS initialization succeeded with `hardware ability[101] ras_mask[101]`.
- SMU firmware version `104.74.0` and DMUB firmware version `0x0A000400`.
- The driver logged `Cannot find any crtc or sizes` for each device. DRM sysfs lists four DisplayPort connectors per GPU, all reported `disconnected` and `disabled`; each writeback connector reports `unknown`/`disabled`. This does not verify physical connector wiring or output operation.

AMD SMI independently reports 32,624 MB of GDDR6, a 256-bit interface, and Samsung as the memory vendor on all four functions. This is driver/tool-reported identity, not inspection of the packages soldered to a board. Sysfs reported 34,208,743,424 bytes total VRAM and 59,912,192 bytes in use per function at the sample. `MAX_BANDWIDTH` was `N/A`; no memory workload was run.

All four functions logged `Fetched VBIOS from VFCT` and the ATOM BIOS identifier `113-48WD6SHD1-P02`. This records the BIOS source and string used by the driver at boot; it is **not** a read, hash, or validation of the image stored in each card's SPI flash. Three functions also logged a VFCT bus-number mismatch and matching by PCI device identity.

Sysfs `vbios_version` returned the same `113-48WD6SHD1-P02` string for each function. AMD SMI's driver version field was `N/A`; the kernel log reports DRM `amdgpu 3.64.0` on Linux `7.0.14-custom-nogpu`.

### Read-only driver-loaded VBIOS capture

On 2026-10-18, two independent reads of `/sys/kernel/debug/dri/0000:03:00.0/amdgpu_vbios` were saved for the function at `0000:03:00.0`. Each file is 58,880 bytes and has SHA-256 `aad3d6957f284a0cce130f8e106ea7a1118ba9bf1bf86b26d86a28ca11d0bc8d`; the files compared byte-for-byte equal. The [per-card record](../bios/xfx-r9700-0000-03-00-0/CARD.md) and [acquisition evidence](../bios/xfx-r9700-0000-03-00-0/evidence/ACQUISITION.md) retain both files, the parser report and command/tool details.

The kernel had logged `Fetched VBIOS from VFCT`; the capture therefore records the driver-exposed VBIOS associated with this PCI function, not an independent read of that card's SPI NOR. Its equivalence to the physical flash contents is unverified. A first attempt to read the PCI sysfs `rom` resource returned `EIO`; cleanup disabled the resource, and the error output is retained with the acquisition evidence. The read-only ROM reporter found one bounded PCIR image (`1002:7551`) and 19 ATOM structures. It reported a zero legacy checksum and warned that the image indicator did not mark the image as last even though the file ended there. This structural report does not establish authenticity or full-chip coverage.

During the 16:12 resume sequence, the kernel logged `Failed to upload overdrive table!` and `Failed to upload customized OD settings` for all four functions. The cause and effect on supported runtime controls are unknown; no overdrive setting was changed or tested.

### AER and ACPI log observations

The boot log includes ACPI `_OSC` messages saying the platform does not support AER, LTR, and DPC for four root bridges. It also contains AER/GHES reports during device initialization and later resume events. At 16:12:52, the kernel printed repeated `AER: buffer overflow in recovery for 0000:04:00.0` messages, along with errors attributed to PCIe switch/root ports. Some endpoint `lspci` status snapshots showed Unsupported Request status masked and Advisory Non-Fatal Error status on `03:00.0`, `83:00.0`, and `86:00.0`.

These are recorded log/status observations, not a diagnosis of a failed card or link. No error registers were cleared, and no recovery or load test was run.

### Runtime telemetry availability

The read-only AMD SMI commands used were `amd-smi static --asic --bus --driver --vram --gpu 0000:03:00.0 0000:06:00.0 0000:83:00.0 0000:86:00.0` and `amd-smi static --board --gpu` with the same BDFs. The board query returned `MODEL_NUMBER`, `FRU_ID`, and `PRODUCT_NAME` as `N/A`. No `--ifwi`, firmware-image, RAS-counter, or write operation was used. Direct reads of `gpu_busy_percent`, edge/junction/memory temperatures, fan RPM, and average power returned `Device or resource busy`; no live sensor values were obtained. A later 16:52:44 sysfs sample showed the GPU functions runtime-suspended; a separate read showed `power/control=auto`.

### Commands and limits

The checks used `hostname -f`, `uname -srmo`, `/etc/os-release`, `lspci -Dnnk`, `lspci --version`, read-only PCI sysfs identity/attribute/slot checks, DRM sysfs device and connector inspection, and `lspci -Dnnvv -s <BDF>` for the four listed functions. The privileged `lspci` output was run by the user in a four-BDF shell loop. AMD SMI static ASIC/bus/driver/VRAM and board queries were read-only and produced no output file. Kernel evidence came from `sudo journalctl -k -b --no-pager | grep -iE 'AER|PCIe Bus Error|03:00.0|06:00.0|83:00.0|86:00.0'`. AMD SMI version was `27.1.0+7da43026` (ROCm 10.1.0).

Not established: exact XFX product number/PCB/board-label serial mapping; board labels or photos; physical display-port wiring; DRAM package markings; SPI flash identity or contents; full-chip recovery image; independent VBIOS dumps; ECC error counters or correction under workload; usable live temperatures, clocks, fan/power behavior; sustained performance; active-workload PCIe bandwidth; or the cause of the PCIe/AER and overdrive log messages.

## AMDVBFlash read-only launch attempt

- **Attempt date:** 2026-10-18.
- **Host:** anonymized remote capture host, Ubuntu 24.04.4 LTS, Linux `7.0.14-custom-nogpu`, x86-64.
- **Payload:** `amdvbflash_879_Moded_v2.1.exe`, SHA-256 `7b84fdff600662d65e51523e8e5ead3f9b19c83756105f3d4269498f21b76258`. The source archive was not retained.
- **Transfer destination:** temporary remote directory; the remote SHA-256 matched the local payload.
- **Static file identification:** `PE32+ executable (console) x86-64, for MS Windows 6.00, 7 sections`.
- **Environment check:** no `wine`, `wine64`, `amdvbflash`, or `amdvbflash_879` executable was found in `PATH`.
- **Read-only command attempted:** `amdvbflash_879_Moded_v2.1.exe -i`.
- **Result:** shell exit status `126`, `exec format error`. Linux rejected the Windows executable before AMDVBFlash started. No AMDVBFlash output, GPU enumeration, driver installation, card reset, firmware read, or firmware write occurred. No GPU is associated with this attempt.

The attempt only establishes that this packaged Windows executable cannot be launched natively on the Linux host. It does not establish R9700 compatibility or incompatibility. The per-card software VBIOS capture recorded above remains the only successful VBIOS read in this repository; it came from the AMDGPU debugfs blob and was sourced by the driver from ACPI VFCT.

## AMDVBFlash Linux 4.71 probe

The Linux 4.71 executable was checked read-only; the historical result below is
unchanged.

- **Attempt date:** 2026-10-18.
- **Source:** third-party SourceForge project, [Linux files page](https://sourceforge.net/projects/ati-atiflash-amd-vbflash/files/for%20linux/) and [amdvbflash_linux_4.71.zip](https://sourceforge.net/projects/ati-atiflash-amd-vbflash/files/for%20linux/amdvbflash_linux_4.71.zip/download), checked 2026-10-18. This is not an AMD-hosted download.
- **Published archive SHA-256:** `2186d60ca95bbf15926a644b1e0e9de787bfd09b5fc3570fb761139df9b7eed5`; the downloaded archive matched the digest displayed by SourceForge.
- **Extracted executable:** `amdvbflash`, SHA-256 `2964c78b5b1cd2f24193184d0feec4927ffaf6db52d3d698929eff9e01b495e4`; static x86-64 Linux ELF. The binary reports AMDVBFLASH version `4.71`, Copyright (c) 2020 Advanced Micro Devices, Inc.
- **Remote path:** temporary directory; remote SHA-256 matched the extracted executable.
- **Read-only command:** `timeout 30s sudo -n /tmp/amdvbflash_linux_4.71 -i`.
- **Output:** `AMDVBFLASH version 4.71, Copyright (c) 2020 Advanced Micro Devices, Inc.` followed by `Adapter not found`; exit status `1`.
- **Result:** the utility started but did not enumerate an adapter. The host's PCI and AMD SMI records show four R9700 functions, but AMDVBFlash provided no adapter index or BDF to target. No `-s` read was attempted, and no firmware or card state was changed.

This is an inconclusive compatibility/read-path result, not proof that Linux cannot dump an AMD card or that R9700 is unsupported by every AMDVBFlash build. The Linux utility's README documents `-i` for adapter enumeration and `-s` for saving a VBIOS; those instructions do not establish compatibility of this 2020 binary with RDNA 4. The [kernel debugfs software capture](../bios/xfx-r9700-0000-03-00-0/evidence/ACQUISITION.md) remains the only successful VBIOS read in this repository, and it came from the ACPI VFCT image loaded by the driver.

