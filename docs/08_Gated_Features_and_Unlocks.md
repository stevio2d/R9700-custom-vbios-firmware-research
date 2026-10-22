# Potentially Gated Features — R9700 Investigation


> Public software-support statements below were checked on 2026-10-18 and are kept separate from board-specific behavior. Four XFX PCI functions on `capture-host` have been queried read-only, but none is tied to a physical label, exact SKU or PCB revision and no workload-based feature test was performed. See the [host check record](../inventory/host_checks.md), [source index](../sources/README.md) and [research gaps](11_Sources_and_Research_Gaps.md). Supplied originals: [N](../sources/originals/notes.md), [R1](../sources/originals/deep-research-report.md), [R2](../sources/originals/deep-research-report%20%281%29.md).

## Published AMD software and feature support


### ROCm

The current AMD [ROCm Linux system requirements](https://rocm.docs.amd.com/projects/install-on-linux/en/latest/reference/system-requirements.html) page lists Radeon AI PRO R9700 (`gfx1201`) as supported and gives Ubuntu 24.04.4, Ubuntu 22.04.5, RHEL 10.1 and RHEL 9.7 as the supported Linux OS combinations for Radeon PRO GPUs in this group. The current [ROCm GPU specifications](https://rocm.docs.amd.com/en/latest/reference/gpu-specs.html) list R9700 and passive R9700S separately, both as RDNA 4 / `gfx1201`. AMD's current [ROCm 10.1.0 release notes](https://rocm.docs.amd.com/en/latest/about/release-notes.html) were checked on **2026-10-18**.

The AMD [Windows compatibility page](https://rocm.docs.amd.com/projects/radeon-ryzen/en/latest/docs/compatibility/compatibilityrad/windows/windows_compatibility.html) is labelled as covering through ROCm 7.2.1. Its GPU table includes R9700 (`gfx1201`) and its PyTorch table lists PyTorch 2.9 with ROCm 7.2.1, but it explicitly says the entire ROCm stack is not yet supported on Windows. Do not generalize this narrow, versioned compatibility entry into full-stack Windows support or a card test. The versioned page also says documentation is unified from ROCm Core SDK 7.13.0 onward; the Windows scope beyond its published matrix remains unclear in the reviewed pages.

### ECC

AMD's [R9700 product specification](https://www.amd.com/en/products/graphics/workstations/radeon-ai-pro/ai-9000-series/amd-radeon-ai-pro-r9700.html) currently says **“Memory ECC Support: Yes (Linux Only)”**. This is a published OS support label, not a measurement of ECC mode, error reporting or correction behavior on a particular card. The public page does not explain whether the Windows limitation comes from the driver, runtime, firmware or another platform requirement. No evidence establishes a VBIOS-based Windows unlock.

On `capture-host`, AMD SMI identifies all four XFX-subsystem functions as Radeon AI PRO R9700, and the Linux kernel log reports `MEM ECC is active` for each. It also reports `GECC is disabled` and `SRAM ECC is not presented`. These are driver boot observations, not a memory-error injection, correction-counter check or workload validation. The exact physical labels, XFX product number and PCB revisions remain unknown. Details and limits are in the [host check record](../inventory/host_checks.md).

The current upstream Linux [ATOM parser](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/amd/amdgpu/amdgpu_atomfirmware.c) makes the `MEM ECC is active` log easy to overread: for UMC v4.0 it reports memory ECC support from `umc_config1 & ENABLE_ECC_CAPABLE`, while the separate `ras_default_ecc_enabled` state comes from `umc_config & DEFAULT_MEM_ECC_ENABLE`. The matching ASUS and XFX tables set the capability bit but leave the default-enable bit clear. The XFX host log separately says GECC is disabled. None of those records proves that error correction was active under workload.

The unassociated ASUS AS04/AS07 payloads contain a revision-matched UMC v4.0 table with `vram_type=0x70` (GDDR6), `channel_num=16`, `channel_width=4`, `umc_config=0`, and `umc_config1=0x00010000`. The public Linux definition names that `umc_config1` bit `ENABLE_ECC_CAPABLE`; `umc_config=0` leaves the default-enable bit clear. The same 84-byte UMC table occurs in the XFX software ROM, but that does not associate either ASUS image with a card or prove active correction. The ASUS `VRAMInfo` pointer is null, and this UMC record contains no memory timing or voltage table.

The XFX boot log also prints `RAS INFO: ... hardware ability[101] ras_mask[101]`. Current upstream [AMDGPU RAS code](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/amd/amdgpu/amdgpu_ras.c) formats those fields with `%x`; the [RAS block enum](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/amd/amdgpu/amdgpu_ras.h) assigns bit 0 to UMC and bit 8 to Data Fabric (DF). If the recorded custom kernel retained that format, `101` is hexadecimal `0x101`, so the driver-reported ability and mask include those two RAS blocks. The exact source revision for that custom kernel is not recorded, and these are RAS manager fields, not proof that GECC is enabled or that memory errors were corrected. Current upstream docs define `amdgpu_ras_enable` as a driver RAS feature switch and `ras_mask` as conditional on it. There is a separate PSP effect on boards advertising dynamic boot configuration: pinned upstream [PSP RAS initialization](https://code.googlesource.com/linux/torvalds/linux/+/a406b8b424fa01f244c1aab02ba186258448c36b/drivers/gpu/drm/amd/amdgpu/amdgpu_psp.c) says that when UMC RAS is unsupported—potentially because `ras_enable`/`ras_mask` disables it—PSP may set GECC off for the next boot. When UMC RAS is supported and GECC is off, it may request GECC for the next boot. This makes the parameter an indirect next-boot GECC input on that specific path, not a direct VBIOS ECC-enable bit or proof of immediate correction. The ASUS image has the dynamic-boot-config capability bit set, but its exact PSP path is unknown.

Upstream [AMDGPU RAS documentation](https://github.com/torvalds/linux/blob/master/Documentation/gpu/amdgpu/ras.rst) describes sysfs informational queries and error counts. Current upstream [`amdgpu_ras.c`](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/amd/amdgpu/amdgpu_ras.c) also documents a debugfs `ras_ctrl` interface to enable or disable RAS for supported blocks such as UMC, and to inject errors. The block state can be checked through the `ras/features` sysfs file. These are driver RAS controls; they do not establish that external-memory GECC is enabled or correcting errors. This repository did not query the counters or run any control or injection operation.

AMD SMI 27.1.0's [RAS guide](https://rocmdocs.amd.com/projects/amdsmi/en/latest/conceptual/ras.html) documents `amd-smi metric -e` for total correctable, uncorrectable and deferred ECC counts, per-block counts, and live monitoring. Its [Python API](https://rocmdocs.amd.com/projects/amdsmi/en/latest/reference/amdsmi-py-api.html) exposes `amdsmi_get_gpu_ecc_enabled` for the enabled-block mask and `amdsmi_get_gpu_ecc_status` for per-block ECC status. It also exposes `amdsmi_get_gpu_ras_block_features_enabled` for each RAS block's status and `amdsmi_get_gpu_ras_feature_info` for RAS version/schema information. The API reference marks ECC-state and RAS-block-status calls unsupported in VM guests. AMD SMI's changelog says guest VMs cannot retrieve host ECC counts, while `amd-smi static --ras` can show enabled/disabled RAS features from host cards. This guest view is RAS-feature state, not proof of external-memory GECC correction. RAS block status is separate from ECC state, and AMD notes that a block can have ECC enabled even if the kernel cannot provide its error counters. AMD SMI also warns that driver/library mismatches can leave data unavailable or produce `N/A`, including when the driver supplies a newer GPU-metrics layout. These are read-only evidence paths where supported; no query was made on this host, and zero counts would not prove GECC is enabled.

A community R9700 report in ROCm issue #6101 uses `amdgpu.ras_enable=0` alongside a GECC-disabled log. A separate [llama.cpp R9700 report](https://github.com/ggml-org/llama.cpp/issues/28093) includes the driver message “GECC is disabled, set amdgpu_ras_enable=1 to enable GECC in next boot cycle if needed.” The upstream PSP path above provides a possible explanation for this next-boot wording, but neither external report isolates the cause or measures memory correction. Do not treat the parameter as an immediate ECC toggle or VBIOS workaround.

### Driver feature masks and CU reporting

The Linux [AMDGPU driver parameter](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/amd/amdgpu/amdgpu_drv.c) `ppfeaturemask` overrides the driver's power-feature mask. Current upstream initializes it to `0xfff7bfff` and comments that OverDrive (bit 14) and GFX DCS (bit 19) are disabled by default. The [shared feature enum](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/amd/include/amd_shared.h) names `0x4000` as the runtime `PP_OVERDRIVE_MASK`. That value is in a separate namespace from ATOM FirmwareInfo's set bit `0x00004000`, which remains unknown; matching numbers do not connect the fields. A driver mask can expose or hide driver-supported runtime controls but does not define a VBIOS edit or prove R9700-specific support. External R9700 reports are mixed: one says the `gpu_od` interface was absent despite the mask being applied and OverDrive reported enabled, while an AMD contributor says the interface exists on their R9700. These reports point to driver/interface initialization as a separate gate; they do not establish that the ASUS ROM blocks OverDrive. The generic default and user-supplied broad masks are not a device-specific tuning recommendation.

For CU reporting, current Linux [GFX 12 code](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/amd/amdgpu/gfx_v12_0.c) combines hardware-visible shader-array state with a user inactive bitmap. The [`amdgpu.disable_cu` parameter and parser](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/amd/amdgpu/amdgpu_drv.c) add requested disabled CUs; this path is a runtime software mask and provides no path to restore hardware-fused or hardware-inactive units. These source snapshots do not establish the exact topology or initialization path of a particular ASUS card.

### AI acceleration and precision formats

RDNA 4 AI accelerators and supported FP8/FP16/INT8/INT4
capabilities are already advertised.

A custom VBIOS cannot create new physical compute units.

### Multi-GPU

AMD's product and ROCm pages describe multi-GPU workloads/support for R9700 systems.

Do not confuse multi-GPU compute support with SR-IOV
virtualization or pooled physical VRAM.

## Potentially software- or firmware-gated


### SR-IOV / virtual GPU partitioning

AMD's current [ROCm virtualization support table](https://rocm.docs.amd.com/projects/install-on-linux/en/latest/reference/system-requirements.html#virtualization-support) lists Radeon PRO V710 for KVM SR-IOV; it does not list active R9700. ROCm 10.1.0 release notes list passive R9700S for KVM passthrough and V710 for SR-IOV, not active R9700. The checked AMD pages therefore provide **no published SR-IOV support claim for active R9700**. This does not determine whether a specific card exposes a PCI capability; that requires exact-card PCI and driver evidence. Do not infer active R9700 SR-IOV from R9700S passthrough, RDNA 4 or Radeon PRO branding, and do not promise a VBIOS unlock.

Privileged `lspci` output on `capture-host` lists no SR-IOV extended capability for four AMD SMI-identified Radeon AI PRO R9700 functions with PCI ID `1002:7551` and XFX subsystem ID `1eae:9801`; their `sriov_*` sysfs attributes are also absent. This is evidence about those functions as enumerated on that host. It does not establish capability behavior for another board revision or driver/platform. PASID is present on these functions, but PASID is not SR-IOV. See the [host check record](../inventory/host_checks.md).

### Workstation application certifications

Status: Primarily a software/driver/vendor support issue.

A BIOS identity change does not confer official certification.

### Power and clock limits

Status: Potential tuning target.

Some limits may be configurable, while others are enforced
by signed firmware, driver policy or hardware protection.

AMD's [Radeon AI PRO R9700 ROCm/PyTorch setup guide](https://www.amd.com/content/dam/amd/en/documents/products/graphics/workstation/radeon-ai-pro-rocm-pytorch-guide.pdf), Rev. 2.0, describes a compute-optimized profile that favors sustained clocks and higher power limits, and a ROCm bandwidth diagnostic that includes GPU internal-memory bandwidth. This is an official runtime-characterization lead, not a claim that any VBIOS field changes or that the profile is supported by every driver/card combination. Its commands were not run for this static research.

### Fan control

The ASUS support page lists a model-specific fan-curve update; see [chapter 3](03_VBIOS_Collection_and_Diff.md). This verifies the vendor's published package and stated purpose, but does not prove that an unsigned fan-table edit can be accepted on ASUS or another board.

The AS04/AS07 payloads have identical ATOM records, including decoded table bodies and opaque revision 6.0 `smc_dpm_info` and revision 3.1 `gfx_info` bodies. Changed bytes outside supported table decoders do not identify a fan curve. The ASUS note is therefore evidence of vendor intent, while the field mapping and acoustic/thermal benefit remain unverified. No ASUS payload-to-card association exists here.

The ASUS ATOM FirmwareInfo capability value is `0x00024000`; the XFX sample is `0x00024001`. The public AMD/Linux definition names the shared `dynamic_boot_cfg_enable` bit (`0x00020000`); XFX also has the `firmware_posted` bit (`0x00000001`). The set bit `0x00004000` remains unnamed. The SRAM ECC capability bit (`0x00000200`) and `ENABLE_2STAGE_BIST_TRAINING` (`0x00000400`) are clear. The latter concerns two-stage BIST memory training; its absence does not mean all memory training is disabled. None of these observations establishes an unlockable restriction. See the [field map](../bios/vendor-packages/asus/ASUS_ROM_ANALYSIS.md).

Linux has a separate PSP boot-configuration path: the public [PSP interface](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/amd/amdgpu/psp_gfx_if.h) defines GET, SET and INVALIDATE commands and `BOOT_CONFIG_GECC=1`; the [PSP RAS path](https://code.googlesource.com/linux/torvalds/linux/+/a406b8b424fa01f244c1aab02ba186258448c36b/drivers/gpu/drm/amd/amdgpu/amdgpu_psp.c) checks dynamic-boot-config support and can request GECC for a later boot when its RAS conditions permit. This is a PSP/driver boot-state control, not a VBIOS bit that by itself enables ECC. The host record says GECC is disabled on the observed XFX functions; no setting was changed here.

The ASUS report ranks continued research on fan behavior first, followed by clocks/power, memory/ECC, display/GOP, feature gates and CU availability. The ordering reflects available static evidence and possible investigation value only; it is not a success estimate or permission to edit. Physical identity and integrity/authentication evidence remain prerequisites for every target. See the explicit [ranked assessment in chapter 9](09_Performance_Modification_Priorities.md).

### Compute units and stream processors

The ASUS `gfx_info` table is revision 3.1 and remains undecoded because the checked public Linux ATOM header defines v3.0 but no v3.1 body. The public driver union covers GFX v2.2, v2.4, v2.7 and v3.0, and its v3.0 path accepts content revision 0. Current Linux GFX 12 code obtains active topology from shader-array/WGP state and builds the CU information from that runtime state; the [AMD product specification](https://www.amd.com/en/products/graphics/workstations/radeon-ai-pro/ai-9000-series/amd-radeon-ai-pro-r9700.html) lists 64 CUs / 4096 stream processors, while this repository observed 64 active CUs only on its XFX-subsystem functions. No active-CU count or mask is established from the ASUS payload. Public maximum-topology fields from other revisions do not prove enabled units. Actual availability depends on exact-card topology and silicon fuse/harvest state; a VBIOS policy cannot create absent or fused-off hardware. Investigation is reasonable after ASUS card identification; editing is no-go without a matching definition, proven functional disabled resources, integrity/authentication evidence and recovery. See the upstream [GFX 12 implementation](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/amd/amdgpu/gfx_v12_0.c).

The aligned legacy-ROM comparison finds the XFX sample's 136-byte `gfx_info` v3.1 table byte-identical to ASUS at the same image-relative offset. This adds a structural comparison point only: both bodies still lack an exact definition in the checked public source, and the XFX table does not establish ASUS CU count, disabled-unit capability, runtime interpretation or cross-vendor compatibility. See the [comparison report](../bios/vendor-packages/asus/ASUS_ROM_ANALYSIS.md) and pinned [Linux ATOM header](https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h).

## Features unlikely to be unlocked through VBIOS alone


### More physical VRAM

Requires actual memory packages, routing and supported
memory initialization. Firmware cannot manufacture capacity.

### More compute units

May be limited by silicon design, defects, fuses or product
configuration. No evidence establishes disabled usable
compute units on the R9700.

### More display connectors

Requires physical connectors, routing and supporting hardware.

### Wider memory bus or more Infinity Cache

These are physical silicon and board characteristics.

### Features from Radeon PRO W7900 or Instinct products

Those products may use different architectures, dies,
memory subsystems and software stacks.

Higher price does not establish that an R9700 contains
the same disabled hardware.

## Unlock investigation decision tree


1. Does AMD list the feature for R9700 already?
   If yes, test driver/OS support before touching firmware.
2. Does the GPU physically contain the necessary hardware?
   If no, stop.
3. Is the feature exposed in PCI capabilities or driver code?
   If no, investigate further; do not assume firmware gating.
4. Is the restriction software, licensing or firmware based?
5. Does changing the relevant setting require signed firmware?
6. Can the change be validated without risking the card?
7. Is there a measurable benefit and a reliable rollback?

## Trace one gate at a time


R1 suggests tracing a specific requested feature through silicon/fuses, AMD firmware, board ATOM data, PCI subsystem policy, kernel/driver and user-space support. Record what is actually exposed in PCI capabilities, logs and supported software. A missing application option is not proof of a VBIOS restriction.

There is no supplied evidence of usable disabled compute units, Windows ECC enabled by a VBIOS edit, SR-IOV/vGPU partitioning, unified pooled VRAM, or W7900/Instinct capability transplantation. Runtime headless policy or board-specific limits may be research targets, but require one concrete use case and validation. Changing a device/subsystem ID is not a substitute for missing hardware, driver support, licensing or certification.

Resolve [source gaps](11_Sources_and_Research_Gaps.md), demonstrate a measurable runtime need, then apply [security gates](06_Firmware_Security_and_Protections.md) before proposing an image change. R9700S observations never establish compatibility for the active R9700.
