# Performance, Efficiency and Thermal Modification Priorities


> No tuning, benchmark or firmware experiment has been run here. The ASUS update reference below was checked against its support page on 2026-10-18; other tuning proposals remain inherited and untested. See the [source index](../sources/README.md) and [research gaps](11_Sources_and_Research_Gaps.md). Supplied originals: [N](../sources/originals/notes.md), [R1](../sources/originals/deep-research-report.md), [R2](../sources/originals/deep-research-report%20%281%29.md).

No tuning, benchmark or firmware experiment has been run here. Priorities below are proposals inherited from N and refined by R1/R2.

## Baseline first


Measure the stock card before proposing a BIOS change.

Capture:

- Sustained GPU clock.
- Memory clock.
- Board power.
- GPU temperature and hotspot temperature.
- Fan speed.
- Workload throughput.
- Error and crash rate.
- Ambient temperature.
- PCIe link width and speed.

## ASUS static target ranking

The ranks below order further evidence gathering by the retained ASUS package and payload evidence. They do not estimate the chance of success, expected performance gain or edit safety. “No-go” means the present evidence does not justify a VBIOS edit. Board identity and integrity are a cross-cutting prerequisite rather than a modification target.

| Rank | Target | Evidence in the ASUS files | Investigation boundary |
|---:|---|---|---|
| 1 | Fan behavior and acoustics | ASUS says AS07 refines the fan curve; a user reports AS07 lowers minimum fan speed from 30% to 12% after a full power cycle. Every mapped ATOM record remains byte-identical across AS04/AS07 and SMC/DPM v6.0 remains opaque. | Best supported firmware-behavior lead, but the 12% result is anecdotal and no changed byte is mapped to fan control. |
| 2 | Core clocks, power and efficiency | The XFX software VBIOS has reserved boot-clock/voltage slots, a null PowerPlayInfo pointer and PPLib ID `0x125b`; ASUS uses `0x1296`. The public header describes a nonzero ID as selecting driver-sourced PowerPlay data; SMC/DPM v6.0 remains unresolved. AMD SMI documents runtime power, clock and overdrive controls. | Profile actual bottlenecks and trace active driver/SMU policy; no general board limit is decoded, and exact-device runtime support is unverified here. |
| 3 | Memory timing, voltage and ECC | UMC v4.0 reports GDDR6, a 100 MHz reference clock, ECC-capable metadata and a clear default-enable bit; it provides no timing/voltage table. | Identify exact DRAM/topology and separate capability, boot configuration and correction telemetry. |
| 4 | Display configuration and GOP | DCE v4.5 and display-object v1.5 are revision-matched; the bounded GOP PE has a static function inventory but its indirect service calls lack established display semantics. | Investigate only a specific reproducible display or pre-OS compatibility need. |
| 5 | Feature gates | ASUS FirmwareInfo capability is `0x00024000`, XFX is `0x00024001`; dynamic boot config is named and `0x00004000` remains unnamed. Linux PSP exposes a separate GECC boot-config path. | Trace one requested feature through hardware, fuses, firmware, driver and OS; the capability is not itself an enable switch. |
| 6 | CU / stream-processor availability | GFX_INFO is v3.1, for which the checked Linux source snapshots provide no exact body definition; Linux GFX 12 gets active topology from runtime register state. No ASUS CU count or mask is decoded. | Establish exact ASIC topology and fuse/harvest evidence before considering policy; VBIOS cannot create absent resources. |
| Gate | Board identity and image integrity | ASUS payloads remain unassociated with an identified card. The updater RAR5 bytes are included by the linked Authenticode step 14 hash procedure; candidate SHA-256 values occur in the PKCS#7 records, but signatures and trust chains remain unverified. | Resolve card association, signer/signature validity, GPU acceptance and independent recovery before any write experiment. |

The linked [ASUS report](../bios/vendor-packages/asus/ASUS_ROM_ANALYSIS.md) carries raw table offsets/hashes, exact definitions, unresolved-body reasons, changed-range values, per-target control layer, plausible benefit, confidence, risk, edit decision and required next evidence.

## XFX benefit verdicts

The XFX assessment compares the `0000:03:00.0` software VBIOS, the separate 2 MiB GPU-mediated capture and ASUS AS04/AS07, then checks current AMD/Linux control paths and lower-confidence community reports. The per-area verdicts, evidence quality, runtime alternatives, two-sweep stopping log and unresolved gates are in the [XFX custom-VBIOS benefit assessment](../bios/xfx-r9700-0000-03-00-0/evidence/CUSTOM_VBIOS_BENEFIT_ASSESSMENT.md).

| Proposed benefit | Verdict for this XFX sample | Current practical path |
|---|---|---|
| Fan noise and thermal behavior | **Credible VBIOS target class**, based on ASUS's official fan-curve update note; XFX field and transfer remain unproven. | Measure a stock fan/temperature baseline; use AMDGPU fan controls when the exact driver exposes them. |
| Core clocks, voltage, power and efficiency | **Possible but unsupported**; XFX FirmwareInfo selects driver-sourced PowerPlay data and SMC/DPM v6.0 is opaque. | Profile the workload; check AMD SMI, driver overdrive and the R9700 compute profile where supported. |
| Memory speed, timing and voltage | **Possible but unsupported**; UMC v4.0 gives metadata, while timing/voltage tables are absent or unresolved. | Read telemetry and characterize memory bandwidth/correctness before considering tuning. |
| ECC enablement and useful correction | **No VBIOS path identified**; the host reports GECC disabled and Linux has a separate PSP/driver boot-configuration path. | Verify supported GECC/RAS state and counters on the exact kernel. |
| Memory training | **Possible but unsupported**; current evidence points to driver/PSP controls, without an exact XFX path match. | Trace the deployed kernel/PSP path and retain resume-stability evidence. |
| More CUs, SR-IOV/vGPU or physical display outputs | **No VBIOS path** established for adding absent hardware/platform capabilities. | Check runtime topology, PCI capabilities, supported passthrough and the physical board connectors. |
| Specific display-mode or GOP fix | **Possible but unsupported**; no reproducible XFX display fault or mapped field is recorded. | Reproduce the fault and check driver, EDID, cable/monitor and virtual-display behavior first. |
| More VRAM, bus width, cache or absent compute precision | **No VBIOS path**; these are physical memory/silicon resources. | Use existing supported multi-GPU or software/precision options if they meet the workload. |

These are research verdicts, not edit approvals or claims of measured benefit. The capture-to-software comparison finds eight byte differences, including capability/reservation/address metadata; it does not expose a performance field. The capture is not verified against the fitted flash capacity, and ASUS payloads remain unassociated with XFX.

## Priority 1 — Cooling and fan behavior


Potential benefit:

- Reduced thermal throttling.
- More consistent sustained clocks.
- Lower noise at equivalent performance.

Evidence: ASUS's [official support page](https://www.asus.com/us/motherboards-components/graphics-cards/turbo/turbo-ai-pro-r9700-32g/helpdesk_bios/?model2Name=TURBO-AI-PRO-R9700-32G) lists BIOS Update Tool v1 dated 2026-06-04 and says it refines the fan curve for a quieter acoustic profile. This is a verified vendor statement, not an independently measured noise result or confirmation that the update applies to any other SKU.

An [ASUS Turbo owner report](https://www.reddit.com/r/LocalLLM/comments/1w8r7rf/psa_for_asus_turbo_ai_pro_r9700_32gb_owners/) says the AS07 payload reduced minimum fan speed from 30% to 12%, with one user needing a full power cycle before the change took effect. Treat this as an external user observation: neither the board nor the ROM bytes are verified against the files analyzed here. Current Linux [AMDGPU thermal controls](https://docs.kernel.org/gpu/amdgpu/thermal.html) also document runtime fan-curve and minimum-PWM controls when the driver exposes them; such writes are staged and must be committed, and the generic support path is not proven for every R9700.

Risks:
Excessive hotspot or VRM temperatures and reduced fan lifespan.

The ASUS AS04 and AS07 payloads provide the strongest present firmware lead: the vendor says AS07 refines the fan curve, but all discovered ATOM table bodies are byte-identical and the differing opaque ranges have not been mapped to fan control. **Go:** identify the exact ASUS card and test the vendor update against a stock acoustic/thermal baseline. **No-go:** do not create a fan edit from guessed offsets or associate either ROM with another board. See the [retained analysis](../bios/vendor-packages/asus/ASUS_ROM_ANALYSIS.md).

## Priority 2 — Efficiency tuning


Potential benefit:

- Lower power for equal throughput.
- Better multi-card density.
- Reduced cooling demand.

Start with supported runtime controls where available.

No direct general clock, voltage or power-limit field was decoded in the ASUS payloads. FirmwareInfo v3.5 has reserved boot-clock and boot-voltage fields, a null PowerPlayInfo pointer, and a nonzero PPLib table ID that the public AMD/Linux header describes as selecting driver-sourced PowerPlay data. This lowers the evidence for a simple in-ROM limit edit; it does not show the complete SMU or driver policy. **No-go for a VBIOS edit** until the workload bottleneck, exact board, driver behavior, field schema, authentication and recovery path are established.

The XFX software-ROM sample's FirmwareInfo v3.5 PPLib ID is `0x125b`, versus `0x1296` in ASUS. Upstream SMU14 carries this ID into setup and can use it to select a matching entry from the driver firmware's v2.1 PowerPlay table directory. The table blobs and entries selected by these exact IDs are not present in this analysis, and the exact R9700 runtime dispatch is unverified. This makes driver PowerPlay policy a concrete read-only tracing target; it does not expose a ROM value to edit or make a similar GPU a safe tuning donor.

There is a conditional alternate path in current upstream: MP1 IP 14.0.2/14.0.3 dispatches to `smu_v14_0_2`, whose setup fetches a combo PowerPlay table from PMFW. That implementation checks OverDrive feature-control masks and derives fan availability from the PMFW PowerPlay table. If this is the route for a particular R9700, the generic FirmwareInfo PPLib selection trace may not be the active source for that setup. The exact ASUS MP1 revision and runtime function path are not established, so both code paths remain investigation targets.

Current Linux also documents a `smu_pptable_id` driver parameter: automatic selection is the default (`-1`), `0` requests the VBIOS table, and a positive ID requests a driver-sourced “soft pptable”. The SMU14 source honors that override, while its separate table-microcode loading path has firmware-load and IP-version gates. This is a software selector that could help trace which policy source a supported driver uses; it does not prove that arbitrary IDs exist, apply to R9700, or persist in VBIOS. No parameter was changed here.

R9700 user reports describe driver/firmware interface versions `0x2e` versus PMFW `0x32`/`0x33`, varying fan and `gpu_od` exposure, and a community driver patch that changes the expected interface value to `0x33`. The report set includes an AMD contributor saying the mismatch is usually nonfatal and another saying `gpu_od` exists on their R9700, so the cause is unresolved. A separate AMD contributor reproduced an R9700 s2idle SMU/DPM resume problem and said a driver patch was submitted. These are external runtime leads, not evidence of a bad ASUS VBIOS field; the source and behavior of a matched card/driver stack should be established before considering firmware changes.

The official [AMD SMI CLI](https://rocm.docs.amd.com/projects/amdsmi/en/latest/how-to/amdsmi-cli-tool.html) and [API reference](https://rocm.docs.amd.com/projects/amdsmi/en/latest/reference/amdsmi-cpp-api/functions.html) document runtime clock, power-cap, performance-level and overdrive controls, plus telemetry for power, temperature, voltage, clocks, ECC counts and voltage curves. These are useful places to characterize a card before pursuing persistence; the documentation does not promise every control for every R9700 board or driver. Upstream [SMU14 code](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/amd/pm/swsmu/smu_v14_0.c) shows how a nonzero PPLib ID can select driver-firmware PowerPlay data, while the [common parser](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/amd/pm/swsmu/smu_cmn.c) matches that ID in a v2.1 directory. This does not identify the entries for these ROMs, confirm exact R9700 dispatch, decode ASUS SMC/DPM v6.0, or establish a custom-ROM format.

AMD's [R9700 ROCm/PyTorch setup guide](https://www.amd.com/content/dam/amd/en/documents/products/graphics/workstation/radeon-ai-pro-rocm-pytorch-guide.pdf), Rev. 2.0, documents a compute-optimized power profile aimed at sustained clocks and higher power limits. It also describes a bandwidth diagnostic for GPU internal memory. This supplies a vendor-documented runtime characterization path, not firmware semantics or a measured result; no guide commands were run here.

Current upstream Linux exposes a separate runtime [`ppfeaturemask`](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/amd/amdgpu/amdgpu_drv.c) parameter. Its generic default is `0xfff7bfff`; the source comments say OverDrive (bit 14) and GFX DCS (bit 19) are disabled by default. The [feature enum](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/amd/include/amd_shared.h) names bit `0x4000` as OverDrive. This driver-side mask is distinct from the ASUS ATOM FirmwareInfo bit `0x00004000`, whose meaning remains unresolved. The numeric overlap is not evidence of a relationship or a ROM edit target, and the generic mask does not establish the exact R9700 driver policy.

The XFX host record contains `Failed to upload overdrive table!` and `Failed to upload customized OD settings` during resume. A third-party [R9700 tuning report](https://github.com/daimonionnn/amd-r9700-vllm-and-tuning-toolkit/blob/main/docs/r9700-oc-uv-findings.md), accessed 2026-10-19, attributes a similar error to an overdrive write during runtime-PM resume and cautions that a sysfs readback can retain a requested value after the upload fails. This is an unverified external hypothesis, not a diagnosis of this host. It makes runtime/SMU state a worthwhile diagnostic lead; it does not identify an image field to edit.

The same report, updated through 2026-08-04, records Linux 7.0.0-28 / ROCm 7.14 / amdgpu DKMS 6.19.4 results: a 1350 MHz OD_MCLK request read back while the DPM ceiling stayed 1258 MHz; after a cooler/service change, one sample measured roughly 295 W rather than 222 W; and `-120 mV` produced a reported 7.7% sustained-prefill gain at nearly equal power, while `-150 mV` plus 330 W crashed a deeper workload. Its memory-clock results also show requested overdrive values not reaching the expected effective DPM level. Another [personal report](https://grosan.co.uk/how-to-reduce-amd-r9700-ai-pro-gpu-power-usage-by-17-for-ai-inference-with-a-dockerised-controller/), accessed 2026-10-19, reports 210 W power capping with no throughput loss for its workload, while a `-100 mV` offset caused silent errors and hangs. These uncontrolled, non-ASUS reports conflict across card, cooling, driver and workload state; they do not provide a safe voltage, power limit or VBIOS edit value.

The completed ASUS control matrix classifies fan behavior, core/power/efficiency, memory/ECC, CU availability, feature gates, display/GOP, and identity/integrity. It records exact raw fields or table hashes, likely control layers, plausible benefit, confidence, risk, next evidence and separate investigation/edit decisions. Current evidence supports read-only profiling and source tracing; it does not justify an ASUS VBIOS edit. The decompressed GOP has a PE certificate table and stripped code with indirect service calls. A candidate Authenticode SHA-256 is calculated, and its raw digest bytes occur in the bounded PKCS#7 record, but CMS signature and trust are unverified; no GPU-side enforcement or runtime tuning path is established. See the [matrix and static code report](../bios/vendor-packages/asus/ASUS_ROM_ANALYSIS.md).

## Priority 3 — Sustained GPU clocks


Potential benefit:
Higher throughput in GPU-compute-bound workloads.

Risks:
Instability, additional power, thermal limits and diminishing returns.

The published boost clock is not a guaranteed sustained clock.

No clock table or editable ceiling was established from the current files. Measure sustained clocks and test supported runtime controls before considering firmware.

## Priority 4 — Memory performance


Potential benefit:
Higher throughput for memory-bandwidth-bound workloads.

Risks:
Silent calculation errors, memory instability and overheating.

Validate with workloads that detect incorrect results,
not only benchmarks that report speed.

The ASUS UMC v4.0 table is now decoded against the exact public definition: it reports the GDDR6 enum, raw channel count/width encoding, 100 MHz reference clock and an ECC-capable bit. It does not provide memory timings or voltage settings, and the ATOM `vram_info` and `voltageobject_info` pointers are null. Current ATOM headers expose GDDR6 timing/init structures in other `vram_info` revisions, but those schemas do not apply to a null ASUS table. The generic SMU 14.0.2 feature map also names `VMEMP_SCALING` and `VDDIO_MEM_SCALING`, without proving they are active or identifying an ASUS voltage value. AMDGPU/PSP has runtime memory-training controls for resume, but exact R9700 applicability is unknown. The unassociated payload does not establish fitted DRAM, PCB routing or runtime ECC behavior. Treat timing or voltage changes as **no-go** until those are identified and recovery plus memory-correctness gates are met. See the [ASUS field map](../bios/vendor-packages/asus/ASUS_ROM_ANALYSIS.md).

A separate third-party [two-card Gigabyte R9700 report](https://github.com/daimonionnn/amd-r9700-vllm-and-tuning-toolkit/blob/main/docs/r9700-mem-vendor-bios-variance.md), accessed 2026-10-19, describes different GDDR6 vendors and VBIOS revisions on its two samples and reports that the same memory-overdrive setting behaved differently. The report later revised its initial weaker-silicon explanation after service corrected a thermal-interface problem. Its companion OC/UV report says that on Samsung samples with amdgpu DKMS 6.19.4, 1300/1350 MHz `OD_MCLK` requests read back as accepted while sampled memory clocks topped at 875 MHz instead of the 1258 MHz DPM ceiling; a later A/B reports 6.6% lower decode with a 1124 MHz maximum and prefill within noise. That is a reported runtime-driver behavior, not a VBIOS timing result. No ROM hashes or revision-matched memory-table decode are supplied, so these observations do not support a transferable timing edit. On the `capture-host` XFX sample, Samsung is a tool-reported vendor value, not a physical package inspection.

## Priority 5 — Power limit


AMD specifies 300W TBP.

Increasing a limit is not automatically beneficial.

Before considering it, characterize:

- VRM capability.
- Cooling capacity.
- Connector and cable temperatures.
- PSU headroom.
- Actual workload bottlenecks.
- Whether firmware authentication permits changes.

The ASUS FirmwareInfo mode-specific MACO and USB limit fields are zero, but neither is a general board power limit. The payload map provides no decoded general power cap; AMD's published 300 W TBP remains product specification, not proof of available margin. Increasing a limit is **no-go** without board electrical evidence and measured headroom.

## Experiment design


Change one variable at a time.

Compare:

- Tokens per second in the same AI model.
- Time per image or rendering task.
- Effective memory bandwidth.
- Performance per watt.
- Sustained performance over 30–60 minutes.
- Reproducibility across multiple runs.

A successful mod must beat the stock configuration
without unacceptable stability or thermal regressions.

## Runtime before persistence


R1/R2 report ASUS GPU Tweak III clock, memory, voltage and fan controls; R2 cites fan-curve adjustment fixes in v2.1.6.0 and V/F tuner changes in v2.1.4.0. These are unverified version leads, not installed/tested tools. R1 also reports 0 dB-capable hardware deliberately disabled by this model's fan policy. Do not infer that forced fan-stop is safe for its VRAM/VRM.

R1's conservative sequence is runtime undervolt, core frequency, then memory frequency while retaining the source-reported 300 W stock envelope. N ranks cooling/fan first. Select the order from the measured bottleneck; both require one variable at a time and correct results. If supported software already provides the desired stable persistence, record that firmware editing adds no demonstrated benefit.

Before any above-stock power experiment, identify the VRM, stage ratings/topology, memory limits, cable/PSU margins and cooler headroom. The reports provide no verified factory 350 W donor R9700. A signed donor ROM still needs exact electrical/board compatibility; similar Navi 48 silicon or waterblock fit is insufficient.

## Additional modification risks from R2


| Candidate | Required evidence / reason for caution |
|---|---|
| Fan curve or fan-stop | Official update is an analysis lead, not proof of unsigned-table mutability; preserve VRAM/VRM airflow and fan-failure detection |
| Core clocks / undervolt | Determine SMU requests versus hard limits and driver overrides; test low-power transitions and long compute correctness |
| Overvoltage / raised thermal limits | Poorly justified with unknown component margins; do not remove protections to obtain a benchmark result |
| GDDR6 timing / VRAM_Info | Exact part, density, width, training and table revision required; bad values may prevent initialization or silently corrupt computations |
| GPIO / fan mappings | Requires schematic/continuity evidence; wrong routing can break power sequencing or cooling |
| DisplayObject / connector map | Board-specific; three-DP/HDMI and four-DP products differ |
| PCI subsystem IDs | No established tuning benefit; may break identification and compatibility checks |
| UEFI GOP replacement | Compatibility research only; no established performance benefit and may remove pre-OS display |

Legacy Polaris/Vega/Navi editors and MorePowerTool-style workflows are reverse-engineering references, not demonstrated R9700 image builders. Opening a file does not prove revision coverage or preservation of opaque/authenticated bytes.

Measure AI model/version, precision, batch size, data, warm-up and repeated-run variance, as well as throughput per watt. Include a 30–60 minute sustained comparison and longer representative workloads; speed without output correctness is a failure. Use the [test plan](10_Laboratory_Test_Plan.md) and [experiment template](../templates/experiment.md).
