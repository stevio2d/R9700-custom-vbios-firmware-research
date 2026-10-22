# Radeon AI PRO R9700 firmware research

Can a custom VBIOS provide a useful, measurable benefit on the modern AMD Radeon AI PRO R9700, and can it be installed and recovered reliably? This repository records the evidence, experiments and remaining work needed to answer that question.

**No custom VBIOS has been flashed, booted or validated.** We have collected firmware artifacts, analyzed their structure and compared runtime software on a four-GPU host. We have not established a full-chip recovery image, demonstrated physical recovery or identified a validated firmware edit. Custom-VBIOS feasibility remains unknown.

The results below summarize retained records from 2026-10-18–20. [GOAL.md](GOAL.md) defines success; [TODO.md](TODO.md) contains the full work queue. R9700 is the primary target. The passive **R9700S is a separate board family**; neither is the ATI Radeon 9700 from 2002.

## What we tested: hardware, firmware collection and analysis

The capture host has four AMD SMI-identified XFX-subsystem R9700 functions. Firmware acquisitions are associated with only **one device, `0000:03:00.0`**. Its exact retail SKU, board-label serial and PCB revision remain unknown; findings do not automatically apply to the other three cards or to other vendors.

| Check | What worked / what we observed | What it does not establish |
|---|---|---|
| Host and PCI inspection | Recorded four R9700 functions, PCI/subsystem IDs, reported Samsung memory, PCIe topology and kernel messages. See [host checks](inventory/host_checks.md). | Physical board identity, DRAM markings, VRM limits and the cause of historical PCIe/resume errors remain unknown. |
| Driver-loaded software VBIOS reads | Preserved two byte-identical **58,880-byte** reads for BDF `0000:03:00.0`, with hashes and [acquisition evidence](bios/xfx-r9700-0000-03-00-0/evidence/ACQUISITION.md). | The kernel sourced this blob from **ACPI VFCT**. Matching software reads do not prove equivalence to the physical flash. |
| GPU-mediated raw capture | `R9700flash-dump` produced one retained **2 MiB address-space capture**, containing two byte-identical embedded option-ROM chains. See the [XFX device record](bios/xfx-r9700-0000-03-00-0/CARD.md). | The configured read extent is not verified against the fitted flash capacity. Duplicate embedded chains do not establish physical banks or a dual-BIOS switch. This is **not a qualified recovery image**. |
| Official ASUS update package | Acquired and hashed the official ZIP; statically extracted AS04 and AS07 ROM payloads without running the updater. See [package provenance](bios/vendor-packages/asus/ACQUISITION.md). | Neither payload is associated with a physical card here, established as a full-chip image or qualified for XFX use. |
| Static firmware comparison | Mapped supported structures, compared XFX and ASUS ROM chains, and analyzed legacy/GOP code. The XFX raw legacy image differs from its driver-loaded copy at eight byte positions. See the [comparison](bios/xfx-r9700-0000-03-00-0/evidence/XFX_ASUS_COMPARISON.md) and [ASUS analysis](bios/vendor-packages/asus/ASUS_ROM_ANALYSIS.md). | No validated clock, voltage, general power-limit, memory-timing or fan-curve edit target was identified. Checked updater/GOP PE signatures and digests do not establish GPU-side VBIOS authentication or acceptance. |
| Linux ECC and virtualization exposure | Kernel logs report `MEM ECC is active`, `GECC is disabled`, and SRAM ECC is not presented. The four functions expose no SR-IOV PCI capability. See [feature findings](docs/08_Gated_Features_and_Unlocks.md). | ECC correction under workload was not demonstrated. These observations do not establish behavior on other boards or a firmware route to Windows ECC or SR-IOV. |
| Offline tooling | Implemented and offline-tested acquisition planning/verification, ROM triage, bounded PE-resource extraction and native file inspection. The [native reader](ports/r9700-reader/README.md) also has a separately linked synthetic acquisition test core. | Synthetic tests are not hardware acquisitions. Production native `identify` and `backup` remain disabled; no physical backup interface is qualified and no driver-extension fallback is selected. |

### Collection attempts that did not work

| Attempt | Actual result | Interpretation |
|---|---|---|
| PCI sysfs ROM read | Returned `EIO`; the driver debugfs blob provided the software captures instead. | This read path failed; the resulting debugfs captures are a different source. |
| Windows AMDVBFlash executable on Linux | Linux rejected it with `exec format error` before AMDVBFlash started. | An executable/platform mismatch, with no R9700 compatibility result. |
| Linux AMDVBFlash 4.71 adapter probe | Started but returned `Adapter not found`; no save operation followed. | This build did not enumerate the cards. It does not establish that every AMDVBFlash version is incompatible. |

The [host record](inventory/host_checks.md) preserves these attempts. No firmware write or custom-image acceptance test was attempted, so there is no failed-flash or successful-flash result to report.

## What we tested: runtime performance

These experiments used Qwen3.8-Flash-Next on a four-GPU tensor-parallel service (TP4). They tested runtime software with unchanged firmware and drivers. Their results do not validate a custom VBIOS.

| Experiment | What worked | What did not meet the goal / remaining limits |
|---|---|---|
| [EXP-0001: existing-service diagnosis](experiments/EXP-0001.md) | One full default BetterBench suite completed without request failures. Weighted single-stream median decode was **268.1 tokens/s**; four-GPU telemetry was retained. | No prior comparison baseline or general answer-quality check. Some answers hit the token cap, and the benchmark inventory listed only three GPUs. Whole-run telemetry did not isolate a power, memory or PCIe bottleneck. |
| [EXP-0002: Radiance 1.6.0 vs 1.9.0](experiments/EXP-0002.md) | Three matched repeats per release completed. 1.9.0 improved client-observed prompt processing by **2.24–5.70% at target depths 2k–32k**, beyond the declared threshold and repeat ranges. Fixed response probes matched. | Decode improved only **0.85%**, below the promotion threshold. Candidate host tests passed **81/88**; failures included a JSON-schema/Unicode correctness issue. These unresolved failures blocked automatic adoption; they were not established as regressions from 1.6.0. |
| [EXP-0003: custom HIP compute kernels](experiments/EXP-0003.md) | GDN output/state, MoE routing/output and collective correctness/replay checks passed. The GDN candidate was about **9–10% faster in an isolated 2048-token kernel test**. Three matched serving repeats completed for each GDN/MoE candidate. | **Neither candidate met the full-model promotion threshold.** GDN decode changed −0.075%; MoE decode changed −0.45%. No collective dispatch change was promoted. Faster isolated kernels did not demonstrate a useful full-model gain. |

At the end of the retained trials, the original **Radiance 1.6.0 service was restored**, with executable/library identity, health and fixed response probes checked. Neither custom compute plugin was promoted. This was software restoration, not a firmware rollback. Raw results and limitations are linked from the experiments and [actual-run log](inventory/test_log.csv).

Cooling deserves further investigation: the diagnostic run reached a **98 °C hotspot**, and the matched release trials reached **100 °C junction temperature**. The latter was below the reported 110 °C critical threshold, but that threshold is not an independently validated board safety limit. Ambient temperature, effective GDDR data rate and exact-board electrical/thermal margins remain missing. These measurements do not prove thermal throttling or justify increasing power.

## What a custom VBIOS might offer, and the leads we have

**No custom-firmware benefit has been measured here.** The table describes research leads, not available modifications. The [XFX benefit assessment](bios/xfx-r9700-0000-03-00-0/evidence/CUSTOM_VBIOS_BENEFIT_ASSESSMENT.md) and [performance priorities](docs/09_Performance_Modification_Priorities.md) contain the supporting evidence and runtime alternatives.

| Potential benefit | Why it is worth investigating | What we still need to establish |
|---|---|---|
| **Quieter fans or better sustained cooling** — strongest firmware-policy lead | ASUS describes its official update as refining the fan curve. AS04/AS07 payloads give us a bounded vendor-update comparison. A suitable policy could reduce noise or improve sustained clocks if cooling is limiting performance. | All discovered ASUS ATOM records are unchanged between those payloads; the differing bytes are not mapped to fan control. XFX fan hardware, active policy and thermal/acoustic margins are unknown. The ASUS update does not establish an XFX edit or cross-flash compatibility. |
| **Better performance per watt or sustained core clocks** | XFX uses PPLib table ID `0x125b`; ASUS uses `0x1296`. This is a concrete lead for tracing power-policy selection through the driver, SMU and power-management firmware (PMFW). | These IDs are selectors, not decoded tuning values. No general in-ROM clock/voltage/power field is mapped, the active table source is unconfirmed, and no firmware-related bottleneck is established. Supported runtime controls may provide the useful adjustment. |
| **Higher memory-bound throughput** | Memory clocks, policy or training could matter if a workload is demonstrably bandwidth-limited. | XFX/ASUS UMC tables match and contain metadata, not a usable timing/voltage table. Physical DRAM, active memory policy, effective rate and correctness margins remain unknown. No safe timing or voltage edit is identified. |
| **A specific boot, resume or display fix** | Firmware contains initialization/display metadata and a GOP component; retained resume/overdrive errors provide a diagnostic lead. | We need a reproducible fault and a traced cause in the exact driver/PSP/firmware path. Static differences and historical errors do not establish that a VBIOS change would fix it. |

There is **no evidenced VBIOS unlock path** for extra compute units, additional VRAM/bus width/cache, absent hardware features, Windows ECC or SR-IOV on these cards. The host already reports 64 active CUs; Linux memory-ECC reporting is not proof of all ECC modes or correction behavior. Feature investigations must trace the hardware, firmware, driver and OS requirements rather than assume a hidden BIOS switch. See [gated features](docs/08_Gated_Features_and_Unlocks.md).

Test supported runtime controls and official vendor options before deciding whether a persistent custom image offers additional value. Whether a useful setting is editable and accepted on this XFX board remains open.

## The unknowns blocking custom firmware

- **Exact hardware:** retail SKU/PCB revision, DRAM population, VRM/fan circuitry, flash part, voltage, capacity and physical topology have not been inspected.
- **Independent recovery:** no qualified full-chip backup, separate recovery copy or demonstrated stock restoration exists. The current software and raw captures do not satisfy this gate.
- **Authentication:** which regions are signed, which component enforces acceptance, and whether a legitimate route exists for the intended edit are unknown. A valid checksum, a writable flash chip and an accepted custom image are separate questions.
- **Active policy and editable fields:** board-specific SMC/DPM v6.0 remains opaque; driver/SMU/PMFW policy selection and exact deployed-module provenance are unqualified. No useful edit is mapped and validated.
- **Benefit and scope:** we have runtime comparisons, but no firmware A/B result or complete board-specific baseline. Sustained correctness, cold/warm boots, display behavior and Windows/Linux compatibility of any candidate remain untested.

Shared versions or nearly identical ROM bytes do not establish board compatibility. If enforced signatures cover the desired change and no legitimate signing route exists, the research outcome may be to use supported runtime controls or vendor firmware. See the [security gates](docs/06_Firmware_Security_and_Protections.md).

## TODO: what comes next

This is the dependency order; [TODO.md](TODO.md) tracks each task and its evidence.

1. **P0 — Identify the board and establish recovery.** Record labels/photos and PCB/DRAM/VRM details; identify the SPI part and electrical requirements. Qualify a physical read route, collect three matching full-chip reads, preserve an independent recovery copy, then demonstrate stock restoration and retesting before an experimental write. Complete the stock baseline with ambient, fan, effective memory-rate and board-limit evidence.
2. **P1 — Decide whether an accepted, useful edit is feasible.** Resolve active power-policy and module provenance, decode the candidate field and map authentication boundaries. Test supported runtime controls and isolate the workload bottleneck. Collect board-matched stock/vendor evidence and resolve remaining source disagreements; the unassociated ASUS payloads alone are insufficient.
3. **P2 — Test one minimal change, only after those gates pass.** Record the exact parent hash, byte diff, integrity checks and stop criteria. Distinguish flasher refusal, initialization failure and accepted behavior. Validate cold/warm boot, declared Windows/Linux stacks, functions, sustained compute, memory correctness and thermals; measure against repeated stock runs and demonstrate firmware rollback, stock retest and candidate revalidation.
4. **P3 — Follow specific feature leads.** Trace a requested feature through its hardware/firmware/driver/OS gates. Consider memory or power changes only with a demonstrated bottleneck, known board limits, authentication feasibility and recovery evidence. Repeat qualification for each additional board/revision.

Future live hardware capture or identification requires separate explicit task authorization and a documented target, scope, cleanup, rollback and recovery plan. The [read/write guide](flashing/README.md) explains the distinction between software dumps and full-chip images; documented AMDVBFlash command forms are not validated R9700 instructions.

## Where to find the evidence

| Path | Contents |
|---|---|
| [XFX card record](bios/xfx-r9700-0000-03-00-0/CARD.md) and [host checks](inventory/host_checks.md) | Device association, captures, host observations and identification gaps |
| [ASUS analysis](bios/vendor-packages/asus/ASUS_ROM_ANALYSIS.md) | Package/payload provenance, field maps, static code analysis and unresolved bytes |
| [Experiments](experiments/README.md) and [test log](inventory/test_log.csv) | Actual workload runs, positive/negative findings and retained logs |
| [BIOS inventory guide](bios/README.md) | Card manifests, preserved acquisitions and unassociated vendor packages |
| [Flashing guide](flashing/README.md) and [native reader](ports/r9700-reader/README.md) | Tool capabilities, disabled physical operations and recovery prerequisites |
| [Source index](sources/README.md) | Three byte-preserved supplied originals, hashes and provenance |
| `tools/` and `tests/` | Offline analysis helpers and repository verification |

### Research chapters

1. [Vendors, models and revisions](docs/01_Vendors_and_Models.md)
2. [GPU, memory and hardware](docs/02_GPU_Memory_and_Hardware.md)
3. [VBIOS collection and binary comparison](docs/03_VBIOS_Collection_and_Diff.md)
4. [SPI flash identification](docs/04_SPI_Flash_Identification.md)
5. [Flashing, backup and recovery](docs/05_Flashing_Backup_and_Recovery.md)
6. [Firmware security and protections](docs/06_Firmware_Security_and_Protections.md)
7. [Custom VBIOS engineering roadmap](docs/07_Custom_VBIOS_Engineering_Roadmap.md)
8. [Gated features and unlock hypotheses](docs/08_Gated_Features_and_Unlocks.md)
9. [Performance modification priorities](docs/09_Performance_Modification_Priorities.md)
10. [Laboratory test plan](docs/10_Laboratory_Test_Plan.md)
11. [Sources, disagreements and research gaps](docs/11_Sources_and_Research_Gaps.md)

## Evidence and contribution rules

Inherited source claims are labelled **INHERITED** (N, R1 or R2); checked primary references are **VERIFIED**; retained reproducible measurements are **OBSERVED**. Deductions stay **HYPOTHESIS / INFERRED**, and missing or conflicting evidence stays **UNKNOWN**. Unresolved citation/image tokens in the originals are not checked references. [Chapter 11](docs/11_Sources_and_Research_Gaps.md) records checked references and disagreements.

For another physical GPU, copy [bios/_template/](bios/_template/) to a unique card directory and record its identity before associating images. Follow the [BIOS inventory guide](bios/README.md): preserve acquisitions in `original/` or `official/`, derivatives in `modified/`, and synchronize card manifests with [inventory/roms.csv](inventory/roms.csv). Unassociated vendor artifacts belong in [inventory/vendor_packages.csv](inventory/vendor_packages.csv). Record actual hashes, sizes and derivative parent hashes; never overwrite the only original or recovery copy.

Use [templates/experiment.md](templates/experiment.md) and the [experiment workflow](experiments/README.md) for new tests. Only actual runs with retained evidence belong in the test log; synthetic reader results never belong in hardware inventories. Working records redact private host/operator identifiers without altering firmware bytes. The three files under `sources/originals/` remain byte-identical to the supplied inputs.

Offline repository verification:

```sh
python3 -m unittest discover -s tests -v
python3 tools/check_repository.py
```

These checks verify tooling and repository consistency, not hardware safety or custom-firmware feasibility. Project workflow and constraints are in [AGENTS.md](AGENTS.md).
