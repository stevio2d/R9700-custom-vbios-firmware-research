# Engineering Roadmap to a Bootable Custom VBIOS


> This chapter is a future-work roadmap built from N/R1/R2. No card-specific gate has been passed in this repository. See the [source index](../sources/README.md) and [research gaps](11_Sources_and_Research_Gaps.md). Supplied originals: [N](../sources/originals/notes.md), [R1](../sources/originals/deep-research-report.md), [R2](../sources/originals/deep-research-report%20%281%29.md).

All phases below are pending. No gate has been passed in this repository.

## Phase 0 — Define the target


Select one exact R9700 SKU and PCB revision.

Define the requested change:

- Better sustained clocks?
- Lower power at equal performance?
- Faster memory?
- Quieter fan behavior?
- A specific feature unlock?

Set measurable success criteria before modifying anything.

Gate: One reproducible stock benchmark and complete card inventory.

## Phase 1 — Establish recovery

Offline Linux capture planning/verification and a bounded software-dump interface
are implemented and tested. Physical SPI capture remains disabled pending chip
identity/geometry, exact target sources and a qualified GPU-access backend. Any
future live operation requires separate explicit task authorization and a
documented target, scope, cleanup, rollback and recovery plan. This advances
tooling only; it does not complete this phase's acquisition or recovery gates.


Identify the exact SPI chip and obtain three matching full-chip hardware reads. Preserve repeatable software dumps separately.

Gate: Known-good full image, verified programmer voltage/logic levels, independent backup, demonstrated stock restoration and stock retest without relying on candidate initialization. See [recovery](05_Flashing_Backup_and_Recovery.md).

## Phase 2 — Establish ROM provenance


Collect multiple stock ROMs from identical cards, if possible.

Compare:

- ROM sizes and hashes.
- BIOS versions.
- PCI IDs.
- Memory and VRM configurations.
- Fan and thermal behavior.

Gate: No unexplained board identity mismatch.

## Phase 3 — Analyze firmware layout


Identify option-ROM structure, configuration tables,
embedded firmware and potential signatures.

Gate: Evidence-based map of candidate fields and
authentication boundaries.

## Phase 4 — Non-writing proof of concept


Build a parser that reads the original ROM and produces
a report of known fields without changing the image.

Test against more than one independent ROM.

Gate: Parser produces consistent and explainable output.

## Phase 5 — Runtime target and controlled modification feasibility


First establish the desired benefit through supported runtime controls where available. Decide what firmware persistence adds, then determine whether a proposed field is:

- Mutable and not authenticated.
- Mutable but authenticated.
- Fixed by hardware.
- Managed by driver or runtime software.

Gate: A technically credible route to an accepted boot image.

## Phase 6 — First candidate write experiment


Only with a recoverable card after the recovery and authentication gates:

- Preserve all originals.
- Make one small, well-understood change.
- Verify image integrity.
- Use a confirmed compatible flashing method.
- Test initialization, display and driver loading.
- Restore stock firmware immediately if unstable.

Do not begin with a power-limit increase or a feature unlock.

## Phase 7 — Stability validation


Run short and long tests covering:

- Cold boot and warm reboot.
- Driver loading.
- PCIe link stability.
- Memory errors.
- AI inference.
- Graphics rendering.
- Thermals and fan control.
- Power and connector temperatures.

Gate: No regressions relative to stock.

## Phase 8 — Generalize across boards


Repeat the entire process for each exact SKU and PCB revision.

Never assume one working image is universal.

## Definition of success


A custom VBIOS is considered successful only when it:

1. Boots repeatedly.
2. Loads the expected drivers.
3. Preserves all required hardware functions.
4. Survives stress testing.
5. Produces a measurable benefit.
6. Has a demonstrated stock rollback, stock retest and candidate reinstallation/revalidation.

## Records required at each gate


Use [CARD.md](../bios/_template/CARD.md), the [artifact manifest](../bios/_template/manifest.csv) and an [experiment record](../templates/experiment.md). Keep offsets, lengths, table revisions, field units, integrity domains and confidence in the read-only map. The completed static map covers the existing ASUS package/payloads, the existing XFX software-ROM sample and the bounded embedded GOP PE. It decodes exact public matches for FirmwareInfo v3.5, UMC v4.0, DCE v4.5, GPIO LUT v2.1, VRAM usage v2.2 and the bounded display-object v1.5 path array; decompresses and statically analyzes the GOP; and compares aligned legacy ROM and ATOM records across the XFX/ASUS samples. Every input byte is classified in the retained [ASUS report](../bios/vendor-packages/asus/ASUS_ROM_ANALYSIS.md) and [JSON map](../bios/vendor-packages/asus/ASUS_ROM_ANALYSIS.json). Semantic interpretation remains unresolved for SMC/DPM v6.0, GFX v3.1, 128 trailing display-object bytes, many opaque ranges and runtime control behavior. No candidate image or hardware write was made.

Every candidate must identify the exact immediate parent, all changed bytes (including understood integrity updates), tool/version and expected behavior. Explain unexpected editor changes before proceeding. Test one semantic variable at a time. Do not begin with a power increase, identity change, memory strap or feature unlock.

A failure returns the work to the relevant gate; it does not justify broadening the patch or bypassing a check. Firmware acceptance and performance qualification are separate experiments. For completion use the fuller [goal criteria](../GOAL.md) and [test plan](10_Laboratory_Test_Plan.md), including both declared OS stacks and function/correctness evidence.

The ASUS static analysis phase now has a revision-aware map of all 35 ATOM master-list slots, exact changed-range evidence, bounded PE/updater geometry, and a function-level GOP inventory. These artifacts complete file-only analysis for the retained package; they do not pass the physical-board identification, recovery, signature verification, authentication, write-acceptance or runtime-benefit gates. The ranked ASUS investigation targets and their evidence limits are in [chapter 9](09_Performance_Modification_Priorities.md) and the [analysis report](../bios/vendor-packages/asus/ASUS_ROM_ANALYSIS.md).
