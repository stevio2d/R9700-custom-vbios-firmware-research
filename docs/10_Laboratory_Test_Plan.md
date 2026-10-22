# Laboratory test plan and acceptance criteria


> This chapter describes future tests. No laboratory work, firmware operation or hardware validation has been performed here. See the [source index](../sources/README.md) and [research gaps](11_Sources_and_Research_Gaps.md). Supplied originals: [N](../sources/originals/notes.md), [R1](../sources/originals/deep-research-report.md), [R2](../sources/originals/deep-research-report%20%281%29.md).

## Present status and equipment


No lab work has been performed here. N proposes a stable test workstation/PSU, known-good display/PCIe configuration, ESD workspace, camera/microscope, voltage-safe SPI setup and recovery computer. R1/R2 add independent thermal/power monitoring, a multimeter and an iGPU/second display adapter. Exact equipment selection depends on the identified board/chip; no programmer support is established by this document.

## Plan before testing


Use [the experiment template](../templates/experiment.md) and [test log](../inventory/test_log.csv). Record date/operator, physical card/SKU/revision/PCI IDs, running stock and candidate image hashes/types/lengths, parent hash and complete byte diff, tool/parser/programmer versions and validated recovery evidence.

Record workstation, PSU/cables, slot/link, ambient, OS/kernel, driver, PMFW/runtime stack, workload/model/data versions, precision, batch size, warm-up, duration and repetition count. Keep raw logs and output-correctness checks. Define numerical thermal/power/clock limits from the exact hardware's validated specifications before testing; do not invent universal R9700 thresholds from these reports.

Choose the benefit and threshold in advance: equal-throughput lower power, equal-temperature lower noise, sustained performance improvement or one validated functional change. Run repeated stock trials to quantify variability. A single faster score cannot establish a benefit.

## Progressive validation matrix


Every row starts pending. Record pass/fail/inconclusive and retained evidence for the declared environment. N/R1/R2 propose Windows 11 and Linux x86-64 coverage; untested OS/functions must be labelled untested and cannot count as passing.

| Stage | Required observations | Evidence to retain |
|---|---|---|
| Intake and stock baseline | Exact identity, original memory capacity, outputs, clocks, fan behavior, PCIe link and stock workload results | CARD.md, inventory, photos and baseline run IDs |
| Backup/recovery gate | Repeatable software reads; three identical plausible full-SPI reads; independent backup; demonstrated stock restoration without candidate initialization | Acquisition metadata, byte/hash comparisons, restore/readback and stock retest logs |
| Candidate integrity | Exact parent/candidate hashes and changed offsets; revision-aware structure/integrity checks; explained authentication route | Manifest and parser/diff report |
| AC-off cold boot and warm restart | Repeatable boot, correct PCI enumeration and observed counts | Predetermined counts, each attempt and boot logs; a warm restart alone is insufficient |
| Drivers | Windows driver and Linux amdgpu initialization on the declared versions; intended ROCm/compute stack works | Driver/kernel/runtime versions, logs and functional output |
| Preserved functions | All intended connectors/pre-OS display, memory capacity, fan tach/PWM, power/temperature telemetry and required ECC behavior | Per-function results; unavailable sensors marked explicitly |
| Idle and transitions | Normal idle power/voltage/fan behavior; idle-to-load transitions; sleep/resume where relevant | Time-series logs and state-transition outcomes |
| Initial load | At least 30 minutes graphics and 30 minutes AI/compute as starting screens | Throughput, errors, logs and telemetry; these are not lifetime-reliability proof |
| Extended qualification | 30–60 minute sustained stock/candidate comparison plus multi-hour representative compute/graphics use and large-memory workloads | Duration, repeat counts, model/data identity, output-correctness evidence and run variance |
| Memory correctness | Large allocations, copies and tests with known/checkable outputs, including compute results | Errors and mismatches, not just speed; ECC does not excuse unstable timing |
| Electrical and thermal behavior | GPU/hotspot/memory/VRM telemetry where available, fan, board power and connector/cable temperatures under validated limits | Sensor availability, measurement method, ambient and recorded maxima |
| Error review | No new AER/WHEA, GPU-reset, SMU/driver, memory or compute errors compared with baseline | Raw OS/driver logs and interpretation |
| Stored-image readback | Written bytes match the intended scope/image, with complete coverage identified | Readback length/hash and byte comparison |
| Rollback and revalidation | Restore exact stock, validate stock, reinstall candidate and repeat qualification | Restore evidence, stock/candidate test IDs and results |

The public [ROCm issue #6101](https://github.com/ROCm/legacy-rocm-build/issues/6101) contains user-submitted ASUS/ASRock R9700 fan/SMU reports, including PMFW `104.76.0` and contributor-provided logs. Treat these as external reports, not a reproduced defect or confirmed VBIOS cause in this repository; inspect thermal-control logs during any future test.

## Stop conditions


Stop the load, power down as appropriate and use the validated stock recovery path for initialization failure, missing outputs/memory, new computation/memory errors, unexpected voltage or fan behavior, thermal runaway, PCIe/reset instability, connector overheating or significant regression. Diagnose the cause before another candidate write; do not mask a fault by increasing voltage or temperature limits.

If full-chip reads are inconsistent or identity/capacity/voltage is unresolved, do not program. If authentication blocks the intended change, record the limitation instead of treating a force switch as a feasibility result.

## Acceptance and reporting


A candidate passes only when the predeclared benefit is repeatable, correctness/functions are preserved, no new relevant errors appear, validated margins are respected, cold/warm boots and sustained tests pass, and stock rollback plus candidate revalidation are demonstrated. All results apply only to the recorded physical card, image hash and environment. Generalization requires repeating the gates for other cards/revisions.

Record negative and inconclusive results. Update [TODO](../TODO.md) only after evidence exists. Match the complete [GOAL criteria](../GOAL.md); a successful write or benchmark is not sufficient.
