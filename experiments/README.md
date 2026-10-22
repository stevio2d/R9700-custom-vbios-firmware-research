# Experiments


## Run records

- [EXP-0001](EXP-0001.md) records one completed R9700 runtime diagnosis.
- [EXP-0002](EXP-0002.md) records the matched Radiance 1.6.0/1.9.0 comparison
  and its host-test limitations.
- [EXP-0003](EXP-0003.md) records scoped GDN and MoE kernel trials, correctness
  checks, and matched runtime repeats.

These runs characterize software workloads on the host. They do not validate a
firmware edit. No custom firmware success is recorded.

1. Copy [the experiment template](../templates/experiment.md) to a new experiment record and choose a unique ID.
2. Describe the exact question, baseline, one changed semantic variable, prerequisites, expected outcomes, failure criteria and recovery evidence. Leave status `planned` until executed.
3. Tie firmware work to a registered `card_id`, parent/candidate hashes and the per-card manifest. For read-only or runtime tests, identify the running stock image; mark non-applicable fields explicitly.
4. Retain acquisition logs, exact byte diffs, workload definitions, outputs and environment details. Add one [test-log row](../inventory/test_log.csv) per actual run; never log a planned run as a pass.
5. Document inconclusive and failed results, rollback and stock retest. A successful write alone is not a boot or stability pass.
6. Keep supporting files in the corresponding `EXP-NNNN/` directory, grouped
   by run or validation phase, and use repository-relative links. Update chapters
   and [TODO](../TODO.md) only to the extent supported by the evidence. Use the
   [laboratory acceptance criteria](../docs/10_Laboratory_Test_Plan.md).

Firmware writes require demonstrated recovery and the [authentication gates](../docs/06_Firmware_Security_and_Protections.md). Runtime tests still need correctness and thermal evidence. Ignore local build caches and compiled products; retain the logs and provenance needed to understand recorded results.
