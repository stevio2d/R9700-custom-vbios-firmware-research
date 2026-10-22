# EXP-TODO — experiment title


Status: planned; no test performed. Copy into `experiments/` before use. Replace TODO fields with evidence or explicit unknown/not-applicable values.

## Question and scope


- Experiment ID / date / operator: TODO
- Physical card ID / CARD.md path / SKU / PCB revision: TODO
- Type (read-only, recovery, runtime tuning, firmware acceptance, validation): TODO
- Hypothesis and one semantic variable: TODO
- Measurable benefit and acceptance threshold set before testing: TODO
- Baseline test IDs and repeat count: TODO

## Image provenance and exact change


- Running/stock image path, type, bytes and SHA-256: TODO
- Full-chip recovery image path and SHA-256: TODO
- Immediate parent path and SHA-256: TODO
- Candidate path, type, bytes and SHA-256: TODO
- Manifest `rom_id` values / tool and parser versions: TODO
- Diff evidence path; each changed offset, old/new bytes, table revision, units and purpose: TODO
- Understood integrity fields and checksum domains: TODO
- Authentication boundary evidence and limitations: TODO

For acquisition-only or runtime work, mark candidate/diff fields not applicable. A runtime tuning experiment still identifies the running firmware.

## Preconditions and recovery gate


- [ ] Board, SPI part, voltage and capacity positively identified if physical access is involved.
- [ ] Required repeat-read and separate-backup evidence retained.
- [ ] Physical recovery route demonstrated and linked before a candidate write.
- [ ] Exact tool/build and target adapter/BDF mapping verified.
- [ ] Stock baseline, thermal/power stop limits and monitoring recorded.
- [ ] Candidate changes and structure validated; no unexplained bytes changed.

Evidence paths / non-applicable items with reasons: TODO. Unchecked required gates block the write.

## Environment and procedure


Record workstation, slot/PCIe state, PSU/cables, ambient, OS/kernel, driver/PMFW/runtime versions, tools/commands and expected reboot/cold-power sequence. Define workload versions, model/data hashes, precision, batch size, warm-up, repetitions, durations and output-correctness checks. Specify one step at a time and avoid assumed adapter indexes.

Procedure and retained logs: TODO

## Stop conditions and rollback


List numeric thermal/power limits and observed-failure triggers before the run. Follow chapter 10 for memory errors, fan/voltage anomalies, initialization failures, PCIe/reset errors and connector heat. Specify exact stock image and verified restoration method; physical programming occurs only on an unpowered, isolated card with a validated setup.

Rollback procedure / demonstration record / stock retest: TODO

## Actual runs and results


No runs yet. Add one test-log row per actual run. Record test IDs, log paths, output correctness, throughput with units, clock/power/thermal/fan data and cold/warm boot counts. Record unavailable sensors and untested OS/functions explicitly.

| Test ID | Baseline or candidate | Evidence path | Result and limitations |
|---|---|---|---|

## Interpretation and follow-up


- Outcome: TODO (pending, pass, fail or inconclusive; a refusal is not automatically proof of cryptographic enforcement)
- Observed behavior versus hypothesis: TODO
- Benefit versus repeated stock results / variability: TODO
- Rollback result, stock retest, candidate reinstall/revalidation: TODO
- Remaining unknowns / next experiment / chapter updates: TODO
