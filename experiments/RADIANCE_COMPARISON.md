# Radiance 1.6.0 versus 1.9.0 comparison mini-spec

Status: three repetitions completed for each release on 2026-10-20.
A took 19.20 minutes and B 18.81 minutes; candidate host checks added
73.91 seconds. The [results](EXP-0002/RESULTS.md) show clear prefill gains
at 2k–32k, with little decode change. Candidate host checks passed 81/88;
the open JSON-schema/Unicode correctness failure blocks automatic adoption.
Original 1.6.0 is restored and its identity and six response probes passed. Testing must take at most 30 minutes per
version or patch; build time is separate.

## Goal, constraints and affected surfaces

Measure the current service first, then the latest unpatched release, then
implement kernel trials against the winning baseline. Preserve the original
1.6.0 executable, plugins, launch arguments, model and rollback path. Do not
change firmware, driver, tuning, model precision, MTP depth, cache dtype or TP
geometry. The current service remains available until the operator releases it.

Matching effective defaults: 1.6.0 uses eight checkpoint slots; 1.9.0 changed
that default to `auto`. Pin `--checkpoint-slots 8` on the candidate to preserve
the baseline's actual setting. This is a documented default-equivalence pin,
not a candidate tuning trial. Keep the remaining launch arguments identical.

Retain comparison tooling and evidence here; stage 1.9.0 in its own remote
source/build/install directories. Do not overwrite `native/` or the existing
Radiance checkout. Service replacement and GPU checks happen only in the
confirmed exclusive window. The [custom trial mini-spec](TP4_TRIALS_SPEC.md)
remains deferred until the version comparison is complete.

## Source baseline checked 2026-10-20

- Live PID 4037 reports `/version` = `1.6.0`, plugin ABI 16. `/proc/4037/exe`,
  `native/bin/radiance` and `radiance/build/bin/radiance` all hash to
  `68358b478d3e3b6182533097d90f3b9d11a6e752762f5c1ff3308e986d7c2ba0`.
  The clean checkout is `b068190326fbf1ff60b2316c43d144bdc0350552` (`v1.6.0`).
- Upstream `HEAD` and peeled tag `v1.9.0` are
  `685ec5bd858a31e90ba0431e844e3353c8c266fc`. The source declares version
  `1.9.0`, ABI 24. Engine and all plugins must therefore be rebuilt together.
- Sources: [upstream 1.9.0](https://codeberg.org/StillDeadcode/radiance/src/tag/v1.9.0),
  [release commit](https://codeberg.org/StillDeadcode/radiance/commit/685ec5bd858a31e90ba0431e844e3353c8c266fc).
  The downloaded tag archive's actual SHA-256 is
  `aee3713474f6561f7950f2af7e6ba1a4e845cb7b80bf7657eef2986a69576b13`.
- The 1.9.0 README still lists this Flash-Next container and TP4. It does not
  establish compatibility of the exact local container until startup and
  correctness checks pass. New cache dtypes stay disabled for this comparison.
- 1.9.0 removed the old GDN NW=16 experiment switch. Do not apply the 1.6.0
  patch plan mechanically to it. The loaded/build kernel provenance discrepancy
  remains separate; no module is replaced or qualified here.

## Candidate build compatibility

The pristine 1.9.0 archive failed to compile `libavx/avx_gemm_tile.cpp:289`:
its AVX level 3 code calls `_pdep_u64` without enabling BMI2. A separate CMake
project include adds `-mbmi2` only to `avx_lvl3`; no source file or GPU compile
flag changed. The EPYC 7532 supports BMI2 and AVX2 but not AVX-512, so that ISA
tier is not selected on this host. Retain the original failure log and external
include with the build evidence. This is a build compatibility adjustment, not
a performance trial.

## Workload and verification plan

Use the existing BetterBench 0.6.1 source, including its existing local changes,
with its source and corpus hashes frozen before A. Do not update BetterBench.
Three repetitions per version, each with the same suite configuration:

- Greedy sampling, fixed seed, deterministic fresh nonce sequence per repetition.
  Repetition r has identical requests on A, B and later patches; repetitions use
  different nonces to avoid within-version cache reuse.
- All eight corpus categories, 2 warmups plus 12 measured requests each.
- Prefill depths 2000/8000/16000/32000/64000, 2 warmups plus 6 measured requests
  each, maximum 16 generated tokens. Record actual token lengths and cached-token counts.
- Concurrency 1/2/4/8, 32 requests per level. Preserve the service's eight-sequence
  maximum and exact TP4 wire.
- A separate fixed deterministic response set, retained in full, before and
  after each version's measurements. Compare bytes and usage across versions;
  a difference blocks automatic promotion and needs diagnosis, not looser
  tolerances. This is a regression probe, not a general quality evaluation.
- Retain raw request definitions, results, timing, process/library/source hashes,
  flags, four-BDF telemetry and filtered kernel logs. Profile disabled during
  throughput measurement. No compile or other controlled GPU load overlaps it.

The runner has one 28-minute deadline for correctness probes plus all three
repetitions, leaving two minutes for cleanup inside the 30-minute allowance.
An interrupted suite is incomplete, never a pass or a zero-throughput sample.

Report per-repetition weighted decode medians, per-depth prefill and per-level
aggregate throughput, with ranges and percentage deltas. Treat an improvement
as actionable only when the median gain exceeds both 2% and observed repeat-run
variation (candidate minimum greater than baseline maximum). A material
regression (>5% and beyond variation) in another primary phase blocks automatic
promotion. Mixed results require an explicit workload-priority decision.

Risks: one running process per version does not establish restart variability;
sequential A/B is exposed to drift; the current kernel/PCIe history, absent ambient sensing and unmeasured
environmental effects limit attribution. Four-BDF fan RPM telemetry is retained. Repeat A after B if a marginal result
would change the choice, within A's remaining allowance or a newly agreed run.
Historical EXP-0001 uses different sampling and is context, not the matched A.

## Stop and rollback

Stop for a GPU reset, new relevant kernel/PCIe error during the window, repeated
request failures, or thermal runaway. No exact-board numeric safety limits are
invented; retain sensor limitations from EXP-0001. If 1.9.0 cannot use the exact
model/configuration, record incompatibility and restore the preserved 1.6.0
launch. Do not silently change flags to make it fit. Do not promote a version
from compilation, host tests, or an incomplete benchmark.
