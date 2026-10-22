# Custom TP4 kernels versus unchanged Radiance 1.9.0

Neither candidate meets the predeclared promotion threshold: a median gain above 2% with candidate minimum above control maximum, without a material regression elsewhere. Keep both candidates experimental.

Three matched repeats per candidate completed 840 requests each. GDN took 18.17 minutes; MoE took 18.71 minutes. The [conservative active-testing accounting](testing-budget.json), including shared validation, failed attempts, startup and restoration, totals 27.80 minutes for GDN and 26.03 minutes for MoE. Build and time spent on the other candidate are separate.

| Metric | Stock 1.9.0 tok/s | GDN tok/s | GDN change | MoE tok/s | MoE change |
|---|---:|---:|---:|---:|---:|
| weighted_decode | 274.81 | 274.60 | -0.08% | 273.58 | -0.45% |
| prefill_2000 | 5903.85 | 6005.34 | +1.72% | 5960.61 | +0.96% |
| prefill_8000 | 7341.43 | 7345.58 | +0.06% | 7391.81 | +0.69% |
| prefill_16000 | 7406.64 | 7416.87 | +0.14% | 7475.54 | +0.93% |
| prefill_32000 | 7402.01 | 7399.93 | -0.03% | 7457.20 | +0.75% |
| prefill_64000 | 7376.35 | 7387.82 | +0.16% | 7443.76 | +0.91% |
| concurrency_1 | 245.73 | 245.03 | -0.28% | 245.63 | -0.04% |
| concurrency_2 | 381.85 | 382.08 | +0.06% | 382.66 | +0.21% |
| concurrency_4 | 526.68 | 519.25 | -1.41% | 530.04 | +0.64% |
| concurrency_8 | 659.25 | 655.47 | -0.57% | 649.90 | -1.42% |

No metric qualifies as a clear gain. No measured regression exceeds 5% beyond the control repeat range. The individual repeat values, ranges and all matching checks are in [GDN comparison](gdn16-comparison.json) and [MoE comparison](moe-comparison.json).

The isolated scan schedule was roughly 9–10% lower latency at 2048 tokens. The MoE production rule improved selected cold-kernel measurements by roughly 9–18% in reciprocal-time terms. Those results did not translate into a demonstrated useful full-model gain. The three four-rank collective sweeps passed 840 geometry/replay rows; their small or inactive-path benefits do not justify a production dispatch table.

Both serving comparisons match the model hash, frozen benchmark/corpus, request definitions, effective configuration and six fixed before/after response texts and token usage. The same engine, argv, model stat and other mapped libraries were independently checked. Prompt/cache token counts match all 840 requests per candidate. Generated-token counts differ in some concurrency requests; see [GDN usage](gdn16-usage-comparison.json) and [MoE usage](moe-usage-comparison.json). Prefill token counts match. MoE also differs on one single-stream request; the remaining generated-token differences occur in concurrency. Full long-answer identity and general quality are not established.

Correctness: 20 initial GDN comparisons; 390 MoE form rows; 64 protected-expert checks; 840 collective rows over three sweeps. Production plugins then passed 20 GDN comparisons plus fallback smoke and 26 MoE fixtures. An expanded self-test additionally passed 60 exact GDN output/state/alias comparisons, including different head counts and two sequences. No tolerance was relaxed.

The initial sensor-unavailable attempt and the system-Python/NumPy launch failure are retained as incomplete attempts; neither supplies performance data. Normal HIP contexts kept idle GPUs awake for validation without changing power settings.

The original 1.6.0 service is restored and healthy as PID 135886; see [restoration checks](restore-1.6.0/restoration.json). The existing 1.9.0 host-test failures and Linux-module source-provenance limitation remain unresolved. No firmware, GPU setting, driver, model, fusion boundary or collective protocol changed.

Reproduction: [procedure](PROCEDURE.md), [exact commands](commands.json), [GDN source diff](build-gdn16/production.patch), [MoE source diff](build-moe/production.patch), [offline verification](host-verification.json).
