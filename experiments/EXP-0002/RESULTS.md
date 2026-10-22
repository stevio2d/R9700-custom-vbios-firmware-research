# Matched Radiance release comparison

Matching checks passed.

Baseline 1.6.0: 19.20 minutes. Candidate 1.9.0: 18.81 minutes.

Three repetitions per version. Rates are tok/s; ranges are the minimum and maximum of the three suite values, not confidence intervals.

| Metric | 1.6.0 median (range) | 1.9.0 median (range) | Change | Clear gain |
|---|---:|---:|---:|---|
| weighted_decode | 272.5 (271.2–274.3) | 274.8 (274.6–276.1) | +0.85% | no |
| prefill_2000 | 5585.6 (5536.6–5625.4) | 5903.9 (5865.5–5957.3) | +5.70% | yes |
| prefill_8000 | 6955.5 (6915.2–6971.3) | 7341.4 (7327.8–7402.5) | +5.55% | yes |
| prefill_16000 | 7149.9 (7134.1–7192.5) | 7406.6 (7405.4–7427.4) | +3.59% | yes |
| prefill_32000 | 7239.9 (7222.7–7260.7) | 7402.0 (7387.7–7423.2) | +2.24% | yes |
| prefill_64000 | 7259.4 (7255.4–7279.2) | 7376.4 (7371.0–7391.7) | +1.61% | no |
| concurrency_1 | 238.6 (237.0–239.2) | 245.7 (245.4–248.1) | +2.99% | yes |
| concurrency_2 | 375.4 (374.3–377.0) | 381.8 (380.9–387.9) | +1.72% | no |
| concurrency_4 | 533.6 (526.1–538.0) | 526.7 (513.6–528.6) | -1.30% | no |
| concurrency_8 | 668.4 (660.7–672.4) | 659.3 (650.5–672.7) | -1.36% | no |

Matching checks:

- same_model_sha256: pass
- same_benchmark_config: pass
- same_effective_repeat_configs: pass
- same_benchmark_sources_and_corpus: pass
- same_probe_texts: pass
- same_probe_usage_before: pass
- same_probe_usage_after: pass
- repeat_1_same_request_multiset: pass
- repeat_2_same_request_multiset: pass
- repeat_3_same_request_multiset: pass

The response probes are a narrow regression check. This comparison does not establish general output quality, restart variability or a causal kernel bottleneck. No release is automatically selected by this report.
