# EXP-0001 telemetry summary

Source: [`telemetry.csv`](artifacts/telemetry.csv), collected with AMD SMI 27.1.0+7da43026 at a requested one-second interval from 09:10:49 to 09:19:27 local time. BetterBench ran from 09:10:51 to 09:19:29.

The capture contains 1,992 rows across 505 timestamps. Each GPU has 498 samples over a 518-second span; 491 timestamps contain all four GPU rows. Each GPU has 21 gaps longer than one second, with a maximum gap of two seconds. Treat this as near-one-second coverage, not a lossless trace.

## Per-GPU measurements

Values below are whole-capture means and observed peaks. The first samples include the idle pre-run interval. AMD SMI reported clocks in MHz, power in W, temperatures in °C, and utilization as percentages.

| BDF / SMI index | Mean power (peak) | Mean GFX clock (peak) | Mean GFX util | Mean `mem` activity | Mean memory clock (peak) | Hotspot mean (peak) | Memory temp mean (peak) | VRAM used mean / total |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `0000:03:00.0` / 0 | 258.3 (300) W | 3,206.8 (3,363) MHz | 97.65% | 36.13% | 1,251 (1,258) MHz | 84.8 (92) °C | 77.9 (84) °C | 32,473 / 32,624 MiB (99.53%) |
| `0000:06:00.0` / 1 | 260.2 (300) W | 3,222.6 (3,393) MHz | 97.65% | 35.70% | 1,251 (1,258) MHz | 85.6 (92) °C | 78.8 (86) °C | 32,471 / 32,624 MiB (99.53%) |
| `0000:83:00.0` / 2 | 265.2 (300) W | 3,219.1 (3,376) MHz | 97.66% | 35.72% | 1,251 (1,258) MHz | 87.2 (93) °C | 83.7 (91) °C | 32,479 / 32,624 MiB (99.55%) |
| `0000:86:00.0` / 3 | 269.9 (300) W | 3,212.0 (3,381) MHz | 97.66% | 35.68% | 1,251 (1,258) MHz | 90.6 (98) °C | 81.8 (90) °C | 32,479 / 32,624 MiB (99.55%) |

Only BDF `0000:03:00.0` is associated with the retained XFX ROM record. This association does not extend to the other three cards.

## Sensor availability and limits

- AMD SMI's reported `max_power` was 300 W on each GPU; sampled `power_usage` reached 300 W. This does not by itself prove sustained power limiting. No throttle reason or power-cap residency counter was captured.
- The `mem` column is AMD SMI activity, not memory bandwidth or effective GDDR data rate. It averaged about 36%; this cannot establish whether memory bandwidth was saturated.
- `pcie_bw` and `pcie_replay` were unavailable in all 498 samples per GPU. PCIe utilization and replay behavior therefore cannot be assessed from this run.
- Single-bit and double-bit ECC counters were zero in all reported samples. These are sampled counter values, not a full error-history audit.
- Fan RPM, ambient temperature, edge temperature, and most board/VRM sensor columns were unavailable or not emitted. Exact-board thermal and power limits are still unknown. The maximum observed hotspot was 98 °C and maximum memory temperature was 91 °C; this is a measurement, not a safety judgment.
- VRAM use remained between 99.52% and 99.56% (about 144–156 MiB free per GPU). Requests completed, but the small reported free margin is relevant to future workload-capacity checks.

## Interpretation

The telemetry shows that all four sampled GPUs were highly utilized and running at high GFX clocks during most of the capture. This does not identify a PP, decode, VRAM, power, cooling, or PCIe bottleneck: telemetry was not tagged to individual BetterBench phases, PCIe counters were missing, and no same-server baseline exists. The 300 W power readings and GPU 3's hotspot peak justify checking supported runtime power/throttle state and board-specific thermal limits in a separate read-only diagnosis before considering control changes.
