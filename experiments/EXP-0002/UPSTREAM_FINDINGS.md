# Changes relevant to the deferred kernel trials

Read-only source inspection of unpatched Radiance 1.9.0, commit
`685ec5bd858a31e90ba0431e844e3353c8c266fc`, during the 1.6.0 baseline.
No custom kernel change or measurement is recorded here.

- `libr4d/r4d_selftest.cpp:12033`: `moe_perf()` still selects the two-class
  `moe_gemm_w4a8` row. The original TP4 benchmark gap remains.
- `libr4d/r4d_selftest.cpp:25329`: the collective driver now dispatches the
  four-rank exact rows to a width-parameterized harness instead of skipping
  them. `ar_wide_pattern()` at line 21106 includes the 524288/524352-element
  boundary and ascending-rank exact oracle. Fused four-rank HyperConn write
  and gather/write cases are also dispatched. Reuse these checks if 1.9.0
  becomes the patch baseline; do not reimplement the old missing harness.
- `libr4d/r4d_gdn_chunk_scan_k128_v128_c64_bf16.hip:39`: NW=8 and its tile
  mapping are now fixed. NW=16 is no longer an existing selectable variant;
  restoring it would be a new bounded port requiring numerical/state checks.
- `core/rad_core.h:801`: checkpoint slots now default to `auto`; the baseline
  source default is eight. The version comparison must pin eight explicitly
  on 1.9.0 to preserve the effective configuration.

Actual inspected source SHA-256 values:

| File | SHA-256 |
|---|---|
| `libr4d/r4d_selftest.cpp` | `b4e30e11864549eb9f3d8bf48511738ae8862e8da381f7e0bfff38a13e12d216` |
| `libr4d/r4d_gdn_chunk_scan_k128_v128_c64_bf16.hip` | `b36561e7c4dce9132f0b9d9796a28b0e10146265dc2212fbc9c30e05e379518f` |
| `core/rad_core.h` | `54ad28e7333a0e8245d13438d8444057415e3e0406a990b0d8be0d08f2660e62` |

The archive hash and acquisition context are in the
[comparison mini-spec](../RADIANCE_COMPARISON.md).
