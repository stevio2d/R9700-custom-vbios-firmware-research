# TP4 trial implementation mini-spec

Date: 2026-10-20. Original source baseline: Radiance
`b068190326fbf1ff60b2316c43d144bdc0350552`, read from the clean checkout on
`operator@REDACTED_HOST_IP:EXTERNAL_WORKTREE/radiance`.

## Goal and affected surfaces

Operator steering: first benchmark unchanged 1.6.0, then unpatched 1.9.0, choose
the baseline from that comparison, and only then implement custom patches.
Testing is capped at 30 minutes per version or patch; build time is separate.
On 2026-10-20 the operator explicitly selected 1.9.0 for custom kernel trials
after reviewing EXP-0002. Use its unchanged engine/plugins as the control, with
the same build compatibility include. Its host-test failures remain recorded;
this choice does not qualify general output quality or deploy 1.9.0 permanently.

After that decision, prepare an isolated, reproducible benchmark patch for the
three trials requested: four-class MoE, GDN scan scheduling, and exact TP4 reductions.
Keep the serving checkout, production dispatch, driver, and firmware untouched.
Retain the patch, fixture source, preparation tool, offline tests, and verification
record in this research repository. EXP-0002 supplies the matched release
baseline; EXP-0001 is historical context with a different workload.

## Constraints and implementation

- Add an explicit TP4 mode to `r4d_selftest.cpp`, retaining the TP2 mode. Exercise
  the real `moe_gemm_w4a8_mod4` row with `w4nl64a8h`, top-10 routing, all four
  rank rotations, 512/510/508 regular experts, and a protected BF16 tail. Gate/up
  class widths are 512/256/256/256; down K widths are 256/128/128/128.
- Compare existing MoE pins, including K staging and sorted down grouping, with
  byte agreement and an independent ownership/padding check. Report failures
  through the process exit status. Free each fixture before the next case.
- Compare separately compiled NW=8/NW=16 scan objects on identical inputs at
  lengths 65/75/81/200/2048, H=12, K=V=128. Hold BFR=1, ABL=0,
  GSPLIT=0, PFV=1. Compare both output and retained state; do not redesign scan.
- Add a four-device exact collective trial using the existing row init/fini
  rendezvous, ascending-rank oracle, varying message sizes and repeated replay.
  Sweep only block/thread geometry; preserve drain=3 and acq=0. Include the
  524288-element boundary and decode/verify sizes. Keep fusion boundaries intact.
- Prepare source/build artifacts only until the user confirms that LLM users
  have stopped. No GPU correctness launch, profiling, benchmark, service stop,
  or restart before that confirmation. Ask when the trial is ready to run.

## Verification and risks

Run host fixture tests, patch preparation/reapplication checks, C++ compilation
where a suitable toolchain is available, the repository unit suite and repository
checker. Use the required `gpt-6.1-sol` reviewer after the implementation batch.
No GPU results may be claimed from host tests or compilation.

Primary risks are compact expert IDs versus original model IDs after protecting
experts, uneven four-class counts, zero padding between gate/up parts, protected
tail ownership, scan state indexing and numerical drift, and collective deadlocks
or stale replay slots. Bound live collective trials with an external timeout.
The renewed instruction authorizes HIP compute-kernel trials on the unchanged
installed driver. Pin the boot and installed-module identity across control and
candidate; the Linux module source/build discrepancy remains unresolved and no
driver patch, reload or reset is part of this work. Profile attribution and end-to-end trials
remain gated on an exclusive window, matched baselines and repeat-run variation.

## Implementation against 1.9.0

Retain pristine source and installed 1.9.0 artifacts from EXP-0002. A preparation
tool checks source hashes and makes a fresh source copy, adds an opt-in TP4
self-test include, and exposes an NW=8/16 compile choice with NW=8 as default.
Production dispatch stays unchanged until measured winners exist.

The MoE fixture uses all four classes at the real widths, top-10 distinct routing,
512/510/508 regular experts and protected trailing slots. An independent sparse
activation oracle checks expert ownership, K extents, part padding and zeroed
protected slots. Dense deterministic activations then compare variants byte for
byte and time the stock rule, aligned/uniform forms, FK128/FK256 and down groups.
Protected BF16 experts receive their own correctness checks.

GDN compares NW=16 with stock NW=8 for output and retained state, using identical
nonzero inputs and initial state at lengths 65/75/81/200/2048, 12 value heads,
both state dtypes. Keep the current rounding, zero padding, gate arithmetic and
prefetch unchanged (the old BFR/ABL/GSPLIT/PFV switches no longer exist).

Reuse the four-rank exact collective oracle and rendezvous, add timing across
block/thread counts and check results again after replay. Keep drain=3, acq=0,
exact wire and fusion boundaries. External timeouts and continuous fault/thermal
monitoring apply to every live command. Microbenchmarks select candidates;
three matched BetterBench repeats compare any winning patch with EXP-0002 B.
Every candidate's correctness plus timing is bounded to 30 minutes, build time
separate. Reject candidates that disagree; never loosen numerical tolerances.

## Measured candidate scope (EXP-0003)

The first 127.64-second selection run passed all 28 commands. Prepare two
independent production candidates before combining any winners: GDN NW16 only
for one sequence with H=12/Hg=4 and both state operands; and TP4 w4nl64a8h MoE
with FK256 through 650 routed gate/up rows plus down G8 at 5120–20480 routed
rows. Preserve all explicit form/group/tile pins. The source generator retains
NW8 and the stock MoE policy outside these predicates. Revalidate each compiled
plugin, including a GDN fallback case, then run three frozen BetterBench repeats
against unchanged EXP-0002 B. Retain unsuccessful/incomplete runs as evidence.
