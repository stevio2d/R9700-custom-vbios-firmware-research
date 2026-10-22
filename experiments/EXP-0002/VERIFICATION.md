# Comparison tooling verification — 2026-10-20

The benchmark runner and offline report received the required read-only
`gpt-6.1-sol` review at medium reasoning. Review fixes were verified and reviewed
again; no remaining major code finding was reported.

- `python3 -m unittest discover -s tests -p 'test_*radiance*.py' -v`:
  **11 passed**. The local HTTP mock requires socket permission; the restricted
  invocation was rerun with that permission. These tests never contact the real
  inference server or import a GPU runtime.
- Historical full-suite run: **105 passed, 2 errors** across 107 tests. Both
  errors came from optional static-audit checks whose fixtures were not included
  in the share tree. Those audit-only checks were later removed from the
  maintained workflow.
- The repository checker then depended on audit manifests that were not present
  in the share tree and incorrectly expected a header-only test log. The current
  checker validates preserved originals from `sources/README.md` and permits
  actual runs when their evidence exists.
- Supplemental offline checks at that time covered eleven chapters, inventory
  CSV widths, new comparison links and all three immutable source hashes. The
  unresolved links to unavailable audit files have since been removed.
- All **1051** candidate source files match the retained upstream archive's
  extracted files. Build provenance includes actual installed-file hashes,
  compiler identity and the narrowly scoped external BMI2 build include.

The [candidate host test log](build-1.9.0/host-tests.log) is separate from these
tooling checks: 81/88 passed in 73.91 seconds. Failures remain failures; neither
numeric tolerances nor test CPU budgets were relaxed. The JSON-schema/Unicode
failure is an open correctness issue. These tests alone do not establish a
regression from 1.6.0 because the same host test catalogue was not run on A. Static inspection finds the
streaming UTF-8 decoder body identical in both versions (SHA-256 of that
function text: `30772d43c5985f7ba4b2d8ea0a0506d6d3d7018f9050ba7b29ba419b24910d40`);
this suggests a shared limitation, but does not reproduce the complete failing
grammar walk on 1.6.0.

The response probes compare six fixed answers and their token usage. Passing
them does not establish general model quality or qualify structured output.
Throughput conclusions require all three completed repetitions and matched
request definitions; the report rejects truncated or tampered request evidence
and suppresses gain verdicts when matching checks fail.

Final evidence checks: every A/B file hash in `comparison.json` was recomputed
and matched; all six repeats contain 280 recorded requests. The candidate
executable and all 26 loaded installed plugins match their build hashes, with
no plugin loaded from the original `native/` prefix. All six actual inventory
rows link to existing results and retain the registered BDF's ROM association.
Comparison document links resolve. The final read-only review independently
confirmed deltas, repeat ranges, token-usage differences, telemetry and restored
service identity; no major finding remained.
