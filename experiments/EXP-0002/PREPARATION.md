# Preparation record — no live benchmark

Date: 2026-10-20. Operator response: keep waiting; LLM still in use.
No GPU request, service change, driver action or firmware action was performed.

Staged directory on capture-host:
`EXTERNAL_WORKTREE`. It contains the reviewed runner, a frozen copy
of BetterBench and its corpus, the downloaded unpatched 1.9.0 archive, and mock
test artifacts. No 1.9.0 build or installation has started. Neither the serving
`native/` tree nor its source checkout has been modified.

Actual local and remote SHA-256 values agreed after transfer:

| Artifact | SHA-256 |
|---|---|
| `radiance_version_trial.py` | `5a9883d3fb977627057e572dee480848a147522c0fbdfcaade7744ff57e57323` |
| `betterbench-snapshot.tar.gz` | `2a8ae400c23e84a34508eebeefed076b83732143d792650aa4ef699ae0b2dca5` |
| `upstream-v1.9.0.tar.gz` | `aee3713474f6561f7950f2af7e6ba1a4e845cb7b80bf7657eef2986a69576b13` |

Verification performed:

- Nine focused unit tests passed, including authorization, timeout cleanup,
  fault cancellation, required telemetry, complete response validation and
  one-token prefill handling.
- Three mock suites against the real BetterBench adapter produced 39 requests;
  matched repetitions had identical request hashes, different repetitions had
  different nonces, and decode timing used response completion. These were
  localhost mock requests, never requests to the LLM. The last changes affect
  one-token validation/model metadata; their focused tests and static review
  passed after the mock suite.
- Final read-only review found no remaining major issue.
- Historical full repository suite: 105 tests, with two errors in optional
  static-audit checks whose fixtures were not included in the share tree. Those
  audit-only checks and their stale links have since been removed from the
  maintained workflow.
- The repository checker at that time also depended on absent audit manifests;
  it now validates the immutable originals directly from `sources/README.md`.
  The stale links to unavailable audit files have been removed.
- All three immutable original sources retain their documented hashes; exactly
  eleven working chapters remain. No card manifest, ROM inventory or actual
  test-log row has been added or changed.

Next action requires the operator's release of the exclusive GPU window.
Then run the bounded 1.6.0 baseline against PID 4037 (recheck the live PID), with
the frozen corpus at `BetterBench/corpus/v1` in the staged directory. Retain
results before building/switching to unpatched 1.9.0. Preserve the original
launch and installation for rollback. Follow [EXP-0002](../EXP-0002.md) and the
[comparison mini-spec](../RADIANCE_COMPARISON.md).
