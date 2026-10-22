# Reproducing the TP4 trial

Use unchanged Radiance 1.9.0 commit `685ec5bd858a31e90ba0431e844e3353c8c266fc`.
The retained EXP-0002 archive and full source manifest are the control. Source
preparation verifies every upstream file and refuses an existing destination:

```sh
python3 tools/prepare_radiance_tp4_trials.py \
  --source .cache/tp4-trials/upstream-v1.9.0 \
  --destination .cache/tp4-trials/new-gdn-trial --gdn-specialization
python3 tools/prepare_radiance_tp4_trials.py \
  --source .cache/tp4-trials/upstream-v1.9.0 \
  --destination .cache/tp4-trials/new-moe-trial --moe-specialization
```

Build each source separately with native ROCm `/opt/rocm/core-10.1`, Release,
`RAD_WITH_HIP=ON`, `RAD_GPU_TARGETS=gfx1201`, `RAD_HIP_VOPD_REPEATABLE=OFF`,
clang/clang++ from that ROCm LLVM directory and its HIP/HSA runtimes. The exact
CMake cache, configure/build logs, preparation manifest and production diffs are
retained under `build-gdn16/` and `build-moe/`. No architecture spoof or GPU
settings are used. Build time is separate from the testing limit.

The control engine and every other installed plugin stay unchanged. Candidate
homes contain symlinks to the control, except `kernels/libr4d.so` points to the
respective candidate build. Verify the actual mapped module hash, engine hash,
argv, model stat and other loaded libraries before timing. Never overwrite the
immutable control installation.

Stop the serving model only in an operator-confirmed exclusive window. Run the
hash-pinned command manifests through `tools/radiance_kernel_trial.py` with its
external deadline, four-BDF telemetry and kernel-log guard. Idle GPUs may runtime
suspend and return EBUSY for sensor reads; the guard refuses to run in that state.
The successful validation runs held normal HIP contexts with one 4 KiB allocation
per device to keep telemetry readable, released after validation. This changes
no power-management setting.

For serving measurements, use the existing benchmark Python environment:

```text
EXTERNAL_WORKTREE/.venv/bin/python
```

Preflight its NumPy and frozen BetterBench imports before starting a trial. Do
not use the system Python, which lacks NumPy. The frozen benchmark root is
`EXTERNAL_WORKTREE/BetterBench`, corpus `corpus/v1`. Use the unchanged
`radiance_version_trial.py` from EXP-0002, version `1.9.0`, actual serving PID,
three matched repeats and `--exclusive-window-confirmed`. Retain a fresh output
directory for each attempt. Current caps are 1,380 seconds for the GDN retry and
1,320 seconds for MoE, reserving time for correctness, startup and cleanup inside
30 minutes of testing per candidate. Retain failed attempts as well.

Use the exact EXP-0002 B launch, including eight checkpoint slots and its UUID
rank order. Profiling stays disabled during throughput measurements. Capture
before/after driver and boot identity; stop on output/state disagreement,
request failure, a new GPU/PCIe fault or an advertised critical temperature.
No automatic GPU reset, driver reload, reboot or firmware action is included.

Compare the completed candidate to `EXP-0002/B-1.9.0` with the offline summary
tool. Its machine-readable comparison is reusable; its release-specific Markdown
column labels need explicit replacement for patch reports. Require matching
inputs and probes, three repeat ranges and the mini-spec's promotion thresholds.
Restore the preserved 1.6.0 launch and normal PID/log paths, then check identity,
health and six fixed responses before releasing the GPUs to LLM users.
