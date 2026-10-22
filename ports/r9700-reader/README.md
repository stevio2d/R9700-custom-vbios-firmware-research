# Source-built R9700 reader

This is a C reader core with **a separately linked synthetic transport**. The
production executable includes cached inventory and native file features but has
no hardware transport: `identify` and `backup` refuse
before creating output or accessing a device. AMDVBFlash binaries are static
protocol evidence only. No physical ROM has been acquired by this reader.

No physical-backup route is qualified. No hardware adapter or driver extension
is included; production physical commands remain disabled.

Build locally with a C11 compiler, Python 3, OpenSSL development headers/libcrypto
and pkg-config already installed. No installer or downloaded dependency is run:

```sh
python3 ports/r9700-reader/build.py --output .cache/r9700-reader-build
.cache/r9700-reader-build/r9700-reader plan
python3 -m unittest discover -s tests -v
python3 tools/check_repository.py
R9700_SANITIZE=1 python3 -m unittest discover -s tests -p test_native_reader.py -v
R9700_SANITIZE=1 python3 -m unittest discover -s tests -p test_native_file_features.py -v
```

## Cached inventory and native file commands

`list` reports the historical four-device inventory from the hash-pinned host
record. `info --bdf FULL_BDF` selects one cached record. Both explicitly report
`live_refreshed: false`; neither contacts capture-host or any GPU. Advanced live
fields, running firmware versions and active partition status remain unknown.
Builds verify the inventory snapshot's source hash before embedding it.

```sh
.cache/r9700-reader-build/r9700-reader list
.cache/r9700-reader-build/r9700-reader info --bdf 0000:03:00.0
.cache/r9700-reader-build/r9700-reader inspect --file bios/vendor-packages/asus/payloads/7551OG.23.8.0.68.AS04.rom
.cache/r9700-reader-build/r9700-reader checksum --file bios/vendor-packages/asus/payloads/7551OG.23.8.0.68.AS04.rom --scope complete
```

File commands open regular nonsymlink inputs, cap files at 256 MiB, use bounded
reads and reject detected changes. They do not alter their inputs. `inspect`
reports bounded IFWI slot layout and the first legacy PCIR/ATOM header and optional
part number per slot. It does not decode EFI/GOP/PSP bodies or establish image
authenticity, physical capacity or active partition. IFWI slots are bounded to
16 and their partition intervals must not overlap. Missing advanced fields do
not count as complete Windows feature coverage.

`checksum --file FILE [--scope SCOPE] [--slot N] [--expect DECIMAL]` uses unsigned
byte sum modulo 65536. The expected value is decimal from 0 to 65535; mismatch
returns nonzero and prints `matches_expected: false`.

| Scope | File range |
|---|---|
| `windows-file` (default) | Selected slot's CSM offset; length from **outer file** byte 2 times 512, preserving the recovered Windows file-command behavior. |
| `vbios` | Selected CSM offset; exact embedded legacy header length. |
| `rom-default` | Selected CSM offset; embedded length rounded up to 64 KiB. Missing rounded bytes fail, including in the short XFX software blob. |
| `complete` | All actual file bytes from zero. It accepts no slot selection and does not imply physical capacity. |
| `region` | Requires `--offset DECIMAL --length DECIMAL`; checked nonempty explicit byte range and no slot selection. |

`compare --kind part-number --left FILE --right FILE` compares the first ten
characters with ASCII case folding, matching the recovered checkpn context's
prefix length. Empty, missing, unterminated or nonprintable/non-ASCII fields fail.
`compare --kind partition --left FILE --right FILE` compares SHA-256 over each
chosen file slot's entire L2-directory/max-length interval. Either accepts
`--left-slot N --right-slot N` (default zero); unequal results return nonzero.
File slot indices do not establish live active/inactive selection.

These commands provide offline file inspection only. EFI/PSP decoding, live
advanced fields and firmware-version/partition queries remain incomplete; none
of this code qualifies a physical transport.

Build output must be a new directory within this repository's `.cache/`.
`build.json` records source digests, compiler/version, flags, crypto version,
commands and executable digests. The embedded build ID hashes the input manifest;
each acquisition also hashes its actual executable. Compiler and library package
binaries are not vendored, so this is provenance, not a reproducible toolchain.

A synthetic example (safe locally, no SSH or root needed):

```sh
.cache/r9700-reader-build/r9700-reader-mock identify --bdf 0000:03:00.0
.cache/r9700-reader-build/r9700-reader-mock backup --bdf 0000:03:00.0 --output .cache/synthetic-read1
.cache/r9700-reader-build/r9700-reader-mock backup --bdf 0000:03:00.0 --output .cache/synthetic-read2
.cache/r9700-reader-build/r9700-reader-mock backup --bdf 0000:03:00.0 --output .cache/synthetic-read3
.cache/r9700-reader-build/r9700-reader verify --synthetic .cache/synthetic-read1 .cache/synthetic-read2 .cache/synthetic-read3
```

These are three independently initiated synthetic acquisitions. Verification
returns `classification: synthetic` and `physical_backup_verified: false`.
Physical verification is deliberately unavailable. Software VFCT captures use
[the separate Python interface](../../tools/linux_spi_capture.py).

The test-only `--capacity`, `--alignment` and `--fixture` options cannot enable the
production backend. Four adapter fixtures have the selected BDF third. Every
other BDF, abbreviated BDF, unknown/duplicate option and legacy flash command is
rejected. No adapter-zero or implicit scan exists. The fixture's PCI identity and
single-bank chip geometry are synthetic constants, not observations of this host.
A 256 MiB implementation ceiling bounds I/O; it does not establish flash capacity.

## Acquisition and verification contract

The new output directory is exclusively created with mode 0700. Files use mode
0600, exclusive creation and no-follow opens. `data.bin` streams bytes without a
whole-image allocation. `coverage.tsv` lists contiguous byte offset and length
pairs. Each chunk is synced. Fixed-order `acquisition.record` is a versioned,
bounded key/value record, not JSON; extra, reordered, duplicate or malformed fields
fail verification. Its synthetic identity, geometry, topology, session/build IDs,
timestamps, actual hashes, byte/chunk counts, cleanup and resource counts are
retained even on handled failure. Unknown geometry never schedules array reads.

An `incomplete` marker is made durable before the transport opens. The initial
record says incomplete. Final records are atomically replaced and synced only
after cleanup, data/coverage sync and close checks. The marker is removed only on
success; verification rejects its presence even if a failed final sync left a
complete-looking record. Marker removal has no subsequent required persistence
step: a power loss may resurrect this marker, conservatively rejecting the result.
Do not manually remove markers to make a failed acquisition pass.

A killed process leaves an incomplete record/marker and retained chunks. SIGINT,
SIGTERM and the mock's 30-second userspace deadline trigger handled cleanup.
SIGKILL cannot demonstrate controller restoration; future hardware cleanup must
be kernel-owned. Synthetic resource counts and cleanup faults test the core's
bookkeeping, not driver locking or restoration. The storage fixture retains a
partially written chunk; such data never count as complete coverage. Directory
creation or initial-record failures can leave only diagnostic stderr/partial
files; preserve the output directory and invoking log.

Verification requires exactly three distinct acquisition IDs, complete contiguous
coverage, matching target/build/geometry/topology, successful cleanup and no
resources, actual image and ledger SHA-256, exact sizes and byte equality. It
rejects symlink/FIFO files. Work in trusted local output directories: these records
are unsigned, and verification does not provide authenticity or resist another
process rewriting evidence during a check. Never add synthetic results to card
manifests, ROM inventories or hardware test logs.

## Remaining work

The [kernel contract](KERNEL_CONTRACT.md) records general safety requirements
for any future physical implementation. A qualified route, exact-kernel
integration, separate live authorization and three matching physical acquisitions
would still be required. An offline test does not qualify a controller protocol.
