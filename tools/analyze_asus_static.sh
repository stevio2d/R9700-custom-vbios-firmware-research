#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tool_root="${repo_root}/.cache/asus-static-toolchain"
work_root="${tool_root}/reproduced"
ghidra_root="${tool_root}/ghidra/ghidra_12.1.4_PUBLIC"
jdk_root="${tool_root}/jdk21"
tianocompress="${tool_root}/edk2/BaseTools/Source/C/bin/TianoCompress"
ghidra_version="Ghidra 12.1.4"
ghidra_archive_sha="ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db"
expected_gop_sha="77779f1c9dd1536338c6d204f82fab865abd8471183e2470942417d25346432b"

cd "${repo_root}"
tools/restore_asus_static_toolchain.sh
mkdir -p "${work_root}/legacy" "${work_root}/gop" "${repo_root}/tools/static-analysis-work/projects"

export JAVA_HOME="${jdk_root}"
export PATH="${JAVA_HOME}/bin:${PATH}"
export JAVA_TOOL_OPTIONS="-Duser.home=${tool_root}/java-user-home"

python3 - <<'PY'
import hashlib
import json
import struct
from pathlib import Path

from tools.rom_triage import analyze_bytes

root = Path.cwd()
work = root / ".cache/asus-static-toolchain/reproduced"
expected_hashes = {
    "package": "cd499dbf1079b2e65666ff66877c367b4823bbe15910446ab1a2a72c7224b0a0",
    "AS04": "0242ce25f406d61f7ff87c3e7be1324ad8f6e1066a2279e6b9ec03b736e60235",
    "AS07": "bee92e0a7092c9849b636bf0ec9eaf172c213cb3e34056bac40bc67c6150ecb4",
}
package = root / "bios/vendor-packages/asus/AI-PRO-R9700.zip"
if hashlib.sha256(package.read_bytes()).hexdigest() != expected_hashes["package"]:
    raise SystemExit("ASUS package SHA-256 differs from the recorded input")
results = {}
for version, relpath in (
    ("AS04", "bios/vendor-packages/asus/payloads/7551OG.23.8.0.68.AS04.rom"),
    ("AS07", "bios/vendor-packages/asus/payloads/7551OG.23.8.0.68.AS07.rom"),
):
    data = (root / relpath).read_bytes()
    if hashlib.sha256(data).hexdigest() != expected_hashes[version]:
        raise SystemExit(f"{version} ROM SHA-256 differs from the recorded input")
    images = analyze_bytes(data, relpath)["pcir_images"]
    legacy = next(item for item in images if item["code_type"] == 0)
    efi = next(item for item in images if item["code_type"] == 3)
    legacy_start = legacy["offset"]
    legacy_end = legacy_start + legacy["declared_length_bytes"]
    legacy_bytes = data[legacy_start:legacy_end]
    (work / "legacy" / f"{version}.rom").write_bytes(legacy_bytes)
    efi_start = efi["offset"]
    efi_body = efi_start + struct.unpack_from("<H", data, efi_start + 0x16)[0]
    compressed_size, uncompressed_size = struct.unpack_from("<II", data, efi_body)
    envelope_end = efi_body + 8 + compressed_size
    envelope = data[efi_body:envelope_end]
    if len(envelope) != compressed_size + 8 or envelope[-1] != 0:
        raise SystemExit(f"Malformed bounded UEFI compression envelope in {version}")
    results[version] = {
        "legacy_sha256": hashlib.sha256(legacy_bytes).hexdigest(),
        "legacy_bytes": len(legacy_bytes),
        "efi_envelope_sha256": hashlib.sha256(envelope).hexdigest(),
        "efi_stream_sha256": hashlib.sha256(envelope[8:]).hexdigest(),
        "efi_declared_output_bytes": uncompressed_size,
    }
    if version == "AS04":
        (work / "gop" / "bounded-compressed.efi").write_bytes(envelope)

if results["AS04"]["efi_envelope_sha256"] != results["AS07"]["efi_envelope_sha256"]:
    raise SystemExit("AS04 and AS07 bounded EFI compression envelopes differ")
if results["AS04"]["efi_stream_sha256"] != "d1eeeeb544af7486cbec12e03c4f6c553eb518dac693e93ed85d0dc51d825c11":
    raise SystemExit("The bounded GOP stream SHA-256 differs from the recorded input")
(work / "input-inventory.json").write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")
PY

"${tianocompress}" -d --uefi -q \
  -o "${work_root}/gop/gop.efi" \
  "${work_root}/gop/bounded-compressed.efi"

python3 - <<'PY' > "${work_root}/gop/entry-rva.txt"
from pathlib import Path
from tools.asus_rom_analysis import _parse_pe_header

pe = _parse_pe_header(Path(".cache/asus-static-toolchain/reproduced/gop/gop.efi").read_bytes())
if not pe.get("recognized") or not pe.get("entry_point_rva"):
    raise SystemExit("The bounded decompressed GOP is not a recognized PE with an entry point")
print(hex(pe["entry_point_rva"]))
PY

gop_entry_rva="$(<"${work_root}/gop/entry-rva.txt")"
gop_sha256="$(sha256sum "${work_root}/gop/gop.efi" | cut -d ' ' -f 1)"
if [[ "${gop_sha256}" != "${expected_gop_sha}" ]]; then
  printf 'Reproduced GOP SHA-256 mismatch: %s\n' "${gop_sha256}" >&2
  exit 1
fi
"${ghidra_root}/support/analyzeHeadless" "${repo_root}/tools/static-analysis-work/projects" gop_repro \
  -import "${work_root}/gop/gop.efi" \
  -scriptPath "${repo_root}/tools" \
  -postScript ghidra_efi_summary.java "${work_root}/gop/ghidra-report.json" "${gop_entry_rva}" "${gop_sha256}" "${ghidra_version}" "${ghidra_archive_sha}" \
  -deleteProject > "${work_root}/gop/ghidra.log" 2>&1

for version in AS04 AS07; do
  legacy_sha256="$(sha256sum "${work_root}/legacy/${version}.rom" | cut -d ' ' -f 1)"
  "${ghidra_root}/support/analyzeHeadless" "${repo_root}/tools/static-analysis-work/projects" "legacy_${version}_repro" \
    -import "${work_root}/legacy/${version}.rom" \
    -loader BinaryLoader \
    -processor 'x86:LE:16:Real Mode' \
    -scriptPath "${repo_root}/tools" \
    -preScript ghidra_create_entry.java 0x3 \
    -postScript ghidra_efi_summary.java "${work_root}/legacy/${version}-ghidra.json" 0x6000 "${legacy_sha256}" "${ghidra_version}" "${ghidra_archive_sha}" \
    -deleteProject > "${work_root}/legacy/${version}-ghidra.log" 2>&1
done

python3 - <<'PY'
import hashlib
import json
from pathlib import Path

work = Path(".cache/asus-static-toolchain/reproduced")
gop_report = json.loads((work / "gop/ghidra-report.json").read_text())
gop_sha = hashlib.sha256((work / "gop/gop.efi").read_bytes()).hexdigest()
if gop_report.get("input_sha256") != gop_sha:
    raise SystemExit("GOP Ghidra sidecar input hash does not match the reproduced PE")
for version in ("AS04", "AS07"):
    sidecar = json.loads((work / f"legacy/{version}-ghidra.json").read_text())
    image_sha = hashlib.sha256((work / f"legacy/{version}.rom").read_bytes()).hexdigest()
    if sidecar.get("input_sha256") != image_sha:
        raise SystemExit(f"{version} Ghidra sidecar input hash does not match its bounded ROM image")
PY

mkdir -p "${repo_root}/bios/vendor-packages/asus/analysis"
cp "${work_root}/legacy/AS04-ghidra.json" "${repo_root}/bios/vendor-packages/asus/analysis/AS04-legacy-ghidra.json"
cp "${work_root}/legacy/AS07-ghidra.json" "${repo_root}/bios/vendor-packages/asus/analysis/AS07-legacy-ghidra.json"

python3 tools/asus_rom_analysis.py \
  --package bios/vendor-packages/asus/AI-PRO-R9700.zip \
  --as04 bios/vendor-packages/asus/payloads/7551OG.23.8.0.68.AS04.rom \
  --as07 bios/vendor-packages/asus/payloads/7551OG.23.8.0.68.AS07.rom \
  --tianocompress-bin "${tianocompress}" \
  --ghidra-report "${work_root}/gop/ghidra-report.json" \
  --legacy-as04-ghidra-report bios/vendor-packages/asus/analysis/AS04-legacy-ghidra.json \
  --legacy-as07-ghidra-report bios/vendor-packages/asus/analysis/AS07-legacy-ghidra.json \
  --xfx-comparison-rom bios/xfx-r9700-0000-03-00-0/original/stock-software-read1.rom \
  --json-output bios/vendor-packages/asus/ASUS_ROM_ANALYSIS.json \
  --markdown-output bios/vendor-packages/asus/ASUS_ROM_ANALYSIS.md

python3 - <<'PY'
import hashlib
import json
from pathlib import Path

root = Path.cwd()
report = json.loads(Path("bios/vendor-packages/asus/ASUS_ROM_ANALYSIS.json").read_text())
expected = {
    "package": "cd499dbf1079b2e65666ff66877c367b4823bbe15910446ab1a2a72c7224b0a0",
    "AS04": "0242ce25f406d61f7ff87c3e7be1324ad8f6e1066a2279e6b9ec03b736e60235",
    "AS07": "bee92e0a7092c9849b636bf0ec9eaf172c213cb3e34056bac40bc67c6150ecb4",
}
actual = {"package": report["package"]["sha256"], **{key: value["sha256"] for key, value in report["payloads"].items()}}
if actual != expected:
    raise SystemExit("Analysis report input hashes differ from the pinned package/payload hashes")
comparison = report.get("xfx_comparison")
if not comparison or comparison.get("status") != "compared":
    raise SystemExit("The bounded XFX software-ROM comparison is missing")
aligned_images = comparison.get("aligned_images", [])
if len(aligned_images) != 2 or any(
    item.get("changed_byte_count") != 591 or item.get("changed_range_count") != 136
    for item in aligned_images
):
    raise SystemExit("XFX/ASUS comparison differs from the recorded 591-byte/136-range result")
for version, rom in report["payloads"].items():
    accounting = rom["region_accounting"]
    regions = accounting["regions"]
    cursor = 0
    for region in regions:
        if region["start"] != cursor or region["end"] <= cursor or not region.get("classification") or not region.get("resolution_note"):
            raise SystemExit(f"{version} region accounting has a gap, overlap, or unresolved classification")
        cursor = region["end"]
    if cursor != 2_031_872 or accounting["size_bytes"] != cursor:
        raise SystemExit(f"{version} region accounting does not cover exactly 2,031,872 bytes")
    legacy_images = [item for item in rom["pcir_images"] if item["code_type"] == 0]
    if len(legacy_images) != 2 or any(item.get("legacy_executable_analysis", {}).get("status") != "static_analysis_hash_and_bounds_validated" for item in legacy_images):
        raise SystemExit(f"{version} legacy code analysis is missing or not hash validated")
    efi_images = [item for item in rom["pcir_images"] if item["code_type"] == 3]
    if len(efi_images) != 2 or any(item.get("efi_payload_inspection", {}).get("decompression", {}).get("uncompressed_sha256") != "77779f1c9dd1536338c6d204f82fab865abd8471183e2470942417d25346432b" for item in efi_images):
        raise SystemExit(f"{version} GOP decompression output hash does not match the recorded output")
    for image in efi_images:
        verification = image["efi_payload_inspection"]["decompression"]["authenticode_sha256_analysis"]["cryptographic_verification"]
        if verification.get("status") != "pkcs7_signer_signature_and_pe_image_digest_verified":
            raise SystemExit(f"{version} embedded GOP signature/digest verification did not complete")
for updater in report["package"]["updaters"]:
    verification = updater["authenticode_sha256_analysis"]["cryptographic_verification"]
    if verification.get("status") != "pkcs7_signer_signature_and_pe_image_digest_verified":
        raise SystemExit(f"Updater signature/digest verification did not complete for {updater['member_name']}")
if report["comparison"]["changed_byte_count"] != 3575 or report["comparison"]["changed_range_count"] != 89:
    raise SystemExit("AS04/AS07 exact difference map differs from the recorded comparison")
print("Validated input hashes, GOP output, PKCS#7/PE digests, exact payload partition and AS04/AS07 diff.")
PY

printf 'Reproduced bounded GOP SHA-256: %s\n' "${gop_sha256}"
printf 'Static Ghidra sidecars: bios/vendor-packages/asus/analysis/AS04-legacy-ghidra.json bios/vendor-packages/asus/analysis/AS07-legacy-ghidra.json\n'
printf 'No updater, firmware, or hardware was executed or modified.\n'
