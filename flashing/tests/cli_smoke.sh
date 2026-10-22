#!/usr/bin/env bash
set -euo pipefail

binary="$1"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
export XDG_CONFIG_HOME="$tmpdir/config"

"$binary" --version | grep -q '5.0.879.0'
"$binary" --help > "$tmpdir/help.txt"
grep -q -- '--device' "$tmpdir/help.txt"
"$binary" --help=all > "$tmpdir/help-all.txt"
grep -q -- 'Options related to the console' "$tmpdir/help-all.txt"
"$binary" --help=internal > "$tmpdir/help-internal.txt"
grep -q -- '--skip-ssid-check' "$tmpdir/help-internal.txt"

printf '\001\002' > "$tmpdir/bytes.bin"
"$binary" --accept-EULA --cf --vbios-file "$tmpdir/bytes.bin" 3 | grep -q 'Checksum is also OK.'
"$binary" --accept-EULA --cf "$tmpdir/bytes.bin" > "$tmpdir/cf-no-expected.txt"
grep -q 'Checksum of file' "$tmpdir/cf-no-expected.txt"
mkdir "$tmpdir/hex-name"
printf '\001\002' > "$tmpdir/hex-name/deadbeef"
(cd "$tmpdir/hex-name" && "$binary" --accept-EULA --cf deadbeef) > "$tmpdir/cf-hex-filename.txt"
grep -q 'Checksum of file' "$tmpdir/cf-hex-filename.txt"
if "$binary" --cf --vbios-file "$tmpdir/bytes.bin" 4 >"$tmpdir/out" 2>&1; then
    echo 'mismatched checksum unexpectedly succeeded' >&2
    exit 1
fi

"$binary" --simulator --show --device 10 --accept-EULA | grep -q 'Navi48'
"$binary" --simulator --save --device 10 --vbios-file "$tmpdir/navi48.rom" --accept-EULA
"$binary" --bios-file-info --vbios-file "$tmpdir/navi48.rom" | grep -q '0x7550'
"$binary" --simulator -cr 10 512 --accept-EULA > "$tmpdir/legacy-cr.txt"
grep -q 'ROM checksum (512 bytes)' "$tmpdir/legacy-cr.txt"

{
    printf '\x55\xaa\x01'
    head -c 21 /dev/zero
    printf '\x20\x00'
    head -c 6 /dev/zero
    printf 'PCIR\x02\x10\x10\x73'
    printf '\x00\x00\x18\x00\x03\x00\x00\x00\x01\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00'
    head -c 452 /dev/zero
} > "$tmpdir/valid.rom"
fix_checksum() {
    local file="$1"
    local sum checksum checksum_hex last
    last=$(($(wc -c < "$file") - 1))
    printf '\0' | dd of="$file" bs=1 seek="$last" conv=notrunc status=none
    sum="$(od -An -v -tu1 "$file" | awk '{ for (i = 1; i <= NF; ++i) total += $i } END { printf "%d", total % 256 }')"
    checksum=$(((256 - sum) % 256))
    printf -v checksum_hex '\\x%02x' "$checksum"
    printf '%b' "$checksum_hex" | dd of="$file" bs=1 seek="$last" conv=notrunc status=none
}
fix_checksum "$tmpdir/valid.rom"
if "$binary" --checkifwi --vbios-file "$tmpdir/valid.rom" --accept-EULA > "$tmpdir/checkifwi.txt" 2>&1; then
    echo 'physical IFWI comparison unexpectedly proceeded without partition metadata' >&2
    exit 1
fi
grep -q 'available only with --simulator' "$tmpdir/checkifwi.txt"
if "$binary" --pavbpn test --accept-EULA > "$tmpdir/pavbpn.txt" 2>&1; then
    echo 'unsupported VBIOS part-number filter unexpectedly succeeded' >&2
    exit 1
fi
grep -q 'part-number filtering is unavailable' "$tmpdir/pavbpn.txt"
"$binary" --simulator --flash --device 0 --vbios-file "$tmpdir/valid.rom" \
    --flash-both-partitions --save-flashed-bytes --accept-EULA | grep -q 'readback verification passed'
test -s "$tmpdir/valid.rom.flashed"
cmp -n 512 "$tmpdir/valid.rom" "$tmpdir/valid.rom.flashed"
cp "$tmpdir/valid.rom" "$tmpdir/bulk.rom"
printf '\x50\x75' | dd of="$tmpdir/bulk.rom" bs=1 seek=38 conv=notrunc status=none
fix_checksum "$tmpdir/bulk.rom"
"$binary" --simulator --pa --device=-1 --padevid=0x7550 --vbios-file "$tmpdir/bulk.rom" \
    --save-flashed-bytes --accept-EULA > "$tmpdir/bulk-flash.txt"
grep -q 'readback verification passed' "$tmpdir/bulk-flash.txt"
test -s "$tmpdir/bulk.rom.flashed"
cmp -n 512 "$tmpdir/bulk.rom" "$tmpdir/bulk.rom.flashed"

printf 'not a VBIOS' > "$tmpdir/bad.rom"
"$binary" --accept-EULA --bios-file-info --vbios-file "$tmpdir/bad.rom" | grep -q 'PCI ROM signature: not found'

if "$binary" --definitely-invalid >"$tmpdir/invalid" 2>&1; then
    echo 'unknown option unexpectedly succeeded' >&2
    exit 1
fi
grep -q 'Invalid command line option' "$tmpdir/invalid"

echo 'CLI smoke checks passed'
