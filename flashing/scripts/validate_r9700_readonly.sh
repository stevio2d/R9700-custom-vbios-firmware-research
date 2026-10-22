#!/usr/bin/env bash
set -euo pipefail

binary="${R9700FLASH_DUMP_BIN:-${R9700FLASH_BIN:-R9700flash-dump}}"
output_dir="${1:-$PWD/r9700flash-dump-backup}"

if ! command -v "$binary" >/dev/null 2>&1; then
    echo "R9700flash-dump binary not found: $binary" >&2
    exit 2
fi

device_list="$("$binary" --list)"
printf '%s\n' "$device_list"

target_index=""
target_bdf=""
while IFS= read -r line; do
    [[ "$line" == *"Raw SPI backup=supported"* ]] || continue
    [[ "$line" == *"Device=0x7550"* || "$line" == *"Device=0x7551"* ]] || continue
    target_index="${line#\[}"
    target_index="${target_index%%\]*}"
    rest="${line#*] }"
    target_bdf="${rest#*\[}"
    target_bdf="${target_bdf%%\]*}"
    break
done <<< "$device_list"

if [[ -z "$target_bdf" ]]; then
    echo "No supported R9700 device with PCI ID 0x7550 or 0x7551 was found." >&2
    exit 1
fi

mkdir -p "$output_dir"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup="$output_dir/Radeon_AI_PRO_R9700_${target_bdf}_${timestamp}.spi.rom"
echo "Backing up raw Navi48 SPI ROM from $target_bdf (tool index $target_index) to $backup"
"$binary" --backup --device "$target_index" --output "$backup"
if [[ ! -s "$backup" ]]; then
    echo "No raw ROM backup was created." >&2
    exit 1
fi
size="$(wc -c < "$backup")"
if [[ "$size" -ne 2097152 ]]; then
    echo "Expected a 2097152-byte Navi48 SPI image, got $size bytes." >&2
    exit 1
fi
python3 - "$backup" <<'PY'
import pathlib
import sys

image = pathlib.Path(sys.argv[1]).read_bytes()
signature = b" 761295520"
header_size = 0x30 + len(signature)
found_offset = None

for offset in range(0, len(image) - header_size + 1, 512):
    if image[offset:offset + 2] != b"\x55\xaa":
        continue
    rom_size = image[offset + 2] << 9
    if rom_size < header_size or offset + rom_size > len(image):
        continue
    if image[offset + 0x30:offset + header_size] == signature:
        found_offset = offset
        break

if found_offset is None:
    print("No complete AMD VBIOS option-ROM image was found in the raw SPI dump.", file=sys.stderr)
    raise SystemExit(1)

print(f"AMD VBIOS option-ROM image found at raw offset 0x{found_offset:x}.")
PY
sha256sum "$backup"
echo "Raw SPI backup complete; no flash erase or programming command was run."
