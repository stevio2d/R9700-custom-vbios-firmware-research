#!/usr/bin/env python3
"""Report bounded PCI option-ROM and ATOM structure facts without modifying input."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


PCIR_MIN_SIZE = 0x16
PCIR_IMAGE_LENGTH_OFFSET = 0x10
ATOM_POINTER_OFFSET = 0x48
ATOM_HEADER_MASTER_DATA_OFFSET = 0x20
ATOM_HEADER_MIN_SIZE = ATOM_HEADER_MASTER_DATA_OFFSET + 2
ATOM_MASTER_TABLE_HEADER_SIZE = 4

# Index names from the AMD ATOM master data table v2.1 layout. The parser
# reports these identifiers and common headers only; it does not decode them.
ATOM_DATA_TABLE_IDS = (
    "utility_pipeline",
    "multimedia_info",
    "smc_dpm_info",
    "unclassified_table_03",
    "firmware_info",
    "unclassified_table_05",
    "lcd_info",
    "unclassified_table_07",
    "smu_info",
    "unclassified_table_09",
    "unclassified_table_10",
    "vram_usage_by_firmware",
    "gpio_pin_lut",
    "unclassified_table_13",
    "gfx_info",
    "powerplay_info",
    "unclassified_table_16",
    "unclassified_table_17",
    "unclassified_table_18",
    "unclassified_table_19",
    "unclassified_table_20",
    "unclassified_table_21",
    "display_object_info",
    "indirect_io_access",
    "umc_info",
    "unclassified_table_25",
    "unclassified_table_26",
    "dce_info",
    "vram_info",
    "unclassified_table_29",
    "integrated_system_info",
    "asic_profiling_info",
    "voltage_object_info",
    "unclassified_table_33",
    "unclassified_table_34",
)


def _has_range(offset: int, length: int, limit: int) -> bool:
    """Return whether [offset, offset + length) stays within limit."""
    return offset >= 0 and length >= 0 and offset <= limit and length <= limit - offset


def _u16(data: bytes, offset: int) -> int:
    """Read a little-endian 16-bit value; callers must validate the range."""
    return data[offset] | (data[offset + 1] << 8)


def _warning(
    warnings: list[dict[str, Any]], code: str, message: str, offset: int | None = None
) -> None:
    item: dict[str, Any] = {"code": code, "message": message}
    if offset is not None:
        item["offset"] = offset
    warnings.append(item)


def _looks_like_pcir_image(data: bytes, image_start: int) -> bool:
    """Recognize a bounded ROM header before accepting an embedded candidate."""
    if not _has_range(image_start, 0x1A, len(data)) or data[image_start : image_start + 2] != b"\x55\xaa":
        return False
    pcir_relative = _u16(data, image_start + 0x18)
    pcir_offset = image_start + pcir_relative
    if pcir_relative < 0x1A or not _has_range(pcir_offset, PCIR_MIN_SIZE, len(data)):
        return False
    if data[pcir_offset : pcir_offset + 4] != b"PCIR":
        return False
    structure_length = _u16(data, pcir_offset + 0x0A)
    image_length_units = _u16(data, pcir_offset + PCIR_IMAGE_LENGTH_OFFSET)
    if structure_length < PCIR_MIN_SIZE or image_length_units == 0:
        return False
    image_end = image_start + image_length_units * 512
    if image_end > len(data) or not _has_range(pcir_offset, structure_length, image_end):
        return False
    return True


def _parse_pcir_chain(
    data: bytes,
    first_image_start: int,
    first_index: int,
    chain_index: int,
    warnings: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[tuple[int, int]]]:
    images: list[dict[str, Any]] = []
    covered_ranges: list[tuple[int, int]] = []
    image_start = first_image_start
    visited: set[int] = set()
    chain_image_index = 0
    while image_start < len(data):
        if image_start in visited:
            _warning(warnings, "rom_chain_loop", "ROM image chain points to an already visited image boundary.", image_start)
            break
        visited.add(image_start)

        if not _has_range(image_start, 0x1A, len(data)):
            _warning(warnings, "rom_header_truncated", "PCI option-ROM header is truncated before the PCIR pointer field.", image_start)
            break
        if data[image_start : image_start + 2] != b"\x55\xaa":
            _warning(warnings, "rom_chain_signature_missing", "Expected a PCI option-ROM signature at the next image boundary.", image_start)
            break

        pcir_relative = _u16(data, image_start + 0x18)
        pcir_offset = image_start + pcir_relative
        if pcir_relative == 0:
            _warning(warnings, "pcir_pointer_zero", "PCI option-ROM header has a zero PCIR pointer.", image_start + 0x18)
            break
        if not _has_range(pcir_offset, PCIR_MIN_SIZE, len(data)):
            _warning(warnings, "pcir_structure_truncated", "PCIR structure is outside the available input bytes.", pcir_offset)
            break
        if data[pcir_offset : pcir_offset + 4] != b"PCIR":
            _warning(warnings, "pcir_signature_missing", "PCIR pointer does not reference the PCIR signature.", pcir_offset)
            break

        pcir_structure_length = _u16(data, pcir_offset + 0x0A)
        image_length_units = _u16(data, pcir_offset + PCIR_IMAGE_LENGTH_OFFSET)
        code_type = data[pcir_offset + 0x14]
        if code_type == 0:
            header_length_units: int | None = data[image_start + 2]
        elif code_type == 3:
            header_length_units = _u16(data, image_start + 2)
        else:
            # The common legacy/EFI header fields do not define the size for
            # unknown code types, so leave it uninterpreted.
            header_length_units = None
        header_length_bytes = (
            header_length_units * 512 if header_length_units is not None else None
        )
        if pcir_structure_length < PCIR_MIN_SIZE:
            _warning(warnings, "pcir_structure_length_invalid", "PCIR structure length is shorter than the fields read by this reporter.", pcir_offset + 0x0A)
        if pcir_relative < 0x1A:
            _warning(warnings, "pcir_pointer_overlaps_rom_header", "PCIR pointer overlaps the PCI option-ROM header.", pcir_offset)
        if image_length_units == 0:
            _warning(warnings, "pcir_image_length_zero", "PCIR image length is zero, so the next boundary cannot be determined.", pcir_offset + PCIR_IMAGE_LENGTH_OFFSET)
            break

        declared_length = image_length_units * 512
        image_end = image_start + declared_length
        complete = image_end <= len(data)
        available_end = min(image_end, len(data))
        available_length = max(0, available_end - image_start)

        pcir_in_declared_image = _has_range(pcir_offset, PCIR_MIN_SIZE, available_end)
        structure_in_declared_image = (
            pcir_structure_length >= PCIR_MIN_SIZE
            and _has_range(pcir_offset, pcir_structure_length, available_end)
        )
        if not pcir_in_declared_image:
            _warning(warnings, "pcir_outside_declared_image", "PCIR structure lies outside the image boundary declared by its own length field.", pcir_offset)
        if pcir_structure_length >= PCIR_MIN_SIZE and not structure_in_declared_image:
            _warning(warnings, "pcir_declared_structure_truncated", "PCIR structure length extends beyond the declared or available image boundary.", pcir_offset)
        if header_length_bytes is not None and header_length_bytes != declared_length:
            _warning(warnings, "rom_length_mismatch", "ROM header and PCIR image lengths do not match.", image_start + 2)
        if not complete:
            _warning(warnings, "rom_image_exceeds_file", "PCIR image length extends beyond the available input bytes.", image_start)

        indicator_available = _has_range(pcir_offset + 0x15, 1, available_end)
        if not indicator_available:
            _warning(warnings, "pcir_indicator_unavailable", "PCIR image indicator is outside the declared or available image boundary.", pcir_offset + 0x15)
            break

        indicator = data[pcir_offset + 0x15]
        is_last = bool(indicator & 0x80)
        checksum = None
        if complete:
            pcir_image_sum = sum(data[image_start:image_end]) & 0xFF
            legacy_checksum: dict[str, Any] | None = None
            if code_type == 0:
                legacy_checksum = {
                    "length_bytes": header_length_bytes,
                    "sum_mod_256": None,
                    "valid": None,
                }
                # Legacy option-ROM checksums use the legacy header's size.
                # Keep this range inside the PCIR image boundary even when
                # the two advertised lengths disagree.
                if (
                    header_length_bytes is not None
                    and header_length_bytes > 0
                    and header_length_bytes <= declared_length
                ):
                    legacy_header_sum = sum(
                        data[image_start : image_start + header_length_bytes]
                    ) & 0xFF
                    legacy_checksum["sum_mod_256"] = legacy_header_sum
                    legacy_checksum["valid"] = legacy_header_sum == 0
                else:
                    _warning(
                        warnings,
                        "legacy_header_checksum_unavailable",
                        "Legacy ROM header checksum range is zero or extends beyond the PCIR image boundary.",
                        image_start + 2,
                    )
            checksum = {
                "algorithm": "8_bit_byte_sum",
                "pcir_image_sum_mod_256": pcir_image_sum,
                "legacy_header_checksum": legacy_checksum,
            }
            if legacy_checksum is not None and legacy_checksum["valid"] is False:
                _warning(
                    warnings,
                    "legacy_header_checksum_invalid",
                    "Legacy option-ROM header byte sum is not zero modulo 256.",
                    image_start,
                )

        pcir_valid = (
            pcir_structure_length >= PCIR_MIN_SIZE
            and structure_in_declared_image
            and pcir_in_declared_image
        )
        images.append(
            {
                "index": first_index,
                "chain_index": chain_index,
                "chain_image_index": chain_image_index,
                "offset": image_start,
                "pcir_offset": pcir_offset,
                "header_length_512_byte_units": header_length_units,
                "header_length_bytes": header_length_bytes,
                "pcir_structure_length": pcir_structure_length,
                "image_length_512_byte_units": image_length_units,
                "declared_length_bytes": declared_length,
                "available_length_bytes": available_length,
                "complete": complete,
                "vendor_id": _u16(data, pcir_offset + 4),
                "device_id": _u16(data, pcir_offset + 6),
                "code_type": code_type,
                "indicator": indicator,
                "is_last_image": is_last,
                "checksum": checksum,
                "pcir_bounds_valid": pcir_valid,
            }
        )
        covered_ranges.append((image_start, image_end if complete else available_end))

        if is_last:
            break
        if not complete or image_end <= image_start:
            _warning(warnings, "rom_chain_next_boundary_unavailable", "Cannot safely locate the next chained ROM image.", image_start)
            break
        if image_end >= len(data):
            _warning(warnings, "rom_chain_missing_last_indicator", "Image is not marked as the last ROM image, but no bytes remain for another image.", pcir_offset + 0x15)
            break

        image_start = image_end
        first_index += 1
        chain_image_index += 1

    return images, covered_ranges


def _parse_pcir_images(data: bytes, warnings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    images: list[dict[str, Any]] = []
    covered_ranges: list[tuple[int, int]] = []
    next_index = 0
    next_chain_index = 0

    # A stand-alone option ROM normally starts at byte zero. Firmware packages
    # can also wrap or concatenate ROM images, so scan for other candidates only
    # after validating both the 55 AA header and its bounded PCIR structure.
    if len(data) >= 2 and data[:2] == b"\x55\xaa":
        chain, ranges = _parse_pcir_chain(data, 0, next_index, next_chain_index, warnings)
        images.extend(chain)
        covered_ranges.extend(ranges)
        next_index += len(chain)
        if chain:
            next_chain_index += 1

    search_from = 0
    while search_from < len(data):
        candidate = data.find(b"\x55\xaa", search_from)
        if candidate < 0:
            break
        search_from = candidate + 1
        if any(start <= candidate < end for start, end in covered_ranges):
            continue
        if not _looks_like_pcir_image(data, candidate):
            continue

        chain, ranges = _parse_pcir_chain(data, candidate, next_index, next_chain_index, warnings)
        if chain:
            images.extend(chain)
            covered_ranges.extend(ranges)
            next_index += len(chain)
            next_chain_index += 1

    if not images and not any(warning["code"].startswith("pcir_") or warning["code"].startswith("rom_") for warning in warnings):
        _warning(
            warnings,
            "option_rom_signature_missing",
            "No bounded PCI option-ROM header and PCIR structure were found in the input.",
            0,
        )
    return images


def _record_overlap(
    structures: list[tuple[int, int, str]],
    start: int,
    end: int,
    name: str,
    warnings: list[dict[str, Any]],
) -> None:
    for other_start, other_end, other_name in structures:
        if start < other_end and other_start < end:
            _warning(
                warnings,
                "atom_structures_overlap",
                f"ATOM structures {name} and {other_name} overlap.",
                max(start, other_start),
            )
    structures.append((start, end, name))


def _parse_atom_for_image(
    data: bytes,
    image_start: int,
    image_end: int,
    image_index: int | None,
    tables: list[dict[str, Any]],
    warnings: list[dict[str, Any]],
) -> None:
    if not _has_range(image_start + ATOM_POINTER_OFFSET, 2, image_end):
        return

    atom_relative = _u16(data, image_start + ATOM_POINTER_OFFSET)
    if atom_relative == 0:
        return
    atom_offset = image_start + atom_relative
    if not _has_range(atom_offset, ATOM_HEADER_MIN_SIZE, image_end):
        _warning(warnings, "atom_rom_header_out_of_bounds", "ATOM ROM-header pointer is outside the bounded image.", atom_offset)
        return
    if data[atom_offset + 4 : atom_offset + 8] != b"ATOM":
        _warning(warnings, "atom_signature_missing", "ATOM ROM-header pointer does not reference the ATOM signature.", atom_offset + 4)
        return

    atom_header_length = _u16(data, atom_offset)
    atom_format_revision = data[atom_offset + 2]
    atom_content_revision = data[atom_offset + 3]
    if atom_header_length < ATOM_HEADER_MIN_SIZE:
        _warning(warnings, "atom_rom_header_too_short", "ATOM ROM-header length does not include the master data-table pointer.", atom_offset)
        return
    if not _has_range(atom_offset, atom_header_length, image_end):
        _warning(warnings, "atom_rom_header_exceeds_image", "ATOM ROM-header length extends beyond the bounded image.", atom_offset)
        return

    if atom_format_revision != 2:
        _warning(warnings, "atom_rom_header_format_unsupported", "ATOM ROM-header format revision is not the supported v2 layout; only its common header is reported.", atom_offset + 2)
        tables.append(
            {
                "table_id": "ATOM_ROM_HEADER",
                "kind": "rom_header",
                "image_index": image_index,
                "offset": atom_offset,
                "image_relative_offset": atom_relative,
                "length": atom_header_length,
                "format_revision": atom_format_revision,
                "content_revision": atom_content_revision,
            }
        )
        return

    master_relative = _u16(data, atom_offset + ATOM_HEADER_MASTER_DATA_OFFSET)
    tables.append(
        {
            "table_id": "ATOM_ROM_HEADER",
            "kind": "rom_header",
            "image_index": image_index,
            "offset": atom_offset,
            "image_relative_offset": atom_relative,
            "length": atom_header_length,
            "format_revision": atom_format_revision,
            "content_revision": atom_content_revision,
        }
    )
    structures: list[tuple[int, int, str]] = []
    _record_overlap(structures, atom_offset, atom_offset + atom_header_length, "ATOM_ROM_HEADER", warnings)

    if master_relative == 0:
        _warning(warnings, "atom_master_data_pointer_zero", "ATOM ROM header has no master data-table pointer.", atom_offset + ATOM_HEADER_MASTER_DATA_OFFSET)
        return

    master_offset = image_start + master_relative
    if not _has_range(master_offset, ATOM_MASTER_TABLE_HEADER_SIZE, image_end):
        _warning(warnings, "atom_master_data_table_header_out_of_bounds", "ATOM master data-table header is outside the bounded image.", master_offset)
        return

    master_length = _u16(data, master_offset)
    master_format_revision = data[master_offset + 2]
    master_content_revision = data[master_offset + 3]
    if master_length < ATOM_MASTER_TABLE_HEADER_SIZE:
        _warning(warnings, "atom_master_data_table_too_short", "ATOM master data-table length is shorter than its common header.", master_offset)
        return
    if not _has_range(master_offset, master_length, image_end):
        _warning(warnings, "atom_master_data_table_exceeds_image", "ATOM master data-table length extends beyond the bounded image.", master_offset)
        return

    tables.append(
        {
            "table_id": "MASTER_DATA_TABLE",
            "kind": "master_data_table",
            "image_index": image_index,
            "offset": master_offset,
            "image_relative_offset": master_relative,
            "length": master_length,
            "format_revision": master_format_revision,
            "content_revision": master_content_revision,
        }
    )
    _record_overlap(structures, master_offset, master_offset + master_length, "MASTER_DATA_TABLE", warnings)

    if (master_format_revision, master_content_revision) != (2, 1):
        _warning(warnings, "atom_master_data_table_revision_unsupported", "Master data-table pointer list is only decoded for ATOM revision 2.1.", master_offset + 2)
        return

    available_entry_bytes = master_length - ATOM_MASTER_TABLE_HEADER_SIZE
    if available_entry_bytes % 2:
        _warning(warnings, "atom_master_data_table_odd_length", "Master data-table pointer list has an odd number of bytes.", master_offset)
    declared_entry_count = available_entry_bytes // 2
    if declared_entry_count < len(ATOM_DATA_TABLE_IDS):
        _warning(warnings, "atom_master_data_table_short", "Master data-table pointer list is shorter than the known 35-entry v2.1 layout.", master_offset)
    elif declared_entry_count > len(ATOM_DATA_TABLE_IDS):
        _warning(warnings, "atom_master_data_table_extra_entries", "Master data-table has entries beyond the known v2.1 identifiers; extra entries are not decoded.", master_offset)

    entry_count = min(declared_entry_count, len(ATOM_DATA_TABLE_IDS))
    for table_index in range(entry_count):
        pointer_offset = master_offset + ATOM_MASTER_TABLE_HEADER_SIZE + table_index * 2
        table_relative = _u16(data, pointer_offset)
        if table_relative == 0:
            continue

        table_offset = image_start + table_relative
        table_id = ATOM_DATA_TABLE_IDS[table_index]
        if not _has_range(table_offset, 4, image_end):
            _warning(warnings, "atom_data_table_header_out_of_bounds", f"ATOM data-table pointer for {table_id} is outside the bounded image.", table_offset)
            continue

        table_length = _u16(data, table_offset)
        table_format_revision = data[table_offset + 2]
        table_content_revision = data[table_offset + 3]
        if table_length < 4:
            _warning(warnings, "atom_data_table_too_short", f"ATOM data table {table_id} is shorter than its common header.", table_offset)
            continue
        if not _has_range(table_offset, table_length, image_end):
            _warning(warnings, "atom_data_table_exceeds_image", f"ATOM data table {table_id} extends beyond the bounded image.", table_offset)
            continue

        _record_overlap(structures, table_offset, table_offset + table_length, table_id, warnings)
        tables.append(
            {
                "table_id": table_id,
                "kind": "data_table",
                "index": table_index,
                "image_index": image_index,
                "offset": table_offset,
                "image_relative_offset": table_relative,
                "length": table_length,
                "format_revision": table_format_revision,
                "content_revision": table_content_revision,
            }
        )


def _parse_atom_tables(
    data: bytes, pcir_images: list[dict[str, Any]], warnings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    tables: list[dict[str, Any]] = []
    bounded_images = [
        image
        for image in pcir_images
        if image["complete"] and image["pcir_bounds_valid"] and image["code_type"] == 0
    ]
    if bounded_images:
        for image in bounded_images:
            _parse_atom_for_image(
                data,
                image["offset"],
                image["offset"] + image["declared_length_bytes"],
                image["index"],
                tables,
                warnings,
            )
    elif not pcir_images and data:
        # Raw extracted payloads sometimes omit the PCI header. Keep the whole
        # file as an explicit fallback boundary, still validating every pointer.
        _parse_atom_for_image(data, 0, len(data), None, tables, warnings)
    return tables


def analyze_bytes(data: bytes, input_path: str = "<bytes>") -> dict[str, Any]:
    warnings: list[dict[str, Any]] = []
    pcir_images = _parse_pcir_images(data, warnings)
    atom_tables = _parse_atom_tables(data, pcir_images, warnings)
    return {
        "schema_version": 1,
        "input_path": input_path,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "pcir_images": pcir_images,
        "atom_tables": atom_tables,
        "warnings": warnings,
    }


def analyze_file(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    return analyze_bytes(data, str(path))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only, bounded PCI option-ROM and ATOM structure reporter."
    )
    parser.add_argument("image", help="ROM or firmware image path")
    args = parser.parse_args(argv)

    try:
        report = analyze_file(Path(args.image))
    except OSError as exc:
        report = {
            "schema_version": 1,
            "input_path": args.image,
            "error": {"type": type(exc).__name__, "message": str(exc)},
            "warnings": [],
        }
        print(json.dumps(report, indent=2, sort_keys=True))
        return 2

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
