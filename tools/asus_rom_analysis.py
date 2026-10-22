#!/usr/bin/env python3
"""Read-only map and compare ASUS R9700 update-package ROM payloads.

The tool reads the ZIP, embedded updater PE files, and ROM inputs only. It does
not execute updater code, invoke a flasher, or modify firmware inputs. Optional
JSON and Markdown outputs are analysis artifacts written only to the requested
output paths.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import struct
import sys
import tempfile
import zipfile
import zlib
from pathlib import Path
from typing import Any

try:
    from tools.rom_triage import ATOM_DATA_TABLE_IDS, analyze_bytes
except ModuleNotFoundError:  # Running this file directly from tools/.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from tools.rom_triage import ATOM_DATA_TABLE_IDS, analyze_bytes


TOOL_VERSION = "1.5.0"
CHECKED_DATE = "2026-10-19"
EXPECTED_INPUT_HASHES = {
    "package": "cd499dbf1079b2e65666ff66877c367b4823bbe15910446ab1a2a72c7224b0a0",
    "AS04": "0242ce25f406d61f7ff87c3e7be1324ad8f6e1066a2279e6b9ec03b736e60235",
    "AS07": "bee92e0a7092c9849b636bf0ec9eaf172c213cb3e34056bac40bc67c6150ecb4",
}
UEFI_SPEC = "https://uefi.org/specs/UEFI/2.10/14_Protocols_PCI_Bus_Support.html"
UEFI_COMPRESSION_SPEC = "https://uefi.org/specs/UEFI/2.10_A/19_Protocols_Compression_Algorithm_Specification.html"
LINUX_SOURCE_COMMIT = "32c52ec87d6245ee2d12ed5dd509e40062939b50"
ATOM_HEADER = f"https://github.com/torvalds/linux/blob/{LINUX_SOURCE_COMMIT}/drivers/gpu/drm/amd/include/atomfirmware.h"
ATOMBIOS_HEADER = f"https://github.com/torvalds/linux/blob/{LINUX_SOURCE_COMMIT}/drivers/gpu/drm/amd/include/atombios.h"
AMDGPU_ATOM_DRIVER = f"https://github.com/torvalds/linux/blob/{LINUX_SOURCE_COMMIT}/drivers/gpu/drm/amd/amdgpu/amdgpu_atomfirmware.c"
CURRENT_ATOM_HEADER = "https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/amd/include/atomfirmware.h"
CURRENT_AMDGPU_ATOM_DRIVER = "https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/amd/amdgpu/amdgpu_atomfirmware.c"
MICROSOFT_PE_FORMAT = "https://learn.microsoft.com/en-us/windows/win32/debug/pe-format"
MICROSOFT_AUTHENTICODE_PE = "https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx"
OPENSSL_SMIME_DOC = "https://docs.openssl.org/3.6/man1/openssl-smime/"
ASUS_EFI_COMPRESSED_STREAM_SHA256 = "d1eeeeb544af7486cbec12e03c4f6c553eb518dac693e93ed85d0dc51d825c11"
RAR5_SIGNATURE = b"Rar!\x1a\x07\x01\x00"
MAX_EFI_OUTPUT_BYTES = 16 * 1024 * 1024
EDK2_TIANOCOMPRESS_SOURCE = "https://github.com/tianocore/edk2/tree/c1415771ac592ad8509351c46cd3cda4f38d7d52/BaseTools/Source/C/TianoCompress"
GHIDRA_RELEASE = "Ghidra 12.1.4"
GHIDRA_RELEASE_URL = "https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build"
GHIDRA_ARCHIVE_SHA256 = "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db"
GHIDRA_JDK = {
    "distribution": "Eclipse Temurin JDK 21.0.12.1+1",
    "archive_sha256": "ce79869e1307ed8ee1e2baa86a412b1eb5b75d10a01006d788a6f968bcfaee94",
    "release_lead": "https://adoptium.net/temurin/releases/?version=21",
}

ATOM_CAPABILITIES = {
    "firmware_posted": 0x00000001,
    "gpu_virtualization": 0x00000002,
    "wmi_support": 0x00000040,
    "hwemu_enable": 0x00000080,
    "hwemu_umc_cfg": 0x00000100,
    "sram_ecc": 0x00000200,
    "enable_2stage_bist_training": 0x00000400,
    "enable_2nd_usb20port": 0x00008000,
    "dynamic_boot_cfg_enable": 0x00020000,
}

# Symbol spellings from atom_master_list_of_data_tables_v2_1 in the pinned
# Linux AMD ATOM header. Generic sw_datatableN entries are deliberately kept
# generic: the public header preserves their slot but does not define meaning.
ATOM_MASTER_DATA_FIELDS = (
    "utilitypipeline",
    "multimedia_info",
    "smc_dpm_info",
    "sw_datatable3",
    "firmwareinfo",
    "sw_datatable5",
    "lcd_info",
    "sw_datatable7",
    "smu_info",
    "sw_datatable9",
    "sw_datatable10",
    "vram_usagebyfirmware",
    "gpio_pin_lut",
    "sw_datatable13",
    "gfx_info",
    "powerplayinfo",
    "sw_datatable16",
    "sw_datatable17",
    "sw_datatable18",
    "sw_datatable19",
    "sw_datatable20",
    "sw_datatable21",
    "displayobjectinfo",
    "indirectioaccess",
    "umc_info",
    "sw_datatable25",
    "sw_datatable26",
    "dce_info",
    "vram_info",
    "sw_datatable29",
    "integratedsysteminfo",
    "asic_profiling_info",
    "voltageobject_info",
    "sw_datatable33",
    "sw_datatable34",
)

STRING_PATTERNS = (
    ("asus_vbios_part", re.compile(r"^115-[A-Z0-9-]+$")),
    ("asus_rom_version", re.compile(r"^7551OG\.23\.8\.0\.68\.AS0[47]$")),
    ("atom_bios_version", re.compile(r"^ATOMBIOSBK-AMD\s+VER[0-9.]+$")),
    ("board_string", re.compile(r"^ASUS_G28702_[A-Z0-9_]+$")),
    ("gop_version_string", re.compile(r"^GOP AMD REV: [0-9.]+$")),
    ("build_timestamp_string", re.compile(r"^\d{1,2}/\d{1,2}/\d{2},\d{2}:\d{2}:\d{2}$")),
    ("product_string", re.compile(r"^TURBO-AI-PRO-R9700$")),
)


def _in_bounds(data: bytes, offset: int, length: int) -> bool:
    return offset >= 0 and length >= 0 and offset <= len(data) and length <= len(data) - offset


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _ascii_strings(data: bytes, base_offset: int = 0) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for match in re.finditer(rb"[\x20-\x7e]{5,}", data):
        value = match.group().decode("ascii", "replace").rstrip()
        for label, pattern in STRING_PATTERNS:
            if pattern.fullmatch(value):
                findings.append(
                    {
                        "label": label,
                        "offset": base_offset + match.start(),
                        "length": len(match.group()),
                        "value": value,
                        "evidence": "literal ASCII bytes",
                        "confidence": "high for the string value; semantics remain limited to the label",
                    }
                )
                break
    return findings


def _parse_pe_header(data: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {"recognized": False, "warnings": []}
    if not _in_bounds(data, 0, 0x40) or data[:2] != b"MZ":
        result["warnings"].append("Missing or truncated DOS MZ header.")
        return result

    pe_offset = _u32(data, 0x3C)
    if not _in_bounds(data, pe_offset, 24) or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        result["warnings"].append("PE signature pointer is out of bounds or does not identify PE\\0\\0.")
        return result

    machine, section_count, timestamp, _, _, optional_size, characteristics = struct.unpack_from(
        "<HHIIIHH", data, pe_offset + 4
    )
    optional_offset = pe_offset + 24
    if not _in_bounds(data, optional_offset, optional_size) or optional_size < 2:
        result["warnings"].append("Optional PE header is truncated.")
        return result

    magic = _u16(data, optional_offset)
    required_optional_size = {0x20B: 112, 0x10B: 96}.get(magic)
    if required_optional_size is None:
        result["warnings"].append(f"Unsupported optional-header magic 0x{magic:04x}.")
        return result
    if optional_size < required_optional_size:
        result["warnings"].append(
            f"PE optional header is too short for its declared PE32/PE32+ layout ({optional_size} < {required_optional_size} bytes)."
        )
        return result

    if magic == 0x20B:
        directory_offset = optional_offset + 112
        image_base = struct.unpack_from("<Q", data, optional_offset + 24)[0]
        directory_count_offset = optional_offset + 108
        directory_count = _u32(data, directory_count_offset)
        entry_point = _u32(data, optional_offset + 16)
    elif magic == 0x10B:
        directory_offset = optional_offset + 96
        image_base = _u32(data, optional_offset + 28)
        directory_count_offset = optional_offset + 92
        directory_count = _u32(data, directory_count_offset)
        entry_point = _u32(data, optional_offset + 16)

    subsystem = _u16(data, optional_offset + 68)
    size_of_image = _u32(data, optional_offset + 56)
    size_of_headers = _u32(data, optional_offset + 60)
    if size_of_image == 0:
        result["warnings"].append("PE SizeOfImage is zero.")
    if size_of_headers == 0 or size_of_headers > len(data):
        result["warnings"].append("PE SizeOfHeaders is zero or exceeds the bounded file.")
    if entry_point >= size_of_image:
        result["warnings"].append("PE entry-point RVA is outside SizeOfImage.")
    available_directories = max(0, (optional_offset + optional_size - directory_offset) // 8)
    parsed_directory_count = min(directory_count, available_directories, 32)
    directories = []
    for index in range(parsed_directory_count):
        virtual_address, size = struct.unpack_from("<II", data, directory_offset + index * 8)
        directories.append({"index": index, "address_or_file_offset": virtual_address, "size": size})
    cert_offset = cert_length = 0
    if parsed_directory_count > 4:
        cert_offset, cert_length = struct.unpack_from("<II", data, directory_offset + 8 * 4)
    elif directory_count > 4:
        result["warnings"].append("PE certificate-table directory is declared but truncated by the optional-header bounds.")
    if (cert_offset == 0) != (cert_length == 0):
        result["warnings"].append("PE certificate-table directory has only one of offset and size set.")

    sections: list[dict[str, Any]] = []
    section_table_offset = optional_offset + optional_size
    if section_table_offset + section_count * 40 > size_of_headers:
        result["warnings"].append("PE section table extends beyond SizeOfHeaders.")
    for index in range(section_count):
        section_offset = section_table_offset + index * 40
        if not _in_bounds(data, section_offset, 40):
            result["warnings"].append("PE section table is truncated.")
            break
        section_name = data[section_offset : section_offset + 8].split(b"\x00", 1)[0].decode(
            "ascii", "replace"
        )
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, section_offset + 8
        )
        section_characteristics = _u32(data, section_offset + 36)
        section_virtual_length = virtual_size or raw_size
        virtual_range_in_image = (
            size_of_image > 0
            and virtual_address <= size_of_image
            and section_virtual_length <= size_of_image - virtual_address
        )
        sections.append(
            {
                "name": section_name,
                "virtual_address": virtual_address,
                "virtual_size": virtual_size,
                "raw_offset": raw_offset,
                "raw_size": raw_size,
                "characteristics_hex": f"0x{section_characteristics:08x}",
                "executable": bool(section_characteristics & 0x20000000),
                "readable": bool(section_characteristics & 0x40000000),
                "writable": bool(section_characteristics & 0x80000000),
                "raw_range_in_bounds": _in_bounds(data, raw_offset, raw_size),
                "virtual_range_in_image": virtual_range_in_image,
            }
        )
        if not virtual_range_in_image:
            result["warnings"].append(f"PE section {section_name} virtual range exceeds SizeOfImage.")

    raw_ranges = sorted(
        (section["raw_offset"], section["raw_offset"] + section["raw_size"], section["name"])
        for section in sections
        if section["raw_size"]
    )
    for previous, current in zip(raw_ranges, raw_ranges[1:]):
        if current[0] < previous[1]:
            result["warnings"].append(f"PE section raw ranges overlap: {previous[2]} and {current[2]}.")

    bounded_section_ends = [
        section["raw_offset"] + section["raw_size"]
        for section in sections
        if section["raw_size"] and section["raw_range_in_bounds"]
    ]
    last_section_raw_end = max(bounded_section_ends, default=None)
    certificate_range_in_bounds = bool(
        cert_offset and cert_length and _in_bounds(data, cert_offset, cert_length)
    )
    overlay_end = cert_offset if certificate_range_in_bounds else len(data)
    pre_certificate_overlay = None
    if last_section_raw_end is not None and overlay_end > last_section_raw_end:
        pre_certificate_overlay = {
            "start": last_section_raw_end,
            "end": overlay_end,
            "length": overlay_end - last_section_raw_end,
        }
    checksum_file_offset = optional_offset + 64
    certificate_directory_entry_file_offset = directory_offset + 8 * 4

    result.update(
        {
            "recognized": True,
            "pe_offset": pe_offset,
            "machine": machine,
            "machine_name": {0x8664: "AMD64", 0x14C: "i386"}.get(machine, "unknown"),
            "section_count": section_count,
            "timestamp_field": timestamp,
            "optional_header_magic": magic,
            "pe32_plus": magic == 0x20B,
            "image_base": image_base,
            "entry_point_rva": entry_point,
            "size_of_image": size_of_image,
            "size_of_headers": size_of_headers,
            "subsystem": subsystem,
            "subsystem_name": {
                2: "Windows GUI",
                3: "Windows console",
                10: "EFI application",
                11: "EFI boot service driver",
                12: "EFI runtime driver",
            }.get(subsystem, "other or unknown"),
            "characteristics": characteristics,
            "certificate_directory": {
                "offset": cert_offset,
                "length": cert_length,
                "present": bool(cert_offset and cert_length),
                "range_in_bounds": _in_bounds(data, cert_offset, cert_length)
                if cert_offset or cert_length
                else None,
                "signature_verification": "not attempted",
            },
            "authenticode_coverage_geometry": {
                "basis": MICROSOFT_AUTHENTICODE_PE,
                "analysis": "PE byte-range geometry; Authenticode hashing is calculated separately below",
                "last_bounded_section_raw_end": last_section_raw_end,
                "pre_certificate_overlay_range": pre_certificate_overlay,
                "checksum_file_offset": checksum_file_offset,
                "certificate_directory_entry_file_offset": certificate_directory_entry_file_offset,
                "size_of_headers": size_of_headers,
                "certificate_table_range": {
                    "start": cert_offset,
                    "end": cert_offset + cert_length,
                    "length": cert_length,
                    "in_bounds": certificate_range_in_bounds,
                } if cert_offset or cert_length else None,
                "standard_authenticode_exclusions": [
                    "optional-header checksum field",
                    "certificate-table data-directory entry",
                    "certificate table and its certificate records",
                ],
                "coverage_limit": "A PKCS_SIGNED_DATA certificate-table entry does not by itself prove a valid Authenticode signature. The linked Authenticode_PE procedure hashes extra file data after the section stream up to the certificate-table size exclusion; byte geometry alone does not establish signer trust, embedded-payload behavior, or GPU image acceptance.",
            },
            "data_directories": directories,
            "sections": sections,
        }
    )
    return result


def _tianocompress_metadata(path: Path) -> dict[str, Any]:
    executable = path.resolve()
    metadata: dict[str, Any] = {
        "name": "EDK II TianoCompress",
        "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "source": EDK2_TIANOCOMPRESS_SOURCE,
        "source_commit": "c1415771ac592ad8509351c46cd3cda4f38d7d52",
        "previously_recorded_executable_sha256": "9d07afc9ff531e9dd901bf03073ee8838d26f8bcbbaea273bdae16e8274a6318",
        "previously_recorded_executable_available_for_comparison": False,
        "rebuild_identity_note": "This executable was rebuilt from the pinned EDK II source commit. The earlier recorded binary was absent, so byte-for-byte restoration cannot be asserted; the decompressed GOP output hash was reproduced.",
        "build_command": "make -C BaseTools/Source/C/Common -f GNUmakefile -j2; make -C BaseTools/Source/C/TianoCompress -f GNUmakefile -j2",
        "mode": "-d --uefi",
    }
    try:
        version = subprocess.run(
            [str(executable), "--version"], capture_output=True, text=True, timeout=5, check=False
        )
        metadata["version"] = (version.stdout or version.stderr).strip().splitlines()[0]
        metadata["version_exit_code"] = version.returncode
    except (OSError, subprocess.TimeoutExpired) as exc:
        metadata["version"] = None
        metadata["version_error"] = f"{type(exc).__name__}: {exc}"
    return metadata


def _certificate_table(data: bytes, pe: dict[str, Any]) -> dict[str, Any] | None:
    directory = pe.get("certificate_directory", {})
    offset = directory.get("offset", 0)
    length = directory.get("length", 0)
    if not offset and not length:
        return None
    result: dict[str, Any] = {
        "offset": offset,
        "length": length,
        "range_in_bounds": _in_bounds(data, offset, length),
        "sha256": hashlib.sha256(data[offset : offset + length]).hexdigest()
        if _in_bounds(data, offset, length)
        else None,
        "signature_verification": "not attempted",
        "entries": [],
    }
    if not _in_bounds(data, offset, length):
        return result
    cursor = offset
    end = offset + length
    while cursor + 8 <= end:
        certificate_length, revision, certificate_type = struct.unpack_from("<IHH", data, cursor)
        if certificate_length < 8 or cursor + certificate_length > end:
            result["entries"].append(
                {"offset": cursor, "status": "malformed_WIN_CERTIFICATE", "declared_length": certificate_length}
            )
            break
        result["entries"].append(
            {
                "offset": cursor,
                "length": certificate_length,
                "revision_hex": f"0x{revision:04x}",
                "type_hex": f"0x{certificate_type:04x}",
                "type_name": "PKCS_SIGNED_DATA" if certificate_type == 2 else "unknown",
                "certificate_data_sha256": hashlib.sha256(data[cursor + 8 : cursor + certificate_length]).hexdigest(),
                "status": "bounded certificate record; cryptographic verification not attempted",
            }
        )
        cursor += (certificate_length + 7) & ~7
    if cursor < end and all(byte == 0 for byte in data[cursor:end]):
        result["padding_range"] = {"start": cursor, "end": end, "value": 0}
    elif cursor != end:
        result["trailing_bytes"] = {"start": cursor, "end": end}
    return result


def _authenticode_sha256_analysis(data: bytes, pe: dict[str, Any]) -> dict[str, Any]:
    """Calculate the SHA-256 byte stream described by Microsoft's Authenticode_PE procedure.

    Cryptographic verification of the CMS record and its SPC image digest is reported
    separately after this byte-range calculation.
    """
    geometry = pe.get("authenticode_coverage_geometry", {})
    certificate = pe.get("certificate_directory", {})
    if not pe.get("recognized"):
        return {"status": "not_computed", "reason": "PE headers were not recognized"}

    size_of_headers = geometry.get("size_of_headers")
    checksum_offset = geometry.get("checksum_file_offset")
    certificate_entry_offset = geometry.get("certificate_directory_entry_file_offset")
    certificate_offset = certificate.get("offset", 0)
    certificate_length = certificate.get("length", 0)
    if not all(isinstance(value, int) for value in (size_of_headers, checksum_offset, certificate_entry_offset)):
        return {"status": "not_computed", "reason": "required PE hash-field offsets are unavailable"}
    if size_of_headers > len(data) or not _in_bounds(data, checksum_offset, 4) or not _in_bounds(data, certificate_entry_offset, 8):
        return {"status": "not_computed", "reason": "header hash fields exceed bounded file data"}
    if checksum_offset + 4 > certificate_entry_offset or certificate_entry_offset + 8 > size_of_headers:
        return {"status": "not_computed", "reason": "checksum, certificate-directory entry, and SizeOfHeaders order is inconsistent"}
    if len(pe.get("data_directories", [])) <= 4:
        return {"status": "not_computed", "reason": "certificate-table directory entry is not declared in the optional header"}
    if (certificate_offset == 0) != (certificate_length == 0):
        return {"status": "not_computed", "reason": "certificate-table directory has only one of offset and size set"}
    if certificate_length and not certificate.get("range_in_bounds"):
        return {"status": "not_computed", "reason": "certificate-table range exceeds bounded file data"}
    if certificate_length and certificate_offset + certificate_length != len(data):
        return {"status": "not_computed", "reason": "certificate table is not at end of file; bounded implementation requires the documented terminal-table layout"}

    sections = sorted(
        (section for section in pe.get("sections", []) if section.get("raw_size", 0)),
        key=lambda section: section.get("raw_offset", -1),
    )
    if len(pe.get("sections", [])) != pe.get("section_count"):
        return {"status": "not_computed", "reason": "section table is truncated or section count is incomplete"}
    if any(not section.get("raw_range_in_bounds") for section in sections):
        return {"status": "not_computed", "reason": "one or more section raw ranges exceed bounded file data"}
    for previous, current in zip(sections, sections[1:]):
        previous_end = previous["raw_offset"] + previous["raw_size"]
        if current["raw_offset"] < previous_end:
            return {"status": "not_computed", "reason": "section raw ranges overlap"}
    if any(section["raw_offset"] < size_of_headers for section in sections):
        return {"status": "not_computed", "reason": "section raw range overlaps PE headers"}
    if certificate_length and any(
        section["raw_offset"] < certificate_offset + certificate_length
        and certificate_offset < section["raw_offset"] + section["raw_size"]
        for section in sections
    ):
        return {"status": "not_computed", "reason": "certificate table overlaps a section raw range"}

    sum_of_bytes_hashed = size_of_headers + sum(section["raw_size"] for section in sections)
    if sum_of_bytes_hashed > len(data):
        return {"status": "not_computed", "reason": "SizeOfHeaders plus section raw sizes exceeds file size"}
    extra_length = len(data) - (certificate_length + sum_of_bytes_hashed)
    if extra_length < 0 or sum_of_bytes_hashed + extra_length > len(data):
        return {"status": "not_computed", "reason": "Microsoft extra-data length formula is inconsistent with bounded file size"}

    hashed_ranges = [
        {"start": 0, "end": checksum_offset, "kind": "PE header before checksum"},
        {"start": checksum_offset + 4, "end": certificate_entry_offset, "kind": "PE header after checksum before certificate directory"},
        {"start": certificate_entry_offset + 8, "end": size_of_headers, "kind": "remaining PE headers, including section table"},
    ]
    hashed_ranges.extend(
        {
            "start": section["raw_offset"],
            "end": section["raw_offset"] + section["raw_size"],
            "kind": f"section {section['name']} raw data",
        }
        for section in sections
    )
    if extra_length:
        hashed_ranges.append(
            {
                "start": sum_of_bytes_hashed,
                "end": sum_of_bytes_hashed + extra_length,
                "kind": "extra file data per Microsoft Authenticode_PE step 14",
            }
        )

    digest = hashlib.sha256()
    for item in hashed_ranges:
        digest.update(data[item["start"] : item["end"]])
    return {
        "status": "computed",
        "algorithm": "SHA-256",
        "candidate_image_digest": digest.hexdigest(),
        "hash_procedure_source": MICROSOFT_AUTHENTICODE_PE,
        "sum_of_bytes_hashed": sum_of_bytes_hashed,
        "file_size_bytes": len(data),
        "certificate_table_size_bytes": certificate_length,
        "extra_data_formula": "file_size - (certificate_table_size + sum_of_bytes_hashed)",
        "extra_data_range": {
            "start": sum_of_bytes_hashed,
            "end": sum_of_bytes_hashed + extra_length,
            "length": extra_length,
        },
        "hashed_ranges": hashed_ranges,
        "excluded_ranges": [
            {"start": checksum_offset, "end": checksum_offset + 4, "kind": "optional-header checksum"},
            {"start": certificate_entry_offset, "end": certificate_entry_offset + 8, "kind": "certificate-table data-directory entry"},
            {"start": certificate_offset, "end": certificate_offset + certificate_length, "kind": "attribute certificate table"},
        ],
        "signature_verification": "see separate cryptographic_verification field",
    }


def _annotate_authenticode_digest_record_match(
    data: bytes, certificate_table: dict[str, Any] | None, analysis: dict[str, Any]
) -> dict[str, Any]:
    candidate_digest = analysis.get("candidate_image_digest")
    matching_offsets: list[int] = []
    if analysis.get("status") == "computed" and candidate_digest and certificate_table:
        candidate_bytes = bytes.fromhex(candidate_digest)
        for entry in certificate_table.get("entries", []):
            if entry.get("type_name") != "PKCS_SIGNED_DATA" or not entry.get("length"):
                continue
            start = entry["offset"] + 8
            end = entry["offset"] + entry["length"]
            if candidate_bytes in data[start:end]:
                matching_offsets.append(entry["offset"])
    analysis["candidate_digest_occurs_in_pkcs_signed_data_record"] = bool(matching_offsets)
    analysis["matching_certificate_record_offsets"] = matching_offsets
    if analysis.get("status") != "computed" or not candidate_digest:
        analysis["digest_match_limit"] = "No candidate image digest was computed, so no certificate-record occurrence check was possible."
    elif certificate_table is None:
        analysis["digest_match_limit"] = "No bounded certificate table was available to search for the candidate SHA-256 digest bytes."
    elif matching_offsets:
        analysis["digest_match_limit"] = (
            "The raw candidate SHA-256 digest bytes occur in a bounded PKCS#7 record. This byte search alone does not validate the signed image digest or CMS signature; see the separate cryptographic_verification record."
        )
    else:
        analysis["digest_match_limit"] = (
            "The raw candidate SHA-256 digest bytes were not found in a bounded PKCS#7 record. See cryptographic_verification for the separate CMS and signed-image-digest check."
        )
    return analysis


def _read_der_tlv(data: bytes, offset: int) -> tuple[int, bytes, int] | None:
    """Read one bounded, definite-length DER element."""
    if not _in_bounds(data, offset, 2):
        return None
    tag = data[offset]
    first_length = data[offset + 1]
    cursor = offset + 2
    if first_length < 0x80:
        length = first_length
    else:
        length_bytes = first_length & 0x7F
        if length_bytes == 0 or length_bytes > 4 or not _in_bounds(data, cursor, length_bytes):
            return None
        if data[cursor] == 0:
            return None
        length = int.from_bytes(data[cursor : cursor + length_bytes], "big")
        if length < 0x80:
            return None
        cursor += length_bytes
    if not _in_bounds(data, cursor, length):
        return None
    return tag, data[cursor : cursor + length], cursor + length


def _spc_image_sha256(content: bytes) -> str | None:
    """Read the SPC PE image digest from the two bounded Authenticode DER values."""
    spc_pe_image_data_oid = bytes.fromhex("2b06010401823702010f")
    sha256_oid = bytes.fromhex("608648016503040201")
    spc_data = _read_der_tlv(content, 0)
    if spc_data is None or spc_data[0] != 0x30:
        return None
    spc_data_content, spc_data_end = spc_data[1], spc_data[2]
    spc_data_oid = _read_der_tlv(spc_data_content, 0)
    if spc_data_oid is None or spc_data_oid[0] != 0x06 or spc_data_oid[1] != spc_pe_image_data_oid:
        return None
    if spc_data_oid[2] >= len(spc_data_content):
        return None

    indirect_data = _read_der_tlv(content, spc_data_end)
    if indirect_data is None or indirect_data[0] != 0x30 or indirect_data[2] != len(content):
        return None
    digest_info = indirect_data[1]
    algorithm = _read_der_tlv(digest_info, 0)
    if algorithm is None or algorithm[0] != 0x30:
        return None
    digest_value = _read_der_tlv(digest_info, algorithm[2])
    if digest_value is None or digest_value[0] != 0x04 or len(digest_value[1]) != 32:
        return None
    if digest_value[2] != len(digest_info):
        return None

    algorithm_oid = _read_der_tlv(algorithm[1], 0)
    if algorithm_oid is None or algorithm_oid[0] != 0x06 or algorithm_oid[1] != sha256_oid:
        return None
    algorithm_remainder = algorithm[1][algorithm_oid[2] :]
    if algorithm_remainder not in (b"", b"\x05\x00"):
        return None
    return digest_value[1].hex()


def _verify_authenticode_cms(
    data: bytes,
    certificate_table: dict[str, Any] | None,
    authenticode: dict[str, Any],
) -> dict[str, Any]:
    """Verify the PKCS#7 signer signature and compare its SPC image digest with our PE hash.

    OpenSSL's `smime -verify -noverify` checks the signed message while skipping
    signer-certificate chain validation. It does not evaluate Windows policy.
    """
    executable = shutil.which("openssl")
    candidate_digest = authenticode.get("candidate_image_digest")
    result: dict[str, Any] = {
        "method": "OpenSSL smime -verify -inform DER -binary -noverify; parse the bounded SPC PE-image DigestInfo and compare its SHA-256 with the separately calculated Authenticode PE image digest",
        "documentation": OPENSSL_SMIME_DOC,
        "spc_image_digest_parse_scope": (
            "bounds-checks the enclosing DER sequences, PE-image data OID, and SHA-256 DigestInfo; "
            "does not decode or validate the optional SpcPeImageData value"
        ),
        "chain_validation": "not performed; OpenSSL was invoked with -noverify",
        "timestamp_validation": "not performed",
        "windows_trust_policy": "not evaluated",
        "candidate_image_digest": candidate_digest,
        "records": [],
    }
    if executable is None:
        result.update({"status": "tool_unavailable", "tool": None})
        return result

    binary = Path(executable).resolve()
    result["tool"] = {
        "name": "OpenSSL",
        "version": None,
        "executable_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
    }
    try:
        version = subprocess.run(
            [str(binary), "version"], capture_output=True, text=True, timeout=5, check=False
        )
        result["tool"]["version"] = (version.stdout or version.stderr).strip().splitlines()[0]
    except (OSError, subprocess.TimeoutExpired, IndexError) as exc:
        result["tool"]["version_error"] = f"{type(exc).__name__}: {exc}"

    if certificate_table is None or not certificate_table.get("range_in_bounds"):
        result["status"] = "no_bounded_certificate_table"
        return result
    entries = [
        entry for entry in certificate_table.get("entries", [])
        if entry.get("type_name") == "PKCS_SIGNED_DATA" and entry.get("length", 0) >= 8
    ]
    if not entries:
        result["status"] = "no_bounded_pkcs_signed_data_record"
        return result

    for entry in entries:
        start = entry["offset"] + 8
        end = entry["offset"] + entry["length"]
        record_result: dict[str, Any] = {"record_offset": entry["offset"]}
        with tempfile.TemporaryDirectory(prefix="asus-authenticode-") as directory:
            signature_path = Path(directory) / "signature.p7"
            content_path = Path(directory) / "signed-content.der"
            signature_path.write_bytes(data[start:end])
            try:
                process = subprocess.run(
                    [
                        str(binary), "smime", "-verify", "-inform", "DER", "-binary", "-noverify",
                        "-in", str(signature_path), "-out", str(content_path),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=20,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                record_result.update({
                    "cms_signature_status": "check_error",
                    "error": f"{type(exc).__name__}: {exc}",
                })
                result["records"].append(record_result)
                continue
            record_result["cms_signature_status"] = "verified" if process.returncode == 0 else "failed"
            record_result["openssl_exit_code"] = process.returncode
            if process.returncode != 0:
                record_result["openssl_error"] = (process.stderr or process.stdout).strip()[:1000]
                result["records"].append(record_result)
                continue
            signed_content = content_path.read_bytes() if content_path.is_file() else b""
            signed_digest = _spc_image_sha256(signed_content)
            record_result["spc_image_sha256"] = signed_digest
            record_result["spc_image_digest_matches_calculated_pe_digest"] = bool(
                signed_digest and candidate_digest and signed_digest.lower() == candidate_digest.lower()
            )
            record_result["authenticode_signature_verified"] = bool(
                record_result["cms_signature_status"] == "verified"
                and record_result["spc_image_digest_matches_calculated_pe_digest"]
            )
            result["records"].append(record_result)

    all_verified = bool(result["records"]) and all(
        item.get("authenticode_signature_verified") is True for item in result["records"]
    )
    result["status"] = "pkcs7_signer_signature_and_pe_image_digest_verified" if all_verified else "verification_incomplete_or_failed"
    result["authenticode_signature_verified"] = all_verified
    return result


def _range_is_covered(start: int, end: int, ranges: list[dict[str, Any]]) -> bool:
    if start < 0 or end < start:
        return False
    cursor = start
    for item in sorted(ranges, key=lambda value: value.get("start", -1)):
        range_start, range_end = item.get("start", -1), item.get("end", -1)
        if range_end <= cursor:
            continue
        if range_start > cursor:
            return False
        cursor = max(cursor, range_end)
        if cursor >= end:
            return True
    return cursor >= end


def _static_string_leads(data: bytes, sections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    leads: list[dict[str, Any]] = []
    searchable = [
        section for section in sections
        if not section.get("executable") and section.get("raw_range_in_bounds") and section.get("raw_size")
    ]
    for section in searchable:
        start = section["raw_offset"]
        end = start + section["raw_size"]
        for match in re.finditer(rb"[\x20-\x7e]{5,}", data[start:end]):
            value = match.group().decode("ascii", "replace").rstrip()
            if not re.search(r"[A-Za-z]{3}", value):
                continue
            leads.append(
                {
                    "section": section["name"],
                    "offset": start + match.start(),
                    "length": len(match.group()),
                    "value": value,
                    "classification": "heuristic printable-string lead; not an interpreted code path",
                }
            )
    return leads[:256]


def _decompress_efi_stream(
    compressed_envelope: bytes,
    declared_size: int,
    tianocompress_bin: Path,
    efi_machine: int,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "decompression_failed",
        "declared_uncompressed_size_bytes": declared_size,
        "inspection": "bounded decompression and static PE parsing only; output was not loaded or executed",
    }
    if declared_size > MAX_EFI_OUTPUT_BYTES:
        result["reason"] = f"declared output exceeds the {MAX_EFI_OUTPUT_BYTES}-byte safety limit"
        return result
    if len(compressed_envelope) < 9 or int.from_bytes(compressed_envelope[:4], "little") != len(compressed_envelope) - 8:
        result["reason"] = "compressed input does not exactly match its bounded 8-byte size envelope"
        return result
    try:
        with tempfile.TemporaryDirectory(prefix="asus-efi-decompress-") as directory:
            input_path = Path(directory) / "bounded-compressed.efi"
            output_path = Path(directory) / "decompressed-pe.efi"
            input_path.write_bytes(compressed_envelope)
            process = subprocess.run(
                [str(tianocompress_bin.resolve()), "-d", "--uefi", "-q", "-o", str(output_path), str(input_path)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            result["tool_exit_code"] = process.returncode
            if process.returncode != 0 or not output_path.is_file():
                result["reason"] = "TianoCompress did not produce output successfully"
                if process.stderr.strip():
                    result["tool_stderr"] = process.stderr.strip()[:1000]
                return result
            output = output_path.read_bytes()
    except (OSError, subprocess.TimeoutExpired) as exc:
        result["reason"] = f"{type(exc).__name__}: {exc}"
        return result

    result["actual_uncompressed_size_bytes"] = len(output)
    result["uncompressed_sha256"] = hashlib.sha256(output).hexdigest()
    if len(output) != declared_size:
        result["status"] = "decompressed_size_mismatch"
        result["reason"] = "decompressed output length does not match the UEFI envelope's original-size field"
        return result

    pe = _parse_pe_header(output)
    result["pe"] = pe
    if not pe.get("recognized"):
        result["status"] = "decompressed_output_not_valid_pe"
        result["reason"] = "decompressed bytes do not contain bounded MZ and PE signatures"
        return result
    machine_matches = pe.get("machine") == efi_machine
    efi_subsystem_matches = pe.get("subsystem") == 0x0B
    section_table_complete = len(pe.get("sections", [])) == pe.get("section_count") and pe.get("section_count", 0) > 0
    all_section_virtual_ranges_in_bounds = all(section.get("virtual_range_in_image") for section in pe.get("sections", []))
    structurally_warning_free = not pe.get("warnings")
    result["pe_validation"] = {
        "machine_matches_efi_option_rom": machine_matches,
        "efi_boot_service_driver_subsystem": efi_subsystem_matches,
        "section_table_complete": section_table_complete,
        "all_section_raw_ranges_in_bounds": all(section["raw_range_in_bounds"] for section in pe["sections"]),
        "all_section_virtual_ranges_in_bounds": all_section_virtual_ranges_in_bounds,
        "structurally_warning_free": structurally_warning_free,
        "warnings": pe["warnings"],
    }
    result["certificate_table"] = _certificate_table(output, pe)
    authenticode_analysis = _annotate_authenticode_digest_record_match(
        output,
        result["certificate_table"],
        _authenticode_sha256_analysis(output, pe),
    )
    cryptographic_verification = _verify_authenticode_cms(
        output, result["certificate_table"], authenticode_analysis
    )
    authenticode_analysis["cryptographic_verification"] = cryptographic_verification
    authenticode_analysis["signature_verification"] = cryptographic_verification["status"]
    if result["certificate_table"]:
        result["certificate_table"]["signature_verification"] = cryptographic_verification["status"]
        for entry in result["certificate_table"].get("entries", []):
            entry["signature_verification"] = cryptographic_verification["status"]
    result["authenticode_sha256_analysis"] = authenticode_analysis
    result["static_string_leads"] = _static_string_leads(output, pe["sections"])
    if not (
        machine_matches
        and efi_subsystem_matches
        and section_table_complete
        and all(section["raw_range_in_bounds"] for section in pe["sections"])
        and all_section_virtual_ranges_in_bounds
        and structurally_warning_free
    ):
        result["status"] = "decompressed_pe_validation_warning"
        result["reason"] = "PE headers parse, but architecture, subsystem, complete-section, bounds, or structural-warning checks failed"
        return result
    result["status"] = "decompressed_pe_validated"
    result["reason"] = "declared output length, PE/COFF signatures, AMD64 machine, EFI boot-service-driver subsystem, and section raw bounds agree"
    return result


def analyze_updater(name: str, data: bytes) -> dict[str, Any]:
    rar_offset = data.find(RAR5_SIGNATURE)
    pe = _parse_pe_header(data)
    pe_sections = pe.get("sections", [])
    last_section_raw_end = pe.get("authenticode_coverage_geometry", {}).get(
        "last_bounded_section_raw_end"
    )
    cert = pe.get("certificate_directory", {})
    certificate_table = _certificate_table(data, pe)
    authenticode_sha256 = _annotate_authenticode_digest_record_match(
        data, certificate_table, _authenticode_sha256_analysis(data, pe)
    )
    cryptographic_verification = _verify_authenticode_cms(data, certificate_table, authenticode_sha256)
    authenticode_sha256["cryptographic_verification"] = cryptographic_verification
    authenticode_sha256["signature_verification"] = cryptographic_verification["status"]
    if certificate_table:
        certificate_table["signature_verification"] = cryptographic_verification["status"]
        for entry in certificate_table.get("entries", []):
            entry["signature_verification"] = cryptographic_verification["status"]
    rar_covered_by_digest = bool(
        rar_offset >= 0
        and authenticode_sha256.get("status") == "computed"
        and any(
            item["start"] <= rar_offset < item["end"]
            for item in authenticode_sha256.get("hashed_ranges", [])
        )
    )
    overlay = pe.get("authenticode_coverage_geometry", {}).get("pre_certificate_overlay_range") or {}
    overlay_covered_by_digest = bool(
        authenticode_sha256.get("status") == "computed"
        and isinstance(overlay.get("start"), int)
        and isinstance(overlay.get("end"), int)
        and _range_is_covered(overlay["start"], overlay["end"], authenticode_sha256.get("hashed_ranges", []))
    )
    rar_in_declared_section = any(
        section.get("raw_range_in_bounds")
        and section["raw_offset"] <= rar_offset < section["raw_offset"] + section["raw_size"]
        for section in pe_sections
    ) if rar_offset >= 0 else False
    strings = []
    for match in re.finditer(rb"[\x20-\x7e]{5,}", data):
        value = match.group().decode("ascii", "replace").rstrip()
        if re.search(r"ASUS|AMDVBFlash|GraphicVBFlash|BIOS/|CMTPath=|Setup=|WinRAR SFX|sfxrar", value, re.I):
            strings.append({"offset": match.start(), "value": value})

    return {
        "member_name": name,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "inspection": "static byte inspection only; updater was not executed",
        "pe": pe,
        "certificate_table": certificate_table,
        "authenticode_sha256_analysis": authenticode_sha256,
        "embedded_rar5": {
            "signature_offset": rar_offset if rar_offset >= 0 else None,
            "recognized": rar_offset >= 0,
            "inside_declared_section": rar_in_declared_section if rar_offset >= 0 else None,
            "at_first_overlay_byte": rar_offset == last_section_raw_end if rar_offset >= 0 and last_section_raw_end is not None else None,
            "overlay_to_certificate_range": (
                {"start": last_section_raw_end, "end": cert["offset"], "length": cert["offset"] - last_section_raw_end}
                if rar_offset >= 0
                and last_section_raw_end is not None
                and cert.get("present")
                and cert["offset"] >= last_section_raw_end
                else None
            ),
            "rar_marker_in_computed_authenticode_sha256_range": rar_covered_by_digest,
            "pre_certificate_overlay_covered_by_computed_digest": overlay_covered_by_digest,
            "signature_coverage_note": "The RAR5 signature is only a structural marker. Microsoft's linked Authenticode_PE procedure hashes extra file data beginning at SUM_OF_BYTES_HASHED; this analysis separately confirms the overlay byte range and calculated image digest. CMS verification checks the included signer signature and the SPC image digest, but skips certificate-chain trust, timestamps, Windows policy, embedded updater behavior, archive execution, and GPU-side image acceptance.",
        },
        "selected_ascii_strings": strings,
    }


def analyze_package(path: Path) -> dict[str, Any]:
    package_bytes = path.read_bytes()
    result: dict[str, Any] = {
        "path": str(path),
        "size_bytes": len(package_bytes),
        "sha256": hashlib.sha256(package_bytes).hexdigest(),
        "archive_members": [],
        "updaters": [],
        "warnings": [],
    }
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                member_bytes = archive.read(info)
                computed_crc32 = zlib.crc32(member_bytes) & 0xFFFFFFFF
                result["archive_members"].append(
                    {
                        "name": info.filename,
                        "size_bytes": info.file_size,
                        "compressed_bytes": info.compress_size,
                        "declared_crc32_hex": f"0x{info.CRC:08x}",
                        "computed_crc32_hex": f"0x{computed_crc32:08x}",
                        "crc32_matches": computed_crc32 == info.CRC,
                        "sha256": hashlib.sha256(member_bytes).hexdigest(),
                        "integrity_limit": "ZIP CRC-32 detects accidental corruption; it is not a cryptographic signature.",
                    }
                )
                if info.filename.lower().endswith(".exe"):
                    # ZIP decompression returns bytes in memory; no executable is launched.
                    result["updaters"].append(analyze_updater(info.filename, member_bytes))
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        result["warnings"].append(f"Package could not be read as ZIP data: {type(exc).__name__}: {exc}")
    return result


def _decode_firmware_info(data: bytes, table: dict[str, Any]) -> dict[str, Any] | None:
    if (
        table.get("format_revision") != 3
        or table.get("content_revision") != 5
        or table.get("length") != 172
        or not _in_bounds(data, table["offset"], table["length"])
    ):
        return None

    offset = table["offset"]
    field = lambda rel: _u32(data, offset + rel)
    capabilities = field(16)
    known_mask = 0
    named_capabilities: list[str] = []
    for name, bit in ATOM_CAPABILITIES.items():
        known_mask |= bit
        if capabilities & bit:
            named_capabilities.append(name)

    return {
        "table_id": "firmware_info",
        "offset": offset,
        "length": table["length"],
        "format_revision": 3,
        "content_revision": 5,
        "definition": "atom_firmware_info_v3_5",
        "definition_source": ATOM_HEADER,
        "confidence": "high for field layout and values because revision and declared length match the public definition; feature implications remain limited to documented field meanings",
        "definition_note": "Decoded only because the observed revision and exact declared size match the public atom_firmware_info_v3_5 structure.",
        "fields": {
            "firmware_revision": {"offset": offset + 4, "value_hex": f"0x{field(4):08x}"},
            "bootup_clock_reserved": {
                "offset": offset + 8,
                "raw_values": [field(8), field(12)],
                "interpretation": "reserved in v3.5; zero is not interpreted as a clock value",
            },
            "firmware_capability": {
                "offset": offset + 16,
                "value_hex": f"0x{capabilities:08x}",
                "named_set_bits": named_capabilities,
                "unmapped_set_bits_hex": f"0x{capabilities & ~known_mask:08x}",
                "source_note": "The public header names these bits; unnamed bits are left uninterpreted.",
            },
            "fw_protect_region_size_in_kb": {
                "offset": offset + 20,
                "value": field(20),
                "interpretation": "ATOM v3.5 comment describes a protected region at the top of framebuffer memory; not an SPI write-protection or signature field",
            },
            "bios_scratch_reg_startaddr": {"offset": offset + 24, "value_hex": f"0x{field(24):08x}"},
            "bootup_voltage_reserved": {
                "offset": offset + 28,
                "raw_values": [field(28), field(32)],
                "interpretation": "reserved in v3.5; zero is not interpreted as a voltage value",
            },
            "memory_module_id": {"offset": offset + 36, "value": data[offset + 36]},
            "cooling_solution_id": {"offset": offset + 37, "value": data[offset + 37]},
            "hw_blt_mode": {"offset": offset + 38, "value": data[offset + 38]},
            "reserved1": {"offset": offset + 39, "value": data[offset + 39]},
            "mc_baseaddr_high": {"offset": offset + 40, "value_hex": f"0x{field(40):08x}"},
            "mc_baseaddr_low": {"offset": offset + 44, "value_hex": f"0x{field(44):08x}"},
            "board_i2c_feature_id": {"offset": offset + 48, "value": data[offset + 48]},
            "board_i2c_feature_gpio_id": {"offset": offset + 49, "value": data[offset + 49]},
            "board_i2c_feature_slave_addr": {"offset": offset + 50, "value": data[offset + 50]},
            "ras_rom_i2c_slave_addr": {"offset": offset + 51, "value": data[offset + 51]},
            "bootup_voltage_reserved1": {"offset": offset + 52, "value_hex": f"0x{field(52):08x}"},
            "zfb_reserved": {"offset": offset + 56, "value_hex": f"0x{field(56):08x}"},
            "pplib_pptable_id": {
                "offset": offset + 60,
                "value_hex": f"0x{field(60):08x}",
                "interpretation": "The public header comment says a nonzero ID means PPLib gets the PowerPlay table from the driver rather than this VBIOS.",
            },
            "hw_voltage_reserved": {"offset": offset + 64, "raw_values": [field(64), field(68), field(72)]},
            "maco_power_limit_mw": {
                "offset": offset + 76,
                "value": field(76),
                "interpretation": "mode-specific field; not a general board power limit",
            },
            "usb_power_limit_mw": {
                "offset": offset + 80,
                "value": field(80),
                "interpretation": "USB-enabled mode field; not a general board power limit",
            },
            "fw_reserved_size_in_kb": {"offset": offset + 84, "value": field(84)},
            "pspbl_init_reserved": {"offset": offset + 88, "raw_values": [field(88), field(92), field(96)]},
            "spi_rom_size": {"offset": offset + 100, "value": field(100)},
            "support_dev_in_objinfo": {"offset": offset + 104, "value": _u16(data, offset + 104)},
            "display_phy_tuning_size": {"offset": offset + 106, "value": _u16(data, offset + 106)},
            "reserved": {
                "offset": offset + 108,
                "raw_values": [_u32(data, offset + 108 + index * 4) for index in range(16)],
            },
        },
    }


def _table_match(data: bytes, table: dict[str, Any], revision: tuple[int, int], length: int) -> bool:
    return (
        (table.get("format_revision"), table.get("content_revision")) == revision
        and table.get("length") == length
        and _in_bounds(data, table.get("offset", -1), length)
    )


def _decode_umc_info(data: bytes, table: dict[str, Any]) -> dict[str, Any] | None:
    if not _table_match(data, table, (4, 0), 84):
        return None
    o = table["offset"]
    config1 = _u32(data, o + 52)
    # Only the ECC-capability bit is named by the matched public definition
    # used here. Preserve every other set bit as unmapped instead of silently
    # treating an unnamed bit as understood.
    known_config1 = 0x00010000
    vram_type = data[o + 26]
    return {
        "table_id": "umc_info",
        "offset": o,
        "length": table["length"],
        "format_revision": 4,
        "content_revision": 0,
        "definition": "atom_umc_info_v4_0",
        "definition_source": ATOM_HEADER,
        "confidence": "high for the exact public structure and raw values; runtime memory behavior is not established",
        "fields": {
            "ucode_reserved": {"offset": o + 4, "raw_values": [_u32(data, o + 4 + i * 4) for i in range(5)]},
            "umcip_min_ver": {"offset": o + 24, "value": data[o + 24]},
            "umcip_max_ver": {"offset": o + 25, "value": data[o + 25]},
            "vram_type": {
                "offset": o + 26,
                "value_hex": f"0x{vram_type:02x}",
                "named_value": {0x50: "GDDR5", 0x60: "HBM2", 0x61: "HBM2E", 0x70: "GDDR6", 0x80: "HBM3", 0x81: "HBM3E"}.get(vram_type),
            },
            "umc_config": {"offset": o + 27, "value_hex": f"0x{data[o + 27]:02x}", "interpretation": "raw configuration byte; no additional bits interpreted here"},
            "mem_refclk_10khz": {"offset": o + 28, "value": _u32(data, o + 28), "value_mhz": _u32(data, o + 28) / 100, "unit": "10 kHz"},
            "clk_reserved": {"offset": o + 32, "raw_values": [_u32(data, o + 32 + i * 4) for i in range(4)]},
            "golden_reserved": {"offset": o + 48, "value_hex": f"0x{_u32(data, o + 48):08x}"},
            "umc_config1": {
                "offset": o + 52,
                "value_hex": f"0x{config1:08x}",
                "named_set_bits": ["ENABLE_ECC_CAPABLE"] if config1 & 0x00010000 else [],
                "unmapped_set_bits_hex": f"0x{config1 & ~known_config1:08x}",
                "interpretation": "ECC-capable metadata is not proof of active error correction on a particular board or workload",
            },
            "reserved": {"offset": o + 56, "raw_values": [_u32(data, o + 56), _u32(data, o + 60)]},
            "channel_num": {"offset": o + 64, "value": data[o + 64]},
            "channel_width": {
                "offset": o + 65,
                "value": data[o + 65],
                "driver_interpretation_bits": 1 << data[o + 65],
                "source_note": "Current amdgpu source computes width as channel_num * (1 << channel_width); this is source-code interpretation, not a hardware measurement.",
                "driver_source": AMDGPU_ATOM_DRIVER,
            },
            "driver_derived_bus_width_bits": {
                "value": data[o + 64] * (1 << data[o + 65]),
                "interpretation": "Derived from the public driver's UMC v4.0 width calculation; not a measured physical bus width.",
                "source": AMDGPU_ATOM_DRIVER,
            },
            "channel_reserve": {"offset": o + 66, "raw_hex": data[o + 66 : o + 68].hex()},
            "umc_info_reserved": {"offset": o + 68, "raw_hex": data[o + 68 : o + 84].hex()},
        },
    }


def _decode_dce_info(data: bytes, table: dict[str, Any]) -> dict[str, Any] | None:
    if not _table_match(data, table, (4, 5), 212):
        return None
    o = table["offset"]
    u8 = lambda rel: data[o + rel]
    u16 = lambda rel: _u16(data, o + rel)
    u32 = lambda rel: _u32(data, o + rel)
    return {
        "table_id": "dce_info",
        "offset": o,
        "length": table["length"],
        "format_revision": 4,
        "content_revision": 5,
        "definition": "atom_display_controller_info_v4_5",
        "definition_source": ATOM_HEADER,
        "confidence": "high for the exact public structure and raw values; capabilities do not establish the physical board configuration or runtime modes",
        "fields": {
            "display_caps": {
                "offset": o + 4,
                "value_hex": f"0x{u32(4):08x}",
                "named_set_bits": [name for bit, name in ((0x02, "force_display_device_connected"), (0x04, "disable_dfp_dp_hbr2"), (0x08, "enable_interlaced_timing"), (0x20, "lttpr_support_enable"), (0x40, "vbios_lttpr_transparent_enable")) if u32(4) & bit],
                "unmapped_set_bits_hex": f"0x{u32(4) & ~0x6e:08x}",
            },
            "bootup_dispclk_10khz": {"offset": o + 8, "value": u32(8), "unit": "10 kHz"},
            "dce_refclk_10khz": {"offset": o + 12, "value": u16(12), "unit": "10 kHz"},
            "i2c_engine_refclk_10khz": {"offset": o + 14, "value": u16(14), "unit": "10 kHz"},
            "spread_spectrum": {
                name: {"percentage_offset": o + pct, "percentage_0_001_percent": u16(pct), "rate_offset": o + rate, "rate_10hz": u16(rate), "mode_offset": o + mode, "mode": u8(mode)}
                for name, pct, rate, mode in (("dvi", 16, 18, 28), ("hdmi", 20, 22, 29), ("dp", 24, 26, 30))
            },
            "ss_reserved": {"offset": o + 31, "value": u8(31)},
            "dfp_hardcode_mode_num": {"offset": o + 32, "value": u8(32)},
            "dfp_hardcode_refreshrate": {"offset": o + 33, "value": u8(33)},
            "vga_hardcode_mode_num": {"offset": o + 34, "value": u8(34)},
            "vga_hardcode_refreshrate": {"offset": o + 35, "value": u8(35)},
            "dpphy_refclk_10khz": {"offset": o + 36, "value": u16(36), "unit": "10 kHz"},
            "hw_chip_id": {"offset": o + 38, "value_hex": f"0x{u16(38):04x}"},
            "dcnip_min_ver": {"offset": o + 40, "value": u8(40)},
            "dcnip_max_ver": {"offset": o + 41, "value": u8(41)},
            "max_disp_pipe_num": {"offset": o + 42, "value": u8(42)},
            "max_vbios_active_disp_pipe_num": {"offset": o + 43, "value": u8(43)},
            "max_ppll_num": {"offset": o + 44, "value": u8(44)},
            "max_disp_phy_num": {"offset": o + 45, "value": u8(45)},
            "max_aux_pairs": {"offset": o + 46, "value": u8(46)},
            "remotedisplayconfig": {"offset": o + 47, "value": u8(47)},
            "dispclk_pll_vco_freq": {"offset": o + 48, "value": u32(48), "unit": "header does not specify here"},
            "dp_ref_clk_freq": {"offset": o + 52, "value": u32(52), "unit": "header does not specify here"},
            "max_mclk_chg_lat": {"offset": o + 56, "value": u32(56), "unit": "100 ns"},
            "max_sr_exit_lat": {"offset": o + 60, "value": u32(60), "unit": "100 ns"},
            "max_sr_enter_exit_lat": {"offset": o + 64, "value": u32(64), "unit": "100 ns"},
            "dc_golden_table_offset": {"offset": o + 68, "value": u16(68)},
            "dc_golden_table_ver": {"offset": o + 70, "value": u16(70)},
            "aux_dphy_rx_control0_val": {"offset": o + 72, "value": u32(72)},
            "aux_dphy_tx_control_val": {"offset": o + 76, "value": u32(76)},
            "aux_dphy_rx_control1_val": {"offset": o + 80, "value": u32(80)},
            "dc_gpio_aux_ctrl_0_val": {"offset": o + 84, "value": u32(84)},
            "dc_gpio_aux_ctrl_1_val": {"offset": o + 88, "value": u32(88)},
            "dc_gpio_aux_ctrl_2_val": {"offset": o + 92, "value": u32(92)},
            "dc_gpio_aux_ctrl_3_val": {"offset": o + 96, "value": u32(96)},
            "dc_gpio_aux_ctrl_4_val": {"offset": o + 100, "value": u32(100)},
            "dc_gpio_aux_ctrl_5_val": {"offset": o + 104, "value": u32(104)},
            "reserved": {"offset": o + 108, "raw_values": [u32(108 + 4 * i) for i in range(26)]},
        },
    }


def _decode_gpio_pin_lut(data: bytes, table: dict[str, Any]) -> dict[str, Any] | None:
    if (table.get("format_revision"), table.get("content_revision")) != (2, 1):
        return None
    length = table.get("length", 0)
    o = table.get("offset", -1)
    if length < 4 or (length - 4) % 8 or not _in_bounds(data, o, length):
        return None
    assignments = []
    for index, position in enumerate(range(o + 4, o + length, 8)):
        assignments.append({
            "index": index,
            "offset": position,
            "data_a_reg_index": _u32(data, position),
            "gpio_bitshift": data[position + 4],
            "gpio_mask_bitshift": data[position + 5],
            "gpio_id": data[position + 6],
            "reserved": data[position + 7],
        })
    return {
        "table_id": "gpio_pin_lut", "offset": o, "length": length,
        "format_revision": 2, "content_revision": 1,
        "definition": "atom_gpio_pin_lut_v2_1 / atom_gpio_pin_assignment",
        "definition_source": ATOM_HEADER,
        "confidence": "high for the bounded entries and field layout; pin assignments do not prove board circuitry or runtime use",
        "entry_count": len(assignments), "assignments": assignments,
    }


def _decode_vram_usage(data: bytes, table: dict[str, Any]) -> dict[str, Any] | None:
    if not _table_match(data, table, (2, 2), 48):
        return None
    o = table["offset"]
    return {
        "table_id": "vram_usage_by_firmware", "offset": o, "length": 48,
        "format_revision": 2, "content_revision": 2,
        "definition": "vram_usagebyfirmware_v2_2", "definition_source": ATOM_HEADER,
        "confidence": "high for reservation metadata; values do not represent memory timings or total VRAM capacity",
        "fields": {
            "fw_region_start_address_in_kb": {"offset": o + 4, "value": _u32(data, o + 4)},
            "used_by_firmware_in_kb": {"offset": o + 8, "value": _u16(data, o + 8)},
            "reserved": {"offset": o + 10, "value_hex": f"0x{_u16(data, o + 10):04x}"},
            "driver_region0_start_address_in_kb": {"offset": o + 12, "value": _u32(data, o + 12)},
            "used_by_driver_region0_in_kb": {"offset": o + 16, "value": _u32(data, o + 16)},
            "reserved32": {"offset": o + 20, "raw_values": [_u32(data, o + 20 + 4 * i) for i in range(7)]},
        },
    }


def _decode_display_object_info(data: bytes, table: dict[str, Any]) -> dict[str, Any] | None:
    if (table.get("format_revision"), table.get("content_revision")) != (1, 5):
        return None
    o = table.get("offset", -1)
    length = table.get("length", 0)
    if length < 8 or not _in_bounds(data, o, length) or (length - 8) % 16:
        return None
    path_count = data[o + 6]
    available = (length - 8) // 16
    if path_count > available:
        return None
    path_array_end = o + 8 + path_count * 16
    paths = []
    field_names = ("display_objid", "disp_recordoffset", "encoderobjid", "reserved1", "reserved2", "reserved3", "device_tag", "reserved4")
    for index in range(path_count):
        start = o + 8 + index * 16
        fields = {name: _u16(data, start + 2 * position) for position, name in enumerate(field_names)}
        relative = fields["disp_recordoffset"]
        fields["disp_recordoffset_target"] = o + relative if relative else None
        fields["disp_recordoffset_within_table"] = bool(relative == 0 or 4 <= relative < length)
        paths.append({"index": index, "offset": start, **fields})
    return {
        "table_id": "display_object_info", "offset": o, "length": length,
        "format_revision": 1, "content_revision": 5,
        "definition": "display_object_info_table_v1_5 / atom_display_object_path_v3",
        "definition_source": ATOM_HEADER,
        "confidence": "high for the bounded path array; nested display records are referenced but not dereferenced",
        "classification": "partially_decoded" if path_array_end < o + length else "decoded",
        "decoded_range": {"start": o, "end": path_array_end},
        "trailing_data_range": {"start": path_array_end, "end": o + length} if path_array_end < o + length else None,
        "supporteddevices": {"offset": o + 4, "value_hex": f"0x{_u16(data, o + 4):04x}"},
        "number_of_path": {"offset": o + 6, "value": path_count},
        "reserved": {"offset": o + 7, "value": data[o + 7]},
        "paths": paths,
    }


def _decode_data_table(data: bytes, table: dict[str, Any]) -> dict[str, Any] | None:
    decoders = {
        "firmware_info": _decode_firmware_info,
        "umc_info": _decode_umc_info,
        "dce_info": _decode_dce_info,
        "gpio_pin_lut": _decode_gpio_pin_lut,
        "vram_usage_by_firmware": _decode_vram_usage,
        "display_object_info": _decode_display_object_info,
    }
    decoder = decoders.get(table.get("table_id"))
    return decoder(data, table) if decoder else None


def _inspect_efi_payload(
    data: bytes,
    image: dict[str, Any],
    tianocompress_bin: Path | None = None,
    ghidra_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    start = image["offset"]
    length = image["declared_length_bytes"]
    end = start + length
    header = image.get("efi_header", {})
    result: dict[str, Any] = {
        "status": "malformed",
        "image_range": {"start": start, "end": end},
        "inspection": "static bounded inspection only; no PE loading or execution",
    }
    if not _in_bounds(data, start, length) or not header.get("signature_valid"):
        result["reason"] = "image range or EFI signature is invalid"
        return result
    image_offset = header.get("efi_image_offset")
    if not isinstance(image_offset, int) or image_offset < 0x1C or image_offset >= length:
        result["reason"] = "EFI image offset is outside the bounded image"
        return result
    if header.get("compression_type") == 0:
        result.update({
            "status": "uncompressed_pe_coff_identified_but_undecoded",
            "body_range": {"start": start + image_offset, "end": end},
            "reason": "UEFI identifies an uncompressed PE/COFF body; no compressed stream is present to decompress",
        })
        return result
    if header.get("compression_type") != 1:
        result.update({"status": "unsupported_compression", "reason": "reserved or unsupported UEFI compression type; body left undecoded"})
        return result
    body = start + image_offset
    if not _in_bounds(data, body, 8) or body + 8 > end:
        result["reason"] = "compressed EFI body is shorter than its 8-byte size envelope"
        return result
    compressed_size = _u32(data, body)
    uncompressed_size = _u32(data, body + 4)
    compressed_start = body + 8
    compressed_end = compressed_start + compressed_size
    if compressed_size == 0 or uncompressed_size == 0 or compressed_end > end:
        result.update({
            "reason": "compressed size envelope is zero or extends beyond the bounded EFI image",
            "compression_header": {"offset": body, "compressed_size_bytes": compressed_size, "uncompressed_size_bytes": uncompressed_size},
        })
        return result
    trailer = data[compressed_end:end]
    compressed_stream = data[compressed_start:compressed_end]
    compressed_stream_sha256 = hashlib.sha256(compressed_stream).hexdigest()
    terminator_valid = compressed_stream[-1] == 0
    padding = bool(trailer) and len(trailer) < 512 and all(byte == 0xFF for byte in trailer) and end % 512 == 0
    result.update({
        "status": "compressed_stream_identified_but_undecoded" if terminator_valid else "malformed_compression_stream",
        "compression_algorithm": "UEFI Compression Algorithm (header type 1)",
        "compression_reference": UEFI_COMPRESSION_SPEC,
        "compression_header": {
            "offset": body,
            "compressed_size_bytes": compressed_size,
            "uncompressed_size_bytes": uncompressed_size,
            "compressed_data_range": {"start": compressed_start, "end": compressed_end},
            "compressed_data_sha256": compressed_stream_sha256,
            "terminator_byte_hex": f"0x{compressed_stream[-1]:02x}",
            "terminator_valid": terminator_valid,
        },
        "padding_range": {"start": compressed_end, "end": end, "length": len(trailer), "byte": "0xff"} if padding else None,
        "trailing_data_range": {"start": compressed_end, "end": end} if trailer and not padding else None,
        "reason": "size envelope and compressed bytes are bounded; UEFI's required zero terminator is " + ("present" if terminator_valid else "missing"),
    })
    if compressed_stream_sha256 == ASUS_EFI_COMPRESSED_STREAM_SHA256:
        result["static_tool_probe"] = "The bounded compressed stream SHA-256 matches the ASUS GOP stream previously identified in this analysis."
    if tianocompress_bin is not None and terminator_valid:
        result["decompression_tool"] = _tianocompress_metadata(tianocompress_bin)
        result["decompression"] = _decompress_efi_stream(
            data[body:compressed_end], uncompressed_size, tianocompress_bin, header.get("machine", 0)
        )
        result["decompression"]["compressed_stream_sha256"] = compressed_stream_sha256
        if (
            ghidra_report is not None
            and ghidra_report.get("input_sha256") == result["decompression"].get("uncompressed_sha256")
            and result["decompression"].get("status") == "decompressed_pe_validated"
        ):
            result["decompression"]["ghidra_static_analysis"] = ghidra_report
        elif ghidra_report is not None:
            result["decompression"]["ghidra_static_analysis"] = {
                "status": "not_applied_hash_mismatch",
                "reason": "Ghidra report input SHA-256 does not match the successfully decompressed EFI image",
            }
    return result


def _master_data_pointers(data: bytes, report: dict[str, Any]) -> list[dict[str, Any]]:
    pointers: list[dict[str, Any]] = []
    for master in (table for table in report["atom_tables"] if table["kind"] == "master_data_table"):
        if (master["format_revision"], master["content_revision"]) != (2, 1):
            continue
        available = max(0, (master["length"] - 4) // 2)
        matching_image = next(
            (image for image in report["pcir_images"] if image["index"] == master["image_index"]),
            None,
        )
        for index, table_id in enumerate(ATOM_DATA_TABLE_IDS[:available]):
            location = master["offset"] + 4 + index * 2
            relative = _u16(data, location)
            if not relative:
                target_offset = None
            elif matching_image is not None:
                target_offset = matching_image["offset"] + relative
            elif master["image_index"] is None:
                target_offset = relative
            else:
                target_offset = None
            pointers.append(
                {
                    "image_index": master["image_index"],
                    "index": index,
                    "table_id": table_id,
                    "public_master_field": ATOM_MASTER_DATA_FIELDS[index],
                    "pointer_field_offset": location,
                    "relative_target": relative,
                    "target_offset": target_offset,
                    "status": "present" if relative else "null pointer",
                }
            )
    return pointers


def _unique_atom_table_map(
    tables: list[dict[str, Any]], pointers: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    first_chain_pointers = [item for item in pointers if item.get("image_index") == 0]
    first_chain_tables = {
        item.get("index"): item
        for item in tables
        if item.get("kind") == "data_table" and item.get("image_index") == 0
    }
    second_chain_tables = {
        item.get("index"): item
        for item in tables
        if item.get("kind") == "data_table" and item.get("image_index") == 2
    }
    mapped = []
    for pointer in first_chain_pointers:
        table = first_chain_tables.get(pointer["index"])
        second = second_chain_tables.get(pointer["index"])
        entry: dict[str, Any] = {
            "index": pointer["index"],
            "table_id": pointer["table_id"],
            "public_master_field": pointer["public_master_field"],
            "pointer_field_offset": pointer["pointer_field_offset"],
            "relative_target": pointer["relative_target"],
            "status": pointer["status"],
            "public_name_status": "generic_placeholder" if pointer["public_master_field"].startswith("sw_datatable") else "named_master_list_field",
        }
        if table:
            entry.update({
                "file_offset": table["offset"],
                "length": table["length"],
                "revision": f"{table['format_revision']}.{table['content_revision']}",
                "classification": table.get("classification"),
                "body_note": table.get("body_note"),
                "raw_sha256": table.get("raw_sha256"),
                "raw_header_hex": table.get("raw_header_hex"),
                "raw_bytes_hex": table.get("raw_bytes_hex"),
                "raw_preview_hex": table.get("raw_preview_hex"),
                "body_sha256": table.get("body_sha256"),
                "body_shannon_entropy_bits_per_byte": table.get("body_shannon_entropy_bits_per_byte"),
                "heuristic_leads": table.get("heuristic_leads"),
            })
        else:
            entry["null_pointer_note"] = "No table record is dereferenced because the master-list pointer is zero."
        if second:
            entry["second_chain_file_offset"] = second["offset"]
            entry["second_chain_raw_sha256"] = second.get("raw_sha256")
            entry["second_chain_identical"] = table is not None and table.get("raw_sha256") == second.get("raw_sha256")
        else:
            entry["second_chain_file_offset"] = None
            entry["second_chain_raw_sha256"] = None
            entry["second_chain_identical"] = None
        mapped.append(entry)
    return mapped


def _table_raw_evidence(data: bytes, table: dict[str, Any]) -> dict[str, Any]:
    offset = table["offset"]
    length = table["length"]
    raw = data[offset : offset + length] if _in_bounds(data, offset, length) else b""
    body = raw[4:] if len(raw) >= 4 else b""
    counts = [0] * 256
    for value in body:
        counts[value] += 1
    body_entropy = -sum(
        (count / len(body)) * math.log2(count / len(body))
        for count in counts
        if count and body
    ) if body else 0.0
    printable = []
    for match in re.finditer(rb"[\x20-\x7e]{8,}", body):
        printable.append(
            {
                "offset": offset + 4 + match.start(),
                "length": len(match.group()),
                "value": match.group().decode("ascii", "replace").rstrip(),
                "classification": "heuristic printable-string lead; semantics not inferred",
            }
        )
        if len(printable) >= 16:
            break
    repeated_runs = [
        {
            "offset": offset + 4 + match.start(),
            "length": len(match.group()),
            "byte_hex": f"0x{match.group()[0]:02x}",
            "classification": "heuristic repeated-byte lead; not interpreted as padding without a format boundary",
        }
        for match in re.finditer(rb"(.)\1{15,}", body)
    ][:16]
    evidence: dict[str, Any] = {
        "raw_sha256": hashlib.sha256(raw).hexdigest() if raw else None,
        "raw_byte_count": len(raw),
        "raw_header_hex": raw[: min(16, len(raw))].hex() if raw else None,
        "raw_bytes_hex": raw.hex() if 0 < len(raw) <= 256 else None,
        "raw_preview_hex": raw[:64].hex() if len(raw) > 256 else None,
        "body_range": {"start": offset + min(4, length), "end": offset + length},
        "body_sha256": hashlib.sha256(body).hexdigest() if body else None,
        "body_byte_count": len(body),
        "body_shannon_entropy_bits_per_byte": round(body_entropy, 4),
        "body_distinct_byte_values": sum(1 for count in counts if count),
        "heuristic_leads": {
            "printable_strings": printable,
            "repeated_byte_runs": repeated_runs,
            "interpretation": "String, repeated-byte, and entropy observations are candidate leads only; none establishes table semantics.",
        },
    }
    return evidence


def _table_body_note(table: dict[str, Any]) -> str | None:
    table_id = table.get("table_id")
    revision = (table.get("format_revision"), table.get("content_revision"))
    if table.get("kind") == "rom_header":
        if revision == (2, 3):
            return "The observed ROM header is revision 2.3. The checked Linux header exposes atom_rom_header_v2_2 but no exact v2.3 body definition; only the common header, ATOM signature, and bounded master-table pointer are reported."
        return "Only the bounded common header, ATOM signature, and revision-supported master-table pointer are reported; no exact body decoder is selected for this revision."
    if table.get("kind") == "master_data_table":
        return "The v2.1 master table is decoded as 35 bounded 16-bit relative pointers. It contains no semantic definitions for the public header's sw_datatableN placeholder slots."
    if table_id == "smc_dpm_info" and revision == (6, 0):
        return "The checked Linux ATOM header and AMDGPU parser source contain no smc_dpm_info v6.0 definition or parser. The 532-byte body remains undecoded; older SMC/DPM layouts are not applied."
    if table_id == "gfx_info" and revision == (3, 1):
        return "The checked Linux header defines GFX_INFO v3.0, not v3.1, and the driver union/parser handles v2.2, v2.4, v2.7, and v3.0. No v3.1 CU count or mask is inferred."
    if table_id == "lcd_info" and revision == (3, 1):
        return "The checked Linux headers expose older LCD_INFO layouts but no exact revision 3.1 structure; the body remains identified by its master-list slot and common header only."
    if table_id == "indirect_io_access" and revision == (1, 1):
        return "The public INDIRECT_IO_ACCESS definition contains a 256-byte sequence after its common header, while this record declares only 8 bytes. The length mismatch prevents applying that body layout."
    if table.get("index") is not None and table["index"] < len(ATOM_MASTER_DATA_FIELDS):
        public_name = ATOM_MASTER_DATA_FIELDS[table["index"]]
        if public_name.startswith("sw_datatable"):
            return f"Linux's master-list v2.1 preserves this slot as {public_name}; no semantic table name or exact body structure is defined there. Revision-specific bytes remain unresolved."
    if table_id == "display_object_info" and table.get("classification") == "partially_decoded":
        return "The exact v1.5 path-array header and four entries are decoded. The remaining 128 bytes are inside the declared table but have no exact matched nested-record definition in the checked source; they remain identified but undecoded."
    if table.get("classification") in {"decoded", "partially_decoded"}:
        return "Decoded only with a bounded range and exact public revision-specific definition; reserved or trailing bytes remain raw where applicable."
    if table_id == "umc_info":
        return "No body decoder is selected because the observed revision does not match supported UMC v4.0."
    return table.get("body_note")


def _legacy_ghidra_summary(
    image_bytes: bytes,
    report: dict[str, Any],
    report_path: Path,
) -> dict[str, Any]:
    """Validate and compact a static Ghidra inventory for one legacy option ROM."""
    input_sha256 = hashlib.sha256(image_bytes).hexdigest()
    if report.get("input_sha256") != input_sha256:
        raise ValueError(
            f"Legacy Ghidra sidecar hash does not match its bounded option-ROM image: {report_path}"
        )
    program = report.get("program", {})
    if program.get("language") != "x86:LE:16:Real Mode":
        raise ValueError(f"Legacy Ghidra sidecar uses an unexpected language: {report_path}")
    analysis = report.get("analysis", {})
    inventory = analysis.get("function_inventory", [])
    entry_paths = analysis.get("entry_direct_call_paths", [])
    if not inventory or analysis.get("execution") != "none; static analysis only":
        raise ValueError(f"Legacy Ghidra sidecar lacks the expected static function inventory: {report_path}")
    if len(image_bytes) < 6 or image_bytes[3] != 0xE9:
        raise ValueError("The bounded legacy image does not contain the recorded near-jump entry opcode at offset 3.")
    jump_displacement = int.from_bytes(image_bytes[4:6], "little", signed=True)
    jump_target = 6 + jump_displacement
    expected_entry = program.get("entry_address")
    if expected_entry is not None and int(expected_entry, 0) != jump_target:
        raise ValueError("Legacy option-ROM entry jump target does not match the Ghidra root address.")

    path_entries = {item.get("function_entry") for item in entry_paths}
    functions: list[dict[str, Any]] = []
    intervals: list[tuple[int, int, str]] = []
    for function in inventory:
        body_ranges = []
        for body in function.get("body_ranges", []):
            range_start = body.get("start_offset_hex")
            range_end = body.get("end_offset_inclusive_hex")
            if range_start is None or range_end is None:
                raise ValueError(f"Legacy Ghidra sidecar lacks offset bounds for {function.get('entry')}.")
            start = int(range_start, 16)
            end = int(range_end, 16) + 1
            if start < 0 or start >= end or end > len(image_bytes):
                raise ValueError(f"Legacy Ghidra function body is outside the bounded image: {function.get('entry')}.")
            body_ranges.append({"start": start, "end": end, "length": end - start})
            intervals.append((start, end, function.get("name", "unknown")))
        functions.append(
            {
                "name": function.get("name"),
                "entry": function.get("entry"),
                "body_address_count": function.get("body_address_count"),
                "thunk": function.get("thunk", False),
                "direct_call_site_count": function.get("direct_call_site_count", 0),
                "indirect_call_site_count": len(function.get("indirect_call_sites", [])),
                "reachable_from_entry_by_direct_calls": function.get("entry") in path_entries,
                "body_ranges": body_ranges,
            }
        )

    merged: list[dict[str, Any]] = []
    for start, end, function_name in sorted(intervals):
        if merged and start <= merged[-1]["end"]:
            merged[-1]["end"] = max(merged[-1]["end"], end)
            merged[-1]["length"] = merged[-1]["end"] - merged[-1]["start"]
            if function_name not in merged[-1]["functions"]:
                merged[-1]["functions"].append(function_name)
        else:
            merged.append({"start": start, "end": end, "length": end - start, "functions": [function_name]})

    code_candidate_bytes = sum(item["length"] for item in merged)
    relative_path = os.path.relpath(report_path.resolve(), Path(__file__).resolve().parents[1])
    return {
        "status": "static_analysis_hash_and_bounds_validated",
        "scope": "Ghidra disassembly and decompilation are static evidence; no option-ROM code was executed.",
        "sidecar_path": relative_path,
        "sidecar_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
        "input_image_sha256": input_sha256,
        "tool": report.get("tool"),
        "program": program,
        "option_rom_entry": {
            "offset": 3,
            "instruction_bytes_hex": image_bytes[3:6].hex(),
            "instruction": "JMP rel16",
            "relative_displacement": jump_displacement,
            "target_offset": jump_target,
            "target_matches_static_analysis_root": jump_target == int(expected_entry, 0) if expected_entry else None,
        },
        "summary": {
            "function_count": analysis.get("function_count"),
            "direct_call_site_count": analysis.get("direct_call_site_count"),
            "function_body_range_count": sum(len(item.get("body_ranges", [])) for item in functions),
            "merged_function_body_candidate_range_count": len(merged),
            "function_body_candidate_bytes": code_candidate_bytes,
            "bytes_without_recovered_function_body": len(image_bytes) - code_candidate_bytes,
            "direct_entry_path_function_count": len(entry_paths),
            "indirect_call_site_count": len(analysis.get("indirect_call_sites", [])),
            "software_interrupt_site_count": len(analysis.get("interrupt_sites", [])),
            "entry_function_name": analysis.get("entry_function_name"),
            "entry_function_body_address_count": analysis.get("entry_function_body_address_count"),
            "decompilation_status": analysis.get("decompilation_status"),
        },
        "function_body_candidate_ranges": merged,
        "functions": functions,
        "direct_entry_paths": entry_paths,
        "indirect_call_sites": analysis.get("indirect_call_sites", []),
        "software_interrupt_sites": analysis.get("interrupt_sites", []),
        "entry_disassembly": analysis.get("entry_disassembly", []),
        "entry_decompilation_excerpt": analysis.get("entry_decompilation_excerpt"),
        "uncovered_byte_interpretation": "Bytes without a recovered Ghidra function body may be tables, strings, padding, unrecognized code, or disassembly gaps; they are not assumed to be non-executable.",
    }


def _region_accounting(
    size: int,
    images: list[dict[str, Any]],
    tables: list[dict[str, Any]],
    strings: list[dict[str, Any]],
    repeated_ranges: list[dict[str, Any]],
) -> dict[str, Any]:
    spans: list[dict[str, Any]] = []

    def add(start: int, end: int, status: str, label: str) -> None:
        if 0 <= start < end <= size:
            spans.append({"start": start, "end": end, "status": status, "label": label})

    for image in images:
        start = image["offset"]
        end = start + image["declared_length_bytes"]
        add(start, end, "identified_but_undecoded", f"PCIR image {image['index']} code type {image['code_type']}")
        add(start, min(end, start + 3), "decoded", f"PCI option-ROM signature and size for image {image['index']}")
        add(start + 3, min(end, start + 0x18), "identified_but_undecoded", f"reserved header bytes for image {image['index']}")
        add(start + 0x18, min(end, start + 0x1A), "decoded", f"PCIR pointer for image {image['index']}")
        pcir_end = image["pcir_offset"] + image["pcir_structure_length"]
        add(image["pcir_offset"], min(end, pcir_end), "decoded", f"PCIR structure for image {image['index']}")
        if image["code_type"] == 3:
            add(start, min(end, start + 0x0E), "decoded", f"EFI option-ROM header fields for image {image['index']}")
            add(start + 0x0E, min(end, start + 0x16), "identified_but_undecoded", f"EFI reserved header bytes for image {image['index']}")
            add(start + 0x16, min(end, start + 0x18), "decoded", f"EFI image pointer for image {image['index']}")
            inspection = image.get("efi_payload_inspection", {})
            padding = inspection.get("padding_range")
            if padding:
                add(padding["start"], padding["end"], "known_padding_or_repeated_data", f"UEFI image {image['index']} 0xff padding to 512-byte boundary")
            trailer = inspection.get("trailing_data_range")
            if trailer:
                add(trailer["start"], trailer["end"], "identified_but_undecoded", f"EFI image {image['index']} trailing bytes after compressed stream")
        legacy_analysis = image.get("legacy_executable_analysis")
        if image["code_type"] == 0 and legacy_analysis:
            for candidate in legacy_analysis.get("function_body_candidate_ranges", []):
                add(
                    start + candidate["start"],
                    start + candidate["end"],
                    "identified_but_undecoded",
                    f"Ghidra static x86 function-body code candidate in legacy image {image['index']}",
                )

    for table in tables:
        start = table["offset"]
        end = start + table["length"]
        label = f"ATOM {table['table_id']} {table['format_revision']}.{table['content_revision']}"
        add(start, end, "identified_but_undecoded", label)
        if table["kind"] == "rom_header":
            add(start, min(end, start + 8), "decoded", f"ATOM common header and signature at {start:#x}")
            if table["format_revision"] == 2 and table["length"] >= 0x22:
                add(start + 0x20, start + 0x22, "decoded", f"ATOM master-data pointer at {start + 0x20:#x}")
        elif table["kind"] == "master_data_table":
            add(start, min(end, start + 4), "decoded", f"ATOM master data-table common header at {start:#x}")
            if (table["format_revision"], table["content_revision"]) == (2, 1):
                known_pointer_end = min(end, start + 4 + len(ATOM_DATA_TABLE_IDS) * 2)
                add(start + 4, known_pointer_end, "decoded", f"ATOM master data-table v2.1 pointer list at {start:#x}")
        elif table.get("classification") == "decoded":
            add(start, end, "decoded", f"ATOM {table['table_id']} v{table['format_revision']}.{table['content_revision']} at {start:#x}")
        elif table.get("classification") == "partially_decoded":
            decoded_range = table.get("decoded_range", {"start": start, "end": min(end, start + 4)})
            add(decoded_range["start"], decoded_range["end"], "decoded", f"ATOM {table['table_id']} v{table['format_revision']}.{table['content_revision']} bounded fields")
            trailing_range = table.get("trailing_data_range")
            if trailing_range:
                add(trailing_range["start"], trailing_range["end"], "identified_but_undecoded", f"ATOM {table['table_id']} trailing record bytes")
        else:
            add(start, min(end, start + 4), "decoded", f"ATOM common table header at {start:#x}")

    for item in strings:
        if item["label"] == "gop_version_string":
            add(item["offset"], item["offset"] + item["length"], "decoded", "literal GOP version string")

    for repeated in repeated_ranges:
        add(repeated["start"], repeated["end"], "known_padding_or_repeated_data", repeated["label"])

    boundaries = {0, size}
    for span in spans:
        boundaries.add(span["start"])
        boundaries.add(span["end"])
    ordered = sorted(boundaries)
    priority = {"opaque": 0, "identified_but_undecoded": 1, "known_padding_or_repeated_data": 2, "decoded": 3}
    regions: list[dict[str, Any]] = []
    for start, end in zip(ordered, ordered[1:]):
        if start == end:
            continue
        covering = [span for span in spans if span["start"] <= start and end <= span["end"]]
        status = max((span["status"] for span in covering), key=lambda value: priority[value], default="opaque")
        labels = sorted({span["label"] for span in covering if span["status"] == status})
        if status == "decoded":
            classification = "supported_structure_or_literal"
            resolution_note = "The bounded bytes match a decoded structure field or identified literal."
        elif status == "known_padding_or_repeated_data":
            classification = "known_padding_or_repeated_data"
            resolution_note = "The byte run or duplicate range is identified; no topology or behavior is inferred."
        elif status == "opaque":
            classification = "explicitly_unresolved"
            resolution_note = "No supported structure or reviewed static code-body candidate maps this range."
        elif any(label.startswith("Ghidra static x86 function-body code candidate") for label in labels):
            classification = "static_code_candidate"
            resolution_note = "Ghidra recovered a bounded legacy x86 function body here; static recovery does not prove runtime reachability or executed behavior."
        else:
            classification = "identified_structure_body_unresolved"
            resolution_note = "The enclosing format or structure is identified, but these bytes are not fully decoded."
        region = {
            "start": start,
            "end": end,
            "length": end - start,
            "status": status,
            "classification": classification,
            "resolution_note": resolution_note,
            "labels": labels,
        }
        if regions and regions[-1]["end"] == start and regions[-1]["status"] == status and regions[-1]["labels"] == labels:
            regions[-1]["end"] = end
            regions[-1]["length"] += end - start
        else:
            regions.append(region)

    totals = {key: 0 for key in priority}
    for region in regions:
        totals[region["status"]] += region["length"]
    return {"size_bytes": size, "totals_bytes": totals, "regions": regions}


def _scan_unmapped_regions(data: bytes, accounting: dict[str, Any]) -> list[dict[str, Any]]:
    signatures = (
        (b"PCIR", "PCI option-ROM PCIR signature"),
        (b"ATOM", "AMD ATOM literal"),
        (b"MZ", "DOS/PE image signature"),
        (b"PE\x00\x00", "PE signature"),
        (b"PK\x03\x04", "ZIP local-file header"),
        (RAR5_SIGNATURE, "RAR5 archive signature"),
        (b"UEFI", "UEFI literal"),
        (b"EFI", "EFI literal"),
    )
    leads: list[dict[str, Any]] = []
    for region in accounting["regions"]:
        if region["status"] not in {"opaque", "identified_but_undecoded"}:
            continue
        start, end = region["start"], region["end"]
        body = data[start:end]
        for signature, label in signatures:
            cursor = 0
            while len(leads) < 2048:
                found = body.find(signature, cursor)
                if found < 0:
                    break
                leads.append({
                    "offset": start + found,
                    "length": len(signature),
                    "signature_hex": signature.hex(),
                    "lead": label,
                    "region_status": region["status"],
                    "classification": "heuristic signature lead; structure not decoded or dereferenced",
                })
                cursor = found + 1
        for match in re.finditer(rb"[\x20-\x7e]{8,}", body):
            value = match.group().decode("ascii", "replace").rstrip()
            if re.search(r"[A-Za-z]{3}", value):
                leads.append({
                    "offset": start + match.start(),
                    "length": len(match.group()),
                    "lead": "printable ASCII string",
                    "value": value,
                    "region_status": region["status"],
                    "classification": "heuristic string lead; semantics not inferred",
                })
        for match in re.finditer(rb"(.)\1{15,}", body):
            leads.append({
                "offset": start + match.start(),
                "length": len(match.group()),
                "repeated_byte_hex": f"0x{match.group()[0]:02x}",
                "region_status": region["status"],
                "classification": "heuristic repeated-byte run; not promoted to padding without a format boundary",
            })
    return sorted(leads, key=lambda item: (item["offset"], item.get("lead", "")))[:4096]


def analyze_rom(
    path: Path,
    *,
    tianocompress_bin: Path | None = None,
    ghidra_report: dict[str, Any] | None = None,
    legacy_ghidra_report: dict[str, Any] | None = None,
    legacy_ghidra_report_path: Path | None = None,
) -> dict[str, Any]:
    data = path.read_bytes()
    triage = analyze_bytes(data, str(path))
    strings = _ascii_strings(data)
    images: list[dict[str, Any]] = []

    for image in triage["pcir_images"]:
        start = image["offset"]
        end = start + image["declared_length_bytes"]
        record: dict[str, Any] = {
            **image,
            "end_offset": end,
            "format_identification": "legacy PCI option-ROM image" if image["code_type"] == 0 else "PCI option-ROM image; see code_type",
            "format_reference": UEFI_SPEC,
            "confidence": "high for bounded PCIR fields and generic image type; no signature or board-acceptance semantics inferred",
        }
        if image["code_type"] == 3 and _in_bounds(data, start, min(0x1C, image["declared_length_bytes"])):
            efi_signature = _u32(data, start + 4)
            efi_offset = _u16(data, start + 0x16)
            record["efi_header"] = {
                "signature": efi_signature,
                "signature_hex": f"0x{efi_signature:04x}",
                "signature_valid": efi_signature == 0x0EF1,
                "subsystem": _u16(data, start + 8),
                "machine": _u16(data, start + 0x0A),
                "compression_type": _u16(data, start + 0x0C),
                "efi_image_offset": efi_offset,
                "efi_image_offset_in_bounds": 0x1C <= efi_offset < image["declared_length_bytes"],
                "payload_interpretation": {
                    0: "uncompressed PE/COFF image per UEFI 2.10",
                    1: "compressed EFI image per UEFI 2.10; decompression and PE/COFF body parsing not attempted",
                }.get(_u16(data, start + 0x0C), "unsupported/reserved compression value; left uninterpreted"),
                "reserved_bytes_hex": data[start + 0x0E : start + 0x16].hex(),
                "gop_strings": [
                    item for item in strings if start <= item["offset"] < end and item["label"] == "gop_version_string"
                ],
                "format_reference": UEFI_SPEC,
                "confidence": "high for EFI header fields validated within the bounded image; the compressed PE/COFF body remains undecoded",
            }
            record["format_identification"] = "EFI option-ROM image (PCIR code type 3)"
        images.append(record)

    for image in images:
        if image["code_type"] == 3:
            image["efi_payload_inspection"] = _inspect_efi_payload(
                data, image, tianocompress_bin=tianocompress_bin, ghidra_report=ghidra_report
            )
            decompression = image["efi_payload_inspection"].get("decompression", {})
            if decompression.get("status") == "decompressed_pe_validated":
                image["efi_payload_inspection"]["status"] = "compressed_stream_decompressed_pe_validated"
                image["efi_payload_inspection"]["reason"] = "The bounded UEFI stream decompressed to its declared size and passed AMD64 EFI PE/COFF section-bound checks."
                image["efi_header"]["payload_interpretation"] = "compressed EFI image per UEFI 2.10; decompression succeeded and bounded PE/COFF details are recorded separately"
                image["efi_header"]["confidence"] = "high for bounded EFI header and decompressed PE structure; code behavior remains unresolved"

    if legacy_ghidra_report is not None:
        if legacy_ghidra_report_path is None:
            raise ValueError("A path is required for a supplied legacy Ghidra sidecar.")
        for image in images:
            if image["code_type"] != 0:
                continue
            image_start = image["offset"]
            image_end = image_start + image["declared_length_bytes"]
            image["legacy_executable_analysis"] = _legacy_ghidra_summary(
                data[image_start:image_end], legacy_ghidra_report, legacy_ghidra_report_path
            )

    repeated_ranges: list[dict[str, Any]] = []
    chain_groups: dict[int, list[dict[str, Any]]] = {}
    for image in images:
        chain_groups.setdefault(image["chain_index"], []).append(image)
    ordered_chains = [sorted(group, key=lambda item: item["offset"]) for _, group in sorted(chain_groups.items())]
    if len(ordered_chains) >= 2:
        first_chain, second_chain = ordered_chains[0], ordered_chains[1]
        first_start, first_end = first_chain[0]["offset"], first_chain[-1]["end_offset"]
        second_start, second_end = second_chain[0]["offset"], second_chain[-1]["end_offset"]
        first_bytes = data[first_start:first_end]
        second_bytes = data[second_start:second_end]
        if len(first_bytes) == len(second_bytes) and first_bytes == second_bytes:
            repeated_ranges.append({
                "start": second_start,
                "end": second_end,
                "label": "byte-identical second PCIR chain; topology and recovery role unknown",
            })

    atom_tables = []
    for table in triage["atom_tables"]:
        item = dict(table)
        if item.get("kind") == "data_table" and item.get("index") is not None:
            item["public_master_field"] = ATOM_MASTER_DATA_FIELDS[item["index"]]
        item["classification"] = (
            "decoded"
            if table["kind"] == "master_data_table"
            and (table["format_revision"], table["content_revision"]) == (2, 1)
            else "identified_but_undecoded"
        )
        item["source"] = ATOM_HEADER
        item["confidence"] = (
            "high for layout and values matched to the public revision-specific definition"
            if item["classification"] == "decoded"
            else "high for bounded common header and pointer; table-body semantics unresolved"
        )
        if table.get("kind") == "rom_header" and (table.get("format_revision"), table.get("content_revision")) == (2, 3) and table.get("length", 0) >= 0x22:
            item["classification"] = "partially_decoded"
            item["decoded_ranges"] = [
                {"start": table["offset"], "end": table["offset"] + 8, "meaning": "common header and ATOM signature"},
                {"start": table["offset"] + 0x20, "end": table["offset"] + 0x22, "meaning": "master data-table pointer"},
            ]
        if table["table_id"] == "gfx_info" and (table["format_revision"], table["content_revision"]) == (3, 1):
            item["body_note"] = "The checked public Linux ATOM header defines gfx_info v3.0 but no v3.1 structure. Same-sized v3.0 layouts are not applied to v3.1; no CU or stream-processor count/mask is decoded."
        elif table["table_id"] == "smc_dpm_info" and (table["format_revision"], table["content_revision"]) == (6, 0):
            item["body_note"] = "The checked public Linux ATOM header has no smc_dpm_info v6.0 definition. The body remains opaque; v4.x offsets are not applied heuristically."
        elif table["table_id"] == "umc_info" and (table["format_revision"], table["content_revision"]) != (4, 0):
            item["body_note"] = "No decoder is selected because the observed UMC revision does not match the supported v4.0 definition."
        if table["kind"] == "master_data_table" and item["classification"] == "decoded":
            item["definition"] = "atom_master_data_table_v2_1"
            item["definition_source"] = ATOM_HEADER
        decoded = _decode_data_table(data, item)
        if decoded is not None:
            item["classification"] = decoded.get("classification", "decoded")
            item["definition"] = decoded["definition"]
            item["definition_source"] = decoded["definition_source"]
            for range_name in ("decoded_range", "trailing_data_range"):
                if range_name in decoded:
                    item[range_name] = decoded[range_name]
            item["body_note"] = _table_body_note(item)
        else:
            item["body_note"] = _table_body_note(item)
        item.update(_table_raw_evidence(data, item))
        atom_tables.append(item)

    decoded_data_tables = []
    for table in atom_tables:
        decoded = _decode_data_table(data, table)
        if decoded is not None:
            decoded_data_tables.append(decoded)
    firmware_info = [item for item in decoded_data_tables if item["table_id"] == "firmware_info"]
    master_pointers = _master_data_pointers(data, triage)
    accounting = _region_accounting(len(data), images, atom_tables, strings, repeated_ranges)
    return {
        "path": str(path),
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "triage_warnings": triage["warnings"],
        "pcir_images": images,
        "atom_tables": atom_tables,
        "atom_master_pointers": master_pointers,
        "atom_table_map": _unique_atom_table_map(atom_tables, master_pointers),
        "firmware_info_decoded": firmware_info,
        "decoded_data_tables": decoded_data_tables,
        "repeated_ranges": repeated_ranges,
        "observed_strings": strings,
        "region_accounting": accounting,
        "unmapped_region_scan_leads": _scan_unmapped_regions(data, accounting),
    }


def _changed_ranges(first: bytes, second: bytes) -> list[dict[str, int]]:
    ranges: list[dict[str, int]] = []
    common = min(len(first), len(second))
    start: int | None = None
    for offset in range(common):
        if first[offset] != second[offset]:
            if start is None:
                start = offset
        elif start is not None:
            ranges.append({"start": start, "end": offset, "length": offset - start})
            start = None
    if start is not None:
        ranges.append({"start": start, "end": common, "length": common - start})
    if len(first) != len(second):
        ranges.append({"start": common, "end": max(len(first), len(second)), "length": abs(len(first) - len(second))})
    return ranges


def _changed_clusters(ranges: list[dict[str, Any]], maximum_gap: int = 0x100) -> list[dict[str, Any]]:
    clusters: list[dict[str, Any]] = []
    for item in ranges:
        if clusters and item["start"] - clusters[-1]["end"] <= maximum_gap:
            clusters[-1]["end"] = item["end"]
            clusters[-1]["changed_bytes"] += item["length"]
            clusters[-1]["exact_ranges"].append(item)
        else:
            clusters.append(
                {
                    "start": item["start"],
                    "end": item["end"],
                    "changed_bytes": item["length"],
                    "exact_ranges": [item],
                }
            )
    return clusters


def _table_comparison(first: dict[str, Any], second: dict[str, Any], first_data: bytes, second_data: bytes) -> list[dict[str, Any]]:
    def keyed(report: dict[str, Any]) -> dict[tuple[Any, ...], dict[str, Any]]:
        return {
            (
                item["image_index"],
                item["table_id"],
                item.get("index"),
                item["image_relative_offset"],
                item["length"],
                item["format_revision"],
                item["content_revision"],
            ): item
            for item in report["atom_tables"]
        }

    a = keyed(first)
    b = keyed(second)
    comparisons: list[dict[str, Any]] = []
    for key in sorted(set(a) | set(b), key=lambda item: (item[0], item[3], item[1])):
        x, y = a.get(key), b.get(key)
        same = bool(
            x
            and y
            and first_data[x["offset"] : x["offset"] + x["length"]]
            == second_data[y["offset"] : y["offset"] + y["length"]]
        )
        comparisons.append(
            {
                "image_index": key[0],
                "table_id": key[1],
                "table_index": key[2],
                "image_relative_offset": key[3],
                "length": key[4],
                "revision": f"{key[5]}.{key[6]}",
                "status": "identical" if same else "different or unmatched",
            }
        )
    return comparisons


def _compare_xfx_to_asus(asus_rom: dict[str, Any], asus_data: bytes, xfx_path: Path) -> dict[str, Any]:
    xfx_data = xfx_path.read_bytes()
    xfx_rom = analyze_rom(xfx_path)
    xfx_image = next((item for item in xfx_rom["pcir_images"] if item["code_type"] == 0), None)
    asus_images = [item for item in asus_rom["pcir_images"] if item["code_type"] == 0]
    result: dict[str, Any] = {
        "sample": {
            "path": str(xfx_path),
            "size_bytes": len(xfx_data),
            "sha256": hashlib.sha256(xfx_data).hexdigest(),
            "artifact_type": "driver-loaded software VBIOS capture",
            "provenance_limit": "The retained host log says AMDGPU sourced this VBIOS from ACPI VFCT. It is not a physical SPI image; the exact XFX SKU and PCB revision are unknown.",
            "source_record": "bios/xfx-r9700-0000-03-00-0/evidence/ACQUISITION.md",
        },
        "comparison_method": "Align the bounded 58,880-byte legacy PCIR image at image-relative offset 0. Compare exact bytes and ATOM tables keyed by table ID/master-list index; only compare tables when both definitions have the same declared length and revision.",
        "asus_findings_are_not_transferred": True,
        "aligned_images": [],
        "xfx_rom_structure": xfx_rom,
    }
    if xfx_image is None:
        result["status"] = "no_bounded_legacy_xfx_image"
        return result

    xfx_start = xfx_image["offset"]
    xfx_end = xfx_start + xfx_image["declared_length_bytes"]
    xfx_bytes = xfx_data[xfx_start:xfx_end]
    xfx_tables = {
        (item["table_id"], item.get("index")): item
        for item in xfx_rom["atom_tables"]
        if item.get("image_index") in (0, None)
    }
    for asus_image in asus_images:
        asus_start = asus_image["offset"]
        asus_end = asus_start + asus_image["declared_length_bytes"]
        asus_bytes = asus_data[asus_start:asus_end]
        aligned: dict[str, Any] = {
            "asus_payload_sha256": asus_rom["sha256"],
            "asus_image_index": asus_image["index"],
            "asus_image_file_range": {"start": asus_start, "end": asus_end},
            "xfx_image_index": xfx_image["index"],
            "xfx_image_file_range": {"start": xfx_start, "end": xfx_end},
            "same_declared_length": len(xfx_bytes) == len(asus_bytes),
            "aligned_length_bytes": min(len(xfx_bytes), len(asus_bytes)),
        }
        if len(xfx_bytes) == len(asus_bytes):
            differences = _changed_ranges(xfx_bytes, asus_bytes)
            aligned.update({
                "status": "bounded_equal_length_alignment",
                "byte_identical": not differences,
                "changed_byte_count": sum(item["length"] for item in differences),
                "changed_range_count": len(differences),
                "exact_changed_ranges_image_relative": differences,
            })
        else:
            differences = []
            aligned["status"] = "different_boundaries_not_compared"
            aligned["reason"] = "The bounded option-ROM image lengths differ; no direct byte alignment is reported."

        asus_tables = {
            (item["table_id"], item.get("index")): item
            for item in asus_rom["atom_tables"]
            if item.get("image_index") == asus_image["index"]
        }
        table_results = []
        for key in sorted(set(xfx_tables) | set(asus_tables), key=lambda item: (str(item[1]), item[0])):
            x_table = xfx_tables.get(key)
            a_table = asus_tables.get(key)
            item: dict[str, Any] = {"table_id": key[0], "master_list_index": key[1]}
            if x_table is None or a_table is None:
                item["status"] = "present_in_one_image_only"
                item["xfx_present"] = x_table is not None
                item["asus_present"] = a_table is not None
            else:
                x_layout = (x_table["length"], x_table["format_revision"], x_table["content_revision"])
                a_layout = (a_table["length"], a_table["format_revision"], a_table["content_revision"])
                item.update({
                    "xfx": {
                        "image_relative_offset": x_table["image_relative_offset"],
                        "length": x_table["length"],
                        "revision": f"{x_table['format_revision']}.{x_table['content_revision']}",
                    },
                    "asus": {
                        "image_relative_offset": a_table["image_relative_offset"],
                        "length": a_table["length"],
                        "revision": f"{a_table['format_revision']}.{a_table['content_revision']}",
                    },
                })
                if x_layout != a_layout or len(xfx_bytes) != len(asus_bytes):
                    item["status"] = "layout_or_revision_differs"
                else:
                    xo = x_table["image_relative_offset"]
                    ao = a_table["image_relative_offset"]
                    xb = xfx_bytes[xo : xo + x_table["length"]]
                    ab = asus_bytes[ao : ao + a_table["length"]]
                    table_differences = _changed_ranges(xb, ab)
                    item.update({
                        "status": "identical_bytes" if not table_differences else "same_revision_different_bytes",
                        "changed_byte_count": sum(change["length"] for change in table_differences),
                        "exact_changed_ranges_table_relative": table_differences,
                        "definition_source": x_table.get("definition_source") or x_table.get("source"),
                        "semantic_limit": "Byte identity or difference at a matched table revision does not establish cross-board behavior or image compatibility.",
                    })
            table_results.append(item)
        aligned["atom_table_comparisons"] = table_results
        result["aligned_images"].append(aligned)
    result["status"] = "compared" if result["aligned_images"] else "no_asus_legacy_image"
    result["interpretation"] = (
        "This is a structural comparison between one XFX driver-loaded software VBIOS capture and the ASUS vendor payload. "
        "Shared byte sequences and matching ATOM revisions are comparison evidence only; they do not establish equal board wiring, "
        "firmware behavior, authentication coverage, or cross-vendor compatibility."
    )
    return result


def _table_blob_evidence(data: bytes, table: dict[str, Any] | None) -> dict[str, Any]:
    if table is None:
        return {"status": "not_present"}
    offset = table["offset"]
    length = table["length"]
    bounded = _in_bounds(data, offset, length)
    raw = data[offset : offset + length] if bounded else b""
    raw_analysis = _table_raw_evidence(data, table)
    return {
        "table_id": table["table_id"],
        "offset": offset,
        "length": length,
        "revision": f"{table['format_revision']}.{table['content_revision']}",
        "classification": table.get("classification", "identified_but_undecoded"),
        "raw_header_hex": raw[: min(12, len(raw))].hex() if bounded else None,
        "raw_sha256": hashlib.sha256(raw).hexdigest() if bounded else None,
        "raw_bytes_hex": raw_analysis.get("raw_bytes_hex"),
        "raw_preview_hex": raw_analysis.get("raw_preview_hex"),
        "body_sha256": raw_analysis.get("body_sha256"),
        "body_byte_count": raw_analysis.get("body_byte_count"),
        "body_shannon_entropy_bits_per_byte": raw_analysis.get("body_shannon_entropy_bits_per_byte"),
        "heuristic_leads": raw_analysis.get("heuristic_leads"),
        "definition": table.get("definition"),
        "definition_source": table.get("definition_source", table.get("source")),
        "body_note": table.get("body_note"),
        "raw_bytes_not_included": raw_analysis.get("raw_bytes_hex") is None,
    }


def _field_evidence(
    data: bytes,
    decoded: dict[str, Any] | None,
    field_name: str,
    field_size: int,
) -> dict[str, Any]:
    if decoded is None:
        return {"field": field_name, "status": "table_not_decoded"}
    field = decoded.get("fields", {}).get(field_name)
    if field is None:
        return {"field": field_name, "status": "field_not_defined_in_matched_revision"}
    offset = field.get("offset")
    bounded = isinstance(offset, int) and _in_bounds(data, offset, field_size)
    raw = data[offset : offset + field_size] if bounded else b""
    return {
        "field": field_name,
        "offset": offset,
        "size_bytes": field_size,
        "raw_hex": raw.hex() if bounded else None,
        "value": field.get("value", field.get("value_hex", field.get("raw_values"))),
        "named_set_bits": field.get("named_set_bits"),
        "unmapped_set_bits_hex": field.get("unmapped_set_bits_hex"),
        "unit": field.get("unit"),
        "definition": decoded.get("definition"),
        "source": decoded.get("definition_source"),
        "bounded": bounded,
    }


def _modification_matrix(
    rom: dict[str, Any], data: bytes, changed_ranges: list[dict[str, Any]]
) -> dict[str, Any]:
    by_id = {
        item["table_id"]: item
        for item in rom["atom_tables"]
        if item.get("image_index") in (0, None)
    }
    decoded = {
        item["table_id"]: item
        for item in rom["decoded_data_tables"]
        if item.get("offset") == by_id.get(item["table_id"], {}).get("offset")
    }
    fw = decoded.get("firmware_info")
    umc = decoded.get("umc_info")
    dce = decoded.get("dce_info")
    gfx = by_id.get("gfx_info")
    smc = by_id.get("smc_dpm_info")
    gop: dict[str, Any] | None = next(
        (
            item.get("efi_payload_inspection", {}).get("decompression")
            for item in rom["pcir_images"]
            if item.get("code_type") == 3
            and item.get("efi_payload_inspection", {}).get("decompression") is not None
        ),
        None,
    )
    unknown_differences = [
        {
            key: value
            for key, value in item.items()
            if key in {"start", "end", "length", "classification", "interpretation", "confidence", "raw_evidence"}
        }
        for item in changed_ranges
        if item.get("classification") in {"option_rom_bytes_unresolved", "opaque_bytes_unresolved"}
    ]
    rows = [
        {
            "area": "Fan behavior and acoustics",
            "artifact_scope": "ASUS AS04/AS07 only",
            "raw_evidence": [
                _table_blob_evidence(data, smc),
                _table_blob_evidence(data, by_id.get("gpio_pin_lut")),
                {
                    "evidence": "AS04/AS07 changed byte ranges outside decoded fields",
                    "ranges": unknown_differences,
                    "interpretation": "No changed range is assigned to a fan curve by a supported structure.",
                },
                {
                    "evidence": "ASUS support-page release note",
                    "value": "AS07 refines the fan curve for a quieter profile",
                    "source": "https://www.asus.com/us/motherboards-components/graphics-cards/turbo/turbo-ai-pro-r9700-32g/helpdesk_bios/?model2Name=TURBO-AI-PRO-R9700-32G",
                },
            ],
            "likely_control_layer": ["VBIOS policy", "SMU firmware", "driver policy", "board fan/thermal circuitry"],
            "plausible_benefit": "A measured lower-noise profile at acceptable GPU, memory, and VRM temperatures, or better sustained clocks if cooling is the bottleneck.",
            "confidence": "Medium for the vendor-stated update purpose; low for any byte-to-fan mapping or runtime result.",
            "risk": "An unsupported curve could raise component temperatures; a faster curve increases noise and fan wear.",
            "evidence_needed": ["Exact ASUS SKU and PCB identity", "Revision-matched fan/SMU definition", "Same-board AS04/AS07 association", "Fan RPM, noise, temperatures, and sustained clocks"],
            "investigation_decision": "GO for exact-card identification and read-only source/behavior tracing.",
            "vbios_edit_decision": "NO-GO until the field and integrity boundary are known, recovery is demonstrated, and the change is accepted on the exact card.",
        },
        {
            "area": "Core clocks, power, and efficiency",
            "artifact_scope": "ASUS payload policy plus generic public definitions; no runtime ASUS conclusion",
            "raw_evidence": [
                _field_evidence(data, fw, "bootup_clock_reserved", 8),
                _field_evidence(data, fw, "bootup_voltage_reserved", 8),
                _field_evidence(data, fw, "pplib_pptable_id", 4),
                _table_blob_evidence(data, smc),
                {"field": "PowerPlayInfo master pointer", "raw_value": 0, "interpretation": "Null pointer in this ATOM master list.", "source": ATOM_HEADER},
            ],
            "likely_control_layer": ["driver-sourced PowerPlay policy", "SMU firmware", "board power delivery", "runtime controls"],
            "plausible_benefit": "Lower energy per workload or higher sustained throughput only if measurements identify a clock, power, or thermal bottleneck.",
            "confidence": "High for matched FirmwareInfo v3.5 field meanings; low for exact-board runtime control behavior.",
            "risk": "Instability, overcurrent, thermal stress, workload errors, or reduced reliability.",
            "evidence_needed": ["Exact-board electrical limits", "Active driver/SMU policy source", "Repeatable workload power and clock telemetry", "Recovery and accepted-image route"],
            "investigation_decision": "GO for profiling and source tracing.",
            "vbios_edit_decision": "NO-GO: no revision-matched general board limit or supported edit route is established.",
        },
        {
            "area": "Memory configuration, timing, and ECC",
            "artifact_scope": "ASUS UMC v4.0 only; XFX runtime observations remain separate",
            "raw_evidence": [
                _field_evidence(data, umc, "vram_type", 1),
                _field_evidence(data, umc, "mem_refclk_10khz", 4),
                _field_evidence(data, umc, "umc_config1", 4),
                _field_evidence(data, umc, "channel_num", 1),
                _field_evidence(data, umc, "channel_width", 1),
                _table_blob_evidence(data, by_id.get("umc_info")),
            ],
            "likely_control_layer": ["UMC/SMU firmware", "driver policy", "fitted DRAM", "PCB routing", "board power delivery", "silicon support"],
            "plausible_benefit": "Memory throughput or energy improvement only for a measured memory-bound workload; ECC can support resilience where hardware and software enable it.",
            "confidence": "High for the revision-matched metadata; low for ASUS DRAM population, timing headroom, and active correction behavior.",
            "risk": "Memory corruption, instability, overheating, or damage to the memory subsystem.",
            "evidence_needed": ["Exact DRAM and PCB topology", "Revision-matched timing definition", "Driver and SMU behavior", "Memory-correctness workloads and ECC error counters"],
            "investigation_decision": "GO for component identification and ECC reporting trace.",
            "vbios_edit_decision": "NO-GO: this UMC table has no decoded timing/voltage controls and its ECC bit is capability metadata.",
        },
        {
            "area": "CU and stream-processor availability",
            "artifact_scope": "ASUS GFX_INFO v3.1 body; XFX CU count is not transferred",
            "raw_evidence": [
                _table_blob_evidence(data, gfx),
                {"observation": "Existing XFX host evidence reports 64 active CUs for an XFX-subsystem device only.", "source": "bios/xfx-r9700-0000-03-00-0/CARD.md", "applies_to_asus": False},
            ],
            "likely_control_layer": ["silicon fuses/harvest state", "GPU initialization", "driver/runtime topology"],
            "plausible_benefit": "More usable compute only if this exact ASUS ASIC contains functional disabled units and a supported policy exposes them.",
            "confidence": "High that public current Linux definitions do not safely expose this v3.1 body; unknown ASUS fused topology.",
            "risk": "A false resource count can prevent initialization or cause unstable execution; a VBIOS cannot create absent or fused-off units.",
            "evidence_needed": ["Exact ASUS ASIC/card", "Revision-matched GFX v3.1 definition", "Read-only runtime topology", "Fuse/harvest evidence"],
            "investigation_decision": "GO for source tracing and exact-card read-only enumeration.",
            "vbios_edit_decision": "NO-GO: no CU enable field or functional disabled resources are established.",
        },
        {
            "area": "Feature gates and ECC enablement",
            "artifact_scope": "ASUS FirmwareInfo capability bits and UMC ECC-capability metadata",
            "raw_evidence": [
                _field_evidence(data, fw, "firmware_capability", 4),
                _field_evidence(data, umc, "umc_config1", 4),
                {"observation": "The dynamic_boot_cfg_enable bit is named in the matched public definition; bit 0x00004000 remains unnamed.", "source": ATOM_HEADER},
            ],
            "likely_control_layer": ["VBIOS metadata", "driver/runtime policy", "SMU/PSP firmware", "silicon fuses", "OS support"],
            "plausible_benefit": "A feature could become available only when required hardware and every firmware/software gate already supports it.",
            "confidence": "High for raw values and named bits; low for any unlock or active ECC behavior.",
            "risk": "Changing an unknown bit can break initialization or misrepresent unsupported hardware.",
            "evidence_needed": ["One concrete feature request", "Full driver/SMU/PSP/OS gate trace", "Exact-card capability evidence", "Workload validation"],
            "investigation_decision": "GO for tracing one supported feature at a time.",
            "vbios_edit_decision": "NO-GO: do not edit unnamed flags or equate ECC capability with active correction.",
        },
        {
            "area": "Display, GOP, and pre-OS output",
            "artifact_scope": "ASUS DCE/display tables and decompressed EFI/GOP image",
            "raw_evidence": [
                _table_blob_evidence(data, by_id.get("dce_info")),
                _table_blob_evidence(data, by_id.get("display_object_info")),
                {
                    "efi_decompression_status": gop.get("status") if gop else "not run",
                    "efi_output_sha256": gop.get("uncompressed_sha256") if gop else None,
                    "efi_pe": gop.get("pe") if gop else None,
                    "efi_authenticode_sha256_analysis": gop.get("authenticode_sha256_analysis") if gop else None,
                    "efi_ghidra": gop.get("ghidra_static_analysis") if gop else None,
                    "source": MICROSOFT_AUTHENTICODE_PE,
                    "efi_format_source": UEFI_COMPRESSION_SPEC,
                },
            ],
            "likely_control_layer": ["VBIOS display tables", "embedded GOP code", "display driver", "display engine silicon", "physical connectors"],
            "plausible_benefit": "Resolve a reproducible pre-OS display or mode compatibility problem; no general performance gain is established.",
            "confidence": "High for bounded PE and display-table structure; low for connector wiring and actual behavior.",
            "risk": "Loss of pre-OS display or broken mode selection/initialization.",
            "evidence_needed": ["Exact connector layout", "Specific reproducible display issue", "Static code trace for the relevant path", "Accepted-image route and recovery"],
            "investigation_decision": "GO only for a concrete display requirement or fault.",
            "vbios_edit_decision": "NO-GO without a demonstrated defect, exact-board evidence, integrity coverage, and recovery.",
        },
        {
            "area": "Board identity and integrity metadata",
            "artifact_scope": "ASUS image strings, PCIR metadata, legacy checksum and EFI PE certificate table",
            "raw_evidence": [
                {"strings": [item for item in rom["observed_strings"] if item["label"] in {"asus_vbios_part", "asus_rom_version", "board_string", "product_string"}]},
                {
                    "legacy_image_checksums": [
                        {
                            "image_index": item["index"],
                            "offset": item["offset"],
                            "length": item["declared_length_bytes"],
                            "sum_mod_256": item.get("checksum", {}).get("legacy_header_checksum", {}).get("sum_mod_256"),
                            "checksum_valid": item.get("checksum", {}).get("legacy_header_checksum", {}).get("valid"),
                        }
                        for item in rom["pcir_images"] if item["code_type"] == 0
                    ],
                    "interpretation": "Byte-sum checks are structural integrity only; they do not establish cryptographic acceptance.",
                },
                {
                    "efi_pe_certificate_table": gop.get("certificate_table") if gop else None,
                    "efi_authenticode_sha256_analysis": gop.get("authenticode_sha256_analysis") if gop else None,
                    "signature_verification": (
                        (gop.get("authenticode_sha256_analysis") or {}).get("cryptographic_verification")
                        if gop else "not available"
                    ),
                    "gpu_side_vbios_authentication": "not evaluated by PE Authenticode checks",
                },
            ],
            "likely_control_layer": ["option-ROM metadata", "PE/Authenticode signing metadata", "GPU/PSP authentication", "host updater policy"],
            "plausible_benefit": "Correctly identify a board/image and distinguish structural checks from signed-image enforcement; identity edits have no demonstrated benefit.",
            "confidence": "High for literal strings, PCIR bounds, checksums, updater/GOP PE signer-signature math and calculated PE digest match; unknown for signer trust, Windows policy and GPU-side VBIOS authentication or acceptance.",
            "risk": "Identity mismatch or integrity changes can cause rejection, failed initialization, or misattributed evidence.",
            "evidence_needed": ["Physical board labels and PCB revision", "Signer trust and platform-policy evaluation if relevant", "GPU-side VBIOS coverage/enforcement evidence", "Independent recovery"],
            "investigation_decision": "GO for provenance and authentication boundary research.",
            "vbios_edit_decision": "NO-GO: no identity change or custom-signing route is justified.",
        },
    ]
    target_ranks = {
        "Fan behavior and acoustics": (1, "Vendor release note names this update area; the byte-to-field mapping and runtime result remain unproven."),
        "Core clocks, power, and efficiency": (2, "Potential workload value is measurable, but the relevant ASUS policy and general limit fields are not identified."),
        "Memory configuration, timing, and ECC": (3, "UMC metadata is decoded, while timing controls and active ECC behavior are not established."),
        "Display, GOP, and pre-OS output": (4, "Exact display structures and GOP code are mapped; relevance depends on a specific compatibility fault."),
        "Feature gates and ECC enablement": (5, "Named capability metadata exists, but the complete feature gate chain and runtime effects are unknown."),
        "CU and stream-processor availability": (6, "The ASUS GFX_INFO body has no exact public revision match; fuses and runtime topology are unknown."),
    }
    for matrix_row in rows:
        if matrix_row["area"] in target_ranks:
            rank, basis = target_ranks[matrix_row["area"]]
            matrix_row["modification_target_rank"] = rank
            matrix_row["rank_basis"] = basis
        else:
            matrix_row["modification_target_rank"] = None
            matrix_row["rank_basis"] = "Cross-cutting provenance and integrity gate, not a modification target."
    rows.sort(key=lambda item: item["modification_target_rank"] if item["modification_target_rank"] is not None else 99)
    return {
        "scope": "ASUS-only decision matrix. XFX evidence appears only as an explicitly separated comparison observation.",
        "ranking_method": "Ranks 1–6 prioritize evidence-backed investigation of potential mod areas, not edit safety, expected performance, or probability of success. Board identity and image integrity are prerequisites and are marked as a gate with no target rank.",
        "columns": [
            "modification_target_rank", "rank_basis", "area", "artifact_scope", "raw_evidence", "likely_control_layer", "plausible_benefit",
            "confidence", "risk", "evidence_needed", "investigation_decision", "vbios_edit_decision",
        ],
        "rows": rows,
    }


def _source_provenance(
    tianocompress_metadata: dict[str, Any] | None,
    ghidra_report: dict[str, Any] | None,
    legacy_ghidra_reports: list[dict[str, Any]],
    openssl_metadata: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "checked_date": CHECKED_DATE,
        "references": [
            {
                "source": "UEFI Specification 2.10, PCI Bus Support",
                "url": UEFI_SPEC,
                "scope": "PCI option-ROM image boundaries, EFI image header, code types, and alignment.",
                "status": "checked",
            },
            {
                "source": "UEFI Specification 2.10 Errata A, Compression Algorithm Specification",
                "url": UEFI_COMPRESSION_SPEC,
                "scope": "UEFI compression type 1 envelope, compressed/original sizes, and zero terminator.",
                "status": "checked",
            },
            {
                "source": "Linux AMD ATOM firmware header",
                "url": ATOM_HEADER,
                "commit": LINUX_SOURCE_COMMIT,
                "scope": "Exact public ATOM structures and revision-specific field names used by this analyzer. No GFX 3.1 or SMC/DPM 6.0 body definition is present at this commit.",
                "status": "checked",
            },
            {
                "source": "Linux AMD legacy ATOM BIOS header",
                "url": ATOMBIOS_HEADER,
                "commit": LINUX_SOURCE_COMMIT,
                "scope": "Cross-checks legacy table names and the known indirect-I/O structure. Its body layout is not applied where the ASUS record's observed revision or declared size does not match.",
                "status": "checked",
            },
            {
                "source": "Linux AMDGPU ATOM firmware parser",
                "url": AMDGPU_ATOM_DRIVER,
                "commit": LINUX_SOURCE_COMMIT,
                "scope": "Driver-side revision handling for GFX, FirmwareInfo, and UMC ECC metadata; this is source interpretation, not proof of ASUS runtime behavior.",
                "status": "checked",
            },
            {
                "source": "Current upstream Linux AMD ATOM firmware header",
                "url": CURRENT_ATOM_HEADER,
                "checked_date": CHECKED_DATE,
                "scope": "Cross-checks the pinned header's current master-list and public table declarations; targeted symbol searches found no exact GFX_INFO v3.1, LCD_INFO v3.1, or SMC/DPM v6.0 body declaration in the inspected snapshot.",
                "status": "checked_snapshot",
                "limit": "The mutable master URL is an access-date snapshot, not an exhaustive search of all branches, vendor trees, or private AMD source.",
            },
            {
                "source": "Current upstream Linux AMDGPU ATOM parser",
                "url": CURRENT_AMDGPU_ATOM_DRIVER,
                "checked_date": CHECKED_DATE,
                "scope": "Cross-checks the pinned parser's GFX_INFO revision cases and UMC ECC metadata handling.",
                "status": "checked_snapshot",
                "limit": "The mutable master URL is an access-date snapshot; driver source does not establish the exact ASUS firmware runtime path.",
            },
            {
                "source": "Microsoft PE Format",
                "url": MICROSOFT_PE_FORMAT,
                "scope": "PE headers, certificate-table placement, and the current page's Authenticode image-hash appendix. Its prose description of post-section data conflicts with the linked procedure's extra-data step; the linked procedure is used for the reported candidate digest.",
                "status": "checked_with_internal_prose_conflict",
            },
            {
                "source": "Microsoft Authenticode PE Signature Format",
                "url": MICROSOFT_AUTHENTICODE_PE,
                "scope": "Static SHA-256 byte-stream calculation follows the documented header exclusions, raw-section order, and extra-data formula in step 14; the calculated digest is compared with the digest in the signed SPC content.",
                "status": "checked",
            },
            {
                "source": "OpenSSL smime command documentation",
                "url": OPENSSL_SMIME_DOC,
                "scope": "The static PKCS#7 check uses -verify without -nosigs and -noverify to skip signer-certificate validation; the signed SPC digest is separately compared with the calculated PE image digest.",
                "status": "checked",
            },
            {
                "source": "EDK II TianoCompress source and tests",
                "url": EDK2_TIANOCOMPRESS_SOURCE,
                "test_url": "https://github.com/tianocore/edk2/blob/c1415771ac592ad8509351c46cd3cda4f38d7d52/BaseTools/Tests/TianoCompress.py",
                "commit": "c1415771ac592ad8509351c46cd3cda4f38d7d52",
                "scope": "Reference implementation used only to decompress the bounded UEFI stream; output was not executed.",
                "status": "checked",
            },
            {
                "source": "Ghidra official release",
                "url": GHIDRA_RELEASE_URL,
                "version": GHIDRA_RELEASE,
                "archive_sha256": GHIDRA_ARCHIVE_SHA256,
                "java_runtime": GHIDRA_JDK if ghidra_report is not None or legacy_ghidra_reports else None,
                "analysis_input_sha256": ghidra_report.get("input_sha256") if ghidra_report else None,
                "analysis_summary": {
                    key: ghidra_report.get("analysis", {}).get(key)
                    for key in (
                        "function_count", "direct_call_site_count", "non_default_named_function_count", "entry_function_name",
                        "entry_function_body_address_count", "decompilation_status",
                    )
                } if ghidra_report else None,
                "analysis_counts": {
                    key: len(ghidra_report.get("analysis", {}).get(key, []))
                    for key in (
                        "function_inventory", "direct_call_edges", "indirect_call_sites",
                        "function_cross_references", "entry_direct_call_paths", "reachable_global_data_references",
                    )
                } if ghidra_report else None,
                "legacy_analyses": legacy_ghidra_reports,
                "scope": "Static GOP PE and legacy x86 option-ROM analysis; no firmware or decompressed code execution.",
                "status": "checked" if ghidra_report is not None or legacy_ghidra_reports else "available_but_no_report_supplied",
            },
            {
                "source": "ASUS TURBO AI PRO R9700 BIOS support page",
                "url": "https://www.asus.com/us/motherboards-components/graphics-cards/turbo/turbo-ai-pro-r9700-32g/helpdesk_bios/?model2Name=TURBO-AI-PRO-R9700-32G",
                "scope": "Vendor-published package metadata and fan-curve release-note claim only.",
                "status": "checked",
            },
            {
                "source": "XFX software VBIOS acquisition record",
                "url": "bios/xfx-r9700-0000-03-00-0/evidence/ACQUISITION.md",
                "scope": "Repository-captured AMDGPU debugfs blob; host log says ACPI VFCT source; not a physical SPI image.",
                "status": "project_observation",
            },
        ],
        "analysis_tools": {
            "tianocompress": tianocompress_metadata,
            "ghidra_report_tool": ghidra_report.get("tool") if ghidra_report else None,
            "legacy_ghidra_reports": legacy_ghidra_reports,
            "openssl": openssl_metadata,
            "gnu_static_probes": _gnu_probe_metadata(),
            "python_version": sys.version.split()[0],
            "ghidra_analysis_script": "tools/ghidra_efi_summary.java",
            "limits": "GNU file, objdump, and strings are used as static format/section/string probes. readelf is ELF-only and is not used to claim successful PE parsing.",
        },
    }


def _gnu_probe_metadata() -> list[dict[str, Any]]:
    probes = []
    for name in ("file", "objdump", "readelf", "strings"):
        executable = shutil.which(name)
        if not executable:
            probes.append({"name": name, "status": "not installed"})
            continue
        binary = Path(executable).resolve()
        try:
            version = subprocess.run(
                [str(binary), "--version"], capture_output=True, text=True, timeout=5, check=False
            )
            first_line = (version.stdout or version.stderr).strip().splitlines()[0]
            probes.append({
                "name": name,
                "version": first_line,
                "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "version_exit_code": version.returncode,
            })
        except (OSError, subprocess.TimeoutExpired, IndexError) as exc:
            probes.append({"name": name, "status": f"version/hash unavailable: {type(exc).__name__}"})
    return probes


def _embedded_efi_comparison(as04: dict[str, Any], as07: dict[str, Any]) -> dict[str, Any]:
    def collect(rom: dict[str, Any]) -> list[dict[str, Any]]:
        entries = []
        for image in rom["pcir_images"]:
            if image.get("code_type") != 3:
                continue
            inspection = image.get("efi_payload_inspection", {})
            compression = inspection.get("compression_header", {})
            decompression = inspection.get("decompression", {})
            entries.append({
                "image_index": image["index"],
                "file_offset": image["offset"],
                "compressed_stream_sha256": compression.get("compressed_data_sha256"),
                "decompression_status": decompression.get("status", "not run"),
                "uncompressed_sha256": decompression.get("uncompressed_sha256"),
                "pe_machine": decompression.get("pe", {}).get("machine_name"),
                "pe_subsystem": decompression.get("pe", {}).get("subsystem_name"),
            })
        return entries

    entries04 = collect(as04)
    entries07 = collect(as07)
    compressed_hashes = [item["compressed_stream_sha256"] for item in entries04 + entries07]
    output_hashes = [item["uncompressed_sha256"] for item in entries04 + entries07]
    return {
        "AS04": entries04,
        "AS07": entries07,
        "all_bounded_streams_have_same_sha256": bool(compressed_hashes) and all(value == compressed_hashes[0] for value in compressed_hashes),
        "all_successfully_decompressed_outputs_have_same_sha256": bool(output_hashes) and all(value and value == output_hashes[0] for value in output_hashes),
        "interpretation": "Identical compressed bytes and decompressed hash establish byte identity of these embedded code streams, not equal runtime behavior on different boards or acceptance/authentication.",
    }


def _modification_assessment(rom: dict[str, Any]) -> dict[str, Any]:
    tables = {item["table_id"]: item for item in rom["atom_tables"] if item["image_index"] in (0, None)}
    selected_offsets = {item["offset"] for item in tables.values()}
    decoded = {item["table_id"]: item for item in rom["decoded_data_tables"] if item["offset"] in selected_offsets}
    fw_fields = decoded.get("firmware_info", {}).get("fields", {})
    umc_fields = decoded.get("umc_info", {}).get("fields", {})
    gfx = tables.get("gfx_info", {})
    smc = tables.get("smc_dpm_info", {})
    umc = decoded.get("umc_info", {})
    ecc = umc_fields.get("umc_config1", {}).get("value_hex", "not decoded")
    mem_type = umc_fields.get("vram_type", {}).get("named_value", "not decoded")
    channel_num = umc_fields.get("channel_num", {}).get("value", "not decoded")
    channel_width = umc_fields.get("channel_width", {}).get("value", "not decoded")
    pp_id = fw_fields.get("pplib_pptable_id", {}).get("value_hex", "not decoded")
    gfx_revision = f"{gfx.get('format_revision', '?')}.{gfx.get('content_revision', '?')}"
    gfx_offset = gfx.get("offset")
    gfx_location = f"{gfx_offset:#x}" if isinstance(gfx_offset, int) else "not present"
    smc_revision = f"{smc.get('format_revision', '?')}.{smc.get('content_revision', '?')}"
    row = lambda **values: values
    return {
        "assessment_basis": "Static ASUS package and payload bytes, exact-revision public definitions, current public Linux driver source, and the ASUS vendor release note. No physical ASUS card, behavior, authentication path, or hardware result is established.",
        "cu_stream_processor_audit": {
            "asus_gfx_info": {
                "table_offset": gfx.get("offset"),
                "length": gfx.get("length"),
                "revision": gfx_revision,
                "body_status": gfx.get("classification", "not found"),
                "reason": gfx.get("body_note", "No ASUS gfx_info body interpretation available."),
            },
            "public_definition": "The checked Linux atomfirmware.h contains atom_gfx_info_v3_0 but no v3.1 definition. The public amdgpu driver union includes v2.2, v2.4, v2.7 and v3.0; its get_gfx_info path accepts v3.0 content 0 and v2.4/v2.7, so this observed v3.1 table exposes no safely decoded CU count or mask in this analysis.",
            "public_sources": [ATOM_HEADER, AMDGPU_ATOM_DRIVER],
            "other_asus_tables": "umc_info v4.0 reports memory metadata only; no CU or stream-processor field is defined in the matching structure. No other decoded ASUS table exposes an active-CU mask.",
            "policy_vs_hardware": "The public gfx_info v3.0 definition includes maximum topology/configuration fields such as max_cu_per_sh, which are not by themselves proof of enabled units. Actual available resources require exact-card driver/runtime topology plus silicon fuse/harvest state; physically absent resources cannot be supplied by a VBIOS policy change.",
            "xfx_context_boundary": "The repository's 64-active-CU observation is for an XFX-subsystem device only. It is not used to infer ASUS hardware capability.",
            "investigation_go_no_go": "GO: continue static source tracing and, only after exact ASUS card identification, compare read-only runtime CU topology with hardware/ASIC evidence.",
            "editing_go_no_go": "NO-GO: no ASUS CU unlock field or candidate image is established; editing cannot restore fused-off or physically absent resources.",
        },
        "proposals": [
            row(
                area="Fan curve and acoustics",
                field_or_region=f"AS04/AS07 changed opaque bytes; ASUS vendor note; SMC/DPM v{smc_revision} ({smc.get('length', 'unknown')} bytes) remains undecoded",
                current_value="Vendor states AS07 refines the fan curve; no decoded fan field is identified and all discovered ATOM records are byte-identical between payloads.",
                controlling_layer="Potentially VBIOS policy, SMU firmware, driver policy, and board fan/thermal circuitry; current payload does not identify the controlling bytes.",
                plausible_benefit="A measured lower-noise profile at acceptable temperatures, or improved thermal stability if the stock profile is inadequate.",
                confidence="Medium that fan behavior was the vendor update intent; low that any changed range maps to fan control or predicts behavior.",
                risk="A guessed edit can raise GPU, hotspot, memory, or VRM temperatures; a faster curve adds noise and fan wear.",
                evidence_needed="Exact ASUS SKU/PCB and matching-card stock/update images; supported SMC/DPM schema; fan RPM, acoustic, GPU/hotspot/VRM temperatures and sustained clocks under repeatable loads.",
                investigation_go_no_go="GO for evidence collection and measurement on the identified card.",
                editing_go_no_go="NO-GO until the field, signature/integrity coverage, accepted-image path, board limits and independent recovery are established.",
            ),
            row(
                area="Core clock, voltage, power and efficiency",
                field_or_region=f"FirmwareInfo v3.5 PPLib ID {pp_id}; null PowerPlayInfo pointer; SMC/DPM v{smc_revision} opaque",
                current_value="No directly decoded general board clock, voltage, or power limit. FirmwareInfo's boot clock/voltage slots are reserved; PPLib ID is nonzero.",
                controlling_layer="Driver-sourced PowerPlay policy, SMU firmware, and board power delivery; an exact ASUS control split is not established.",
                plausible_benefit="Lower energy per workload or improved sustained throughput only if a measured clock, power, or thermal limit is the bottleneck.",
                confidence="High for the table fields and PPLib source comment; low for any ASUS runtime consequence.",
                risk="Instability, elevated current/temperature, workload errors, or reduced reliability.",
                evidence_needed="Exact-board driver/SMU trace, measured power and clocks under target workloads, board electrical limits, matching policy schema and recovery evidence.",
                investigation_go_no_go="GO for workload profiling and source tracing.",
                editing_go_no_go="NO-GO: no revision-matched general limit field or safe acceptance path is established.",
            ),
            row(
                area="Memory timing, voltage and ECC",
                field_or_region=f"UMC v4.0: GDDR6 code {umc_fields.get('vram_type', {}).get('value_hex', 'unknown')}; channel_num={channel_num}; channel_width encoding={channel_width}; umc_config1={ecc}; VRAMInfo master pointer is null",
                current_value="UMC v4.0 metadata is decoded; it contains no memory timing table. ECC-capable bit is set in this payload; this does not demonstrate runtime correction. DRAM population and routing are unknown.",
                controlling_layer="SMU/driver policy and UMC firmware, plus fitted DRAM, board routing, power delivery and silicon support.",
                plausible_benefit="Potential memory throughput or energy improvement only for a demonstrated memory-bound workload; ECC may support error resilience when the full stack and hardware enable it.",
                confidence="High for exact UMC fields; low for physical configuration, tuning headroom, and ECC runtime behavior.",
                risk="Silent data corruption, memory instability, elevated temperature, or board/DRAM damage.",
                evidence_needed="Exact DRAM ICs/topology and board revision, revision-matched timing schema, driver and SMU behavior, memory-correctness tests, ECC status/error counters under workload, and recovery route.",
                investigation_go_no_go="GO for identifying memory components and tracing ECC reporting; memory tuning only after baseline validation.",
                editing_go_no_go="NO-GO: no timing/voltage field or verified ASUS memory configuration is established.",
            ),
            row(
                area="CU / stream-processor unlock",
                field_or_region=f"gfx_info v{gfx_revision} at {gfx_location} ({gfx.get('length', 'unknown')} bytes), body not decoded",
                current_value="No ASUS active-CU count or enable mask is exposed by a revision-matched definition in this audit.",
                controlling_layer="Potentially fused/harvested silicon resources and driver/runtime topology; configurable policy cannot create fused-off or physically absent units.",
                plausible_benefit="More usable compute only if the exact card has functional disabled units and an authorized policy path that permits them.",
                confidence="High that this payload does not safely expose a v3.1 CU field; unknown ASUS physical or fused capacity.",
                risk="Invalid resource topology can prevent initialization or cause instability; an apparent count change cannot establish functional hardware.",
                evidence_needed="Exact ASUS ASIC/card identity, revision-matched v3.1 definition if available, public/validated driver path, runtime CU topology and fuse/harvest evidence.",
                investigation_go_no_go="GO for research into public definitions and exact-card read-only resource enumeration.",
                editing_go_no_go="NO-GO: no ASUS unlock field, candidate image, or un-fused disabled resources have been demonstrated.",
            ),
            row(
                area="Feature gates and ECC enablement",
                field_or_region=f"FirmwareInfo v3.5 capability {fw_fields.get('firmware_capability', {}).get('value_hex', 'unknown')}; UMC v4.0 umc_config1 {ecc}",
                current_value="The public dynamic-boot-config capability is set; another capability bit is unnamed. UMC ECC-capable metadata is set. Neither field establishes a user-facing unlock or active correction behavior.",
                controlling_layer="Firmware capability metadata, driver/runtime policy, SMU/PSP firmware, fuses and OS support; the ASUS payload does not reveal the complete gate chain.",
                plausible_benefit="A supported feature could become available only where required hardware and every software/firmware gate already permit it.",
                confidence="High for named bits and raw values; low for their availability or effect on this ASUS board.",
                risk="Changing unknown flags may block initialization, weaken reliability, or misrepresent unsupported hardware.",
                evidence_needed="Trace one concrete feature through exact board, driver, SMU/PSP, OS support and silicon capability; verify runtime behavior with an appropriate workload.",
                investigation_go_no_go="GO for tracing a specific requested feature and collecting supported runtime evidence.",
                editing_go_no_go="NO-GO: do not edit an unidentified capability or assume ECC, virtualization, or policy behavior from a bit alone.",
            ),
            row(
                area="Display configuration and GOP",
                field_or_region="DCE v4.5, display-object v1.5, and decompressed GOP PE structure",
                current_value="Display metadata is decoded; the bounded GOP stream decompresses to an AMD64 EFI boot-service-driver PE. Static disassembly shows indirect function-pointer calls, but their targets and display semantics remain unresolved.",
                controlling_layer="VBIOS display tables, embedded GOP code, driver policy, display engine silicon, and physical connectors.",
                plausible_benefit="Correct a reproducible output compatibility issue; no general performance benefit is established.",
                confidence="High for decoded tables and PE structure; low for GOP behavior or actual ASUS output mapping.",
                risk="Loss of pre-OS output, unsupported mode selection, or broken display initialization.",
                evidence_needed="Exact ASUS card and connector layout, supported display record definitions, a static trace to the relevant GOP path, and a reproducible display fault.",
                investigation_go_no_go="GO only for a specific display issue or required mode.",
                editing_go_no_go="NO-GO without a demonstrated defect, matching board evidence, integrity coverage and recovery.",
            ),
        ],
    }


def analyze_asus(
    package_path: Path,
    as04_path: Path,
    as07_path: Path,
    *,
    xfx_path: Path | None = None,
    tianocompress_bin: Path | None = None,
    ghidra_report_path: Path | None = None,
    legacy_as04_ghidra_report_path: Path | None = None,
    legacy_as07_ghidra_report_path: Path | None = None,
) -> dict[str, Any]:
    ghidra_report = None
    if ghidra_report_path is not None:
        loaded_ghidra_report = json.loads(ghidra_report_path.read_text(encoding="utf-8"))
        if not isinstance(loaded_ghidra_report, dict):
            raise ValueError("Ghidra report must be a JSON object.")
        ghidra_report = loaded_ghidra_report
    legacy_reports: dict[str, tuple[dict[str, Any], Path] | None] = {}
    for version, report_path in (
        ("AS04", legacy_as04_ghidra_report_path),
        ("AS07", legacy_as07_ghidra_report_path),
    ):
        if report_path is None:
            legacy_reports[version] = None
            continue
        loaded_report = json.loads(report_path.read_text(encoding="utf-8"))
        if not isinstance(loaded_report, dict):
            raise ValueError(f"{version} legacy Ghidra report must be a JSON object.")
        legacy_reports[version] = (loaded_report, report_path)
    package = analyze_package(package_path)
    as04_legacy = legacy_reports["AS04"]
    as07_legacy = legacy_reports["AS07"]
    as04 = analyze_rom(
        as04_path,
        tianocompress_bin=tianocompress_bin,
        ghidra_report=ghidra_report,
        legacy_ghidra_report=as04_legacy[0] if as04_legacy else None,
        legacy_ghidra_report_path=as04_legacy[1] if as04_legacy else None,
    )
    as07 = analyze_rom(
        as07_path,
        tianocompress_bin=tianocompress_bin,
        ghidra_report=ghidra_report,
        legacy_ghidra_report=as07_legacy[0] if as07_legacy else None,
        legacy_ghidra_report_path=as07_legacy[1] if as07_legacy else None,
    )
    as04_data = as04_path.read_bytes()
    as07_data = as07_path.read_bytes()
    differences = _changed_ranges(as04_data, as07_data)
    text_fields = [
        item
        for item in as04["observed_strings"]
        if any(
            other["offset"] == item["offset"] and other["label"] == item["label"]
            for other in as07["observed_strings"]
        )
    ]
    for difference in differences:
        labels = sorted(
            {
                field["label"]
                for field in text_fields
                if difference["start"] < field["offset"] + field["length"]
                and field["offset"] < difference["end"]
            }
        )
        if labels:
            difference["classification"] = "identified_text_bytes"
            difference["text_labels"] = labels
            difference["interpretation"] = "A recognized literal string changes; any non-string semantics remain unassigned."
        elif any(
            difference["start"] < image["offset"] + image["declared_length_bytes"]
            and image["offset"] < difference["end"]
            for image in as04["pcir_images"]
        ):
            difference["classification"] = "option_rom_bytes_unresolved"
            difference["text_labels"] = []
            difference["interpretation"] = "Inside a bounded option-ROM image but outside a decoded field; meaning unresolved."
        else:
            difference["classification"] = "opaque_bytes_unresolved"
            difference["text_labels"] = []
            difference["interpretation"] = "Outside bounded option-ROM images and supported decoded fields; meaning unresolved."
        difference["confidence"] = "high for the exact byte-difference range; semantic interpretation is limited as described"
        as04_slice = as04_data[difference["start"] : min(difference["end"], len(as04_data))]
        as07_slice = as07_data[difference["start"] : min(difference["end"], len(as07_data))]
        difference["raw_evidence"] = {
            "AS04_sha256": hashlib.sha256(as04_slice).hexdigest(),
            "AS07_sha256": hashlib.sha256(as07_slice).hexdigest(),
            "AS04_hex": as04_slice.hex() if len(as04_slice) <= 256 else None,
            "AS07_hex": as07_slice.hex() if len(as07_slice) <= 256 else None,
            "AS04_preview_hex": as04_slice[:64].hex() if len(as04_slice) > 256 else None,
            "AS07_preview_hex": as07_slice[:64].hex() if len(as07_slice) > 256 else None,
            "raw_byte_capture_limit": "Full range bytes are retained as hex for ranges up to 256 bytes; longer ranges retain a 64-byte prefix and full SHA-256.",
        }

    # Compare repeated PCIR chains as raw bytes. This establishes duplication
    # within each payload without claiming that either copy is a recovery bank.
    repeated_chains: list[dict[str, Any]] = []
    for rom, raw in ((as04, as04_data), (as07, as07_data)):
        if len(rom["pcir_images"]) >= 4:
            left = rom["pcir_images"][0]
            right = rom["pcir_images"][2]
            left_end = left["offset"] + left["declared_length_bytes"] + rom["pcir_images"][1]["declared_length_bytes"]
            right_end = right["offset"] + right["declared_length_bytes"] + rom["pcir_images"][3]["declared_length_bytes"]
            left_bytes = raw[left["offset"] : left_end]
            right_bytes = raw[right["offset"] : right_end]
            repeated_chains.append(
                {
                    "path": rom["path"],
                    "first_range": {"start": left["offset"], "end": left_end},
                    "second_range": {"start": right["offset"], "end": right_end},
                    "identical": left_bytes == right_bytes,
                    "sha256": hashlib.sha256(left_bytes).hexdigest(),
                }
            )

    table_comparison = _table_comparison(as04, as07, as04_data, as07_data)
    all_tables_identical = bool(table_comparison) and all(
        item["status"] == "identical" for item in table_comparison
    )
    xfx_comparison = _compare_xfx_to_asus(as04, as04_data, xfx_path) if xfx_path is not None else None
    efi_tool = next(
        (
            image.get("efi_payload_inspection", {}).get("decompression_tool")
            for image in as04["pcir_images"]
            if image.get("efi_payload_inspection", {}).get("decompression_tool")
        ),
        None,
    )
    legacy_provenance = []
    for version, rom in (("AS04", as04), ("AS07", as07)):
        first_legacy = next((item for item in rom["pcir_images"] if item.get("code_type") == 0), None)
        legacy = first_legacy.get("legacy_executable_analysis") if first_legacy else None
        if legacy:
            legacy_provenance.append(
                {
                    "payload": version,
                    "sidecar_path": legacy["sidecar_path"],
                    "sidecar_sha256": legacy["sidecar_sha256"],
                    "input_image_sha256": legacy["input_image_sha256"],
                    "summary": legacy["summary"],
                }
            )
    openssl_metadata = next(
        (
            updater.get("authenticode_sha256_analysis", {})
            .get("cryptographic_verification", {})
            .get("tool")
            for updater in package.get("updaters", [])
            if updater.get("authenticode_sha256_analysis", {}).get("cryptographic_verification", {}).get("tool")
        ),
        None,
    )
    modification_matrix = _modification_matrix(as04, as04_data, differences)
    integrity_row = next(
        row for row in modification_matrix["rows"] if row["area"] == "Board identity and integrity metadata"
    )
    for updater in package["updaters"]:
        integrity_row["raw_evidence"].append({
            "evidence": "updater PE certificate and embedded RAR overlay geometry",
            "member_name": updater.get("member_name"),
            "updater_sha256": updater.get("sha256"),
            "certificate_table": updater.get("certificate_table"),
            "authenticode_coverage_geometry": updater.get("pe", {}).get("authenticode_coverage_geometry"),
            "authenticode_sha256_analysis": updater.get("authenticode_sha256_analysis"),
            "embedded_rar5": updater.get("embedded_rar5"),
            "interpretation": "The RAR5 marker is at the first pre-certificate overlay byte. Microsoft's linked Authenticode_PE step 14 hash stream covers the pre-certificate overlay; OpenSSL verifies the included PKCS#7 signer signature and the signed SPC image digest matches the calculated PE digest. Certificate-chain trust, timestamps, Windows policy, archive behavior and GPU-side image acceptance are not established.",
            "definition_source": MICROSOFT_AUTHENTICODE_PE,
        })
    return {
        "schema_version": 5,
        "tool": {"name": "asus_rom_analysis.py", "version": TOOL_VERSION},
        "scope": "Static analysis of the ASUS package and its two extracted ROM payloads, with an optional bounded XFX software-ROM comparison. No updater, firmware, or hardware was executed or modified.",
        "package": package,
        "payloads": {"AS04": as04, "AS07": as07},
        "comparison": {
            "size_equal": len(as04_data) == len(as07_data),
            "changed_byte_count": sum(item["length"] for item in differences),
            "changed_range_count": len(differences),
            "exact_changed_ranges": differences,
            "changed_clusters": _changed_clusters(differences),
            "atom_table_comparisons": table_comparison,
            "all_discovered_atom_records_identical": all_tables_identical,
            "repeated_pcir_chains": repeated_chains,
            "embedded_efi_comparison": _embedded_efi_comparison(as04, as07),
            "interpretation": "Differences outside mapped fields remain unresolved. Exact before/after range bytes or hashes are retained; no signature, checksum, board policy, or fan-table meaning is inferred from byte differences alone.",
        },
        "xfx_comparison": xfx_comparison,
        "source_provenance": _source_provenance(efi_tool, ghidra_report, legacy_provenance, openssl_metadata),
        "modification_matrix": modification_matrix,
        "modification_assessment": _modification_assessment(as04),
    }


def _hex_range(start: int, end: int) -> str:
    return f"`0x{start:x}–0x{end:x}`"


def _find_strings(rom: dict[str, Any], label: str) -> list[str]:
    return [f"{_hex_range(item['offset'], item['offset'] + item['length'])}: `{item['value']}`" for item in rom["observed_strings"] if item["label"] == label]


def render_markdown(report: dict[str, Any]) -> str:
    observed_hashes = {
        "package": report["package"]["sha256"],
        "AS04": report["payloads"]["AS04"]["sha256"],
        "AS07": report["payloads"]["AS07"]["sha256"],
    }
    if observed_hashes != EXPECTED_INPUT_HASHES:
        raise ValueError(
            "The package-specific Markdown report is only valid for the ASUS package and payload hashes recorded by this analysis."
        )

    as04 = report["payloads"]["AS04"]
    as07 = report["payloads"]["AS07"]
    comparison = report["comparison"]
    efi_image = next((item for item in as04["pcir_images"] if item.get("code_type") == 3), None)
    efi_inspection = efi_image.get("efi_payload_inspection", {}) if efi_image else {}
    efi_decompression = efi_inspection.get("decompression", {})
    ghidra_report = efi_decompression.get("ghidra_static_analysis", {})
    ghidra_analysis = ghidra_report.get("analysis", {})
    efi_pe = efi_decompression.get("pe", {})
    efi_sections = efi_pe.get("sections", [])
    efi_certificate = efi_decompression.get("certificate_table") or {}
    efi_authenticode = efi_decompression.get("authenticode_sha256_analysis") or {}
    xfx_comparison = report.get("xfx_comparison")
    legacy_analysis_by_version = {}
    for version, rom in (("AS04", as04), ("AS07", as07)):
        first_legacy = next((item for item in rom["pcir_images"] if item.get("code_type") == 0), None)
        if first_legacy and first_legacy.get("legacy_executable_analysis"):
            legacy_analysis_by_version[version] = first_legacy["legacy_executable_analysis"]
    rows = [
        "# ASUS R9700 ROM static analysis",
        "",
        f"> Read-only file analysis recorded {CHECKED_DATE}. The updater was not executed; the payloads are not associated with an identified physical ASUS card and are not established full-chip SPI images.",
        "",
        "## Inputs and integrity",
        "",
        f"- Package: `{report['package']['path']}` — {report['package']['size_bytes']:,} bytes, SHA-256 `{report['package']['sha256']}`.",
        f"- AS04: `{as04['path']}` — {as04['size_bytes']:,} bytes, SHA-256 `{as04['sha256']}`.",
        f"- AS07: `{as07['path']}` — {as07['size_bytes']:,} bytes, SHA-256 `{as07['sha256']}`.",
        f"- Analyzer: `{report['tool']['name']} {report['tool']['version']}` plus `tools/rom_triage.py`; JSON details are in [`ASUS_ROM_ANALYSIS.json`](ASUS_ROM_ANALYSIS.json).",
        "",
        "The hashes match the previously recorded package and payload hashes. The package contains two AMD64 PE32+ GUI self-extractors. Static headers show an embedded RAR5 signature at file offset `0x6b600`; selected strings name `ASUSGraphicVBFlashTool.exe`, `amdvbflash.exe`, both BIOS members, and ASUS SFX settings. OpenSSL verifies each updater's PKCS#7 signer signature, and each signed SPC image digest matches the independently calculated Authenticode PE SHA-256. The PE hash ranges cover the RAR5 pre-certificate overlay. Certificate-chain trust, timestamps and Windows policy were not checked. No executable was launched.",
        "",
        "## Image and code map",
        "",
        "Each payload is `0x1f0100` bytes. The bounded PCIR chains are repeated exactly at `0x40000–0x5ca00` and `0x120000–0x13ca00` within each file. That duplication alone does not establish a dual-BIOS topology, a recovery bank, or full-chip coverage.",
    ]
    rows.extend(["", "### Package member integrity and updater overlay geometry", ""])
    rows.extend([
        "| Member | Declared CRC32 | Computed CRC32 | CRC status | Member SHA-256 |",
        "|---|---|---|---|---|",
    ])
    for member in report["package"]["archive_members"]:
        rows.append(
            f"| `{member['name']}` | `{member['declared_crc32_hex']}` | `{member['computed_crc32_hex']}` | "
            f"{'match' if member['crc32_matches'] else 'MISMATCH'} | `{member['sha256']}` |"
        )
    rows.extend([
        "",
        "ZIP CRC-32 matches are corruption checks, not cryptographic authentication. For each updater, the table below compares the embedded RAR5 marker to the last declared PE section and certificate-table boundaries:",
        "",
        "| Updater | Last section raw end | RAR5 offset | First overlay byte | Certificate range | SHA-256 coverage result |",
        "|---|---:|---:|---|---|---|",
    ])
    for updater in report["package"]["updaters"]:
        geometry = updater.get("pe", {}).get("authenticode_coverage_geometry", {})
        overlay = geometry.get("pre_certificate_overlay_range") or {}
        certificate = updater.get("certificate_table") or {}
        rar = updater.get("embedded_rar5", {})
        authenticode = updater.get("authenticode_sha256_analysis", {})
        last_end = geometry.get("last_bounded_section_raw_end")
        coverage = (
            "PKCS#7 signer signature verified; signed SPC digest matches calculated PE SHA-256; overlay covered"
            if authenticode.get("cryptographic_verification", {}).get("authenticode_signature_verified") is True
            and overlay
            and certificate
            else "geometry incomplete or does not establish overlay placement"
        )
        last_end_text = f"0x{last_end:x}" if isinstance(last_end, int) else "unknown"
        rar_offset = rar.get("signature_offset")
        rar_offset_text = f"0x{rar_offset:x}" if isinstance(rar_offset, int) else "not found"
        rows.append(
            f"| `{updater['member_name']}` | `{last_end_text}` | `{rar_offset_text}` | "
            f"{str(rar.get('at_first_overlay_byte')).lower()} | "
            f"`0x{certificate.get('offset', 0):x}+0x{certificate.get('length', 0):x}` | {coverage}."
        )
    rows.extend([
        "",
        "The calculated SHA-256 stream follows the linked Microsoft Authenticode_PE step 14 formula: bytes beginning at `SUM_OF_BYTES_HASHED` are included up to the certificate-table size exclusion. OpenSSL verifies the PKCS#7 signer signature, and the signed SPC SHA-256 matches the calculated PE digest, whose range covers the RAR5 marker and pre-certificate overlay. `-noverify` skips signer-certificate chain validation; timestamps and Windows policy were not evaluated. The Learn PE page's general prose about post-section bytes conflicts with this linked procedure, so the step-by-step procedure is used here. This updater signature result does not establish archive behavior or GPU-side VBIOS acceptance.",
        "",
        "### PCIR image chain",
        "",
        "| Offset | Length | PCIR code type | PCI IDs | Findings |",
        "|---|---:|---:|---|---|",
    ])
    for image in as04["pcir_images"]:
        pci = f"`{image['vendor_id']:04x}:{image['device_id']:04x}`"
        if image["code_type"] == 0:
            legacy = image.get("legacy_executable_analysis", {})
            legacy_summary = legacy.get("summary", {})
            detail = (
                f"Legacy option-ROM; checksum is valid; Ghidra recovered {legacy_summary.get('function_count', 'no')} functions "
                f"and {legacy_summary.get('direct_call_site_count', 'no')} direct-call sites."
                if legacy else "Legacy option-ROM image; ATOM tables are within the first legacy image in each chain. Legacy checksum is valid; no Ghidra report supplied."
            )
        elif image["code_type"] == 3:
            efi = image["efi_header"]
            payload = image["efi_payload_inspection"]
            gop = ", ".join(f"`{entry['value']}` at `0x{entry['offset']:x}`" for entry in efi["gop_strings"])
            if payload.get("compression_header"):
                envelope = payload["compression_header"]
                pad = payload.get("padding_range")
                pad_note = f" {pad['length']} bytes of `0xff` end padding are identified." if pad else " Trailing bytes are not classified as padding."
                terminator = "zero terminator valid" if envelope["terminator_valid"] else "zero terminator missing"
                compressed_note = f" Compressed stream: {envelope['compressed_size_bytes']:,} bytes; declared output: {envelope['uncompressed_size_bytes']:,} bytes; {terminator}; SHA-256 `{envelope['compressed_data_sha256']}`."
                decompressed = payload.get("decompression", {})
                if decompressed.get("status") == "decompressed_pe_validated":
                    pe = decompressed["pe"]
                    compressed_note += (
                        f" EDK II TianoCompress produced a {decompressed['actual_uncompressed_size_bytes']:,}-byte "
                        f"{pe['machine_name']} PE image (subsystem: {pe['subsystem_name']}; entry RVA 0x{pe['entry_point_rva']:x}; "
                        f"{pe['section_count']} bounded sections; output SHA-256 `{decompressed['uncompressed_sha256']}`)."
                    )
                elif decompressed:
                    compressed_note += f" Decompression result: {decompressed.get('status')}."
            else:
                compressed_note = ""
                pad_note = ""
            decompressed = payload.get("decompression", {})
            efi_status = "compressed stream identified and PE validated" if decompressed.get("status") == "decompressed_pe_validated" else payload["status"]
            detail = f"EFI image signature `0x{efi['signature']:04x}`, x64 machine `0x{efi['machine']:04x}`, compression type {efi['compression_type']}; {gop or 'no GOP version string detected'}. {efi_status}.{compressed_note}{pad_note}"
        else:
            detail = "Unknown code type; body left uninterpreted."
        rows.append(f"| {_hex_range(image['offset'], image['end_offset'])} | {image['declared_length_bytes']:,} | `{image['code_type']}` | {pci} | {detail} |")

    rows.extend(
        [
            "",
            f"UEFI defines code type 0x03 as EFI, compression type 0x0001 as compressed, and requires each option-ROM image to be padded to a multiple of 512 bytes. The bounded 8-byte envelope, declared output size, zero terminator, and compressed-stream hash were checked. {('EDK II TianoCompress decompressed the stream; the result passed bounded PE/COFF, AMD64, EFI boot-service-driver, and section-range checks. The output was never loaded or executed.' if efi_decompression.get('status') == 'decompressed_pe_validated' else 'No successful decompression result is recorded; the EFI body remains undecoded at the code level.')} The GOP revision string is before the EFI image payload offset 0x60, so it is not a code-path finding. PE signature verification is described below and does not establish GPU-side image authentication. See [UEFI 2.10, PCI bus support](" + UEFI_SPEC + ") and the [UEFI compression algorithm specification](" + UEFI_COMPRESSION_SPEC + ").",
            "",
            "### Visible strings",
            "",
        ]
    )
    for label, title in (
        ("asus_vbios_part", "VBIOS part"),
        ("asus_rom_version", "ASUS ROM version"),
        ("atom_bios_version", "ATOM BIOS version"),
        ("board_string", "Board string"),
        ("gop_version_string", "GOP revision string"),
        ("build_timestamp_string", "Timestamp strings"),
        ("product_string", "Product string"),
    ):
        values04 = _find_strings(as04, label)
        values07 = _find_strings(as07, label)
        if values04 or values07:
            rows.append(
                f"- **{title}:** AS04: "
                + ("; ".join(values04) or "not found")
                + "; AS07: "
                + ("; ".join(values07) or "not found")
            )
    if efi_decompression.get("status") == "decompressed_pe_validated":
        import_directory = efi_pe.get("data_directories", [])[1] if len(efi_pe.get("data_directories", [])) > 1 else None
        rows.extend([
            "",
            "### Embedded GOP PE static inspection",
            "",
            f"The decompressed image is PE32+ `{efi_pe.get('machine_name')}`, entry RVA `0x{efi_pe.get('entry_point_rva', 0):x}`, image size {efi_pe.get('size_of_image', 0):,} bytes, and EFI boot-service-driver subsystem. Its {efi_pe.get('section_count', 0)} section raw ranges are bounded:",
            "",
            "| Section | RVA | Raw offset | Raw size | Flags |",
            "|---|---:|---:|---:|---|",
        ])
        for section in efi_sections:
            flags = ", ".join(flag for flag, enabled in (("R", section.get("readable")), ("W", section.get("writable")), ("X", section.get("executable"))) if enabled) or "none"
            rows.append(f"| `{section['name']}` | `0x{section['virtual_address']:x}` | `0x{section['raw_offset']:x}` | {section['raw_size']:,} | {flags} |")
        cert_entries = efi_certificate.get("entries", [])
        cert_types = ", ".join(item.get("type_name", "unknown") for item in cert_entries) or "no bounded WIN_CERTIFICATE entry"
        extra_data = efi_authenticode.get("extra_data_range") or {}
        extra_range_text = (
            f"`0x{extra_data.get('start', 0):x}–0x{extra_data.get('end', 0):x}` ({extra_data.get('length', 0)} bytes)"
            if efi_authenticode.get("status") == "computed"
            else "not computed"
        )
        digest_occurrence = efi_authenticode.get("candidate_digest_occurs_in_pkcs_signed_data_record", False)
        rows.extend([
            "",
        f"The PE import directory is {'zero/zero (no conventional imports declared)' if import_directory and not import_directory['address_or_file_offset'] and not import_directory['size'] else 'not empty or unavailable in the parsed directory table'}. The certificate directory is at file offset `0x{efi_certificate.get('offset', 0):x}`, length {efi_certificate.get('length', 0):,}, with {cert_types}; its table SHA-256 is `{efi_certificate.get('sha256', 'not available')}`. Applying [Microsoft Authenticode procedure step 14]({MICROSOFT_AUTHENTICODE_PE}) yields candidate SHA-256 `{efi_authenticode.get('candidate_image_digest', 'not computed')}` with extra-data range {extra_range_text}. OpenSSL verification status is `{efi_authenticode.get('cryptographic_verification', {}).get('status', 'not available')}`; the signed SPC SHA-256 {'matches' if efi_authenticode.get('cryptographic_verification', {}).get('authenticode_signature_verified') else 'does not match or could not be compared with'} the calculated PE digest. Signer-certificate chain validation, timestamp and Windows trust policy were not performed.",
        ])
        ghidra_hash_matches = ghidra_report.get("input_sha256") == efi_decompression.get("uncompressed_sha256")
        if ghidra_hash_matches and ghidra_analysis.get("function_count"):
            inventory = ghidra_analysis.get("function_inventory", [])
            cross_references = ghidra_analysis.get("function_cross_references", [])
            call_paths = ghidra_analysis.get("entry_direct_call_paths", [])
            indirect_calls = ghidra_analysis.get("indirect_call_sites", [])
            globals_reached = ghidra_analysis.get("reachable_global_data_references", [])
            path_depth_by_entry = {item.get("function_entry"): item.get("depth") for item in call_paths}
            xrefs_by_target: dict[str, int] = {}
            for reference in cross_references:
                target = reference.get("target_function_entry")
                xrefs_by_target[target] = xrefs_by_target.get(target, 0) + 1
            rows.extend([
                "",
                f"{ghidra_report.get('tool', {}).get('version', 'Ghidra version not recorded')} analyzed the exact output SHA-256 `{ghidra_report.get('input_sha256')}` statically. Ghidra identified {ghidra_analysis['function_count']} functions ({ghidra_analysis.get('non_default_named_function_count', 'unknown')} non-default names); the entry routine has {ghidra_analysis.get('entry_function_body_address_count', ghidra_analysis.get('entry_function_body_bytes', 'unknown'))} addresses. This is a disassembly/decompilation view, not a runtime trace.",
                "",
                "#### Recovered function inventory",
                "",
                "All Ghidra-recovered functions are listed below. `Entry depth` is the shortest path from the PE entry through statically resolved direct calls; computed calls do not contribute to this graph. `Data refs` retains all static data references, including stack references; the separate reachable-global table includes only references mapped to program memory. `—` means no direct-call path was recovered.",
                "",
                "| Entry | Function | Body address count | Thunk | Direct call sites | Indirect/unresolved calls | Function xrefs | Data refs | Entry depth |",
                "|---:|---|---:|---|---:|---:|---:|---:|---:|",
            ])
            for function in inventory:
                entry = function.get("entry", "?")
                rows.append(
                    f"| `{entry}` | `{function.get('name', 'unknown')}` | {function.get('body_address_count', '—')} | "
                    f"{str(function.get('thunk', False)).lower()} | {function.get('direct_call_site_count', 0)} | "
                    f"{len(function.get('indirect_call_sites', []))} | {xrefs_by_target.get(entry, 0)} | "
                    f"{len(function.get('data_references', []))} | {path_depth_by_entry.get(entry, '—')} |"
                )
            rows.extend([
                "",
                f"#### Direct entry paths, indirect calls, and referenced globals",
                "",
                f"{len(call_paths)} functions have a direct-call path from the entry. Each recovered path is listed; these paths exclude computed calls.",
                "",
                "| Function | Entry | Depth | Direct path |",
                "|---|---:|---:|---|",
            ])
            for path in call_paths:
                route = " → ".join(path.get("path", []))
                rows.append(f"| `{path.get('function_name', 'unknown')}` | `{path.get('function_entry', '?')}` | {path.get('depth', '—')} | `{route}` |")
            rows.extend([
                "",
                f"Ghidra recorded {len(indirect_calls)} computed or unresolved call sites. All sites are summarized here with their instruction, bounded resolved targets, and nearby data references:",
                "",
                "| Caller | Site | Instruction | Resolved targets | Nearby data refs |",
                "|---|---:|---|---|---|",
            ])
            for call in indirect_calls:
                targets = ", ".join(
                    f"{target.get('function_name') or 'unresolved'}@{target.get('address')}"
                    for target in call.get("resolved_targets", [])
                ) or "none"
                data_refs = ", ".join(ref.get("target", "?") for ref in call.get("nearby_data_references", [])) or "none"
                rows.append(
                    f"| `{call.get('caller_name')}` (`{call.get('caller_entry')}`) | `{call.get('site')}` | "
                    f"`{call.get('instruction')}` | {targets} | {data_refs} |"
                )
            rows.extend([
                "",
                f"There are {len(globals_reached)} static data references mapped to program memory in the direct-call-reachable functions. Stack and other unmapped references remain in the per-function data-reference inventory. These globals remain addresses, symbols, or sections only; they are not assigned hardware semantics:",
                "",
                "| Function | Entry | Target | Reference type | Symbol | Memory block |",
                "|---|---:|---:|---|---|---|",
            ])
            for item in globals_reached:
                reference = item.get("reference", {})
                rows.append(
                    f"| `{item.get('function_name', 'unknown')}` | `{item.get('function_entry', '?')}` | "
                    f"`{reference.get('target', '?')}` | `{reference.get('reference_type', '?')}` | "
                    f"{reference.get('symbol') or '—'} | `{reference.get('memory_block') or '—'}` |"
                )
            rows.extend([
                "",
                "All direct edges, xrefs and call-site records are retained in JSON. The entry decompilation shows indirect calls through a global function-pointer table, including offsets `+0x98` and `+0x148`; stripped names and unresolved pointers prevent assigning those calls to fan, clock, power, memory, CU, or board control.",
            ])
        elif ghidra_report:
            rows.append("The supplied Ghidra report was not applied because its root `input_sha256` does not exactly match the decompressed GOP SHA-256.")
        leads = efi_decompression.get("static_string_leads", [])
        rows.append(f"The non-executable sections contain {len(leads)} printable-string leads. They are heuristic extraction results, not interpreted behavior; the visible examples are generic UEFI status text and do not disclose a supported fan, clock, power, memory-timing, or CU control path.")
    if legacy_analysis_by_version:
        rows.extend([
            "",
            "### Legacy x86 static code inventory",
            "",
            "Each code-type-0 image was analyzed as a bounded raw binary with Ghidra's `x86:LE:16:Real Mode` language. The PCI option-ROM entry at offset `0x3` contains `E9 FA 5F` (`JMP rel16`), whose target is `0x6000`; the Ghidra root address matches that calculation. The 244 recovered function records, body ranges, direct edges, all 144 root-reachable direct paths, entry disassembly and decompilation are retained in the versioned sidecars. The entry decompilation remains at Ghidra's synthetic symbol level; no hardware or runtime semantics are assigned.",
            "",
            "| Payload | Input image SHA-256 | Ghidra functions | Direct call sites | Root direct-call paths | Candidate body bytes / ranges | Indirect calls | Software interrupts | Sidecar |",
            "|---|---|---:|---:|---:|---:|---:|---:|---|",
        ])
        for version in ("AS04", "AS07"):
            legacy = legacy_analysis_by_version.get(version)
            if not legacy:
                continue
            summary = legacy["summary"]
            sidecar_link = f"[Ghidra JSON](analysis/{version}-legacy-ghidra.json)"
            rows.append(
                f"| {version} | `{legacy['input_image_sha256']}` | {summary['function_count']} | "
                f"{summary['direct_call_site_count']} | {summary['direct_entry_path_function_count']} | "
                f"{summary['function_body_candidate_bytes']:,} / {summary['merged_function_body_candidate_range_count']} | "
                f"{summary['indirect_call_site_count']} | {summary['software_interrupt_site_count']} | {sidecar_link} |"
            )
        reference_legacy = legacy_analysis_by_version.get("AS04") or next(iter(legacy_analysis_by_version.values()))
        code_ranges = reference_legacy.get("function_body_candidate_ranges", [])
        range_text = ", ".join(_hex_range(item["start"], item["end"]) for item in code_ranges)
        rows.extend([
            "",
            f"AS04 and AS07 produced identical function entries, function-body ranges, direct-call edges, root paths, indirect calls and software-interrupt findings. The union of recovered function-body extents is **{len(code_ranges)} static code-candidate ranges** ({reference_legacy['summary']['function_body_candidate_bytes']:,} bytes): {range_text}.",
            "",
            f"The other {reference_legacy['summary']['bytes_without_recovered_function_body']:,} bytes in each legacy image have no recovered function body. That complement may include tables, strings, padding, unrecognized code or disassembly gaps; it is explicitly not classified as non-executable.",
            "",
            "| Site type | Caller | Address | Instruction | Static disposition |",
            "|---|---|---:|---|---|",
        ])
        for site_type, sites in (
            ("Indirect call", reference_legacy.get("indirect_call_sites", [])),
            ("Software interrupt", reference_legacy.get("software_interrupt_sites", [])),
        ):
            for site in sites:
                rows.append(
                    f"| {site_type} | `{site.get('caller_name', 'unknown')}` (`{site.get('caller_entry', '?')}`) | "
                    f"`{site.get('site', '?')}` | `{site.get('instruction', '?')}` | "
                    f"{site.get('interpretation', 'Target or environment behavior unresolved.')} |"
                )
        rows.append("")
    rows.extend(
        [
            "",
            "The measured file ends at `0x1f0100` (2,031,872 bytes), while the ATOM FirmwareInfo field declares a 2 MiB SPI device size (`0x200000`), a difference of `0xff00` bytes. This capacity field does not establish payload coverage. The payload also contains unparsed bytes outside the option-ROM ranges, including a product string near the end and padding-like `0xff` runs. All such bytes remain accounted as opaque unless a supported structure identifies them.",
            "",
            "## ATOM map and decoded fields",
            "",
            "The common ATOM ROM header is format/content `2.3`; the master data table is `2.1` with 35 bounded pointers. In each duplicated legacy image the reporter records 19 ATOM structures: the ROM header, master table, and 17 non-null data-table pointers. The full table-by-table offsets, lengths and revisions are in the JSON record. The bounded reporter emitted no warnings.",
            "",
            "#### All 35 public master-list data slots (first chain)",
            "",
            f"Slot names and pointer positions follow `atom_master_list_of_data_tables_v2_1` in the [pinned Linux AMD ATOM header]({ATOM_HEADER}). Generic `sw_datatableN` names are source placeholders; their semantics are not inferred. Repeated-chain locations and hashes are compared explicitly:",
            "",
            "| Index | Public field | Pointer field | Target | Length/revision | Classification | Repeat | SHA-256 | Body status or null-pointer note |",
            "|---:|---|---:|---:|---|---|---|---|---|",
        ]
    )
    for slot in as04.get("atom_table_map", []):
        target = slot.get("file_offset")
        target_text = f"`0x{target:x}`" if isinstance(target, int) else "null"
        length_revision = (
            f"{slot.get('length')} / v{slot.get('revision')}" if isinstance(target, int) else "—"
        )
        repeated = (
            f"`0x{slot['second_chain_file_offset']:x}`, {'identical' if slot.get('second_chain_identical') else 'different'}"
            if slot.get("second_chain_file_offset") is not None
            else "—"
        )
        note = slot.get("body_note") or slot.get("null_pointer_note") or slot.get("classification", "unresolved")
        rows.append(
            f"| {slot['index']} | `{slot['public_master_field']}` | `0x{slot['pointer_field_offset']:x}` | {target_text} | "
            f"{length_revision} | `{slot.get('classification', slot.get('status', 'null'))}` | {repeated} | "
            f"`{slot.get('raw_sha256') or '—'}` | {note} |"
        )
    rows.extend(
        [
            "",
            "The checked public AMD/Linux [ATOM firmware header](" + ATOM_HEADER + ") defines the observed `FirmwareInfo` revision `3.5` and its 172-byte structure. Both copies are identical between AS04 and AS07. At file offsets `0x42374` and `0x122374`, the table reports:",
            "",
            "| Field | Value in both payloads | Interpretation limit |",
            "|---|---:|---|",
            "| `firmware_capability` | `0x00024000` | Public header names `dynamic_boot_cfg_enable` (`0x00020000`); set bit `0x00004000` is unnamed there and remains uninterpreted. This does not establish an unlock or disabled feature. |",
            "| `pplib_pptable_id` | `0x00001296` | Header comment says a nonzero ID selects a driver-sourced PowerPlay table rather than one from this VBIOS. This points away from editing a classic in-ROM PowerPlay table; exact R9700 driver behavior still needs board/stack evidence. |",
            "| PowerPlayInfo master pointer | null | No PowerPlayInfo data table is directly pointed to by the ATOM master list. This is not evidence that no tuning policy exists elsewhere. |",
            "| `bootup_clk_reserved[2]` | `0, 0` | Reserved fields, not zero-valued clocks. |",
            "| `bootup_voltage_reserved[2]` | `0, 0` | Reserved fields, not zero-valued voltages. |",
            "| `maco_pwrlimit_mw`, `usb_pwrlimit_mw` | `0`, `0` | Mode-specific limits; not general board power limits. |",
            "| `fw_protect_region_size_in_kb` | `524288` | Header describes framebuffer memory reservation/protection, not SPI write protection or ROM authentication. |",
            "| `spi_rom_size` | `2097152` (2 MiB) | Declared SPI capacity, not proof that the 2,031,872-byte payload is a full-chip read. |",
            "",
            "`smc_dpm_info` is present at `0x42420` / `0x122420`, length 532, revision `6.0`. The checked Linux header has no matching v6.0 body definition, so it remains opaque; v4.x offsets are not applied. `gfx_info` is revision `3.1`; the checked header defines v3.0 but not v3.1, so no CU count or mask is decoded. Exact public definitions now decode UMC v4.0, DCE v4.5, GPIO LUT v2.1, VRAM usage v2.2 and the path array in display-object v1.5. The PowerPlayInfo, SMUInfo and VRAMInfo master slots are null. A zero pointer or absent table is only an observation about this ROM structure, not proof that the driver, SMU, fuses or board circuitry lack that function.",
            "",
            "## AS04 versus AS07",
            "",
            f"The files have equal size. The raw comparison found **{comparison['changed_byte_count']:,} changed bytes in {comparison['changed_range_count']} exact contiguous ranges**. All {len(comparison['atom_table_comparisons'])} discovered ATOM records compare byte-identically at the same image-relative offsets and revisions. PCIR boundaries and IDs are unchanged; both legacy checksums remain valid. The two ROM chains are byte-identical duplicates within each version.",
            "",
            "The readable version identifier changes from `7551OG.23.8.0.68.AS04` to `7551OG.23.8.0.68.AS07` at `0x400a0` and `0x1200a0`; the timestamp strings at `0x40050`, `0x43220`, `0x37fa0` and their repeated-chain copies change from `03/17/26,22:38:29` to `05/07/26,23:10:43`. The ATOM version string, VBIOS part string, board string, and GOP revision string stay the same. EFI headers, size envelopes, compressed stream hashes and decompressed PE hashes are stable across all four EFI images. The bounded PE was statically analyzed; no code was run.",
            "",
            "The changed ranges cluster in pre-ROM data, inter-chain opaque bytes, legacy/EFI metadata and trailing opaque bytes. Every exact interval is listed in the JSON with a classification: recognized text, option-ROM bytes outside a decoded field, or opaque bytes. The grouped extents below are only for readability; their listed intervals are exact.",
            "",
            "The [ASUS support page](https://www.asus.com/us/motherboards-components/graphics-cards/turbo/turbo-ai-pro-r9700-32g/helpdesk_bios/?model2Name=TURBO-AI-PRO-R9700-32G) says the package refines the fan curve for a quieter profile. That release note and changed opaque bytes make fan behavior a reasonable investigation hypothesis, but none of the revision-6.0 SMC/DPM or other changed data has been tied to a fan-table schema. No AS04/AS07 byte difference currently proves a fan curve change.",
            "",
            "### Exact changed-range clusters",
            "",
            "| Cluster extent | Exact changed intervals | Changed bytes | Disposition |",
            "|---|---|---:|---|",
        ]
    )
    for cluster in comparison["changed_clusters"]:
        exact = ", ".join(_hex_range(item["start"], item["end"]) for item in cluster["exact_ranges"])
        dispositions = sorted({item["classification"] for item in cluster["exact_ranges"]})
        rows.append(
            f"| {_hex_range(cluster['start'], cluster['end'])} | {exact} | {cluster['changed_bytes']:,} | `{', '.join(dispositions)}`; unresolved intervals remain unresolved in the JSON record. |"
        )
    rows.extend([
        "",
        "#### Exact changed intervals and raw evidence",
        "",
        "Every contiguous changed interval is listed with its classification, before/after SHA-256, and complete hex bytes for ranges up to 256 bytes. Longer ranges retain a 64-byte prefix and full hash in JSON.",
        "",
        "| Exact range | Bytes | Classification | AS04 raw hex / prefix | AS07 raw hex / prefix | AS04 SHA-256 | AS07 SHA-256 |",
        "|---|---:|---|---|---|---|---|",
    ])
    for change in comparison["exact_changed_ranges"]:
        raw = change.get("raw_evidence", {})
        before = raw.get("AS04_hex") or raw.get("AS04_preview_hex") or "—"
        after = raw.get("AS07_hex") or raw.get("AS07_preview_hex") or "—"
        rows.append(
            f"| {_hex_range(change['start'], change['end'])} | {change['length']} | `{change['classification']}` | "
            f"`{before}` | `{after}` | `{raw.get('AS04_sha256', '—')}` | `{raw.get('AS07_sha256', '—')}` |"
        )

    if xfx_comparison and xfx_comparison.get("aligned_images"):
        aligned = xfx_comparison["aligned_images"][0]
        table_rows = aligned.get("atom_table_comparisons", [])
        equal_tables = sum(item.get("status") == "identical_bytes" for item in table_rows)
        differing_tables = [item for item in table_rows if item.get("status") == "same_revision_different_bytes"]
        xfx_sample = xfx_comparison["sample"]
        rows.extend([
            "",
            "## XFX software-ROM comparison sample",
            "",
            f"The existing XFX AMDGPU debugfs capture (`{xfx_sample['size_bytes']:,}` bytes; SHA-256 `{xfx_sample['sha256']}`) contains a bounded legacy PCIR image that aligns at equal length with the ASUS legacy image. The file-relative PCIR image ranges differ, so comparison is made at image-relative offset zero. It finds {aligned.get('changed_byte_count', 0):,} differing bytes in {aligned.get('changed_range_count', 0)} ranges. This is a structural comparison only: the XFX capture came from ACPI VFCT per the retained host log, its physical SPI contents are unverified, and its exact retail SKU/PCB revision are unknown.",
            "",
            f"Among {len(table_rows)} ATOM table records aligned by table ID and master-list index, {equal_tables} are byte-identical. {len(differing_tables)} have the same declared length and revision but different bytes; no layout/revision mismatch is reported for this sample:",
            "",
            "| Table | Length | Revision | Byte differences |",
            "|---|---:|---:|---:|",
        ])
        for item in differing_tables:
            x_side = item.get("xfx", {})
            table_change_count = item.get("changed_byte_count", "not compared")
            rows.append(f"| `{item['table_id']}` | {x_side.get('length', '—')} | {x_side.get('revision', '—')} | {table_change_count} |")
        rows.extend([
            "",
            "These table differences include board-specific ATOM ROM header offsets and small field/body differences in FirmwareInfo, SMC/DPM v6.0, display-object, VRAM-usage, and one unclassified table. Matching table IDs, lengths and revisions make these useful comparison targets for later source research, but do not make any ASUS interpretation transferable. In particular, the XFX host's 64 active CUs cannot establish ASUS CU capability; neither byte sharing nor matching layout proves cross-flash compatibility, runtime behavior, authentication coverage, or image acceptance. Exact byte ranges and per-table hashes/statuses are preserved in JSON.",
        ])

    rows.extend(
        [
            "",
            "## Region accounting",
            "",
            "The JSON file partitions every byte of each ASUS payload and the XFX comparison file into exactly one of `decoded`, `identified_but_undecoded`, `known_padding_or_repeated_data`, or `opaque`, after applying bounded structure spans. A companion `classification` and `resolution_note` distinguishes supported fields/literals, static code candidates, identified-but-unresolved structure bodies, repeated/padding bytes and unresolved regions. `opaque` means no supported structure or reviewed code-body candidate maps that range; it does not mean the bytes are empty. Exact duplicate bytes and the EFI `0xff` tail are classified as known repeated data or padding without inferring topology or behavior. The summary below is for AS04; AS07 has the same boundaries and accounting.",
            "",
            "| Classification | Bytes |",
            "|---|---:|",
        ]
    )
    for status, count in as04["region_accounting"]["totals_bytes"].items():
        rows.append(f"| `{status}` | {count:,} |")
    if xfx_comparison:
        xfx_accounting = xfx_comparison.get("xfx_rom_structure", {}).get("region_accounting", {})
        if xfx_accounting:
            rows.extend([
                "",
                f"XFX comparison sample (`{xfx_accounting['size_bytes']:,}` bytes):",
                "",
                "| Classification | Bytes |",
                "|---|---:|",
            ])
            for status, count in xfx_accounting["totals_bytes"].items():
                rows.append(f"| `{status}` | {count:,} |")

    rows.extend(
        [
            "",
            "## Decoded table detail",
            "",
            "Each decoded table below matched its exact observed revision and validated declared length or bounded variable-length array. Exact structure names and source URLs are retained in JSON. Reserved bytes remain raw; display-object record references are not followed into unvalidated nested content.",
            "",
            "| Table | Fields or bounded interpretation | Limit |",
            "|---|---|---|",
        ]
    )
    decoded_tables = {}
    for item in as04["decoded_data_tables"]:
        decoded_tables.setdefault(item["table_id"], item)
    umc = decoded_tables.get("umc_info", {}).get("fields", {})
    dce = decoded_tables.get("dce_info", {}).get("fields", {})
    vram_usage = decoded_tables.get("vram_usage_by_firmware", {}).get("fields", {})
    gpio = decoded_tables.get("gpio_pin_lut", {})
    display = decoded_tables.get("display_object_info", {})
    rows.extend([
        f"| `umc_info` v4.0 | VRAM type `{umc.get('vram_type', {}).get('named_value')}` (`{umc.get('vram_type', {}).get('value_hex')}`); UMC IP bounds `{umc.get('umcip_min_ver', {}).get('value')}/{umc.get('umcip_max_ver', {}).get('value')}` raw; reference clock `{umc.get('mem_refclk_10khz', {}).get('value_mhz')} MHz`; ECC-capable metadata `{umc.get('umc_config1', {}).get('value_hex')}`; channel count/width encoding `{umc.get('channel_num', {}).get('value')}/{umc.get('channel_width', {}).get('value')}`; public-driver-derived width `{umc.get('driver_derived_bus_width_bits', {}).get('value')} bits. | The width is derived from current driver code, not a physical measurement; metadata does not prove active ECC correction. |",
        f"| `dce_info` v4.5 | Display caps `{dce.get('display_caps', {}).get('value_hex')}`; boot display clock `{dce.get('bootup_dispclk_10khz', {}).get('value')}` in 10 kHz units; DCN IP range `{dce.get('dcnip_min_ver', {}).get('value')}–{dce.get('dcnip_max_ver', {}).get('value')}`; max display pipe fields `{dce.get('max_disp_pipe_num', {}).get('value')}/{dce.get('max_vbios_active_disp_pipe_num', {}).get('value')}`. | This is VBIOS display capability/configuration metadata; it does not identify physical connector wiring or prove runtime modes. |",
        f"| `gpio_pin_lut` v2.1 | {gpio.get('entry_count', 0)} bounded 8-byte GPIO assignments decoded from the 160-byte entry array. | Pin/register mapping alone does not establish board circuitry, fan control, or runtime use. |",
        f"| `vram_usage_by_firmware` v2.2 | Firmware framebuffer reservation start `{vram_usage.get('fw_region_start_address_in_kb', {}).get('value')} KiB`; firmware reservation `{vram_usage.get('used_by_firmware_in_kb', {}).get('value')} KiB`; driver region-0 reservation start/size `{vram_usage.get('driver_region0_start_address_in_kb', {}).get('value')}/{vram_usage.get('used_by_driver_region0_in_kb', {}).get('value')} KiB`. | Reservation metadata, not memory timing, capacity, or performance tuning. |",
        f"| `display_object_info` v1.5 | {display.get('number_of_path', {}).get('value', 0)} bounded 16-byte display paths decoded; {display.get('trailing_data_range', {}).get('end', 0) - display.get('trailing_data_range', {}).get('start', 0) if display.get('trailing_data_range') else 0} trailing bytes remain identified but undecoded. | Nested record offsets are range-checked and reported, not dereferenced. |",
        "",
        "## Customization opportunity assessment",
            "",
            "Each proposal separates the evidence, controlling layer, plausible benefit, confidence, risk, investigation decision, editing decision, and evidence still needed.",
            "",
        ])
    for proposal in report["modification_assessment"]["proposals"]:
        rows.extend([
            f"### {proposal['area']}",
            "",
            f"- **Field or region:** {proposal['field_or_region']}",
            f"- **Current value:** {proposal['current_value']}",
            f"- **Controlling layer:** {proposal['controlling_layer']}",
            f"- **Plausible benefit:** {proposal['plausible_benefit']}",
            f"- **Confidence:** {proposal['confidence']}",
            f"- **Risk:** {proposal['risk']}",
            f"- **Investigation:** {proposal['investigation_go_no_go']}",
            f"- **Editing:** {proposal['editing_go_no_go']}",
            f"- **Evidence needed:** {proposal['evidence_needed']}",
            "",
        ])

    rows.extend([
        "## Revision-aware modification/control matrix",
        "",
        "This decision matrix is ASUS-specific. Target ranks prioritize further investigation based on the available static evidence; they do not estimate success or approve editing. Board identity and integrity are a cross-cutting gate, so that row has no target rank. Raw observations include local offsets or table hashes and definition sources where available. XFX evidence is explicitly marked as a separate comparison observation.",
        "",
    ])
    for matrix_row in report["modification_matrix"]["rows"]:
        rank = matrix_row.get("modification_target_rank")
        rank_text = f"{rank} (higher investigation priority)" if rank is not None else "Prerequisite gate; not a modification target"
        rows.extend([f"### {matrix_row['area']}", "", f"**Target rank:** {rank_text}. {matrix_row.get('rank_basis', '')}", "", f"**Artifact scope:** {matrix_row['artifact_scope']}", "", "**Raw evidence and sources:**"])
        for evidence in matrix_row["raw_evidence"]:
            source = evidence.get("source") or evidence.get("definition_source")
            if evidence.get("table_id"):
                summary = (
                    f"`{evidence['table_id']}` v{evidence.get('revision', 'unknown')} at `0x{evidence.get('offset', 0):x}`, "
                    f"{evidence.get('length', '?')} bytes, SHA-256 `{evidence.get('raw_sha256', 'unavailable')}`; "
                    f"{evidence.get('body_note') or evidence.get('classification', 'table record')}"
                )
            elif evidence.get("field"):
                raw_value = evidence.get("raw_hex")
                value = evidence.get("value", evidence.get("named_set_bits"))
                summary = f"`{evidence['field']}` at {evidence.get('offset', 'unknown offset')}: raw `{raw_value}`; decoded value `{json.dumps(value, sort_keys=True)}`; definition `{evidence.get('definition', 'none')}`"
                source = source or evidence.get("source")
            elif evidence.get("evidence") == "AS04/AS07 changed byte ranges outside decoded fields":
                summary = f"{len(evidence.get('ranges', []))} changed ranges remain outside supported decoded fields; none is assigned to fan policy by a public definition."
            elif evidence.get("efi_decompression_status"):
                pe = evidence.get("efi_pe") or {}
                cert = pe.get("certificate_directory") or {}
                digest = evidence.get("efi_authenticode_sha256_analysis") or {}
                extra = digest.get("extra_data_range") or {}
                summary = (
                    f"Embedded GOP: {evidence['efi_decompression_status']}; output SHA-256 `{evidence.get('efi_output_sha256')}`; "
                    f"PE `{pe.get('machine_name')}`/`{pe.get('subsystem_name')}`; certificate directory range "
                    f"`{cert.get('offset')}+{cert.get('length')}`; candidate Authenticode SHA-256 "
                    f"`{digest.get('candidate_image_digest', 'not computed')}`, extra data `0x{extra.get('start', 0):x}–0x{extra.get('end', 0):x}`, "
                    f"PKCS#7 check `{(digest.get('cryptographic_verification') or {}).get('status', 'not available')}`; "
                    "signer-chain trust, timestamp and Windows policy were not evaluated."
                )
            elif evidence.get("legacy_image_checksums") is not None:
                summary = f"Legacy image byte-sum records: `{json.dumps(evidence['legacy_image_checksums'], sort_keys=True)}`; {evidence.get('interpretation', '')}"
            elif evidence.get("strings") is not None:
                summary = f"Literal identity/version strings: `{json.dumps(evidence['strings'][:4], sort_keys=True)}` (up to four shown)."
            elif evidence.get("observation"):
                summary = evidence["observation"]
            elif evidence.get("evidence") == "ASUS support-page release note":
                summary = f"{evidence.get('value')} (vendor statement, not a byte mapping or runtime result)."
            elif evidence.get("evidence") == "updater PE certificate and embedded RAR overlay geometry":
                rar = evidence.get("embedded_rar5") or {}
                geometry = evidence.get("authenticode_coverage_geometry") or {}
                overlay = geometry.get("pre_certificate_overlay_range") or {}
                digest = evidence.get("authenticode_sha256_analysis") or {}
                summary = (
                    f"`{evidence.get('member_name')}`: RAR5 marker at `0x{rar.get('signature_offset', 0):x}`, "
                    f"last section raw end `0x{geometry.get('last_bounded_section_raw_end', 0):x}`, "
                    f"overlay length {overlay.get('length', 'unknown')} bytes before certificate offset "
                    f"`0x{(evidence.get('certificate_table') or {}).get('offset', 0):x}`; candidate SHA-256 "
                    f"`{digest.get('candidate_image_digest', 'not computed')}`, raw digest-byte occurrence in PKCS#7 record "
                    f"`{digest.get('candidate_digest_occurs_in_pkcs_signed_data_record', False)}`. "
                    f"{evidence.get('interpretation')}"
                )
                source = evidence.get("definition_source")
            else:
                summary = f"`{json.dumps(evidence, sort_keys=True)[:480]}`"
            rows.append(f"- {summary}" + (f" Source: [{source}]({source})" if source and str(source).startswith("http") else (f" Source: `{source}`." if source else "")))
        rows.extend([
            f"- **Likely control layer:** {', '.join(matrix_row['likely_control_layer'])}",
            f"- **Plausible benefit:** {matrix_row['plausible_benefit']}",
            f"- **Confidence:** {matrix_row['confidence']}",
            f"- **Risk:** {matrix_row['risk']}",
            f"- **Investigation:** {matrix_row['investigation_decision']}",
            f"- **VBIOS edit:** {matrix_row['vbios_edit_decision']}",
            f"- **Evidence still needed:** {'; '.join(matrix_row['evidence_needed'])}",
            "",
        ])

    cu_audit = report["modification_assessment"]["cu_stream_processor_audit"]
    rows.extend([
            "",
            "### CU / stream-processor audit",
            "",
            f"ASUS `gfx_info` is revision {cu_audit['asus_gfx_info']['revision']} at `{cu_audit['asus_gfx_info']['table_offset']:#x}`, length {cu_audit['asus_gfx_info']['length']}; its body is not decoded. {cu_audit['public_definition']}",
            "",
            f"{cu_audit['policy_vs_hardware']} {cu_audit['xfx_context_boundary']}",
            "",
            f"**Investigation:** {cu_audit['investigation_go_no_go']} **Editing:** {cu_audit['editing_go_no_go']}",
            "",
            "The updater and GOP PE PKCS#7 signer signatures and signed PE image digests verify in the static checks recorded above. Signer-chain trust, timestamps and Windows policy were not evaluated. GPU-side VBIOS signature coverage, enforcement and accepted-image behavior remain unknown. No candidate VBIOS image was produced. The XFX software dump was not used to infer ASUS compatibility.",
            "",
            "A field value by itself does not show whether it is a hard limit or a default request. To distinguish them, compare same-board stock and official-update images, trace the active driver/SMU source, measure sustained behavior and telemetry under a repeatable workload, and identify board electrical/thermal limits and relevant silicon fuses.",
            "",
            "## Boundaries and required follow-up",
            "",
            "- Identify and photograph an exact ASUS TURBO R9700 SKU, PCB revision, flash device, DRAM and power circuitry before associating either payload with a card.",
            "- Obtain repeatable software reads and full-chip SPI backups; demonstrate recovery independently of GPU initialization before any experimental write.",
            "- Compare same-board stock and ASUS-updated images. Confirm the fan-table hypothesis by mapping an authoritative revision and correlating table changes with measured fan behavior.",
            "- Establish host-flasher restrictions separately from GPU/PSP/SMU, UEFI and driver checks. The present files do not establish cryptographic authentication or a legitimate custom-signing route.",
            "- Run baseline and post-change performance, power, acoustic, thermal, display, memory-correctness and rollback tests only after the recovery and authentication gates pass.",
            "",
            "No updater was run; no firmware was written; no physical ASUS card, recovery image or test result was supplied. This analysis is structural and does not establish flash acceptance, bootability, safety, or performance benefit.",
            "",
        ])
    provenance = report.get("source_provenance", {})
    tools_used = provenance.get("analysis_tools", {})
    tiano = tools_used.get("tianocompress") or {}
    ghidra_tool = tools_used.get("ghidra_report_tool") or {}
    rows.extend([
        "## Sources and tool provenance",
        "",
        f"- AMD ATOM structures and driver behavior were checked against pinned Linux commit [`{LINUX_SOURCE_COMMIT[:12]}`]({ATOM_HEADER}) and the [current upstream ATOM header]({CURRENT_ATOM_HEADER}) plus [driver parser]({CURRENT_AMDGPU_ATOM_DRIVER}). Targeted symbol checks found no exact GFX_INFO v3.1 or SMC/DPM v6.0 body definition in the inspected snapshots; this is not an exhaustive review of vendor-private sources or every branch.",
        f"- [Microsoft PE Format]({MICROSOFT_PE_FORMAT}) documents PE headers and certificate records; its prose about post-section data conflicts with its [linked Authenticode PE Signature Format procedure]({MICROSOFT_AUTHENTICODE_PE}). The calculated candidate SHA-256 follows step 14, including the bounded extra-data range; OpenSSL verifies the PKCS#7 signer signature and matching signed SPC digest. Certificate-chain trust, timestamps and Windows policy were not evaluated. See the [OpenSSL smime documentation]({OPENSSL_SMIME_DOC}).",
        f"- The [UEFI 2.10 PCI bus specification]({UEFI_SPEC}) and [compression specification]({UEFI_COMPRESSION_SPEC}) supply option-ROM boundaries and compression-envelope rules.",
        f"- [EDK II TianoCompress source/tests]({EDK2_TIANOCOMPRESS_SOURCE}) at commit `c1415771ac592ad8509351c46cd3cda4f38d7d52`: `{tiano.get('version', 'version unavailable')}`, rebuilt executable SHA-256 `{tiano.get('executable_sha256', 'not supplied')}`. {tiano.get('rebuild_identity_note', 'Used only for bounded decompression.')}",
        f"- [{ghidra_tool.get('version', GHIDRA_RELEASE)}]({GHIDRA_RELEASE_URL}), release archive SHA-256 `{ghidra_tool.get('release_archive_sha256', GHIDRA_ARCHIVE_SHA256)}`; Java runtime `{GHIDRA_JDK['distribution']}`, archive SHA-256 `{GHIDRA_JDK['archive_sha256']}`. Helper: `tools/ghidra_efi_summary.java`.",
        "- GNU `file`, `objdump`, `readelf`, and `strings` static probes, Python version, exact executable versions and hashes are recorded in the accompanying JSON `source_provenance.analysis_tools` object.",
        "",
    ])
    return "\n".join(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True, type=Path, help="Official ASUS ZIP package")
    parser.add_argument("--as04", required=True, type=Path, help="Extracted AS04 ROM payload")
    parser.add_argument("--as07", required=True, type=Path, help="Extracted AS07 ROM payload")
    parser.add_argument("--xfx-comparison-rom", type=Path, help="Optional existing XFX software-ROM sample for a bounded comparison")
    parser.add_argument("--tianocompress-bin", type=Path, help="Optional EDK II TianoCompress binary for bounded UEFI decompression")
    parser.add_argument("--ghidra-report", type=Path, help="Optional JSON output from tools/ghidra_efi_summary.java")
    parser.add_argument("--legacy-as04-ghidra-report", type=Path, help="Static Ghidra inventory for the bounded AS04 legacy option-ROM image")
    parser.add_argument("--legacy-as07-ghidra-report", type=Path, help="Static Ghidra inventory for the bounded AS07 legacy option-ROM image")
    parser.add_argument("--json-output", type=Path, help="Write structured JSON analysis to this path")
    parser.add_argument("--markdown-output", type=Path, help="Write the human-readable report to this path")
    args = parser.parse_args(argv)

    inputs = tuple(
        path for path in (
            args.package,
            args.as04,
            args.as07,
            args.xfx_comparison_rom,
            args.tianocompress_bin,
            args.ghidra_report,
            args.legacy_as04_ghidra_report,
            args.legacy_as07_ghidra_report,
        ) if path is not None
    )
    outputs = tuple(path for path in (args.json_output, args.markdown_output) if path is not None)
    for output in outputs:
        for input_path in inputs:
            if _paths_alias(output, input_path):
                print(f"Refusing to write output over an input path: {output}", file=sys.stderr)
                return 2
    if args.json_output and args.markdown_output and _paths_alias(args.json_output, args.markdown_output):
        print("Refusing to write JSON and Markdown outputs to the same path.", file=sys.stderr)
        return 2

    try:
        report = analyze_asus(
            args.package,
            args.as04,
            args.as07,
            xfx_path=args.xfx_comparison_rom,
            tianocompress_bin=args.tianocompress_bin,
            ghidra_report_path=args.ghidra_report,
            legacy_as04_ghidra_report_path=args.legacy_as04_ghidra_report,
            legacy_as07_ghidra_report_path=args.legacy_as07_ghidra_report,
        )
    except (OSError, ValueError) as exc:
        print(f"Could not read an analysis input: {exc}", file=sys.stderr)
        return 2

    structured = json.dumps(report, indent=2, sort_keys=True) + "\n"
    human: str | None = None
    if args.markdown_output or not args.json_output:
        try:
            human = render_markdown(report)
        except ValueError as exc:
            print(f"Could not render Markdown report: {exc}", file=sys.stderr)
            return 2
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(structured, encoding="utf-8")
    if args.markdown_output:
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        assert human is not None
        args.markdown_output.write_text(human, encoding="utf-8")
    if not args.json_output and not args.markdown_output:
        assert human is not None
        print(human)
        print("Structured JSON:", file=sys.stderr)
        print(structured, file=sys.stderr)
    elif not args.json_output:
        print(structured)
    return 0


def _paths_alias(first: Path, second: Path) -> bool:
    """Detect equal paths plus existing symlink and hard-link aliases."""
    try:
        if first.resolve(strict=False) == second.resolve(strict=False):
            return True
    except (OSError, RuntimeError):
        pass
    try:
        return first.exists() and second.exists() and os.path.samefile(first, second)
    except OSError:
        return False


if __name__ == "__main__":
    raise SystemExit(main())
