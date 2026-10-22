import contextlib
import io
import json
import os
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from tools.asus_rom_analysis import (
    _annotate_authenticode_digest_record_match,
    _authenticode_sha256_analysis,
    _certificate_table,
    _decompress_efi_stream,
    _inspect_efi_payload,
    _parse_pe_header,
    analyze_rom,
    analyze_asus,
    main,
    render_markdown,
)
from tools.rom_triage import ATOM_DATA_TABLE_IDS


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ASUS_DIR = REPOSITORY_ROOT / "bios" / "vendor-packages" / "asus"


def put_u16(data: bytearray, offset: int, value: int) -> None:
    data[offset : offset + 2] = value.to_bytes(2, "little")


def put_u32(data: bytearray, offset: int, value: int) -> None:
    data[offset : offset + 4] = value.to_bytes(4, "little")


def make_rom(
    *, atom_format_revision: int = 2, master_format_revision: int = 2, master_content_revision: int = 1
) -> bytes:
    data = bytearray(512)
    data[0:2] = b"\x55\xaa"
    data[2] = 1
    put_u16(data, 0x18, 0x20)
    data[0x20:0x24] = b"PCIR"
    put_u16(data, 0x24, 0x1002)
    put_u16(data, 0x26, 0x7551)
    put_u16(data, 0x2A, 0x18)
    put_u16(data, 0x30, 1)
    data[0x34] = 0
    data[0x35] = 0x80

    put_u16(data, 0x48, 0x80)
    atom = 0x80
    put_u16(data, atom, 0x22)
    data[atom + 2] = atom_format_revision
    data[atom + 3] = 2
    data[atom + 4 : atom + 8] = b"ATOM"
    put_u16(data, atom + 0x20, 0xC0)
    put_u16(data, 0xC0, 4 + 35 * 2)
    data[0xC2] = master_format_revision
    data[0xC3] = master_content_revision
    data[-1] = (-sum(data[:-1])) & 0xFF
    return bytes(data)


def make_table_rom(table_id: str, revision: tuple[int, int], length: int, *, offset: int = 0x120) -> bytes:
    data = bytearray(make_rom())
    table_index = ATOM_DATA_TABLE_IDS.index(table_id)
    put_u16(data, 0xC4 + table_index * 2, offset)
    put_u16(data, offset, length)
    data[offset + 2] = revision[0]
    data[offset + 3] = revision[1]
    for index in range(offset + 4, min(offset + length, len(data))):
        data[index] = (index * 37 + 11) & 0xFF
    data[-1] = (-sum(data[:-1])) & 0xFF
    return bytes(data)


def make_efi_rom(*, signature: int = 0x0EF1, compression: int = 1, image_offset: int = 0x60, compressed_size: int = 8) -> bytes:
    data = bytearray(make_rom())
    data[0x34] = 3  # PCIR code type EFI
    put_u16(data, 4, signature & 0xFFFF)
    put_u16(data, 8, 0x000B)  # EFI boot-service driver subsystem
    put_u16(data, 0x0A, 0x8664)
    put_u16(data, 0x0C, compression)
    put_u16(data, 0x16, image_offset)
    if image_offset + 8 <= len(data):
        data[image_offset : image_offset + 8] = struct.pack("<II", compressed_size, 32)
    data[-1] = (-sum(data[:-1])) & 0xFF
    return bytes(data)


class AsusRomAnalysisTests(unittest.TestCase):
    def test_real_payload_map_is_stable_and_accounts_for_every_byte(self) -> None:
        package = ASUS_DIR / "AI-PRO-R9700.zip"
        as04 = ASUS_DIR / "payloads" / "7551OG.23.8.0.68.AS04.rom"
        as07 = ASUS_DIR / "payloads" / "7551OG.23.8.0.68.AS07.rom"

        first = analyze_asus(package, as04, as07)
        second = analyze_asus(package, as04, as07)

        self.assertEqual(first, second)
        self.assertEqual(
            json.dumps(first, sort_keys=True, indent=2),
            json.dumps(second, sort_keys=True, indent=2),
        )
        self.assertEqual(render_markdown(first), render_markdown(second))
        self.assertEqual(first["package"]["sha256"], "cd499dbf1079b2e65666ff66877c367b4823bbe15910446ab1a2a72c7224b0a0")
        self.assertEqual(first["payloads"]["AS04"]["sha256"], "0242ce25f406d61f7ff87c3e7be1324ad8f6e1066a2279e6b9ec03b736e60235")
        self.assertEqual(first["payloads"]["AS07"]["sha256"], "bee92e0a7092c9849b636bf0ec9eaf172c213cb3e34056bac40bc67c6150ecb4")
        self.assertEqual(len(first["payloads"]["AS04"]["pcir_images"]), 4)
        self.assertEqual(first["comparison"]["changed_range_count"], 89)
        self.assertTrue(first["comparison"]["all_discovered_atom_records_identical"])
        for version in ("AS04", "AS07"):
            rom = first["payloads"][version]
            accounting = rom["region_accounting"]
            self.assertEqual(
                set(accounting["totals_bytes"]),
                {"decoded", "identified_but_undecoded", "known_padding_or_repeated_data", "opaque"},
            )
            self.assertEqual(sum(accounting["totals_bytes"].values()), rom["size_bytes"])
            self.assertEqual(accounting["regions"][0]["start"], 0)
            self.assertEqual(accounting["regions"][-1]["end"], rom["size_bytes"])
            for previous, current in zip(accounting["regions"], accounting["regions"][1:]):
                self.assertEqual(previous["end"], current["start"])
        report = render_markdown(first)
        self.assertIn("No AS04/AS07 byte difference currently proves a fan curve change.", report)
        self.assertIn("identified_text_bytes", report)
        self.assertIn("no smc_dpm_info v6.0 definition", json.dumps(first))
        self.assertIn("known_padding_or_repeated_data", report)
        self.assertIn("no CU count or mask is decoded", report)
        self.assertIn("GDDR6", report)
        self.assertIn("All 35 public master-list data slots", report)
        self.assertIn("Exact changed intervals and raw evidence", report)
        self.assertIn("Target rank:** 1", report)
        self.assertEqual(first["schema_version"], 5)
        matrix = first["modification_matrix"]["rows"]
        self.assertEqual(len(matrix), 7)
        for item in matrix:
            for required in ("raw_evidence", "likely_control_layer", "plausible_benefit", "confidence", "risk", "evidence_needed", "investigation_decision", "vbios_edit_decision"):
                self.assertIn(required, item)
        identity_row = next(item for item in matrix if item["area"] == "Board identity and integrity metadata")
        self.assertIsNone(identity_row["modification_target_rank"])
        self.assertIn("updater PE certificate", json.dumps(identity_row["raw_evidence"]))
        self.assertEqual(
            {item["modification_target_rank"] for item in matrix if item["modification_target_rank"] is not None},
            set(range(1, 7)),
        )
        checksum_record = next(item["legacy_image_checksums"] for item in identity_row["raw_evidence"] if "legacy_image_checksums" in item)
        self.assertTrue(all(item["checksum_valid"] for item in checksum_record))
        self.assertTrue(all(item["crc32_matches"] for item in first["package"]["archive_members"]))
        self.assertIn(
            "https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx",
            json.dumps(first["source_provenance"]),
        )
        updater_digests = {
            item["member_name"]: item["authenticode_sha256_analysis"]
            for item in first["package"]["updaters"]
        }
        self.assertEqual(
            updater_digests["AI-PRO-R9700_default.exe"]["candidate_image_digest"],
            "e468e856b4f85ee85e15d38af21dce05c1b36c88b71f533b3ca6d6b8ed150ee5",
        )
        self.assertEqual(
            updater_digests["AI-PRO-R9700_update.exe"]["candidate_image_digest"],
            "7d72aa285ddf1011ff7be004b04da1bcd516187098b83f06c57fe8d628cef86f",
        )
        for updater in first["package"]["updaters"]:
            digest = updater["authenticode_sha256_analysis"]
            rar = updater["embedded_rar5"]
            certificate = updater["certificate_table"]
            self.assertEqual(digest["status"], "computed")
            self.assertEqual(digest["extra_data_range"]["start"], 0x6B600)
            self.assertEqual(digest["extra_data_range"]["end"], certificate["offset"])
            self.assertTrue(digest["candidate_digest_occurs_in_pkcs_signed_data_record"])
            verification = digest["cryptographic_verification"]
            self.assertEqual(verification["status"], "pkcs7_signer_signature_and_pe_image_digest_verified")
            self.assertIn("does not decode or validate", verification["spc_image_digest_parse_scope"])
            self.assertTrue(verification["authenticode_signature_verified"])
            self.assertTrue(verification["records"][0]["spc_image_digest_matches_calculated_pe_digest"])
            self.assertTrue(rar["rar_marker_in_computed_authenticode_sha256_range"])
        lines = report.splitlines()
        pcir_table = next(index for index, line in enumerate(lines) if line.startswith("| Offset | Length | PCIR code type"))
        self.assertTrue(all(line.startswith("| `") for line in lines[pcir_table + 2 : pcir_table + 6]))
        self.assertEqual(len(first["payloads"]["AS04"]["atom_table_map"]), 35)
        master_map = first["payloads"]["AS04"]["atom_table_map"]
        self.assertEqual(master_map[3]["public_master_field"], "sw_datatable3")
        self.assertEqual(master_map[25]["public_master_field"], "sw_datatable25")
        self.assertTrue(all(item.get("second_chain_identical") in {True, None} for item in master_map))
        self.assertIn("https://learn.microsoft.com/en-us/windows/win32/debug/pe-format", json.dumps(first["source_provenance"]))
        self.assertIn("32c52ec87d6245ee2d12ed5dd509e40062939b50", json.dumps(first["source_provenance"]))
        self.assertTrue(all("raw_evidence" in item for item in first["comparison"]["exact_changed_ranges"]))

        as04_report = first["payloads"]["AS04"]
        decoded = {item["table_id"]: item for item in as04_report["decoded_data_tables"]}
        expected_definitions = {
            "firmware_info": "atom_firmware_info_v3_5",
            "umc_info": "atom_umc_info_v4_0",
            "dce_info": "atom_display_controller_info_v4_5",
            "gpio_pin_lut": "atom_gpio_pin_lut_v2_1 / atom_gpio_pin_assignment",
            "vram_usage_by_firmware": "vram_usagebyfirmware_v2_2",
            "display_object_info": "display_object_info_table_v1_5 / atom_display_object_path_v3",
        }
        for table_id, definition in expected_definitions.items():
            self.assertEqual(decoded[table_id]["definition"], definition)
            self.assertIn("atomfirmware.h", decoded[table_id]["definition_source"])
            self.assertIn("32c52ec87d6245ee2d12ed5dd509e40062939b50", decoded[table_id]["definition_source"])
        dce_fields = decoded["dce_info"]["fields"]
        self.assertEqual(dce_fields["max_ppll_num"]["offset"], decoded["dce_info"]["offset"] + 44)
        self.assertEqual(dce_fields["max_disp_phy_num"]["offset"], decoded["dce_info"]["offset"] + 45)
        self.assertEqual(dce_fields["max_aux_pairs"]["offset"], decoded["dce_info"]["offset"] + 46)
        self.assertEqual(dce_fields["aux_dphy_rx_control0_val"]["offset"], decoded["dce_info"]["offset"] + 72)
        self.assertEqual(dce_fields["dc_gpio_aux_ctrl_5_val"]["offset"], decoded["dce_info"]["offset"] + 104)
        self.assertEqual(decoded["umc_info"]["fields"]["vram_type"]["named_value"], "GDDR6")
        self.assertEqual(decoded["umc_info"]["fields"]["driver_derived_bus_width_bits"]["value"], 256)
        self.assertEqual(decoded["gpio_pin_lut"]["entry_count"], 20)
        self.assertEqual(decoded["display_object_info"]["number_of_path"]["value"], 4)
        self.assertEqual(decoded["display_object_info"]["trailing_data_range"]["end"] - decoded["display_object_info"]["trailing_data_range"]["start"], 128)
        display_table = next(
            item for item in as04_report["atom_tables"]
            if item["table_id"] == "display_object_info" and item["image_index"] == 0
        )
        self.assertEqual(display_table["classification"], "partially_decoded")
        self.assertEqual(display_table["decoded_range"]["end"] - display_table["decoded_range"]["start"], 72)
        decoded_prefix = display_table["decoded_range"]["end"] - 1
        decoded_region = next(
            region for region in as04_report["region_accounting"]["regions"]
            if region["start"] <= decoded_prefix < region["end"]
        )
        self.assertEqual(decoded_region["status"], "decoded")
        trailing_start = display_table["trailing_data_range"]["start"]
        trailing_region = next(
            region for region in as04_report["region_accounting"]["regions"]
            if region["start"] <= trailing_start < region["end"]
        )
        self.assertEqual(trailing_region["status"], "identified_but_undecoded")
        self.assertEqual(
            next(item for item in as04_report["atom_tables"] if item["table_id"] == "gfx_info")["classification"],
            "identified_but_undecoded",
        )
        efi = next(image for image in as04_report["pcir_images"] if image["code_type"] == 3)
        self.assertEqual(efi["efi_payload_inspection"]["status"], "compressed_stream_identified_but_undecoded")
        self.assertEqual(efi["efi_payload_inspection"]["compression_header"]["compressed_size_bytes"], 57824)
        self.assertEqual(
            efi["efi_payload_inspection"]["compression_header"]["compressed_data_sha256"],
            "d1eeeeb544af7486cbec12e03c4f6c553eb518dac693e93ed85d0dc51d825c11",
        )
        self.assertIn("static_tool_probe", efi["efi_payload_inspection"])
        self.assertEqual(efi["efi_payload_inspection"]["padding_range"]["length"], 440)
        self.assertEqual(len(first["modification_matrix"]["rows"]), 7)
        self.assertEqual(first["modification_matrix"]["rows"][0]["area"], "Fan behavior and acoustics")

    def test_umc_unknown_config1_bits_remain_visible(self) -> None:
        data = bytearray(make_table_rom("umc_info", (4, 0), 84))
        config1_offset = 0x120 + 52
        data[config1_offset : config1_offset + 4] = (0x0001001F).to_bytes(4, "little")
        data[-1] = (-sum(data[:-1])) & 0xFF
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "umc-config1-flags.rom"
            path.write_bytes(data)
            report = analyze_rom(path)

        decoded = next(item for item in report["decoded_data_tables"] if item["table_id"] == "umc_info")
        config1 = decoded["fields"]["umc_config1"]
        self.assertEqual(config1["named_set_bits"], ["ENABLE_ECC_CAPABLE"])
        self.assertEqual(config1["unmapped_set_bits_hex"], "0x0000001f")

    def test_static_efi_tool_probe_is_limited_to_the_measured_stream(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "synthetic-efi.rom"
            path.write_bytes(make_efi_rom())
            report = analyze_rom(path)

        inspection = report["pcir_images"][0]["efi_payload_inspection"]
        self.assertEqual(inspection["status"], "compressed_stream_identified_but_undecoded")
        self.assertNotEqual(
            inspection["compression_header"]["compressed_data_sha256"],
            "d1eeeeb544af7486cbec12e03c4f6c553eb518dac693e93ed85d0dc51d825c11",
        )
        self.assertNotIn("static_tool_probe", inspection)

    def test_json_analysis_handles_roms_without_gfx_table(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            package = temporary / "empty.zip"
            with zipfile.ZipFile(package, "w"):
                pass
            as04 = temporary / "as04-truncated.rom"
            as07 = temporary / "as07-truncated.rom"
            as04.write_bytes(b"\x55\xaa")
            as07.write_bytes(b"\x55\xaa")

            report = analyze_asus(package, as04, as07)

        cu = report["modification_assessment"]["proposals"][3]
        self.assertEqual(cu["area"], "CU / stream-processor unlock")
        self.assertIn("not present", cu["field_or_region"])
        self.assertEqual(report["payloads"]["AS04"]["size_bytes"], 2)

    def test_truncated_data_table_is_rejected_and_payload_is_still_accounted(self) -> None:
        data = bytearray(make_rom())
        table_offset = 0x1F0
        put_u16(data, 0xC4 + ATOM_DATA_TABLE_IDS.index("umc_info") * 2, table_offset)
        put_u16(data, table_offset, 84)
        data[table_offset + 2 : table_offset + 4] = b"\x04\x00"
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "truncated-table.rom"
            path.write_bytes(data)
            report = analyze_rom(path)

        self.assertFalse(any(item["table_id"] == "umc_info" for item in report["atom_tables"]))
        self.assertIn(
            "atom_data_table_exceeds_image",
            {warning["code"] for warning in report["triage_warnings"]},
        )
        self.assertEqual(sum(report["region_accounting"]["totals_bytes"].values()), len(data))

    def test_unsupported_table_revision_is_not_decoded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "unsupported-umc.rom"
            path.write_bytes(make_table_rom("umc_info", (4, 1), 84))
            report = analyze_rom(path)

        table = next(item for item in report["atom_tables"] if item["table_id"] == "umc_info")
        self.assertEqual(table["classification"], "identified_but_undecoded")
        self.assertFalse(any(item["table_id"] == "umc_info" for item in report["decoded_data_tables"]))
        self.assertEqual(sum(report["region_accounting"]["totals_bytes"].values()), 512)

    def test_unknown_gfx_table_body_remains_identified_but_undecoded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "unknown-gfx.rom"
            path.write_bytes(make_table_rom("gfx_info", (3, 1), 136))
            report = analyze_rom(path)

        table = next(item for item in report["atom_tables"] if item["table_id"] == "gfx_info")
        self.assertEqual(table["classification"], "identified_but_undecoded")
        self.assertFalse(any(item["table_id"] == "gfx_info" for item in report["decoded_data_tables"]))
        body = next(region for region in report["region_accounting"]["regions"] if region["start"] <= 0x124 < region["end"])
        self.assertEqual(body["status"], "identified_but_undecoded")

    def test_malformed_and_unsupported_efi_payloads_are_bounded(self) -> None:
        bad_terminator = bytearray(make_efi_rom())
        bad_terminator[0x60 + 8 + 7] = 0x7F
        cases = (
            ("bad-signature", make_efi_rom(signature=0), "malformed"),
            ("bad-compressed-size", make_efi_rom(compressed_size=0x1000), "malformed"),
            ("bad-compression-terminator", bytes(bad_terminator), "malformed_compression_stream"),
            ("unsupported-compression", make_efi_rom(compression=7), "unsupported_compression"),
            ("bad-image-offset", make_efi_rom(image_offset=0x200), "malformed"),
            ("truncated-compression-envelope", make_efi_rom(image_offset=0x1fc), "malformed"),
        )
        for name, data, expected_status in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary_directory:
                path = Path(temporary_directory) / f"{name}.rom"
                path.write_bytes(data)
                report = analyze_rom(path)

            self.assertEqual(len(report["pcir_images"]), 1)
            self.assertEqual(report["pcir_images"][0]["efi_payload_inspection"]["status"], expected_status)
            self.assertEqual(sum(report["region_accounting"]["totals_bytes"].values()), len(data))

    def test_unknown_smc_dpm_body_remains_opaque_at_field_level(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "unknown-smc-dpm.rom"
            data = bytearray(make_table_rom("smc_dpm_info", (6, 0), 532))
            data.extend(bytes(512))
            data[2] = 2
            put_u16(data, 0x30, 2)
            data[-1] = (-sum(data[:-1])) & 0xFF
            path.write_bytes(data)
            report = analyze_rom(path)

        table = next(item for item in report["atom_tables"] if item["table_id"] == "smc_dpm_info")
        self.assertEqual(table["classification"], "identified_but_undecoded")
        self.assertIn("no smc_dpm_info v6.0 definition", table["body_note"])
        self.assertFalse(any(item["table_id"] == "smc_dpm_info" for item in report["decoded_data_tables"]))
        self.assertEqual(sum(report["region_accounting"]["totals_bytes"].values()), 1024)

    def test_pe_header_parser_accepts_bounded_pe32_plus_and_rejects_truncation(self) -> None:
        data = bytearray(0x200)
        data[:2] = b"MZ"
        put_u32(data, 0x3C, 0x80)
        data[0x80:0x84] = b"PE\x00\x00"
        struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
        optional = 0x98
        put_u16(data, optional, 0x20B)
        struct.pack_into("<I", data, optional + 16, 0x1000)
        struct.pack_into("<Q", data, optional + 24, 0)
        struct.pack_into("<I", data, optional + 56, 0x2000)
        struct.pack_into("<I", data, optional + 60, 0x1C0)
        put_u16(data, optional + 68, 11)
        struct.pack_into("<I", data, optional + 108, 16)
        struct.pack_into("<II", data, optional + 112 + 4 * 8, 0x1E0, 0x10)
        section = optional + 0xF0
        data[section : section + 8] = b".text\x00\x00\x00"
        struct.pack_into("<IIII", data, section + 8, 0x20, 0x1000, 0x20, 0x1C0)
        struct.pack_into("<I", data, section + 36, 0x60000020)
        data[0x1E0:0x1E8] = struct.pack("<IHH", 16, 0x0200, 2)

        parsed = _parse_pe_header(bytes(data))
        self.assertTrue(parsed["recognized"])
        self.assertEqual(parsed["machine_name"], "AMD64")
        self.assertEqual(parsed["entry_point_rva"], 0x1000)
        self.assertEqual(parsed["subsystem_name"], "EFI boot service driver")
        self.assertEqual(parsed["characteristics"], 0x2022)
        self.assertTrue(parsed["sections"][0]["raw_range_in_bounds"])
        self.assertTrue(parsed["certificate_directory"]["range_in_bounds"])
        self.assertEqual(parsed["sections"][0]["characteristics_hex"], "0x60000020")
        coverage = parsed["authenticode_coverage_geometry"]
        self.assertEqual(coverage["last_bounded_section_raw_end"], 0x1E0)
        self.assertIsNone(coverage["pre_certificate_overlay_range"])

        for magic in (0x10B, 0x20B):
            truncated_optional = bytearray(data)
            put_u16(truncated_optional, 0x98, magic)
            put_u16(truncated_optional, 0x84 + 16, 70)
            incomplete = _parse_pe_header(bytes(truncated_optional))
            self.assertFalse(incomplete["recognized"])
            self.assertTrue(any("optional header" in warning.lower() for warning in incomplete["warnings"]))

        truncated = bytearray(data[:0xA0])
        self.assertFalse(_parse_pe_header(bytes(truncated))["recognized"])

    def test_pe_overlay_is_covered_by_authenticode_extra_data_formula(self) -> None:
        data = bytearray(0x220)
        data[:2] = b"MZ"
        put_u32(data, 0x3C, 0x80)
        data[0x80:0x84] = b"PE\x00\x00"
        struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
        optional = 0x98
        put_u16(data, optional, 0x20B)
        struct.pack_into("<I", data, optional + 16, 0x1000)
        struct.pack_into("<I", data, optional + 56, 0x2000)
        struct.pack_into("<I", data, optional + 60, 0x1C0)
        put_u16(data, optional + 68, 11)
        struct.pack_into("<I", data, optional + 108, 16)
        struct.pack_into("<II", data, optional + 112 + 4 * 8, 0x210, 0x10)
        section = optional + 0xF0
        data[section : section + 8] = b".text\x00\x00\x00"
        struct.pack_into("<IIII", data, section + 8, 0x40, 0x1000, 0x40, 0x1C0)
        struct.pack_into("<I", data, section + 36, 0x60000020)
        data[0x200:0x208] = b"Rar!\x1a\x07\x01\x00"
        data[0x210:0x220] = struct.pack("<IHH", 16, 0x0200, 2) + bytes(8)

        parsed = _parse_pe_header(bytes(data))
        geometry = parsed["authenticode_coverage_geometry"]
        self.assertEqual(geometry["last_bounded_section_raw_end"], 0x200)
        self.assertEqual(geometry["pre_certificate_overlay_range"], {"start": 0x200, "end": 0x210, "length": 0x10})
        self.assertEqual(parsed["certificate_directory"]["offset"], 0x210)
        analysis = _authenticode_sha256_analysis(bytes(data), parsed)
        self.assertEqual(analysis["status"], "computed")
        self.assertEqual(analysis["extra_data_range"], {"start": 0x200, "end": 0x210, "length": 0x10})
        self.assertTrue(any(item["start"] <= 0x200 < item["end"] for item in analysis["hashed_ranges"]))

        baseline = analysis["candidate_image_digest"]
        for offset in (geometry["checksum_file_offset"], geometry["certificate_directory_entry_file_offset"], 0x210):
            changed_exclusion = bytearray(data)
            changed_exclusion[offset] ^= 0xFF
            self.assertEqual(_authenticode_sha256_analysis(bytes(changed_exclusion), parsed)["candidate_image_digest"], baseline)
        changed_overlay = bytearray(data)
        changed_overlay[0x208] ^= 0xFF
        self.assertNotEqual(_authenticode_sha256_analysis(bytes(changed_overlay), parsed)["candidate_image_digest"], baseline)

    def test_authenticode_hash_rejects_nonterminal_certificate_and_truncated_headers(self) -> None:
        data = bytearray(0x240)
        data[:2] = b"MZ"
        put_u32(data, 0x3C, 0x80)
        data[0x80:0x84] = b"PE\x00\x00"
        struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
        optional = 0x98
        put_u16(data, optional, 0x20B)
        struct.pack_into("<I", data, optional + 56, 0x2000)
        struct.pack_into("<I", data, optional + 60, 0x1C0)
        put_u16(data, optional + 68, 11)
        struct.pack_into("<I", data, optional + 108, 16)
        struct.pack_into("<II", data, optional + 112 + 4 * 8, 0x210, 0x10)
        section = optional + 0xF0
        data[section : section + 8] = b".text\x00\x00\x00"
        struct.pack_into("<IIII", data, section + 8, 0x40, 0x1000, 0x40, 0x1C0)
        struct.pack_into("<I", data, section + 36, 0x60000020)
        data[0x210:0x220] = struct.pack("<IHH", 16, 0x0200, 2) + bytes(8)
        parsed = _parse_pe_header(bytes(data))
        self.assertEqual(
            _authenticode_sha256_analysis(bytes(data), parsed)["reason"],
            "certificate table is not at end of file; bounded implementation requires the documented terminal-table layout",
        )
        truncated = _parse_pe_header(bytes(data[:0xA0]))
        self.assertEqual(_authenticode_sha256_analysis(bytes(data[:0xA0]), truncated)["status"], "not_computed")

    def test_digest_record_match_limit_reports_negative_and_unavailable_checks(self) -> None:
        not_computed = _annotate_authenticode_digest_record_match(
            b"", None, {"status": "not_computed"}
        )
        self.assertFalse(not_computed["candidate_digest_occurs_in_pkcs_signed_data_record"])
        self.assertIn("No candidate image digest was computed", not_computed["digest_match_limit"])
        self.assertNotIn("digest bytes occur", not_computed["digest_match_limit"])

        no_certificate = _annotate_authenticode_digest_record_match(
            b"", None, {"status": "computed", "candidate_image_digest": "11" * 32}
        )
        self.assertFalse(no_certificate["candidate_digest_occurs_in_pkcs_signed_data_record"])
        self.assertIn("No bounded certificate table", no_certificate["digest_match_limit"])

        no_match = _annotate_authenticode_digest_record_match(
            struct.pack("<IHH", 8, 0x0200, 2),
            {"entries": [{"offset": 0, "length": 8, "type_name": "PKCS_SIGNED_DATA"}]},
            {"status": "computed", "candidate_image_digest": "22" * 32},
        )
        self.assertFalse(no_match["candidate_digest_occurs_in_pkcs_signed_data_record"])
        self.assertIn("were not found", no_match["digest_match_limit"])

    def test_certificate_table_malformed_records_and_truncated_range_are_bounded(self) -> None:
        data = bytearray(32)
        data[8:16] = struct.pack("<IHH", 4, 0x0200, 2)
        malformed = _certificate_table(bytes(data), {"certificate_directory": {"offset": 8, "length": 8}})
        self.assertEqual(malformed["entries"][0]["status"], "malformed_WIN_CERTIFICATE")

        data[8:16] = struct.pack("<IHH", 24, 0x0200, 2)
        truncated_record = _certificate_table(bytes(data), {"certificate_directory": {"offset": 8, "length": 8}})
        self.assertEqual(truncated_record["entries"][0]["status"], "malformed_WIN_CERTIFICATE")

        out_of_bounds = _certificate_table(bytes(data), {"certificate_directory": {"offset": 28, "length": 8}})
        self.assertFalse(out_of_bounds["range_in_bounds"])

    def test_ghidra_report_requires_exact_decompressed_input_hash(self) -> None:
        raw = make_efi_rom()
        image = {
            "offset": 0,
            "declared_length_bytes": len(raw),
            "efi_header": {"signature_valid": True, "efi_image_offset": 0x60, "compression_type": 1, "machine": 0x8664},
        }
        digest = "a" * 64
        decomp = {
            "status": "decompressed_pe_validated",
            "uncompressed_sha256": digest,
            "pe": {"recognized": True},
            "certificate_table": None,
            "static_string_leads": [],
        }
        with patch("tools.asus_rom_analysis._tianocompress_metadata", return_value={"name": "test"}), patch(
            "tools.asus_rom_analysis._decompress_efi_stream", side_effect=lambda *args: dict(decomp)
        ):
            matched = _inspect_efi_payload(
                raw, image, Path("tianocompress"), {"input_sha256": digest, "analysis": {"function_inventory": []}}
            )
            mismatched = _inspect_efi_payload(
                raw, image, Path("tianocompress"), {"input_sha256": "b" * 64, "analysis": {}}
            )
            missing_hash = _inspect_efi_payload(raw, image, Path("tianocompress"), {"analysis": {}})

        self.assertEqual(matched["decompression"]["ghidra_static_analysis"]["input_sha256"], digest)
        self.assertEqual(mismatched["decompression"]["ghidra_static_analysis"]["status"], "not_applied_hash_mismatch")
        self.assertEqual(missing_hash["decompression"]["ghidra_static_analysis"]["status"], "not_applied_hash_mismatch")

    def test_efi_decompression_rejects_output_size_over_limit_before_running_tool(self) -> None:
        result = _decompress_efi_stream(b"\x01\x00\x00\x00\x01\x00\x00\x00\x00", 16 * 1024 * 1024 + 1, Path("/does/not/exist"), 0x8664)
        self.assertEqual(result["status"], "decompression_failed")
        self.assertIn("safety limit", result["reason"])

    def test_decompressed_output_rejects_non_pe_and_truncated_section_table(self) -> None:
        def run_fake_decompressor(output: bytes) -> dict:
            envelope = struct.pack("<II", 1, len(output)) + b"\x00"

            def fake_run(command, **kwargs):
                if len(command) > 1 and command[1] == "version":
                    return type("Process", (), {"returncode": 0, "stdout": "OpenSSL test", "stderr": ""})()
                if len(command) > 1 and command[1] == "smime":
                    return type("Process", (), {"returncode": 1, "stdout": "", "stderr": "synthetic PKCS#7 fixture"})()
                out_path = Path(command[command.index("-o") + 1])
                out_path.write_bytes(output)
                return type("Process", (), {"returncode": 0, "stdout": "", "stderr": ""})()

            with patch("tools.asus_rom_analysis.subprocess.run", side_effect=fake_run):
                return _decompress_efi_stream(envelope, len(output), Path("fake-tianocompress"), 0x8664)

        invalid = run_fake_decompressor(b"not a PE")
        self.assertEqual(invalid["status"], "decompressed_output_not_valid_pe")

        pe = bytearray(0x200)
        pe[:2] = b"MZ"
        put_u32(pe, 0x3C, 0x80)
        pe[0x80:0x84] = b"PE\x00\x00"
        struct.pack_into("<HHIIIHH", pe, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
        optional = 0x98
        put_u16(pe, optional, 0x20B)
        struct.pack_into("<I", pe, optional + 16, 0x1000)
        struct.pack_into("<I", pe, optional + 56, 0x2000)
        struct.pack_into("<I", pe, optional + 60, 0x200)
        put_u16(pe, optional + 68, 11)
        struct.pack_into("<I", pe, optional + 108, 16)
        truncated = bytes(pe[:0x194])
        result = run_fake_decompressor(truncated)
        self.assertEqual(result["status"], "decompressed_pe_validation_warning")
        self.assertFalse(result["pe_validation"]["section_table_complete"])
        self.assertFalse(result["pe_validation"]["structurally_warning_free"])

    def test_decompressed_gop_pe_gets_bounded_authenticode_digest_analysis(self) -> None:
        output = bytearray(0x248)
        output[:2] = b"MZ"
        put_u32(output, 0x3C, 0x80)
        output[0x80:0x84] = b"PE\x00\x00"
        struct.pack_into("<HHIIIHH", output, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
        optional = 0x98
        put_u16(output, optional, 0x20B)
        struct.pack_into("<I", output, optional + 16, 0x1000)
        struct.pack_into("<I", output, optional + 56, 0x2000)
        struct.pack_into("<I", output, optional + 60, 0x200)
        put_u16(output, optional + 68, 11)
        struct.pack_into("<I", output, optional + 108, 16)
        struct.pack_into("<II", output, optional + 112 + 4 * 8, 0x220, 0x28)
        section = optional + 0xF0
        output[section : section + 8] = b".text\x00\x00\x00"
        struct.pack_into("<IIII", output, section + 8, 0x20, 0x1000, 0x20, 0x200)
        struct.pack_into("<I", output, section + 36, 0x60000020)
        output[0x200:0x220] = bytes(range(0x20))
        output[0x220:0x248] = struct.pack("<IHH", 0x28, 0x0200, 2) + bytes(0x20)

        first_parse = _parse_pe_header(bytes(output))
        digest = _authenticode_sha256_analysis(bytes(output), first_parse)["candidate_image_digest"]
        output[0x228:0x248] = bytes.fromhex(digest)
        envelope = struct.pack("<II", 1, len(output)) + b"\x00"

        def fake_run(command, **kwargs):
            if len(command) > 1 and command[1] == "version":
                return type("Process", (), {"returncode": 0, "stdout": "OpenSSL test", "stderr": ""})()
            if len(command) > 1 and command[1] == "smime":
                return type("Process", (), {"returncode": 1, "stdout": "", "stderr": "synthetic PKCS#7 fixture"})()
            Path(command[command.index("-o") + 1]).write_bytes(output)
            return type("Process", (), {"returncode": 0, "stdout": "", "stderr": ""})()

        with patch("tools.asus_rom_analysis.subprocess.run", side_effect=fake_run):
            result = _decompress_efi_stream(envelope, len(output), Path("fake-tianocompress"), 0x8664)

        authenticode = result["authenticode_sha256_analysis"]
        self.assertEqual(result["status"], "decompressed_pe_validated")
        self.assertEqual(authenticode["status"], "computed")
        self.assertEqual(authenticode["candidate_image_digest"], digest)
        self.assertEqual(authenticode["extra_data_range"]["length"], 0)
        self.assertTrue(authenticode["candidate_digest_occurs_in_pkcs_signed_data_record"])

    def test_xfx_comparison_is_bounded_and_keeps_card_conclusions_separate(self) -> None:
        package = ASUS_DIR / "AI-PRO-R9700.zip"
        as04 = ASUS_DIR / "payloads" / "7551OG.23.8.0.68.AS04.rom"
        as07 = ASUS_DIR / "payloads" / "7551OG.23.8.0.68.AS07.rom"
        xfx = REPOSITORY_ROOT / "bios" / "xfx-r9700-0000-03-00-0" / "original" / "stock-software-read1.rom"
        report = analyze_asus(package, as04, as07, xfx_path=xfx)

        comparison = report["xfx_comparison"]
        self.assertEqual(comparison["status"], "compared")
        self.assertTrue(comparison["asus_findings_are_not_transferred"])
        self.assertEqual(comparison["sample"]["artifact_type"], "driver-loaded software VBIOS capture")
        self.assertEqual(len(comparison["aligned_images"]), 2)
        first = comparison["aligned_images"][0]
        xfx_accounting = comparison["xfx_rom_structure"]["region_accounting"]
        self.assertEqual(sum(xfx_accounting["totals_bytes"].values()), xfx_accounting["size_bytes"])
        self.assertEqual(xfx_accounting["regions"][0]["start"], 0)
        self.assertEqual(xfx_accounting["regions"][-1]["end"], xfx_accounting["size_bytes"])
        self.assertTrue(first["same_declared_length"])
        self.assertEqual(first["aligned_length_bytes"], 58880)
        self.assertEqual(first["changed_byte_count"], 591)
        self.assertEqual(first["changed_range_count"], 136)
        states = [item["status"] for item in first["atom_table_comparisons"]]
        self.assertEqual(states.count("identical_bytes"), 13)
        self.assertEqual(states.count("same_revision_different_bytes"), 6)

    def test_truncated_file_is_accounted_without_dereferencing_out_of_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "truncated.rom"
            path.write_bytes(b"\x55\xaa")
            report = analyze_rom(path)

        self.assertEqual(report["pcir_images"], [])
        self.assertEqual(report["atom_tables"], [])
        self.assertEqual(report["region_accounting"]["totals_bytes"]["opaque"], 2)
        self.assertTrue(report["triage_warnings"])

    def test_unsupported_atom_header_revision_is_identified_but_not_decoded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "unsupported.rom"
            path.write_bytes(make_rom(atom_format_revision=3))
            report = analyze_rom(path)

        atom_header = next(item for item in report["atom_tables"] if item["table_id"] == "ATOM_ROM_HEADER")
        self.assertEqual(atom_header["format_revision"], 3)
        self.assertEqual(atom_header["classification"], "identified_but_undecoded")
        self.assertIn(
            "atom_rom_header_format_unsupported",
            {warning["code"] for warning in report["triage_warnings"]},
        )
        pointer_region = next(
            region
            for region in report["region_accounting"]["regions"]
            if region["start"] <= 0xA0 < region["end"]
        )
        self.assertEqual(pointer_region["status"], "identified_but_undecoded")
        self.assertEqual(sum(report["region_accounting"]["totals_bytes"].values()), 512)

    def test_unsupported_master_table_revision_is_not_decoded_as_v21(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "unsupported-master.rom"
            path.write_bytes(make_rom(master_format_revision=3, master_content_revision=1))
            report = analyze_rom(path)

        master = next(item for item in report["atom_tables"] if item["kind"] == "master_data_table")
        self.assertEqual(master["classification"], "identified_but_undecoded")
        self.assertEqual(report["atom_master_pointers"], [])
        body_region = next(
            region
            for region in report["region_accounting"]["regions"]
            if region["start"] <= 0xC4 < region["end"]
        )
        self.assertEqual(body_region["status"], "identified_but_undecoded")
        self.assertIn(
            "atom_master_data_table_revision_unsupported",
            {warning["code"] for warning in report["triage_warnings"]},
        )

    def test_cli_refuses_output_aliases_to_inputs_and_other_outputs(self) -> None:
        package = ASUS_DIR / "AI-PRO-R9700.zip"
        as04 = ASUS_DIR / "payloads" / "7551OG.23.8.0.68.AS04.rom"
        as07 = ASUS_DIR / "payloads" / "7551OG.23.8.0.68.AS07.rom"
        original_bytes = as04.read_bytes()

        with tempfile.TemporaryDirectory(dir=as04.parent) as temporary_directory:
            temporary = Path(temporary_directory)
            aliases = [temporary / "as04-hardlink.rom", temporary / "as04-symlink.rom"]
            os.link(as04, aliases[0])
            aliases[1].symlink_to(as04)
            for alias in aliases:
                with contextlib.redirect_stderr(io.StringIO()):
                    code = main(
                        [
                            "--package", str(package), "--as04", str(as04), "--as07", str(as07),
                            "--json-output", str(alias),
                        ]
                    )
                self.assertEqual(code, 2)
                self.assertEqual(as04.read_bytes(), original_bytes)

            same_output = temporary / "same-output"
            with contextlib.redirect_stderr(io.StringIO()):
                code = main(
                    [
                        "--package", str(package), "--as04", str(as04), "--as07", str(as07),
                        "--json-output", str(same_output), "--markdown-output", str(same_output),
                    ]
                )
            self.assertEqual(code, 2)
            self.assertFalse(same_output.exists())

    def test_cli_rejects_package_specific_markdown_for_unexpected_hashes(self) -> None:
        package = ASUS_DIR / "AI-PRO-R9700.zip"
        as04 = ASUS_DIR / "payloads" / "7551OG.23.8.0.68.AS04.rom"
        as07 = ASUS_DIR / "payloads" / "7551OG.23.8.0.68.AS07.rom"

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            altered_as04 = temporary / "altered.rom"
            altered_bytes = bytearray(as04.read_bytes())
            altered_bytes[0] ^= 1
            altered_as04.write_bytes(altered_bytes)
            output = temporary / "report.md"
            with contextlib.redirect_stderr(io.StringIO()):
                code = main(
                    [
                        "--package", str(package), "--as04", str(altered_as04), "--as07", str(as07),
                        "--markdown-output", str(output),
                    ]
                )
            self.assertEqual(code, 2)
            self.assertFalse(output.exists())

    def test_cli_json_only_output_completes_without_markdown(self) -> None:
        package = ASUS_DIR / "AI-PRO-R9700.zip"
        as04 = ASUS_DIR / "payloads" / "7551OG.23.8.0.68.AS04.rom"
        as07 = ASUS_DIR / "payloads" / "7551OG.23.8.0.68.AS07.rom"

        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "analysis.json"
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(
                    [
                        "--package", str(package), "--as04", str(as04), "--as07", str(as07),
                        "--json-output", str(output),
                    ]
                )
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["schema_version"], 5)


if __name__ == "__main__":
    unittest.main()
