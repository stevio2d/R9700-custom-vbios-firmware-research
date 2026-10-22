import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools.rom_triage import analyze_bytes


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CLI_PATH = REPOSITORY_ROOT / "tools" / "rom_triage.py"


def put_u16(data: bytearray, offset: int, value: int) -> None:
    data[offset : offset + 2] = value.to_bytes(2, "little")


def make_rom(
    *,
    last_image: bool = True,
    malformed_data_pointer: bool = False,
    code_type: int = 0,
) -> bytes:
    data = bytearray(512)
    data[0:2] = b"\x55\xaa"
    data[2] = 1
    put_u16(data, 0x18, 0x20)

    pcir = 0x20
    data[pcir : pcir + 4] = b"PCIR"
    put_u16(data, pcir + 4, 0x1002)
    put_u16(data, pcir + 6, 0x7551)
    put_u16(data, pcir + 0x0A, 0x18)
    put_u16(data, pcir + 0x10, 1)
    data[pcir + 0x14] = code_type
    data[pcir + 0x15] = 0x80 if last_image else 0

    put_u16(data, 0x48, 0x80)
    atom = 0x80
    put_u16(data, atom, 0x22)
    data[atom + 2] = 2
    data[atom + 3] = 2
    data[atom + 4 : atom + 8] = b"ATOM"
    put_u16(data, atom + 0x20, 0xC0)

    master = 0xC0
    put_u16(data, master, 4 + 35 * 2)
    data[master + 2] = 2
    data[master + 3] = 1
    firmware_info = 0x120
    pointer = 0xFFFF if malformed_data_pointer else firmware_info
    put_u16(data, master + 4 + 4 * 2, pointer)
    if not malformed_data_pointer:
        put_u16(data, firmware_info, 8)
        data[firmware_info + 2] = 3
        data[firmware_info + 3] = 5

    data[-1] = (-sum(data[:-1])) & 0xFF
    return bytes(data)


def warning_codes(report: dict) -> set[str]:
    return {warning["code"] for warning in report["warnings"]}


class RomTriageTests(unittest.TestCase):
    def test_valid_rom_reports_pcir_and_atom_tables(self) -> None:
        report = analyze_bytes(make_rom())

        self.assertEqual(report["size_bytes"], 512)
        self.assertEqual(len(report["pcir_images"]), 1)
        self.assertTrue(
            report["pcir_images"][0]["checksum"]["legacy_header_checksum"]["valid"]
        )
        self.assertEqual(report["pcir_images"][0]["vendor_id"], 0x1002)
        firmware = [table for table in report["atom_tables"] if table["table_id"] == "firmware_info"]
        self.assertEqual(len(firmware), 1)
        self.assertEqual(firmware[0]["offset"], 0x120)
        self.assertEqual(firmware[0]["length"], 8)
        self.assertEqual(firmware[0]["format_revision"], 3)
        self.assertEqual(report["warnings"], [])

    def test_multiple_chained_images_are_bounded_independently(self) -> None:
        report = analyze_bytes(make_rom(last_image=False) + make_rom(last_image=True))

        self.assertEqual(len(report["pcir_images"]), 2)
        self.assertEqual([image["offset"] for image in report["pcir_images"]], [0, 512])
        self.assertEqual(
            [table["offset"] for table in report["atom_tables"] if table["table_id"] == "ATOM_ROM_HEADER"],
            [0x80, 512 + 0x80],
        )
        self.assertNotIn("rom_chain_signature_missing", warning_codes(report))

    def test_embedded_rom_chain_is_found_after_non_rom_prefix(self) -> None:
        report = analyze_bytes(b"container".ljust(512, b"\x00") + make_rom())

        self.assertEqual(len(report["pcir_images"]), 1)
        self.assertEqual(report["pcir_images"][0]["offset"], 512)
        self.assertTrue(any(table["table_id"] == "firmware_info" for table in report["atom_tables"]))

    def test_embedded_rom_with_length_mismatch_is_still_discovered(self) -> None:
        rom = bytearray(make_rom())
        rom.extend(b"\x01" + bytes(511))
        put_u16(rom, 0x20 + 0x10, 2)
        rom[511] = (-sum(rom[:511])) & 0xFF

        report = analyze_bytes(bytes(512) + bytes(rom))

        self.assertEqual(len(report["pcir_images"]), 1)
        image = report["pcir_images"][0]
        self.assertEqual(image["offset"], 512)
        self.assertIn("rom_length_mismatch", warning_codes(report))
        self.assertTrue(image["checksum"]["legacy_header_checksum"]["valid"])
        self.assertEqual(image["checksum"]["pcir_image_sum_mod_256"], 1)

    def test_efi_image_byte_sum_is_reported_without_legacy_validity_claim(self) -> None:
        report = analyze_bytes(make_rom(code_type=3))

        self.assertEqual(report["pcir_images"][0]["code_type"], 3)
        self.assertIsNone(
            report["pcir_images"][0]["checksum"]["legacy_header_checksum"]
        )
        self.assertNotIn("legacy_header_checksum_invalid", warning_codes(report))
        self.assertEqual(report["atom_tables"], [])

    def test_unknown_code_type_does_not_interpret_reserved_header_size(self) -> None:
        data = bytearray(make_rom(code_type=4))
        data[2] = 0

        report = analyze_bytes(bytes(data))
        image = report["pcir_images"][0]

        self.assertIsNone(image["header_length_512_byte_units"])
        self.assertIsNone(image["header_length_bytes"])
        self.assertIsNone(image["checksum"]["legacy_header_checksum"])
        self.assertNotIn("rom_length_mismatch", warning_codes(report))

    def test_truncated_pcir_and_image_return_warnings(self) -> None:
        truncated = bytearray(70)
        truncated[0:2] = b"\x55\xaa"
        truncated[2] = 1
        put_u16(truncated, 0x18, 0x20)
        truncated[0x20:0x24] = b"PCIR"
        put_u16(truncated, 0x20 + 0x0A, 0x18)
        put_u16(truncated, 0x20 + 0x10, 1)
        truncated[0x20 + 0x15] = 0x80

        report = analyze_bytes(bytes(truncated))

        self.assertIn("rom_image_exceeds_file", warning_codes(report))
        self.assertIsNone(report["pcir_images"][0]["checksum"])
        self.assertEqual(report["pcir_images"][0]["available_length_bytes"], 70)

    def test_malformed_atom_header_pointer_is_reported(self) -> None:
        data = bytearray(make_rom())
        put_u16(data, 0x48, 0x1FF)
        data[-1] = 0
        data[-1] = (-sum(data[:-1])) & 0xFF

        report = analyze_bytes(bytes(data))

        self.assertIn("atom_rom_header_out_of_bounds", warning_codes(report))
        self.assertEqual(report["atom_tables"], [])

    def test_malformed_atom_data_pointer_is_reported(self) -> None:
        report = analyze_bytes(make_rom(malformed_data_pointer=True))

        self.assertIn("atom_data_table_header_out_of_bounds", warning_codes(report))
        self.assertFalse(any(table["table_id"] == "firmware_info" for table in report["atom_tables"]))

    def test_bad_option_rom_checksum_is_reported(self) -> None:
        data = bytearray(make_rom())
        data[0x180] ^= 0x01

        report = analyze_bytes(bytes(data))

        self.assertFalse(
            report["pcir_images"][0]["checksum"]["legacy_header_checksum"]["valid"]
        )
        self.assertIn("legacy_header_checksum_invalid", warning_codes(report))

    def test_legacy_checksum_uses_header_range_when_pcir_image_sum_is_zero(self) -> None:
        data = bytearray(make_rom())
        data.extend(bytes(512))
        put_u16(data, 0x20 + 0x10, 2)
        data[0x180] ^= 0x01
        data[-1] = (-sum(data[:-1])) & 0xFF

        report = analyze_bytes(bytes(data))
        checksum = report["pcir_images"][0]["checksum"]

        self.assertEqual(checksum["pcir_image_sum_mod_256"], 0)
        self.assertEqual(checksum["legacy_header_checksum"]["sum_mod_256"], 2)
        self.assertFalse(checksum["legacy_header_checksum"]["valid"])
        self.assertIn("legacy_header_checksum_invalid", warning_codes(report))

    def test_non_rom_input_returns_json_ready_warning(self) -> None:
        report = analyze_bytes(b"not a ROM")

        self.assertEqual(report["pcir_images"], [])
        self.assertEqual(report["atom_tables"], [])
        self.assertIn("option_rom_signature_missing", warning_codes(report))
        json.dumps(report)

    def test_cli_emits_json_and_does_not_change_input(self) -> None:
        data = make_rom()
        with tempfile.TemporaryDirectory() as temporary_directory:
            image_path = Path(temporary_directory) / "fixture.rom"
            image_path.write_bytes(data)
            before = image_path.read_bytes()
            result = subprocess.run(
                [sys.executable, str(CLI_PATH), str(image_path)],
                check=True,
                capture_output=True,
                text=True,
            )

            report = json.loads(result.stdout)
            self.assertEqual(report["input_path"], str(image_path))
            self.assertEqual(image_path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
