import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from tools.pe_resources import PEError, extract_archive, resources


def fixture():
    data = bytearray(0x600)
    data[:2] = b'MZ'; struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<H', data, 0x86, 1)
    struct.pack_into('<H', data, 0x94, 0xf0)
    opt = 0x98; struct.pack_into('<H', data, opt, 0x20b)
    struct.pack_into('<I', data, opt + 108, 16)
    struct.pack_into('<II', data, opt + 112 + 16, 0x1000, 0x100)
    sec = opt + 0xf0
    struct.pack_into('<IIII', data, sec + 8, 0x400, 0x1000, 0x400, 0x200)
    # Three directories: type 1001, id 104, language 1033.
    for relative, key, target in [(0, 1001, 0x80000020), (0x20, 104, 0x80000040),
                                   (0x40, 1033, 0x60)]:
        struct.pack_into('<HH', data, 0x200 + relative + 12, 0, 1)
        struct.pack_into('<II', data, 0x200 + relative + 16, key, target)
    struct.pack_into('<IIII', data, 0x260, 0x1080, 4, 0, 0)
    data[0x280:0x284] = b'MZxx'
    return data


class ResourceTests(unittest.TestCase):
    def test_resource_bounds_and_identity(self):
        data = fixture(); leaf, = resources(data)
        self.assertEqual(leaf['resource'], [1001, 104, 1033])
        self.assertEqual(leaf['file_offset'], 0x280)
        self.assertEqual(leaf['sha256'], hashlib.sha256(b'MZxx').hexdigest())

    def test_malformed(self):
        cases = [b'', b'MZ', fixture()[:0x250]]
        for off, value in [(0x3c, 0xffffffff), (0x214, 0x80000000),
                           (0x260, 0xfffffff0), (0x264, 0xffffffff),
                           (0x264, 0), (0x214, 0x80001000)]:
            b = fixture(); struct.pack_into('<I', b, off, value); cases.append(b)
        for data in cases:
            with self.subTest(size=len(data)), self.assertRaises(PEError): resources(data)

    def test_provenance_and_no_clobber(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); package = root / 'p.zip'; out = root / 'out'
            with zipfile.ZipFile(package, 'w') as z: z.writestr('../../unsafe.exe', fixture())
            result = extract_archive(package, out)
            self.assertEqual(result['package_sha256'], hashlib.sha256(package.read_bytes()).hexdigest())
            self.assertEqual(result['members'][0]['sha256'], hashlib.sha256(fixture()).hexdigest())
            self.assertEqual((out / 'member-0-resource-0.bin').read_bytes(), b'MZxx')
            self.assertFalse((root.parent / 'unsafe.exe').exists())
            with self.assertRaises(FileExistsError): extract_archive(package, out)
            self.assertEqual(json.loads((out / 'provenance.json').read_text()), result)

    def test_alias_payloads_count_toward_aggregate_limit(self):
        data = fixture()
        struct.pack_into('<HH', data, 0x24c, 0, 2)
        struct.pack_into('<II', data, 0x258, 1034, 0x70)
        struct.pack_into('<IIII', data, 0x270, 0x1080, 4, 0, 0)
        self.assertEqual(len(resources(data)), 2)
        with self.assertRaisesRegex(PEError, 'aggregate resource'):
            resources(data, max_resource_bytes=7)

    def test_archive_count_limits_before_output(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); package = root / 'p.zip'
            with zipfile.ZipFile(package, 'w') as z:
                z.writestr('a.exe', fixture()); z.writestr('b.exe', fixture())
            with patch('tools.pe_resources.MAX_MEMBERS', 1):
                with self.assertRaisesRegex(PEError, 'member count'):
                    extract_archive(package, root / 'out')
            with patch('tools.pe_resources.MAX_RESOURCES', 1):
                with self.assertRaisesRegex(PEError, 'archive resource count'):
                    extract_archive(package, root / 'out')
            self.assertFalse((root / 'out').exists())

    def test_retained_executable_resource_provenance(self):
        root = Path(__file__).resolve().parents[1]
        executable = root / 'flashing/amdvbflash_879_Moded_v2.1.exe'
        data = executable.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(),
                         '7b84fdff600662d65e51523e8e5ead3f9b19c83756105f3d4269498f21b76258')
        driver, = [r for r in resources(data) if r['resource'] == [1001, 104, 1033]]
        self.assertEqual(driver['file_offset'], 0x85c460)
        self.assertEqual(driver['bytes'], 77264)
        self.assertEqual(driver['sha256'], 'd60f3196b722fb1600281d7891fd00ff451293cc5fbb2be752c1683affb3820a')


if __name__ == '__main__': unittest.main()
