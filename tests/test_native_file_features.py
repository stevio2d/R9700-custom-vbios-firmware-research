"""Recovered Windows algorithms on independent byte vectors and retained images."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('native_file_build', ROOT / 'ports/r9700-reader/build.py')
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)
ASUS = ROOT / 'bios/vendor-packages/asus/payloads/7551OG.23.8.0.68.AS04.rom'
XFX = ROOT / 'bios/xfx-r9700-0000-03-00-0/original/stock-software-read1.rom'


def legacy(pn=b'113-TEST01-EXTRA'):
    data = bytearray(512)
    data[:3] = b'\x55\xaa\x01'
    struct.pack_into('<H', data, 0x18, 0x100)
    data[0x100:0x104] = b'PCIR'
    struct.pack_into('<HH', data, 0x104, 0x1002, 0x7551)
    struct.pack_into('<H', data, 0x10a, 0x16)
    struct.pack_into('<H', data, 0x110, 1)
    data[0x115] = 0x80
    struct.pack_into('<H', data, 0x48, 0x180)
    struct.pack_into('<H', data, 0x180, 0x22)
    data[0x182:0x188] = b'\x02\x02ATOM'
    struct.pack_into('<H', data, 0x18c, 0xc0)
    struct.pack_into('<H', data, 0x6e, 0x70)
    data[0x70:0x70+len(pn)+1] = pn + b'\0'
    return data


class NativeFileFeaturesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (ROOT / '.cache').mkdir(exist_ok=True)
        cls.tmp = tempfile.TemporaryDirectory(prefix='native-files-', dir=ROOT / '.cache')
        cls.base = Path(cls.tmp.name)
        BUILD.build(cls.base / 'build', bool(os.environ.get('R9700_SANITIZE')))
        cls.exe = cls.base / 'build/r9700-reader'

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_cli(self, *args):
        return subprocess.run([str(self.exe), *map(str, args)], capture_output=True, text=True, timeout=10)

    def check_sum(self, path, scope, offset, length, *args):
        before = path.read_bytes()
        result = self.run_cli('checksum', '--file', path, '--scope', scope, *args)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        selected = before[offset:offset+length]
        self.assertEqual(report['offset'], offset)
        self.assertEqual(report['length'], length)
        self.assertEqual(report['checksum'], sum(selected) % 65536)
        self.assertEqual(report['sha256'], hashlib.sha256(selected).hexdigest())
        self.assertEqual(path.read_bytes(), before)
        return report

    def test_checksum_independent_vectors_wrapping_and_odd_tails(self):
        path = self.base / 'vector'
        for data in [b'', b'\x01\x02\x03', b'\xff' * 65537, bytes(range(256)) * 1025 + b'\x7f']:
            path.write_bytes(data)
            self.check_sum(path, 'complete', 0, len(data))
        data = path.read_bytes()
        self.check_sum(path, 'region', 1, 65539, '--offset', 1, '--length', 65539)
        expected = sum(data) & 65535
        self.assertEqual(self.run_cli('checksum', '--file', path, '--scope', 'complete', '--expect', expected).returncode, 0)
        result = self.run_cli('checksum', '--file', path, '--scope', 'complete', '--expect', expected ^ 1)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(json.loads(result.stdout)['matches_expected'])

    def test_retained_ifwi_ranges_match_recovered_file_and_rom_semantics(self):
        # Independent offsets from the retained ASUS payload, not CLI parsing.
        self.check_sum(ASUS, 'windows-file', 0x40000, 0xaa * 512)
        self.check_sum(ASUS, 'vbios', 0x40000, 0x73 * 512)
        self.check_sum(ASUS, 'rom-default', 0x40000, 65536)
        self.check_sum(ASUS, 'vbios', 0x120000, 0x73 * 512, '--slot', 1)
        self.check_sum(ASUS, 'complete', 0, ASUS.stat().st_size)
        self.check_sum(XFX, 'windows-file', 0, 58880)
        self.assertNotEqual(self.run_cli('checksum', '--file', XFX, '--scope', 'rom-default').returncode, 0)

    def test_inspect_actual_ifwi_and_software_vbios_without_boot_claims(self):
        for path, count in [(ASUS, 2), (XFX, 1)]:
            result = self.run_cli('inspect', '--file', path)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertFalse(report['physical_backup_verified'])
            self.assertIsNone(report['active_partition'])
            self.assertIsNone(report['running_firmware_versions'])
            self.assertEqual(len(report['slots']), count)
            for slot in report['slots']:
                self.assertEqual(slot['vendor'], 0x1002)
                self.assertEqual(slot['device'], 0x7551)
                self.assertEqual(slot['part_number'], '115-G287BP00-100' if path == ASUS else '113-48WD6SHD1-P02')

    def test_inventory_is_historical_and_lists_all_four_actual_bdfs(self):
        result = self.run_cli('list')
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual([d['bdf'] for d in report['devices']], ['0000:03:00.0', '0000:06:00.0', '0000:83:00.0', '0000:86:00.0'])
        self.assertFalse(report['live_refreshed'])
        self.assertEqual(report['source_sha256'], hashlib.sha256((ROOT / report['source']).read_bytes()).hexdigest())
        for device in report['devices']:
            info = self.run_cli('info', '--bdf', device['bdf'])
            self.assertEqual(info.returncode, 0, info.stderr)
            self.assertIsNone(json.loads(info.stdout)['active_partition'])
        self.assertNotEqual(self.run_cli('info', '--bdf', '03:00.0').returncode, 0)
        self.assertNotEqual(self.run_cli('list', '--identify').returncode, 0)

    def test_prefix_ten_part_number_comparison_and_case(self):
        a, b = self.base / 'pn-a', self.base / 'pn-b'
        a.write_bytes(legacy(b'113-ABCDEF-ONE'))
        b.write_bytes(legacy(b'113-abcdef-TWO'))
        def compare():
            return self.run_cli('compare', '--kind', 'part-number', '--left', a, '--right', b)
        result = compare()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)['equal'])
        b.write_bytes(legacy(b'113-XBCDEF-ONE'))
        self.assertEqual(compare().returncode, 1)
        b.write_bytes(legacy(b'113'))
        self.assertEqual(compare().returncode, 1)
        b.write_bytes(legacy(b''))
        self.assertEqual(compare().returncode, 1)
        b.write_bytes(legacy(b'\xff'))
        self.assertEqual(compare().returncode, 1)

    def test_partition_comparison_hashes_exact_slot_range(self):
        result = self.run_cli('compare', '--kind', 'partition', '--left', ASUS, '--right', ASUS, '--left-slot', 1, '--right-slot', 1)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['left_offset'], 0x100000)
        self.assertEqual(report['left_length'], 0xe0000)
        self.assertEqual(report['left_sha256'], hashlib.sha256(ASUS.read_bytes()[0x100000:0x1e0000]).hexdigest())
        self.assertIsNone(report['active_partition'])
        changed = self.base / 'partition-changed'
        data = bytearray(ASUS.read_bytes()); data[0x100100] ^= 1
        changed.write_bytes(data)
        self.assertEqual(self.run_cli('compare', '--kind', 'partition', '--left', ASUS, '--right', changed, '--left-slot', 1, '--right-slot', 1).returncode, 1)
        self.assertNotEqual(self.run_cli('compare', '--kind', 'partition', '--left', XFX, '--right', XFX).returncode, 0)

    def test_malformed_layouts_and_region_bounds(self):
        path = self.base / 'malformed'
        original = ASUS.read_bytes()
        variants = [b'', b'\x55\xaa', bytes(512), original[:0x13010]]
        for at, fmt, value in [(0x14, '<I', 0xffffffff), (0x2008, '<I', 0xffffffff),
                               (0x2018, '<Q', 0xffffffffffffffff), (0x12018, '<I', 0xffffffff),
                               (0x13010, '<I', 0x20000), (0x1201c, '<I', 0x100),
                               (0x40018, '<H', 0xffff), (0x4019c, '<H', 0xffff)]:
            data = bytearray(original); struct.pack_into(fmt, data, at, value); variants.append(data)
        for data in variants:
            path.write_bytes(data)
            self.assertNotEqual(self.run_cli('inspect', '--file', path).returncode, 0)
        path.write_bytes(b'1234')
        for args in [('--offset', 1, '--length', 4), ('--offset', 0, '--length', 0),
                     ('--offset', '18446744073709551616', '--length', 1),
                     ('--offset', '18446744073709551615', '--length', 1),
                     ('--offset', 0, '--length', 1, '--slot', 0)]:
            self.assertNotEqual(self.run_cli('checksum', '--file', path, '--scope', 'region', *args).returncode, 0)

    def test_nonregular_and_duplicate_arguments_fail_without_blocking(self):
        fifo = self.base / 'fifo'; os.mkfifo(fifo)
        link = self.base / 'symlink'; link.symlink_to(XFX)
        for p in [fifo, link, self.base, self.base / 'missing']:
            self.assertNotEqual(self.run_cli('checksum', '--file', p, '--scope', 'complete').returncode, 0)
        for args in [('inspect', '--file', XFX, '--file', XFX),
                     ('checksum', '--file', XFX, '--scope', 'complete', '--slot', 0),
                     ('checksum', '--file', XFX, '--expect', 65536),
                     ('compare', '--kind', 'partition', '--left', ASUS, '--left', ASUS, '--right', ASUS)]:
            self.assertNotEqual(self.run_cli(*args).returncode, 0)

    def test_unterminated_or_out_of_image_message_rejected(self):
        a, b = self.base / 'message-a', self.base / 'message-b'
        a.write_bytes(legacy())
        for message_end, message_start in [(0x70, 0x70), (0xffff, 0x70), (0xc0, 0xffff), (0xc0, 0x70)]:
            data = legacy()
            struct.pack_into('<H', data, 0x6e, message_start)
            struct.pack_into('<H', data, 0x18c, message_end)
            if message_start == 0x70 and message_end == 0xc0:
                data[0x70:0xc0] = b'A' * 0x50
            b.write_bytes(data)
            result = self.run_cli('compare', '--kind', 'part-number', '--left', a, '--right', b)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, '')

    def test_changed_file_detection_and_bounded_pread(self):
        # Exercise the shared reader directly for a deterministic mutation,
        # avoiding a timing-dependent subprocess race.
        source = self.base / 'changed-file.c'
        source.write_text('''#include "image.h"
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
int main(int argc, char **argv) {
 (void)argc; struct image_file f; unsigned char b[4];
 assert(!image_open(&f,argv[1]));
 assert(!image_read(&f,0,b,4));
 assert(image_read(&f,UINT64_MAX,b,4));
 int out = open(argv[1],O_WRONLY|O_TRUNC); assert(out>=0);
 assert(write(out,"x",1)==1); assert(!close(out));
 assert(image_stable(&f)); assert(image_read(&f,0,b,4));
 assert(!close(f.fd)); return 0;
}''')
        path = self.base / 'changing-input'; path.write_bytes(b'1234')
        exe = self.base / 'changed-file'
        flags = ['-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie'] if os.environ.get('R9700_SANITIZE') else []
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', *flags,
                        '-I', str(ROOT / 'ports/r9700-reader'), str(source),
                        str(ROOT / 'ports/r9700-reader/image.c'),
                        str(ROOT / 'ports/r9700-reader/record.c'), '-lcrypto', '-o', str(exe)], check=True)
        subprocess.run([str(exe), str(path)], check=True, timeout=10)
