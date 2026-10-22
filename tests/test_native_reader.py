"""Offline C reader tests. All acquisitions are synthetic and remain in .cache."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('native_build', ROOT / 'ports/r9700-reader/build.py')
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)
BDF = '0000:03:00.0'


def record(path):
    return dict(line.split('=', 1) for line in (path / 'acquisition.record').read_text().splitlines())


class NativeReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (ROOT / '.cache').mkdir(exist_ok=True)
        cls.workspace = tempfile.TemporaryDirectory(prefix='native-tests-', dir=ROOT / '.cache')
        cls.base = Path(cls.workspace.name)
        cls.manifest = BUILD.build(cls.base / 'build', bool(os.environ.get('R9700_SANITIZE')))
        cls.mock = cls.base / 'build/r9700-reader-mock'
        cls.native = cls.base / 'build/r9700-reader'
        cls.counter = 0

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def run_reader(self, *args, native=False):
        return subprocess.run([str(self.native if native else self.mock), *map(str, args)],
                              capture_output=True, text=True, timeout=40)

    def acquire(self, *extra):
        type(self).counter += 1
        path = self.base / f'acquisition-{self.counter}'
        result = self.run_reader('backup', '--bdf', BDF, '--output', path, *extra)
        return path, result

    def triple(self):
        paths = []
        for _ in range(3):
            path, r = self.acquire()
            self.assertEqual(r.returncode, 0, r.stderr)
            paths.append(path)
        return paths

    def test_plan_and_live_build_refuse_before_output(self):
        self.assertFalse(json.loads(self.run_reader('plan', native=True).stdout)['live_enabled'])
        p = self.base / 'must-not-exist'
        for args in [('identify', '--bdf', BDF), ('backup', '--bdf', BDF, '--output', p)]:
            r = self.run_reader(*args, native=True)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn('live-disabled', r.stderr)
        self.assertFalse(p.exists())
        self.assertNotEqual(self.run_reader('identify', '--bdf', BDF, '--capacity', '4', native=True).returncode, 0)

    def test_full_bdf_selection_and_legacy_rejection(self):
        for bdf in ['03:00.0', '0', '0000:0c:00.0', '0000:09:00.0', '0000:06:00.0', '0000:03:00.1']:
            self.assertNotEqual(self.run_reader('identify', '--bdf', bdf).returncode, 0)
        r = self.run_reader('identify', '--bdf', BDF)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)['bdf'], BDF)
        for args in [('-s', '0'), ('erase',), ('identify', '--bdf', BDF, '--force', '1'),
                     ('identify', '--bdf', BDF, '--bdf', BDF), ('identify', '--bdf', BDF, '--fixture', 'typo')]:
            self.assertNotEqual(self.run_reader(*args).returncode, 0)

    def test_large_image_coverage_hashes_and_build_provenance(self):
        path, r = self.acquire()
        self.assertEqual(r.returncode, 0, r.stderr)
        meta = record(path)
        data = (path / 'data.bin').read_bytes()
        self.assertGreater(len(data), 1024 * 1024)
        self.assertEqual(len(data), 2097164)
        for address in [0, 255, 65536, 1048576, len(data)-1]:
            self.assertEqual(data[address], (address ^ (address >> 8) ^ (address >> 16) ^ (address >> 24)) & 255)
        self.assertEqual(meta['sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(meta['build_sha256'], self.manifest['build_sha256'])
        self.assertEqual(meta['executable_sha256'], self.manifest['outputs']['r9700-reader-mock']['sha256'])
        self.assertEqual(meta['cleanup'], 'ok')
        self.assertEqual(meta['resources'], '0')
        self.assertEqual((path / 'coverage.tsv').read_text().splitlines()[-1], '2097152 12')

    def test_three_separate_sessions_verify_only_as_synthetic(self):
        paths = self.triple()
        r = self.run_reader('verify', '--synthetic', *paths, native=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(json.loads(r.stdout)['physical_backup_verified'])
        self.assertNotEqual(self.run_reader('verify', *paths).returncode, 0)
        self.assertNotEqual(self.run_reader('verify', '--synthetic', paths[0], paths[0], paths[0]).returncode, 0)

    def test_unknown_conflicting_geometry_and_overflow(self):
        for fixture in ['unknown', 'conflict', 'topology', 'identify']:
            with self.subTest(fixture=fixture):
                path, r = self.acquire('--fixture', fixture)
                self.assertNotEqual(r.returncode, 0)
                self.assertEqual((path / 'data.bin').stat().st_size, 0)
                self.assertEqual(record(path)['cleanup'], 'ok')
        for args in [('--capacity', '0'), ('--capacity', '18446744073709551615'),
                     ('--capacity', '18446744073709551616'), ('--capacity', '-1'),
                     ('--capacity', '2097163'), ('--alignment', '0'),
                     ('--alignment', '3'), ('--alignment', '131072')]:
            with self.subTest(args=args):
                _, r = self.acquire(*args)
                self.assertNotEqual(r.returncode, 0)

    def test_all_failure_edges_retain_partial_and_balance_resources(self):
        for fixture in ['init', 'read', 'timeout', 'cancel', 'identity', 'reset', 'short',
                        'oversized', 'cleanup', 'storage', 'sync', 'close']:
            with self.subTest(fixture=fixture):
                path, r = self.acquire('--fixture', fixture)
                self.assertNotEqual(r.returncode, 0, r.stdout)
                meta = record(path)
                self.assertEqual(meta['status'], 'failed')
                self.assertEqual(meta['resources'], '0')
                self.assertEqual(meta['cleanup'], 'failed' if fixture in ['cleanup', 'reset'] else 'ok')
                self.assertEqual(meta['sha256'], hashlib.sha256((path / 'data.bin').read_bytes()).hexdigest())
                if fixture in ['read', 'timeout', 'cancel', 'short', 'oversized']:
                    self.assertEqual((path / 'data.bin').stat().st_size, 65536)
                if fixture == 'storage':
                    self.assertEqual((path / 'data.bin').stat().st_size, 65536 + 4096)
                self.assertNotEqual(self.run_reader('verify', '--synthetic', path, path, path).returncode, 0)

    def test_unhandled_death_and_record_failure_remain_incomplete(self):
        for fixture in ['crash', 'record', 'record-sync']:
            path, r = self.acquire('--fixture', fixture)
            self.assertNotEqual(r.returncode, 0)
            self.assertEqual(record(path)['status'], 'complete' if fixture == 'record-sync' else 'incomplete')
            self.assertTrue((path / 'incomplete').exists())
            self.assertGreater((path / 'data.bin').stat().st_size, 0)
            self.assertNotEqual(self.run_reader('verify', '--synthetic', path, path, path).returncode, 0)

    def test_output_collision_never_changes_original(self):
        path, r = self.acquire()
        self.assertEqual(r.returncode, 0, r.stderr)
        before = {p.name: p.read_bytes() for p in path.iterdir()}
        r = self.run_reader('backup', '--bdf', BDF, '--output', path)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(before, {p.name: p.read_bytes() for p in path.iterdir()})
        symlink = self.base / 'output-symlink'; symlink.symlink_to(path, target_is_directory=True)
        self.assertNotEqual(self.run_reader('backup', '--bdf', BDF, '--output', symlink).returncode, 0)

    def test_storage_creation_failure_is_retained(self):
        # A regular file in the parent position must fail before any transport call.
        parent = self.base / 'regular-parent'; parent.write_text('sentinel')
        r = self.run_reader('backup', '--bdf', BDF, '--output', parent / 'child')
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(parent.read_text(), 'sentinel')

    def test_verifier_rejects_data_ledger_and_metadata_corruption(self):
        paths = self.triple(); p = paths[0]
        image = (p / 'data.bin').read_bytes()
        (p / 'data.bin').write_bytes(image[:-1])
        self.assertNotEqual(self.run_reader('verify', '--synthetic', *paths).returncode, 0)
        (p / 'data.bin').write_bytes(image)
        original = (p / 'acquisition.record').read_text()
        for old, new in [('classification=synthetic', 'classification=physical'),
                         ('capacity=2097164', 'capacity=18446744073709551616'),
                         ('cleanup=ok', 'cleanup=failed'), ('resources=0', 'resources=1'),
                         ('topology=synthetic-one-bank', 'topology=unknown'),
                         ('schema=r9700-reader-v1', 'schema=unknown')]:
            (p / 'acquisition.record').write_text(original.replace(old, new))
            self.assertNotEqual(self.run_reader('verify', '--synthetic', *paths).returncode, 0)
        for content in [original + 'extra=1\n', original[:-1], original.replace('status=complete', 'status=comp\x00lete')]:
            (p / 'acquisition.record').write_text(content)
            self.assertNotEqual(self.run_reader('verify', '--synthetic', *paths).returncode, 0)
        (p / 'acquisition.record').write_text(original)
        ledger = (p / 'coverage.tsv').read_text()
        # Even updating the ledger hash must not hide gaps, overlaps or overflow.
        for content in [ledger.replace('65536 65536', '65540 65536', 1),
                        ledger.replace('65536 65536', '0 65536', 1),
                        ledger.replace('65536 65536', '18446744073709551615 65536', 1),
                        ledger.replace('65536 65536', '18446744073709551616 65536', 1),
                        ledger.replace('65536 65536', '9' * 200 + ' 65536', 1)]:
            (p / 'coverage.tsv').write_text(content)
            meta = original.replace(hashlib.sha256(ledger.encode()).hexdigest(), hashlib.sha256(content.encode()).hexdigest())
            (p / 'acquisition.record').write_text(meta)
            self.assertNotEqual(self.run_reader('verify', '--synthetic', *paths).returncode, 0)

    def test_verifier_rejects_fifo_and_symlink_without_blocking(self):
        paths = self.triple(); p = paths[0]
        (p / 'data.bin').unlink(); os.mkfifo(p / 'data.bin')
        self.assertNotEqual(self.run_reader('verify', '--synthetic', *paths).returncode, 0)
        (p / 'data.bin').unlink(); (p / 'data.bin').symlink_to(paths[1] / 'data.bin')
        self.assertNotEqual(self.run_reader('verify', '--synthetic', *paths).returncode, 0)

    def test_pure_window_alignment_and_checked_bounds(self):
        source = self.base / 'window-test.c'
        source.write_text('''#include "reader.h"
#include <assert.h>
#include <stdint.h>
int main(void) {
 struct geometry g={2097164,4,65536,1,1}; uint64_t s; size_t w,k,u;
 assert(!read_window(&g,1,1,&s,&w,&k,&u) && s==0 && w==4 && k==1 && u==1);
 assert(!read_window(&g,3,65536,&s,&w,&k,&u) && s==0 && w==65536 && k==3 && u==65533);
 assert(!read_window(&g,2097163,1,&s,&w,&k,&u) && s==2097160 && w==4 && k==3 && u==1);
 assert(read_window(&g,UINT64_MAX,1,&s,&w,&k,&u));
 assert(read_window(&g,1,UINT64_MAX,&s,&w,&k,&u));
 assert(read_window(&g,2097164,1,&s,&w,&k,&u));
 assert(read_window(&g,0,0,&s,&w,&k,&u));
 return 0;
}''')
        exe = self.base / 'window-test'
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-I', str(ROOT / 'ports/r9700-reader'), str(source),
                        str(ROOT / 'ports/r9700-reader/window.c'), '-o', str(exe)], check=True)
        subprocess.run([str(exe)], check=True)


if __name__ == '__main__':
    unittest.main()
