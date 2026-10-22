import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import linux_spi_capture as c

BDF = '0000:03:00.0'
DATA = bytes(range(256)) * 4


def evidence():
    return {'schema_version': 1, 'device': {'bdf': BDF, 'identity': c.IDENTITY.copy(),
            'evidence': 'fixture'}, 'vbios': {'bytes': len(DATA), 'sha256': c.digest(DATA),
            'provenance': 'synthetic fixture; software VFCT blob'}, 'chip': None}


def chip():
    return {'part': 'synthetic', 'jedec_id': 'test-only', 'marking_evidence': 'fixture',
            'identification_evidence': 'fixture', 'datasheet_evidence': 'fixture',
            'capacity_bytes': len(DATA), 'address_bits': 24,
            'capacity_evidence': {'datasheet': len(DATA), 'identification': len(DATA)}}


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def fake_mapping(self, bdf):
        return {'identity': c.IDENTITY.copy(), 'pci_path': '/fixture/' + bdf,
                'drm_card': 'card3', 'drm_dev': '226:3',
                'debugfs_name': 'amdgpu dev=' + bdf, 'blob': '/fixture/amdgpu_vbios'}

    def acquire(self, name='read1', data=DATA, resolver=None):
        path = self.root / name
        stream = io.BytesIO(data)
        record = c.capture(evidence(), BDF, 'vbios', path,
                           resolver or self.fake_mapping, lambda p: stream)
        self.assertTrue(stream.closed)
        return path, record

    def test_bdf(self):
        self.assertEqual(c.bdf_value('FFFF:AF:1F.7'), 'ffff:af:1f.7')
        for bdf in ['03:00.0', '0000:03:20.0', '0000:03:00.8', '../0000:03:00.0',
                    '0000:3:00.0', '00000:03:00.0', '0000:03:00.0\n']:
            with self.subTest(bdf=bdf), self.assertRaises(c.CaptureError):
                c.bdf_value(bdf)

    def test_offline_paths_reject_pseudo_filesystems_before_open(self):
        with patch.object(Path, 'resolve', return_value=Path('/sys/kernel/debug/dri/0/psp_vbflash')):
            with patch.object(Path, 'read_text', side_effect=AssertionError('hardware read')):
                with self.assertRaises(c.CaptureError): c.load_json('/fixture/evidence.json')

    def test_plan_and_spi_never_resolve_or_open_hardware(self):
        ev = evidence()
        ev['chip'] = chip()
        ev['backend'] = {'enabled': True, 'id': 'user-supplied-claim'}
        with patch.object(c, 'resolve_vbios', side_effect=AssertionError('hardware')):
            result = c.plan(ev, BDF)
            self.assertFalse(result['hardware_accessed'])
            self.assertFalse(result['spi']['enabled'])
            with self.assertRaises(c.CaptureError):
                c.capture(ev, BDF, 'spi', self.root / 'spi',
                          resolver=lambda b: self.fail('SPI resolved hardware'),
                          opener=lambda p: self.fail('SPI emitted transaction'))
        self.assertFalse((self.root / 'spi').exists())

    def test_unsupported_identity_fails_before_resolution(self):
        ev = evidence(); ev['device']['identity']['device'] = 'ffff'
        with self.assertRaises(c.CaptureError):
            c.capture(ev, BDF, 'vbios', self.root / 'unsupported',
                      lambda b: self.fail('unsupported ASIC reached resolver'))
        self.assertFalse((self.root / 'unsupported').exists())

    def test_geometry_coverage_bounds(self):
        self.assertEqual(c.geometry(chip()), (len(DATA), 24))
        c.coverage(1024, 24, [[0, 512], [512, 1024]], 1024)
        for ch in [None, {}, dict(chip(), capacity_bytes=2048),
                   dict(chip(), address_bits=8), dict(chip(), capacity_bytes=True)]:
            with self.assertRaises(c.CaptureError): c.geometry(ch)
        for ranges, size in [([[0, 1023]], 1023), ([[1, 1024]], 1024),
                             ([[0, 1025]], 1025), ([[0, 600], [512, 1024]], 1024),
                             ([[0, 512], [513, 1024]], 1024), ([[0, 2**32]], 1024),
                             ([[0, 1024]], 1023), ([[False, 1024]], 1024)]:
            with self.subTest(ranges=ranges), self.assertRaises(c.CaptureError):
                c.coverage(1024, 24, ranges, size)

    def test_capture_repeats_classification_preservation(self):
        p, r = self.acquire()
        p2, r2 = self.acquire('read2')
        p3, r3 = self.acquire('read3')
        result = c.verify([p, p2, p3])
        self.assertTrue(result['valid'], result)
        self.assertTrue(result['matching_bytes'])
        self.assertFalse(result['full_chip_verified'])
        self.assertEqual({row['classification'] for row in result['acquisitions']}, {'software_dump'})
        before = (p / 'data.bin').read_bytes()
        with self.assertRaises(FileExistsError): self.acquire()
        self.assertEqual((p / 'data.bin').read_bytes(), before)
        self.assertFalse(c.verify([p, p])['valid'])

    def test_short_oversized_blank_changed(self):
        for i, data in enumerate([DATA[:-1], DATA + b'excess', b'\xff' * len(DATA), DATA[::-1]]):
            p, r = self.acquire(str(i), data)
            self.assertEqual(r['status'], 'failed')
            self.assertIn('error', r)
            self.assertEqual((p / 'data.bin').stat().st_size, min(len(data), len(DATA) + 1))
            self.assertFalse(c.verify([p])['valid'])

    def test_initialization_and_read_errors_close_stream_retain_partial(self):
        def broken(bdf): raise c.CaptureError('initialization failed')
        p = self.root / 'init'
        r = c.capture(evidence(), BDF, 'vbios', p, broken)
        self.assertEqual(r['status'], 'failed')
        self.assertFalse((p / 'data.bin').exists())
        class Failing(io.BytesIO):
            def read(self, n=-1):
                if self.tell(): raise OSError('injected read error')
                return super().read(32)
        stream = Failing(DATA)
        p = self.root / 'partial'
        r = c.capture(evidence(), BDF, 'vbios', p, self.fake_mapping, lambda p: stream)
        self.assertEqual(r['status'], 'failed')
        self.assertTrue(stream.closed)
        self.assertEqual((p / 'data.bin').read_bytes(), DATA[:32])

    def test_timeout_cleanup_and_mapping_change(self):
        class Timeout(io.BytesIO):
            def read(self, n=-1): raise c.CaptureError('capture exceeded timeout')
        stream = Timeout(DATA)
        r = c.capture(evidence(), BDF, 'vbios', self.root / 'timeout', self.fake_mapping, lambda p: stream)
        self.assertEqual(r['status'], 'failed')
        self.assertTrue(stream.closed)
        with patch.object(c.signal, 'getitimer', wraps=c.signal.getitimer):
            self.assertEqual(c.signal.getitimer(c.signal.ITIMER_REAL)[0], 0)
        calls = []
        def mapping(bdf):
            calls.append(1)
            return dict(self.fake_mapping(bdf), drm_card='card' + str(len(calls)))
        p, r = self.acquire('changed-mapping', resolver=mapping)
        self.assertEqual(r['status'], 'failed')
        self.assertIn('changed during', r['error'])

    def test_verify_tampering_and_partial_record(self):
        p, r = self.acquire()
        (p / 'data.bin').write_bytes(DATA[:-1] + b'x')
        self.assertFalse(c.verify([p])['valid'])
        (p / 'data.bin').write_bytes(DATA)
        r['image_type'] = 'full_spi'
        (p / 'acquisition.json').write_text(json.dumps(r))
        self.assertFalse(c.verify([p])['valid'])
        r['image_type'], r['status'] = 'software_dump', 'incomplete'
        (p / 'acquisition.json').write_text(json.dumps(r))
        self.assertFalse(c.verify([p])['valid'])

    def test_controller_output_never_promoted(self):
        paths = []
        for i in range(3):
            p, r = self.acquire(str(i))
            ev = evidence(); ev['chip'] = chip()
            raw = json.dumps(ev).encode()
            (p / 'evidence.json').write_bytes(raw)
            r.update(mode='spi', image_type='controller_dump', physical_coverage=[[0, len(DATA)]],
                     evidence_sha256=c.digest(raw), source={'kind': 'unverified-controller'})
            (p / 'acquisition.json').write_text(json.dumps(r))
            paths.append(p)
        result = c.verify(paths)
        self.assertTrue(result['valid'], result)
        self.assertFalse(result['full_chip_verified'])
        r['physical_coverage'] = [[0, len(DATA) - 1]]
        (p / 'acquisition.json').write_text(json.dumps(r))
        self.assertFalse(c.verify(paths)['valid'])

    def test_mismatched_repeats(self):
        p1, _ = self.acquire('first')
        p2, r = self.acquire('second')
        changed = DATA[::-1]
        ev = evidence(); ev['vbios']['sha256'] = c.digest(changed)
        raw = json.dumps(ev).encode()
        (p2 / 'evidence.json').write_bytes(raw)
        (p2 / 'data.bin').write_bytes(changed)
        r.update(sha256=c.digest(changed), evidence_sha256=c.digest(raw))
        (p2 / 'acquisition.json').write_text(json.dumps(r))
        result = c.verify([p1, p2])
        self.assertFalse(result['valid'])
        self.assertIn('repeat acquisitions differ byte for byte', result['errors'])


class DeviceResolutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.sys = self.root / 'sys'; self.debug = self.root / 'debug'
        self.debug.mkdir()
        self.cards = self.sys / 'class/drm'; self.cards.mkdir(parents=True)
        self.device = self.add_device(BDF, 3)
        self.add_device('0000:06:00.0', 4)

    def add_device(self, bdf, minor):
        d = self.sys / 'bus/pci/devices' / bdf; d.mkdir(parents=True)
        for key, value in c.IDENTITY.items(): (d / key).write_text('0x' + value + '\n')
        driver = self.sys / 'bus/pci/drivers/amdgpu'; driver.mkdir(parents=True, exist_ok=True)
        (d / 'driver').symlink_to(driver)
        card = self.cards / f'card{minor}'; card.mkdir()
        (card / 'device').symlink_to(d); (card / 'dev').write_text(f'226:{minor}')
        debug = self.debug / str(minor); debug.mkdir()
        (self.debug / bdf).symlink_to(debug)
        (debug / 'name').write_text('amdgpu dev=' + bdf)
        (debug / 'amdgpu_vbios').write_bytes(DATA)
        return d

    def resolve(self): return c.resolve_vbios(BDF, self.sys, self.debug)

    def test_identical_gpus_resolve_by_bdf_only(self):
        self.assertEqual(self.resolve()['drm_card'], 'card3')
        self.assertEqual(Path(self.resolve()['blob']).read_bytes(), DATA)

    def test_wrong_subsystem_driver_and_ambiguity(self):
        (self.device / 'subsystem_device').write_text('0x0001')
        with self.assertRaises(c.CaptureError): self.resolve()
        (self.device / 'subsystem_device').write_text('0x9801')
        extra = self.cards / 'card9'; extra.mkdir(); (extra / 'device').symlink_to(self.device)
        with self.assertRaises(c.CaptureError): self.resolve()
        (extra / 'device').unlink(); extra.rmdir()
        (self.debug / BDF).unlink(); (self.debug / BDF).mkdir()
        with self.assertRaises(c.CaptureError): self.resolve()

    def test_wrong_debugfs_bdf_and_blob_symlink(self):
        (self.debug / '3/name').write_text('amdgpu dev=0000:06:00.0')
        with self.assertRaises(c.CaptureError): self.resolve()
        (self.debug / '3/name').write_text('amdgpu dev=' + BDF)
        (self.debug / '3/amdgpu_vbios').unlink()
        (self.debug / '3/amdgpu_vbios').symlink_to(self.root / 'untrusted')
        with self.assertRaises(c.CaptureError): self.resolve()

    def test_all_hardware_opens_are_allowlisted_reads(self):
        import builtins
        import io
        seen = []
        real_builtin, real_io = builtins.open, io.open
        allowed = set(c.IDENTITY) | {'dev', 'name', 'amdgpu_vbios'}
        def guard(real):
            def opened(path, mode='r', *args, **kwargs):
                if isinstance(path, (str, Path)) and Path(path).is_relative_to(self.root):
                    seen.append((str(path), mode))
                    self.assertIn(Path(path).name, allowed)
                    self.assertIn(mode, ('r', 'rb'))
                return real(path, mode, *args, **kwargs)
            return opened
        # Only resolver/blob use fake hardware roots. Output lives in another temporary tree.
        with tempfile.TemporaryDirectory() as out, patch('builtins.open', guard(real_builtin)), patch('io.open', guard(real_io)):
            result = c.capture(evidence(), BDF, 'vbios', Path(out) / 'read',
                               lambda b: c.resolve_vbios(b, self.sys, self.debug))
        self.assertEqual(result['status'], 'complete')
        self.assertTrue(any(Path(path).name == 'amdgpu_vbios' for path, mode in seen))


if __name__ == '__main__': unittest.main()
