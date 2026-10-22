"""Offline module-file comparison, including an installation-style debug strip."""
import importlib.util
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('module_sections', ROOT / 'tools/audit_module_sections.py')
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class ModuleSectionsTests(unittest.TestCase):
    def test_debug_strip_preserves_executable_and_allocated_sections(self):
        (ROOT / '.cache').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / '.cache') as base:
            p = Path(base)
            source = p / 'module.c'
            source.write_text('int value; int get(void) { return value + 42; }\n')
            built, installed = p / 'built.ko', p / 'installed.ko'
            subprocess.run(['cc', '-g', '-c', str(source), '-o', str(built)], check=True)
            subprocess.run(['objcopy', '--strip-debug', str(built), str(installed)], check=True)
            result = AUDIT.compare(AUDIT.fingerprint(built), AUDIT.fingerprint(installed))
            self.assertFalse(result['whole_file_equal'])
            self.assertTrue(result['executable']['equal'])
            self.assertTrue(result['allocated']['equal'])
            self.assertFalse(result['loaded_module_equivalence_proven'])
            source.write_text('int value; int get(void) { return value + 43; }\n')
            subprocess.run(['cc', '-g', '-c', str(source), '-o', str(installed)], check=True)
            self.assertFalse(AUDIT.compare(AUDIT.fingerprint(built), AUDIT.fingerprint(installed))['executable']['equal'])

    def test_malformed_or_nonregular_input_rejected(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.cache') as base:
            p = Path(base) / 'file'
            for data in [b'', b'\x7fELF' + b'\0' * 100, b'x' * 100]:
                p.write_bytes(data)
                with self.assertRaises(ValueError):
                    AUDIT.fingerprint(p)
            link = Path(base) / 'link'
            link.symlink_to(p)
            with self.assertRaises(OSError):
                AUDIT.fingerprint(link)
            fifo = Path(base) / 'fifo'
            os.mkfifo(fifo)
            with self.assertRaises(ValueError):
                AUDIT.fingerprint(fifo)
