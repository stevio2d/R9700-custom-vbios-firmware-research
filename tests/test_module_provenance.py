"""Synthetic ELF regressions for offline provenance localization."""
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import audit_module_provenance as AUDIT


class ModuleProvenanceTests(unittest.TestCase):
    def setUp(self):
        (ROOT / '.cache').mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT / '.cache')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def build(self, text, name):
        source, obj = self.base / 'module.c', self.base / name
        source.write_text(text)
        subprocess.run(['cc', '-g', '-O0', '-fno-pie', '-c', str(source), '-o', str(obj)], check=True)
        return obj

    def test_debug_strip_does_not_change_function_or_load_relocation_comparison(self):
        left = self.build('extern int x; static int local(void) {return x;} int get(void) {return local();}', 'a.o')
        right = self.base / 'b.o'
        subprocess.run(['objcopy', '--strip-debug', str(left), str(right)], check=True)
        result = AUDIT.audit(left, right)
        self.assertFalse(result['section_comparison']['whole_file_equal'])
        self.assertTrue(result['section_comparison']['allocated']['equal'])
        self.assertEqual(result['changed_functions'], [])
        self.assertTrue(all(r['equal'] for r in result['allocated_relocations']))
        self.assertFalse(result['source_provenance_proven'])

    def test_changed_instruction_is_localized(self):
        left = self.build('int get(void) {return 42;}', 'a.o')
        right = self.build('int get(void) {return 43;}', 'b.o')
        result = AUDIT.audit(left, right)
        self.assertEqual([r['identity'][1] for r in result['raw_changed_functions']], ['get'])
        self.assertFalse(result['section_comparison']['executable']['equal'])

    def test_changed_relocation_target_with_identical_instructions(self):
        left = self.build('extern int x,y; int get(void) {return x;}', 'a.o')
        right = self.build('extern int x,y; int get(void) {return y;}', 'b.o')
        result = AUDIT.audit(left, right)
        self.assertTrue(result['section_comparison']['executable']['equal'])
        self.assertEqual(result['raw_changed_functions'], [])
        self.assertEqual([r['identity'][1] for r in result['changed_functions']], ['get'])
        self.assertFalse(next(r for r in result['allocated_relocations'] if r['section'] == '.text')['equal'])

    def test_malformed_tables_and_nonregular_inputs_rejected(self):
        original = self.build('extern int x; int get(void) {return x;}', 'a.o')
        e = AUDIT.ELF(original)
        try:
            rel_index = next(i for i, s in enumerate(e.sections) if s[1] == 4 and e.names[s[7]] == '.text')
            rel = e.sections[rel_index]
            table = struct.unpack_from('<Q', original.read_bytes(), 40)[0]
        finally:
            e.close()
        data = original.read_bytes()
        mutations = []
        for offset, fmt, value in [(40, '<Q', len(data)), (table + rel_index * 64 + 40, '<I', 65535),
                                   (rel[4] + 8, '<Q', 0xffffffff00000002), (rel[4], '<Q', 0xffffffffffffffff),
                                   (table + rel_index * 64 + 56, '<Q', 8)]:
            changed = bytearray(data)
            struct.pack_into(fmt, changed, offset, value)
            mutations.append(changed)
        malformed = self.base / 'bad.o'
        for content in [b'', b'not ELF', data[:64], *mutations]:
            with self.subTest(length=len(content)):
                malformed.write_bytes(content)
                with self.assertRaises(ValueError):
                    AUDIT.audit(original, malformed)
        link = self.base / 'link'; link.symlink_to(original)
        with self.assertRaises(OSError):
            AUDIT.audit(original, link)
        fifo = self.base / 'fifo'; os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            AUDIT.audit(original, fifo)

    def test_changed_symbol_value_redirects_relocation(self):
        left = self.build('int x=1,y=2; int get(void) {return x;}', 'a.o')
        data = bytearray(left.read_bytes())
        e = AUDIT.ELF(left)
        try:
            index = next(i for i, s in enumerate(e.sections) if s[1] == 2)
            symbols = e.symbols(index)
            x = next(i for i, s in enumerate(symbols) if s['name'] == 'x')
            y = next(s for s in symbols if s['name'] == 'y')
            struct.pack_into('<Q', data, e.sections[index][4] + x * 24 + 8, y['value'])
        finally:
            e.close()
        right = self.base / 'b.o'; right.write_bytes(data)
        result = AUDIT.audit(left, right)
        self.assertTrue(result['section_comparison']['allocated']['equal'])
        self.assertEqual(result['raw_changed_functions'], [])
        self.assertEqual([r['identity'][1] for r in result['changed_functions']], ['get'])
        self.assertFalse(next(r for r in result['allocated_relocations'] if r['section'] == '.text')['equal'])


if __name__ == '__main__':
    unittest.main()
