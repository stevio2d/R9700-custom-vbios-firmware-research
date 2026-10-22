"""Synthetic ELF faults for the offline installed-interface audit; no devices."""
from pathlib import Path
import os
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import audit_installed_interfaces as audit

LAYOUT = '''type = struct psp_funcs {
/* 176 | 8 */ int (*update_spirom)(void);
/* 184 | 8 */ int (*dump_spirom)(void);
/* 192 | 8 */ int (*vbflash_stat)(void);
/* total size (bytes): 248 */
}
'''


class InstalledInterfaceTests(unittest.TestCase):
    def setUp(self):
        (ROOT / '.cache').mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT / '.cache')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def build(self, update='psp_v14_0_update_spirom', dump='0'):
        src = self.base / 'fixture.c'
        src.write_text('''
static int psp_v14_0_update_spirom(void) {return 1;}
static int psp_v14_0_vbflash_status(void) {return 2;}
static int other(void) {return 3;}
int (*const psp_v14_0_funcs[31])(void) = {
''' + f'[22]={update},[23]={dump},[24]=psp_v14_0_vbflash_status' + '};\n')
        obj = self.base / 'fixture.o'
        subprocess.run(['cc', '-O0', '-fno-pie', '-c', str(src), '-o', str(obj)], check=True)
        return obj

    def inspect(self, obj, layout=LAYOUT, table='psp_v14_0_funcs'):
        return audit.audit(obj, layout, [table])

    def test_null_dump_is_distinct_from_available_update(self):
        result = self.inspect(self.build())
        self.assertTrue(result['matches_expected'])
        self.assertFalse(result['physical_read_qualified'])
        fields = result['tables']['psp_v14_0_funcs']['callbacks']
        self.assertEqual(fields['dump_spirom']['state'], 'null')
        self.assertEqual(fields['update_spirom']['target']['name'], 'psp_v14_0_update_spirom')
        self.assertEqual(fields['update_spirom']['relocation_symbol']['type'], 3)

    def test_missing_callback_and_redirected_section_addend(self):
        for update, dump, state, field in [
                ('0', '0', 'missing-callback', 'update_spirom'),
                ('other', '0', 'unexpected-target', 'update_spirom'),
                ('psp_v14_0_update_spirom', 'other', 'unexpected-target', 'dump_spirom')]:
            with self.subTest(update=update, dump=dump):
                result = self.inspect(self.build(update, dump))
                self.assertFalse(result['matches_expected'])
                self.assertFalse(result['physical_read_qualified'])
                self.assertEqual(result['tables']['psp_v14_0_funcs']['callbacks'][field]['state'], state)

    def test_unknown_layout_or_unsupported_interface_rejected(self):
        obj = self.build()
        for text in [LAYOUT.replace('176 |', '168 |'), LAYOUT.replace('248', '256'),
                     LAYOUT.replace('dump_spirom', 'unknown'), LAYOUT + LAYOUT, '']:
            with self.subTest(layout=text), self.assertRaises(ValueError):
                self.inspect(obj, text)
        with self.assertRaisesRegex(ValueError, 'unsupported interface'):
            self.inspect(obj, table='psp_vbflash')
        result = subprocess.run([sys.executable, str(ROOT / 'tools/audit_installed_interfaces.py'),
                                 str(obj), '--layouts', str(obj), '--table', 'psp_vbflash'],
                                capture_output=True)
        self.assertNotEqual(result.returncode, 0)

    def test_malformed_relocations_and_nonentry_targets_rejected(self):
        obj = self.build()
        elf = audit.ELF(obj)
        try:
            tab = next(i for i, s in enumerate(elf.sections) if s[1] == 2)
            syms = elf.symbols(tab)
            table = audit.defined_symbol(elf, syms, 'psp_v14_0_funcs', 1)
            rel = next(s for s in elf.sections if s[1] == 4 and s[7] == table['section_index'])
            at = rel[4]
            off, info, addend = struct.unpack('<QQq', elf.read(at, 24))
            text_index = elf.names.index('.text')
            section_table = struct.unpack('<Q', elf.read(40, 8))[0]
        finally:
            elf.close()
        original = obj.read_bytes()
        mutations = [(at, '<Q', off + 1), (at + 8, '<Q', (info & ~0xffffffff) | 2),
                     (at + 8, '<Q', 0xffffffff00000001), (at + 16, '<q', addend + 1),
                     (40, '<Q', len(original)),
                     (section_table + text_index * 64 + 8, '<Q', 4)]
        for offset, fmt, value in mutations:
            changed = bytearray(original)
            struct.pack_into(fmt, changed, offset, value)
            obj.write_bytes(changed)
            with self.subTest(offset=offset, value=value), self.assertRaises(ValueError):
                self.inspect(obj)
        for data in [b'', original[:64], b'not ELF']:
            obj.write_bytes(data)
            with self.assertRaises(ValueError):
                self.inspect(obj)

    def test_nonregular_modules_rejected_without_opening_devices(self):
        obj = self.build()
        link = self.base / 'link'; link.symlink_to(obj)
        with self.assertRaises(OSError):
            self.inspect(link)
        fifo = self.base / 'fifo'; os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            self.inspect(fifo)
        for path, error in [(link, OSError), (fifo, ValueError)]:
            with self.assertRaises(error):
                audit.read_layout(path)
        large = self.base / 'oversize-layout'
        with large.open('wb') as f:
            f.truncate(1024 * 1024 + 1)
        with self.assertRaises(ValueError):
            audit.read_layout(large)


if __name__ == '__main__':
    unittest.main()
