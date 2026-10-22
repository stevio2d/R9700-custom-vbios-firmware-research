#!/usr/bin/env python3
"""Inspect selected installed-module callback slots offline; never qualify hardware.

The layout input is retained `gdb -nx -batch -iex 'set auto-load off' MODULE
-ex 'ptype /o struct TYPE'` output. Its association with MODULE must be reviewed
against the collection record. This tool checks a deliberately narrow known
layout, defined function targets, explicit-addend relocations and null slots.
It neither opens GPU interfaces nor authorizes or implements any backup route.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct

from audit_module_provenance import ELF
from audit_module_sections import fingerprint


# Offsets/sizes checked against the installed module's retained DWARF, not
# inferred from the order of declarations in a surviving source checkout.
TABLES = {
    'psp_v14_0_funcs': ('psp_funcs', 248, {
        'update_spirom': (176, 'psp_v14_0_update_spirom'),
        'dump_spirom': (184, None),
        'vbflash_stat': (192, 'psp_v14_0_vbflash_status'),
    }),
    'smuio_v14_0_2_funcs': ('amdgpu_smuio_funcs', 88, {
        'get_rom_index_offset': (0, 'smuio_v14_0_2_get_rom_index_offset'),
        'get_rom_data_offset': (8, 'smuio_v14_0_2_get_rom_data_offset'),
        'update_rom_clock_gating': (16, None),
    }),
    'nbio_v7_11_funcs': ('amdgpu_nbio_funcs', 288, {
        'get_rom_offset': (240, None),
    }),
    'soc24_asic_funcs': ('amdgpu_asic_funcs', 200, {
        'read_bios_from_rom': (8, 'amdgpu_soc15_read_bios_from_rom'),
        'read_register': (16, 'soc24_read_register'),
    }),
    'psp_dump_spirom_debugfs_ops': ('file_operations', 272, {
        'read': (24, 'psp_read_spirom_debugfs_read'),
        'open': (104, 'psp_read_spirom_debugfs_open'),
        'release': (120, 'psp_read_spirom_debugfs_release'),
    }),
    'amdgpu_debugfs_regs_fops': ('file_operations', 272, {
        'read': (24, 'amdgpu_debugfs_regs_read'),
        'write': (32, 'amdgpu_debugfs_regs_write'),
    }),
    'amdgpu_debugfs_regs2_fops': ('file_operations', 272, {
        'read': (24, 'amdgpu_debugfs_regs2_read'),
        'write': (32, 'amdgpu_debugfs_regs2_write'),
        'unlocked_ioctl': (80, 'amdgpu_debugfs_regs2_ioctl'),
        'open': (104, 'amdgpu_debugfs_regs2_open'),
        'release': (120, 'amdgpu_debugfs_regs2_release'),
    }),
    'psp_vbflash_bin_attr': ('bin_attribute', 72, {
        'read': (40, 'amdgpu_psp_vbflash_read'),
        'write': (48, 'amdgpu_psp_vbflash_write'),
    }),
}


def validate_layout(text, name, size, slots):
    starts = list(re.finditer(r'type = struct (\w+) \{', text))
    blocks = [text[m.end():starts[i + 1].start() if i + 1 < len(starts) else len(text)]
              for i, m in enumerate(starts) if m[1] == name]
    if len(blocks) != 1:
        raise ValueError(f'missing or ambiguous layout: {name}')
    block = blocks[0]
    sizes = re.findall(r'total size \(bytes\):\s*(\d+)', block)
    if not sizes or int(sizes[-1]) != size:
        raise ValueError(f'unknown layout size: {name}')
    for field, (offset, _) in slots.items():
        matches = re.findall(r'/\*\s*(\d+)\s*\|\s*(\d+)\s*\*/[^\n]*\(\*'
                             + re.escape(field) + r'\)', block)
        if matches != [(str(offset), '8')]:
            raise ValueError(f'unknown callback layout: {name}.{field}')


def defined_symbol(elf, symbols, name, typ):
    found = [s for s in symbols if s['name'] == name and s['type'] == typ
             and 0 < s['section_index'] < len(elf.sections)]
    if len(found) != 1:
        raise ValueError(f'missing or ambiguous symbol: {name}')
    s = found[0]
    section = elf.sections[s['section_index']]
    if (section[1] == 8 or s['value'] > section[5] or
            s['bytes'] > section[5] - s['value'] or not s['bytes']):
        raise ValueError(f'symbol outside file-backed section: {name}')
    return s


def inspect_table(elf, table_name, layout_text):
    if table_name not in TABLES:
        raise ValueError('unsupported interface table')
    layout, size, slots = TABLES[table_name]
    validate_layout(layout_text, layout, size, slots)
    symtabs = [i for i, s in enumerate(elf.sections) if s[1] == 2]
    if len(symtabs) != 1:
        raise ValueError('require one ELF symbol table')
    symbols = elf.symbols(symtabs[0])
    table = defined_symbol(elf, symbols, table_name, 1)
    if table['bytes'] != size:
        raise ValueError('table size disagrees with known DWARF layout')
    section = elf.sections[table['section_index']]
    if not section[2] & 2:
        raise ValueError('table is not allocated')
    raw = elf.read(section[4] + table['value'], size)
    relocations = []
    for s in elf.sections:
        if s[1] not in (4, 9) or s[7] != table['section_index']:
            continue
        if s[1] != 4 or s[9] != 24 or s[5] % 24 or s[6] != symtabs[0]:
            raise ValueError('unsupported table relocation format')
        data = elf.read(s[4], s[5])
        for at in range(0, len(data), 24):
            offset, info, addend = struct.unpack_from('<QQq', data, at)
            if offset >= section[5] or info >> 32 >= len(symbols):
                raise ValueError('invalid table relocation')
            relocations.append((offset, info & 0xffffffff, symbols[info >> 32], addend))
    callbacks = {}
    for field, (offset, expected) in slots.items():
        absolute = table['value'] + offset
        # Treat every relocation as up to eight bytes for overlap detection;
        # only exact, aligned R_X86_64_64 references are supported below.
        refs = [r for r in relocations if r[0] < absolute + 8 and r[0] + 8 > absolute]
        value = int.from_bytes(raw[offset:offset + 8], 'little')
        row = dict(offset=offset, raw=value, expected=expected)
        if not refs:
            if value:
                raise ValueError('unrelocated non-null callback')
            row.update(state='null' if expected is None else 'missing-callback',
                       matches_expected=expected is None)
        else:
            if len(refs) != 1 or refs[0][0] != absolute or refs[0][1] != 1 or value:
                raise ValueError('unsupported or overlapping callback relocation')
            _, kind, relocation_symbol, addend = refs[0]
            target = relocation_symbol
            if target['type'] == 3:
                # Local callbacks are commonly relocated as .text + addend.
                # Resolve the exact entry, never the nearest containing body.
                candidates = [s for s in symbols if s['type'] == 2
                              and s['section_index'] == target['section_index']
                              and s['value'] == target['value'] + addend]
                if len(candidates) != 1:
                    raise ValueError('section relocation is not a unique function entry')
                target = candidates[0]
            elif addend:
                raise ValueError('interior function relocation unsupported')
            definition = defined_symbol(elf, symbols, target['name'], 2)
            if target != definition or elf.sections[target['section_index']][2] & 6 != 6:
                raise ValueError('callback target is not unique allocated executable function')
            target_section = elf.sections[target['section_index']]
            body = elf.read(target_section[4] + target['value'], target['bytes'])
            row.update(state='expected-target' if target['name'] == expected else 'unexpected-target',
                       matches_expected=target['name'] == expected,
                       relocation_type=kind, relocation_symbol=relocation_symbol,
                       addend=addend, target=target,
                       target_sha256=hashlib.sha256(body).hexdigest())
        callbacks[field] = row
    return dict(symbol=table, layout=layout, callbacks=callbacks,
                matches_expected=all(r['matches_expected'] for r in callbacks.values()))


def audit(path, layout_text, tables):
    elf = ELF(path)
    try:
        identity = fingerprint(path)
        # fingerprint uses its own regular-file descriptor. Detect replacement
        # between opens as well as mutation on the original descriptor at close.
        current = os.stat(path, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (elf.before.st_dev, elf.before.st_ino):
            raise ValueError('module replaced during inspection')
        result = {name: inspect_table(elf, name, layout_text) for name in tables}
        return dict(schema=1, module={k: identity[k] for k in ('path', 'bytes', 'sha256')},
                    layout_sha256=hashlib.sha256(layout_text.encode()).hexdigest(),
                    tables=result, matches_expected=all(r['matches_expected'] for r in result.values()),
                    physical_read_qualified=False,
                    limitations=['Layout-to-module association requires the retained collection record.',
                                 'Callback correspondence is not runtime, firmware or physical-coverage qualification.'])
    finally:
        elf.close()


def read_layout(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > 1024 * 1024:
            raise ValueError('layout must be a bounded regular file')
        data = os.pread(fd, before.st_size + 1, 0)
        after = os.fstat(fd)
        if (len(data) != before.st_size or
                (before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError('layout changed during inspection')
        return data.decode('utf-8')
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('module', type=Path)
    parser.add_argument('--layouts', type=Path, required=True)
    parser.add_argument('--table', action='append', choices=TABLES)
    args = parser.parse_args()
    try:
        result = audit(args.module, read_layout(args.layouts), args.table or list(TABLES))
        print(json.dumps(result, indent=2))
        return 0 if result['matches_expected'] else 1
    except (OSError, ValueError, UnicodeError, struct.error) as exc:
        parser.exit(1, f'interface audit failed: {exc}\n')


if __name__ == '__main__':
    raise SystemExit(main())
