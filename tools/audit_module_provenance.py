#!/usr/bin/env python3
"""Offline ELF symbol/relocation localization, never module loading.

Uses the retained section auditor without changing it. Relocations are compared
by names rather than ELF table indices. Section-symbol addends remain literal:
layout changes can therefore appear as differences and require disassembly.
No equivalence result proves loaded bytes, build provenance or hardware safety.
"""
import argparse
import bisect
import hashlib
import json
import os
from pathlib import Path
import stat
import struct

from audit_module_sections import fingerprint, compare as compare_sections


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


class ELF:
    def __init__(self, path):
        self.fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            self.before = os.fstat(self.fd)
            if not stat.S_ISREG(self.before.st_mode):
                raise ValueError('requires regular ELF file')
            h = self.read(0, 64)
            if h[:7] != b'\x7fELF\x02\x01\x01' or struct.unpack_from('<HHI', h, 16) != (1, 62, 1):
                raise ValueError('requires ELF64 little-endian x86-64 relocatable object')
            at = struct.unpack_from('<Q', h, 40)[0]
            stride, count, names = struct.unpack_from('<HHH', h, 58)
            if stride != 64 or not 0 < names < count < 65536:
                raise ValueError('invalid section table')
            self.sections = [struct.unpack('<IIQQQQIIQQ', self.read(at + i * 64, 64)) for i in range(count)]
            strings = self.section(names, 3)
            self.names = [self.string(strings, s[0]) for s in self.sections]
            if len(set(self.names)) != count:
                raise ValueError('duplicate section names')
            for s in self.sections:
                if s[1] != 8:
                    self.range(s[4], s[5])
            self.symbol_tables = {}
        except BaseException:
            os.close(self.fd)
            raise

    def range(self, offset, size):
        if offset < 0 or size < 0 or offset > self.before.st_size or size > self.before.st_size - offset:
            raise ValueError('ELF range outside file')

    def read(self, offset, size):
        self.range(offset, size)
        data = os.pread(self.fd, size, offset)
        if len(data) != size:
            raise ValueError('short ELF read')
        return data

    def section(self, index, typ):
        if not 0 < index < len(self.sections):
            raise ValueError('invalid section link')
        s = self.sections[index]
        if s[1] != typ or s[5] > 128 * 1024 * 1024:
            raise ValueError('invalid or oversized metadata section')
        return self.read(s[4], s[5])

    @staticmethod
    def string(data, at):
        end = data.find(b'\0', at)
        if at >= len(data) or end < 0:
            raise ValueError('invalid ELF string')
        return data[at:end].decode('utf-8', errors='strict')

    def symbols(self, index):
        if index in self.symbol_tables:
            return self.symbol_tables[index]
        data = self.section(index, 2)
        s = self.sections[index]
        if s[9] != 24 or len(data) % 24:
            raise ValueError('invalid symbol table size')
        strings = self.section(s[6], 3)
        result, source = [], ''
        for at in range(0, len(data), 24):
            name, info, other, section, value, size = struct.unpack_from('<IBBHQQ', data, at)
            name = self.string(strings, name)
            if section == 0xffff or (section >= len(self.sections) and section < 0xff00):
                raise ValueError('unsupported symbol section')
            if info & 15 == 4:
                source = name
            target = self.names[section] if 0 < section < len(self.sections) else str(section)
            result.append(dict(name=name, type=info & 15, binding=info >> 4, visibility=other,
                               section=target, section_index=section, value=value, bytes=size,
                               source=source if info >> 4 == 0 else ''))
        self.symbol_tables[index] = result
        return result

    def inspect(self):
        functions, relocations, occurrences = {}, {}, {}
        for i, s in enumerate(self.sections):
            if s[1] == 2:
                for symbol in sorted(self.symbols(i), key=lambda r: (r['section'], r['name'], r['value'])):
                    if symbol['type'] != 2 or not 0 < symbol['section_index'] < len(self.sections):
                        continue
                    target = self.sections[symbol['section_index']]
                    if symbol['value'] > target[5] or symbol['bytes'] > target[5] - symbol['value'] or target[1] == 8:
                        raise ValueError('function outside section')
                    # objtool appends local __pfx symbols after the last STT_FILE;
                    # that file is not their compilation unit. Rank duplicates
                    # by section offset, retaining the ambiguity in the report.
                    symbol = dict(symbol)
                    if symbol['name'].startswith('__pfx_'):
                        symbol['source'] = ''
                    identity = [symbol['section'], symbol['name']]
                    group = json.dumps(identity)
                    ordinal = occurrences.get(group, 0)
                    occurrences[group] = ordinal + 1
                    key = json.dumps([*identity, ordinal])
                    row = dict(symbol)
                    row['sha256'] = hashlib.sha256(self.read(target[4] + symbol['value'], symbol['bytes'])).hexdigest()
                    functions[key] = row
            if s[1] == 9:
                raise ValueError('SHT_REL unsupported; require explicit-addend relocations')
            if s[1] != 4:
                continue
            if not 0 < s[7] < len(self.sections) or s[9] != 24 or s[5] % 24:
                raise ValueError('invalid relocation table')
            target = self.sections[s[7]]
            if not target[2] & 2:
                continue
            symbols = self.symbols(s[6])
            rows = relocations.setdefault(self.names[s[7]], [])
            data = self.section(i, 4)
            for at in range(0, len(data), 24):
                offset, info, addend = struct.unpack_from('<QQq', data, at)
                if offset >= target[5] or info >> 32 >= len(symbols):
                    raise ValueError('relocation outside target or symbol table')
                symbol = symbols[info >> 32]
                # The definition's value matters even when its name is stable:
                # changing st_value alone redirects an otherwise identical RELA.
                identity = [symbol[k] for k in ('name', 'type', 'binding', 'visibility', 'section', 'value', 'bytes')]
                rows.append([offset, info & 0xffffffff, identity, addend])
        for rows in relocations.values():
            rows.sort()
        offsets = {k: [r[0] for r in v] for k, v in relocations.items()}
        for f in functions.values():
            rows = relocations.get(f['section'], [])
            positions = offsets.get(f['section'], [])
            lo = bisect.bisect_left(positions, f['value'])
            hi = bisect.bisect_left(positions, f['value'] + f['bytes'])
            f['relocations'] = [[r[0] - f['value'], *r[1:]] for r in rows[lo:hi]]
        return functions, relocations

    def close(self):
        try:
            after = os.fstat(self.fd)
            if (self.before.st_size, self.before.st_mtime_ns, self.before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError('ELF changed during inspection')
        finally:
            os.close(self.fd)


def audit(left, right):
    files, details = [], []
    for path in (left, right):
        elf = ELF(path)
        try:
            files.append(fingerprint(path))
            details.append(elf.inspect())
            # fingerprint opens a separate fd: confirm it refers to this file.
            if os.stat(path, follow_symlinks=False).st_ino != elf.before.st_ino:
                raise ValueError('ELF replaced during inspection')
        finally:
            elf.close()
    a, b = details[0][0], details[1][0]
    changes = []
    raw_changes = []
    def compact(row):
        if row is None:
            return None
        return {**{k: v for k, v in row.items() if k != 'relocations'},
                'relocation_count': len(row['relocations']),
                'relocation_sha256': digest(row['relocations'])}
    for key in sorted(a.keys() | b.keys()):
        x, y = a.get(key), b.get(key)
        if x is None or y is None or any(x[k] != y[k] for k in ('sha256', 'bytes', 'relocations')):
            changes.append(dict(identity=json.loads(key), left=compact(x), right=compact(y)))
        if x is None or y is None or x['sha256'] != y['sha256']:
            raw_changes.append(dict(identity=json.loads(key), left=x, right=y))
    rels = []
    for name in sorted(details[0][1].keys() | details[1][1].keys()):
        x, y = details[0][1].get(name, []), details[1][1].get(name, [])
        rels.append(dict(section=name, left_count=len(x), right_count=len(y),
                         left_sha256=digest(x), right_sha256=digest(y), equal=x == y))
    return dict(schema=1, modules=files, section_comparison=compare_sections(*files),
                function_counts=[len(d[0]) for d in details], changed_functions=changes,
                raw_changed_functions=raw_changes,
                allocated_relocations=rels, source_provenance_proven=False,
                loaded_module_equivalence_proven=False,
                limitations=['Raw function hashes include layout-dependent instructions.',
                             'Relocation identities ignore table indices; section-symbol addends retain layout offsets.',
                             'Duplicate function names pair by offset rank, not proven CU identity; __pfx source labels are omitted.',
                             'Function comparison excludes padding and non-function bytes; section comparison covers these.',
                             'No source lineage, runtime state or physical read safety is established.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('left', type=Path)
    parser.add_argument('right', type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(audit(args.left, args.right), indent=2))
    except (ValueError, OSError, UnicodeError, struct.error) as exc:
        parser.exit(1, f'audit failed: {exc}\n')


if __name__ == '__main__':
    main()
