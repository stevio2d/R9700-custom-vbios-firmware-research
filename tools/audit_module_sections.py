#!/usr/bin/env python3
"""Read regular ELF64 modules without loading them; compare section contents.

Uses only Python's standard library so the exact script can run over read-only
SSH via ``python3 - MODULE1 MODULE2``. Output describes files, never live code.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys

LIMIT = 65536


def fingerprint(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('module must be a regular file')

        def read(offset, size):
            if offset < 0 or size < 0 or offset > before.st_size or size > before.st_size - offset:
                raise ValueError('ELF range outside file')
            data = os.pread(fd, size, offset)
            if len(data) != size:
                raise ValueError('short ELF read')
            return data

        header = read(0, 64)
        if header[:7] != b'\x7fELF\x02\x01\x01':
            raise ValueError('requires little-endian ELF64 version 1')
        kind, machine, version = struct.unpack_from('<HHI', header, 16)
        if kind != 1 or machine != 62 or version != 1:
            raise ValueError('requires x86-64 relocatable module')
        table = struct.unpack_from('<Q', header, 40)[0]
        stride, count, names_index = struct.unpack_from('<HHH', header, 58)
        if stride != 64 or not 0 < count < LIMIT or not 0 < names_index < count:
            raise ValueError('unsupported ELF section table')
        rows = [struct.unpack('<IIQQQQIIQQ', read(table + i * stride, stride)) for i in range(count)]
        names_row = rows[names_index]
        if names_row[1] != 3 or names_row[5] > 16 * 1024 * 1024:
            raise ValueError('invalid ELF string table')
        names = read(names_row[4], names_row[5])

        def digest(offset, size):
            result = hashlib.sha256()
            for start in range(offset, offset + size, 1024 * 1024):
                result.update(read(start, min(1024 * 1024, offset + size - start)))
            return result.hexdigest()

        sections = {}
        for name_at, typ, flags, address, offset, size, link, info, align, entsize in rows[1:]:
            if name_at >= len(names) or b'\0' not in names[name_at:]:
                raise ValueError('invalid ELF section name')
            name = names[name_at:names.index(b'\0', name_at)].decode('ascii')
            if name in sections:
                raise ValueError('duplicate ELF section name')
            if typ != 8 and (offset > before.st_size or size > before.st_size - offset):
                raise ValueError('ELF section outside file')
            sections[name] = dict(type=typ, flags=flags, bytes=size,
                                  alignment=align, entry_size=entsize, link=link, info=info,
                                  sha256=None if typ == 8 else digest(offset, size))
        modinfo = None
        for row in rows:
            if names[row[0]:].split(b'\0', 1)[0] == b'.modinfo':
                if row[5] > 1024 * 1024:
                    raise ValueError('oversized modinfo')
                modinfo = read(row[4], row[5]).decode('utf-8').strip('\0').split('\0')
        whole = digest(0, before.st_size)
        after = os.fstat(fd)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('module changed during inspection')
        return dict(path=str(path), bytes=before.st_size, sha256=whole,
                    sections=sections, modinfo=modinfo)
    finally:
        os.close(fd)


def compare(left, right):
    a, b = left['sections'], right['sections']

    def group(predicate):
        names = sorted({name for name, row in a.items() if predicate(row)} |
                       {name for name, row in b.items() if predicate(row)})
        # Section header indices/links can change when installation drops debug
        # sections. Compare contents and load-relevant attributes, not indices.
        keys = ('type', 'flags', 'bytes', 'alignment', 'entry_size', 'sha256')
        changed = [n for n in names if n not in a or n not in b or
                   any(a[n][k] != b[n][k] for k in keys)]
        return dict(section_count=len(names), differences=changed,
                    equal=bool(names) and not changed)

    return dict(whole_file_equal=left['sha256'] == right['sha256'],
                executable=group(lambda r: bool(r['flags'] & 4)),
                allocated=group(lambda r: bool(r['flags'] & 2)),
                differences=sorted(n for n in a.keys() | b.keys() if a.get(n) != b.get(n)),
                loaded_module_equivalence_proven=False,
                limitation='File comparison does not establish loaded bytes or source provenance.')


def main(argv):
    if len(argv) != 2:
        raise ValueError('usage: audit_module_sections.py MODULE1 MODULE2')
    modules = [fingerprint(Path(p)) for p in argv]
    print(json.dumps(dict(schema=1, modules=modules, comparison=compare(*modules)), indent=2))


if __name__ == '__main__':
    main(sys.argv[1:])
