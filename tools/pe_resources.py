#!/usr/bin/env python3
"""Bounded static PE resource extraction. Never loads or executes a PE image."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

MAX_INPUT = 64 * 1024 * 1024
MAX_RESOURCES = 4096
MAX_MEMBERS = 128


class PEError(ValueError):
    pass


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def resources(data, max_resource_bytes=MAX_INPUT):
    """Return raw resource ranges and numeric/string paths; reject ambiguity."""
    def bounded(offset, length):
        if offset < 0 or length < 0 or offset + length > len(data):
            raise PEError("PE range outside file")
        return data[offset:offset + length]

    def unpack(fmt, offset):
        return struct.unpack(fmt, bounded(offset, struct.calcsize(fmt)))

    if len(data) > MAX_INPUT or bounded(0, 2) != b'MZ':
        raise PEError("not a bounded DOS/PE image")
    pe, = unpack('<I', 0x3c)
    if bounded(pe, 4) != b'PE\0\0':
        raise PEError("missing PE signature")
    count, = unpack('<H', pe + 6)
    optional_size, = unpack('<H', pe + 20)
    if not 1 <= count <= 96:
        raise PEError("invalid section count")
    opt = pe + 24
    bounded(opt, optional_size)
    magic, = unpack('<H', opt)
    if magic not in (0x10b, 0x20b):
        raise PEError("unsupported optional header")
    dd = opt + (112 if magic == 0x20b else 96)
    if dd + 24 > opt + optional_size:
        raise PEError("short optional header")
    ndd, = unpack('<I', dd - 4)
    if ndd < 3:
        return []
    sections = []
    for i in range(count):
        off = opt + optional_size + i * 40
        virtual_size, rva, size, raw = unpack('<IIII', off + 8)
        bounded(off, 40)
        bounded(raw, size)
        sections.append((rva, size, raw))

    def rva_offset(rva, size):
        if rva + size > 2**32:
            raise PEError("RVA overflow")
        matches = [raw + rva - base for base, length, raw in sections
                   if base <= rva and rva + size <= base + length]
        if len(matches) != 1:
            raise PEError("unmapped or ambiguous resource RVA")
        bounded(matches[0], size)
        return matches[0]

    root_rva, root_size = unpack('<II', dd + 16)
    if not root_rva and not root_size:
        return []
    if not root_rva or root_size < 16:
        raise PEError("invalid resource directory")
    root = rva_offset(root_rva, root_size)

    def resource_bytes(relative, size):
        if relative < 0 or relative + size > root_size:
            raise PEError("resource metadata outside directory")
        return bounded(root + relative, size)

    leaves = []
    visited = set()
    extracted_bytes = 0

    def walk(relative, path):
        nonlocal extracted_bytes
        if len(path) > 3 or relative in visited or len(visited) > 4096:
            raise PEError("resource cycle, depth or node limit")
        visited.add(relative)
        header = resource_bytes(relative, 16)
        named, ids = struct.unpack_from('<HH', header, 12)
        entries = resource_bytes(relative + 16, (named + ids) * 8)
        names = set()
        for i in range(named + ids):
            name, target = struct.unpack_from('<II', entries, i * 8)
            if name & 0x80000000:
                loc = name & 0x7fffffff
                length, = struct.unpack('<H', resource_bytes(loc, 2))
                try:
                    key = resource_bytes(loc + 2, length * 2).decode('utf-16le')
                except UnicodeError as exc:
                    raise PEError("invalid resource name") from exc
            else:
                key = name
            if key in names:
                raise PEError("duplicate resource name")
            names.add(key)
            branch = path + [key]
            if target & 0x80000000:
                walk(target & 0x7fffffff, branch)
                continue
            if len(branch) != 3:
                raise PEError("resource leaf is not type/name/language")
            rva, size, codepage, reserved = struct.unpack('<IIII', resource_bytes(target, 16))
            if not size or reserved:
                raise PEError("invalid resource data entry")
            extracted_bytes += size
            if len(leaves) >= MAX_RESOURCES or extracted_bytes > max_resource_bytes:
                raise PEError("aggregate resource count/byte limit")
            offset = rva_offset(rva, size)
            payload = bounded(offset, size)
            leaves.append({'resource': branch, 'file_offset': offset, 'rva': rva,
                           'bytes': size, 'sha256': sha256(payload), 'codepage': codepage})
    walk(0, [])
    return leaves


def extract_archive(package, output):
    """Extract only bounded members/resources to a new directory with provenance."""
    package = Path(package)
    if package.stat().st_size > MAX_INPUT:
        raise PEError("package too large")
    raw = package.read_bytes()
    result = {'package': package.as_posix(), 'package_sha256': sha256(raw),
              'package_bytes': len(raw), 'members': []}
    # Validate everything before creating output; never trust archive filenames.
    payloads = {}
    total = 0
    extracted_total = 0
    resource_count = 0
    with zipfile.ZipFile(package) as z:
        if len(z.infolist()) > MAX_MEMBERS:
            raise PEError("archive member count limit")
        for i, info in enumerate(z.infolist()):
            if info.is_dir():
                continue
            total += info.file_size
            if total > MAX_INPUT:
                raise PEError("uncompressed package limit")
            content = z.read(info)
            extracted_total += len(content)
            if extracted_total > MAX_INPUT:
                raise PEError("aggregate extraction byte limit")
            member_resources = resources(content, MAX_INPUT - extracted_total)
            resource_count += len(member_resources)
            if resource_count > MAX_RESOURCES:
                raise PEError("aggregate archive resource count limit")
            extracted_total += sum(r['bytes'] for r in member_resources)
            item = {'member': info.filename, 'bytes': len(content), 'sha256': sha256(content),
                    'output': f'member-{i}.exe', 'resources': member_resources}
            payloads[item['output']] = content
            for j, resource in enumerate(item['resources']):
                resource['output'] = f'member-{i}-resource-{j}.bin'
                start = resource['file_offset']
                payloads[resource['output']] = content[start:start + resource['bytes']]
            result['members'].append(item)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    for name, content in payloads.items():
        with (output / name).open('xb') as f:
            f.write(content)
    with (output / 'provenance.json').open('x') as f:
        json.dump(result, f, indent=2)
        f.write('\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package', type=Path)
    parser.add_argument('output', type=Path, help='new directory; never overwritten')
    args = parser.parse_args()
    try:
        print(json.dumps(extract_archive(args.package, args.output), indent=2))
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        parser.exit(1, f'{exc}\n')


if __name__ == '__main__':
    main()
