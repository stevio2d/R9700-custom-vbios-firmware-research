#!/usr/bin/env python3
"""Evidence-led Linux VBIOS capture; physical SPI access is deliberately blocked.

plan/verify are offline. capture is live and requires separate operator approval.
Only a uniquely BDF-resolved AMDGPU amdgpu_vbios file can be read by this build.
"""

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import sys
import uuid

VERSION = '1.0'
MAX_BYTES = 16 * 1024 * 1024
TIMEOUT_SECONDS = 15
BDF_RE = re.compile(r'[0-9a-f]{4}:[0-9a-f]{2}:[01][0-9a-f]\.[0-7]')
IDENTITY = {'vendor': '1002', 'device': '7551', 'subsystem_vendor': '1eae',
            'subsystem_device': '9801', 'revision': 'c0'}


class CaptureError(ValueError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def bdf_value(value):
    value = value.lower()
    if not BDF_RE.fullmatch(value):
        raise CaptureError('require full PCI BDF dddd:bb:dd.f (device <= 1f, function <= 7)')
    return value


def integer(value, lower, upper, label):
    if type(value) is not int or not lower <= value <= upper:
        raise CaptureError(f'invalid {label}')
    return value


def offline_path(path):
    path = Path(path).resolve(strict=True)
    if any(path.is_relative_to(root) for root in (Path('/sys'), Path('/proc'), Path('/dev'))):
        raise CaptureError('offline evidence must not come from a hardware or pseudo-filesystem path')
    return path


def load_json(path):
    path = offline_path(path)
    st = path.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_size > 1024 * 1024:
        raise CaptureError('JSON record is not a bounded regular file')
    return json.loads(path.read_text())


def check_evidence(evidence, bdf):
    if evidence.get('schema_version') != 1:
        raise CaptureError('unsupported evidence schema')
    device = evidence.get('device', {})
    if device.get('bdf') != bdf or device.get('identity') != IDENTITY:
        raise CaptureError('recorded BDF/PCI/subsystem identity does not match target')
    vbios = evidence.get('vbios', {})
    integer(vbios.get('bytes'), 1, MAX_BYTES, 'recorded VBIOS length')
    if not re.fullmatch('[0-9a-f]{64}', vbios.get('sha256', '')):
        raise CaptureError('missing recorded VBIOS digest')
    if not vbios.get('provenance') or not device.get('evidence'):
        raise CaptureError('missing device/VBIOS provenance')


def geometry(chip):
    if not isinstance(chip, dict):
        raise CaptureError('physical chip identity and capacity unknown')
    for key in ('part', 'jedec_id', 'marking_evidence', 'identification_evidence', 'datasheet_evidence'):
        if not chip.get(key):
            raise CaptureError(f'missing chip {key}')
    capacity = integer(chip.get('capacity_bytes'), 1, MAX_BYTES, 'chip capacity')
    bits = integer(chip.get('address_bits'), 1, 32, 'address width')
    # Executable ROMSize and dump length are never identity/capacity sources.
    sources = chip.get('capacity_evidence', {})
    if set(sources) != {'datasheet', 'identification'} or any(v != capacity for v in sources.values()):
        raise CaptureError('unknown or conflicting chip capacities')
    if capacity > 1 << bits:
        raise CaptureError('chip capacity exceeds address width')
    return capacity, bits


def coverage(capacity, bits, ranges, actual_size):
    integer(capacity, 1, MAX_BYTES, 'capacity')
    integer(bits, 1, 32, 'address width')
    if capacity > 1 << bits or not isinstance(ranges, list) or not ranges:
        raise CaptureError('invalid physical address coverage')
    cursor = 0
    for pair in ranges:
        if not isinstance(pair, list) or len(pair) != 2:
            raise CaptureError('invalid address range')
        start = integer(pair[0], 0, capacity, 'range start')
        end = integer(pair[1], 1, capacity, 'range end')
        if start != cursor or end <= start or end > 1 << bits:
            raise CaptureError('address overflow, gap, overlap or unordered coverage')
        cursor = end
    if cursor != capacity or actual_size != capacity:
        raise CaptureError('incomplete coverage or capacity/length mismatch')


def spi_blockers(evidence):
    reasons = ['no audited Linux SPI backend is implemented in this build',
               'exact 7.0.14-custom-nogpu source/config/module provenance is unavailable',
               'target controller initialization, synchronization and full-array reads are unresolved']
    try:
        geometry(evidence.get('chip'))
    except CaptureError as exc:
        reasons.append(str(exc))
    return reasons


def plan(evidence, bdf):
    check_evidence(evidence, bdf)
    return {'schema_version': 1, 'bdf': bdf, 'hardware_accessed': False,
            'vbios': {'image_type': 'software_dump', 'expected_bytes': evidence['vbios']['bytes'],
                      'operations': ['validate PCI/subsystem/revision and bound amdgpu driver',
                                     'resolve unique primary DRM device and debugfs directory',
                                     'check debugfs name identifies the exact BDF',
                                     'read only amdgpu_vbios with a fixed bound and timeout',
                                     'revalidate identity/mapping; retain bytes/hash/record'],
                      'approval_required_before_live_access': True,
                      'physical_spi_coverage': 'unproven; recorded driver source is ACPI VFCT'},
            'spi': {'enabled': False, 'operations': [], 'blockers': spi_blockers(evidence)}}


def read_identity(device):
    actual = {}
    for key, expected in IDENTITY.items():
        value = (device / key).read_text().strip().lower().removeprefix('0x')
        if value != expected:
            raise CaptureError(f'PCI {key} mismatch: {value}, expected {expected}')
        actual[key] = value
    if (device / 'driver').resolve(strict=True).name != 'amdgpu':
        raise CaptureError('target is not bound to amdgpu')
    return actual


def resolve_vbios(bdf, sysfs=Path('/sys'), debugfs=Path('/sys/kernel/debug/dri')):
    """Strict mapping; injectable roots are for offline tests, never CLI options."""
    bdf = bdf_value(bdf)
    device = (sysfs / 'bus/pci/devices' / bdf).resolve(strict=True)
    identity = read_identity(device)
    cards = []
    for card in (sysfs / 'class/drm').iterdir():
        if re.fullmatch(r'card[0-9]+', card.name) and (card / 'device').resolve() == device:
            cards.append(card)
    if len(cards) != 1:
        raise CaptureError('missing or ambiguous primary DRM mapping')
    card = cards[0]
    dev = (card / 'dev').read_text().strip()
    if not re.fullmatch(r'226:[0-9]+', dev):
        raise CaptureError('invalid primary DRM major/minor')
    minor = dev.split(':')[1]
    dirs = {p.resolve(strict=True) for p in (debugfs / bdf, debugfs / minor) if p.exists()}
    if len(dirs) != 1:
        raise CaptureError('missing or ambiguous debugfs mapping')
    directory = dirs.pop()
    name = (directory / 'name').read_text().strip()
    bdfs = set(re.findall(r'[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]', name.lower()))
    if not name.startswith('amdgpu ') or bdfs != {bdf}:
        raise CaptureError('debugfs name does not uniquely identify target BDF')
    blob = directory / 'amdgpu_vbios'
    if blob.is_symlink():
        raise CaptureError('unexpected symlink at VBIOS blob')
    return {'identity': identity, 'pci_path': str(device), 'drm_card': card.name,
            'drm_dev': dev, 'debugfs_name': name, 'blob': str(blob)}


@contextmanager
def deadline():
    def expired(signum, frame):
        raise CaptureError(f'capture exceeded {TIMEOUT_SECONDS}s timeout')
    old = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, TIMEOUT_SECONDS)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def suspicious(data):
    return not data or len(set(data)) <= 1 or (data.count(0) + data.count(255)) / len(data) > .995


def stream_copy(source, output, expected):
    """Bound even a stream that never reaches EOF; retain one excess diagnostic byte."""
    integer(expected, 1, MAX_BYTES, 'read bound')
    count = 0
    while count <= expected:
        part = source.read(min(65536, expected + 1 - count))
        if not part:
            break
        output.write(part)
        output.flush()
        count += len(part)
    if count != expected:
        raise CaptureError(f'read length {count} differs from recorded length {expected}')


def save_record(directory, record):
    pending = directory / 'record.pending'
    with pending.open('x') as f:
        json.dump(record, f, indent=2)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    pending.replace(directory / 'acquisition.json')


def capture(evidence, bdf, mode, output, resolver=resolve_vbios, opener=None):
    bdf = bdf_value(bdf)
    check_evidence(evidence, bdf)
    if mode != 'vbios':
        raise CaptureError('; '.join(spi_blockers(evidence)))
    output = Path(output)
    output.mkdir(parents=False, exist_ok=False)
    evidence_bytes = (json.dumps(evidence, sort_keys=True, indent=2) + '\n').encode()
    with (output / 'evidence.json').open('xb') as f:
        f.write(evidence_bytes)
    record = {'schema_version': 1, 'acquisition_id': str(uuid.uuid4()), 'started_utc': utc_now(),
              'status': 'incomplete', 'bdf': bdf, 'mode': 'vbios', 'image_type': 'software_dump',
              'physical_coverage': [], 'provenance': evidence['vbios']['provenance'],
              'data_file': 'data.bin', 'expected_bytes': evidence['vbios']['bytes'],
              'evidence_sha256': digest(evidence_bytes), 'tool_version': VERSION,
              'tool_sha256': digest(Path(__file__).read_bytes()), 'timeout_seconds': TIMEOUT_SECONDS,
              'host': platform.node(), 'kernel_release': platform.release(),
              'python_version': platform.python_version()}
    save_record(output, record)
    try:
        with deadline():
            mapping = resolver(bdf)
            record['source'] = dict(mapping, kind='amdgpu_vbios')
            # No alternate path, sysfs ROM, device node, MMIO or IOCTL fallback.
            with (output / 'data.bin').open('xb') as dest:
                with (opener(mapping['blob']) if opener else open(mapping['blob'], 'rb', buffering=0)) as src:
                    stream_copy(src, dest, record['expected_bytes'])
                os.fsync(dest.fileno())
            if resolver(bdf) != mapping:
                raise CaptureError('identity or DRM mapping changed during acquisition')
            data = (output / 'data.bin').read_bytes()
            if suspicious(data):
                raise CaptureError('suspicious blank or nearly blank output')
            if digest(data) != evidence['vbios']['sha256']:
                raise CaptureError('VBIOS differs from recorded stock digest; retain and investigate')
            record['status'] = 'complete'
    except (OSError, ValueError, KeyboardInterrupt) as exc:
        record['status'] = 'failed'
        record['error'] = f'{type(exc).__name__}: {exc}'
    finally:
        data_path = output / 'data.bin'
        if data_path.exists():
            data = data_path.read_bytes()
            record.update(bytes=len(data), sha256=digest(data))
        record['finished_utc'] = utc_now()
        save_record(output, record)
    return record


def verify(directories):
    """Validate retained acquisition directories; metadata is evidence, not attestation."""
    errors, rows, payloads, ids, inodes = [], [], [], set(), set()
    for directory in map(Path, directories):
        try:
            r = load_json(directory / 'acquisition.json')
            if r.get('schema_version') != 1 or r.get('status') != 'complete':
                raise CaptureError('acquisition is incomplete, failed or unsupported')
            ident = r.get('acquisition_id')
            if not ident or ident in ids:
                raise CaptureError('missing or repeated independent acquisition ID')
            ids.add(ident)
            bdf = bdf_value(r['bdf'])
            evidence_path = offline_path(directory / 'evidence.json')
            if not stat.S_ISREG(evidence_path.stat().st_mode) or evidence_path.stat().st_size > 1024 * 1024:
                raise CaptureError('evidence snapshot is not a bounded regular file')
            evidence_raw = evidence_path.read_bytes()
            if digest(evidence_raw) != r['evidence_sha256']:
                raise CaptureError('evidence snapshot digest mismatch')
            ev = json.loads(evidence_raw)
            check_evidence(ev, bdf)
            if r.get('data_file') != 'data.bin':
                raise CaptureError('unexpected acquisition filename')
            path = directory / 'data.bin'
            st = path.stat()
            if not stat.S_ISREG(st.st_mode):
                raise CaptureError('acquisition is not a regular file')
            inode = (st.st_dev, st.st_ino)
            if inode in inodes or path.is_symlink():
                raise CaptureError('reused acquisition inode or symlink')
            inodes.add(inode)
            integer(st.st_size, 1, MAX_BYTES, 'retained image length')
            data = path.read_bytes()
            if len(data) != r['bytes'] or digest(data) != r['sha256'] or suspicious(data):
                raise CaptureError('retained bytes/hash mismatch or suspicious blank output')
            if not r.get('started_utc') or not r.get('finished_utc'):
                raise CaptureError('missing acquisition timing')
            start = datetime.fromisoformat(r['started_utc'])
            end = datetime.fromisoformat(r['finished_utc'])
            if start.tzinfo is None or end.tzinfo is None or end < start:
                raise CaptureError('invalid acquisition timing')
            if r.get('mode') == 'vbios' and r.get('source', {}).get('kind') == 'amdgpu_vbios':
                classification = 'software_dump'
                if r['source'].get('identity') != IDENTITY or r.get('expected_bytes') != ev['vbios']['bytes']:
                    raise CaptureError('recorded acquisition identity/length mismatch')
                if r.get('image_type') != classification or r.get('physical_coverage') != []:
                    raise CaptureError('software blob falsely claims physical SPI coverage')
                if len(data) != ev['vbios']['bytes'] or digest(data) != ev['vbios']['sha256']:
                    raise CaptureError('software image differs from recorded evidence')
            elif r.get('mode') == 'spi' and r.get('image_type') == 'controller_dump':
                classification = 'controller_dump'
                capacity, bits = geometry(ev.get('chip'))
                coverage(capacity, bits, r.get('physical_coverage'), len(data))
            else:
                raise CaptureError('unsupported acquisition source/classification')
            rows.append({'directory': str(directory), 'bdf': bdf, 'classification': classification,
                         'bytes': len(data), 'sha256': digest(data), 'start': start.isoformat(),
                         'end': end.isoformat()})
            payloads.append(data)
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            errors.append(f'{directory}: {exc}')
    if rows and len({(r['bdf'], r['classification']) for r in rows}) != 1:
        errors.append('repeat set mixes BDFs or acquisition classes')
    ordered = sorted(rows, key=lambda row: row['start'])
    if any(datetime.fromisoformat(a['end']) > datetime.fromisoformat(b['start'])
           for a, b in zip(ordered, ordered[1:])):
        errors.append('repeat acquisitions overlap; separate initiation is not evidenced')
    matching = bool(payloads) and all(data == payloads[0] for data in payloads)
    if len(payloads) > 1 and not matching:
        errors.append('repeat acquisitions differ byte for byte')
    if not rows:
        errors.append('no valid acquisitions')
    return {'valid': not errors, 'acquisitions': rows, 'errors': errors,
            'matching_bytes': matching, 'independent_records': len(rows),
            'full_chip_verified': False,
            'limitation': 'software blobs have no physical coverage; no audited SPI backend in this build; '
                          'records cannot independently attest that an operator performed separate reads'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    for name in ('plan', 'capture'):
        p = sub.add_parser(name)
        p.add_argument('--evidence', type=Path, required=True)
        p.add_argument('--bdf', required=True)
        if name == 'capture':
            p.add_argument('--mode', choices=('vbios', 'spi'), required=True)
            p.add_argument('--output', type=Path, required=True, help='new acquisition directory')
    v = sub.add_parser('verify')
    v.add_argument('directories', nargs='+', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.operation == 'verify':
            result = verify(args.directories)
            code = 0 if result['valid'] else 1
        else:
            bdf = bdf_value(args.bdf)
            ev = load_json(args.evidence)
            if args.operation == 'plan':
                result, code = plan(ev, bdf), 0
            else:
                if sys.platform != 'linux':
                    raise CaptureError('live capture requires Linux')
                result = capture(ev, bdf, args.mode, args.output)
                code = 0 if result['status'] == 'complete' else 1
        print(json.dumps(result, indent=2))
        return code
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        print(json.dumps({'status': 'blocked', 'error': str(exc)}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
