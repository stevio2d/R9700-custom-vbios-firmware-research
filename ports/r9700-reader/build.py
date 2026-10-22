#!/usr/bin/env python3
"""Build separate fail-closed and test-only C executables; never load a module."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def build(output, sanitize=False):
    output = Path(output).resolve()
    if not output.is_relative_to(ROOT / '.cache'):
        raise ValueError('build output must be under repository .cache/')
    output.mkdir(parents=True, exist_ok=False)
    compiler = os.environ.get('CC', 'cc')
    version = subprocess.check_output([compiler, '--version'], text=True, timeout=10).splitlines()[0]
    flags = ['-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-Wconversion', '-pedantic']
    if sanitize:
        flags += ['-O1', '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie']
    inputs = sorted(p for p in HERE.iterdir() if p.suffix in ('.c', '.h', '.py', '.json'))
    manifest = {'schema': 1, 'compiler': compiler, 'compiler_version': version, 'flags': flags,
                'crypto_version': subprocess.check_output(['pkg-config', '--modversion', 'openssl'], text=True, timeout=10).strip(),
                'sources': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}}
    inventory = json.loads((HERE / 'cached_inventory.json').read_text())
    evidence = ROOT / inventory['source']
    if evidence != ROOT / 'inventory/host_checks.md' or hashlib.sha256(evidence.read_bytes()).hexdigest() != inventory['source_sha256']:
        raise ValueError('cached device inventory evidence changed; reconcile the snapshot')
    manifest['inventory_evidence'] = {inventory['source']: inventory['source_sha256']}
    common = {k: v for k, v in inventory.items() if k != 'devices'}
    common.update(classification='cached-inventory', live_refreshed=False,
                  active_partition=None, running_firmware_versions=None,
                  limitation='Historical cached PCI identity; unique hardware identifiers are redacted; board labels, flash geometry and advanced live information remain unqualified.')
    records, bdfs = [], set()
    for device in inventory['devices']:
        bdf = device['bdf']
        if not re.fullmatch(r'[0-9a-f]{4}:[0-9a-f]{2}:[01][0-9a-f]\.[0-7]', bdf) or bdf in bdfs:
            raise ValueError('invalid or duplicate cached BDF')
        bdfs.add(bdf)
        records.append({**common, **device})
    header = '#ifndef CACHED_INVENTORY_H\n#define CACHED_INVENTORY_H\n'
    header += 'static const char *const cached_bdfs[] = {' + ','.join(json.dumps(r['bdf']) for r in records) + '};\n'
    header += 'static const char *const cached_info[] = {' + ','.join(json.dumps(json.dumps(r, separators=(',', ':'))) for r in records) + '};\n'
    header += '#define CACHED_LIST ' + json.dumps(json.dumps({**common, 'devices': inventory['devices']}, separators=(',', ':'))) + '\n#endif\n'
    (output / 'cached_inventory.h').write_text(header)
    build_id = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
    (output / 'build.h').write_text(f'#define BUILD_SHA256 "{build_id}"\n')
    manifest['build_sha256'] = build_id
    manifest['outputs'] = {}
    for name, backend, extra in [('r9700-reader', 'blocked.c', []),
                                 ('r9700-reader-mock', 'mock.c', ['-DTEST_TRANSPORT'])]:
        command = [compiler, *flags, *extra, '-I', str(output),
                   *[str(HERE / p) for p in ['main.c', 'record.c', 'window.c', 'image.c', backend]],
                   '-lcrypto', '-o', str(output / name)]
        subprocess.run(command, check=True, timeout=60)
        manifest['outputs'][name] = {'sha256': hashlib.sha256((output / name).read_bytes()).hexdigest(), 'command': command}
    (output / 'build.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--sanitize', action='store_true')
    args = parser.parse_args()
    print(json.dumps(build(args.output, args.sanitize), indent=2))
