#!/usr/bin/env python3
"""Read-only documentation, inventory and preserved-input checks."""

import csv
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


def check(root=ROOT):
    errors = []
    counts = {}

    def require(condition, message):
        if not condition:
            errors.append(message)

    def csv_rows(path):
        with path.open(newline='') as f:
            rows = list(csv.reader(f, strict=True))
        require(bool(rows), f'{path}: empty CSV')
        if not rows:
            return [], []
        header = rows[0]
        require(len(set(header)) == len(header), f'{path}: duplicate CSV headers')
        require(all(len(row) == len(header) for row in rows[1:]), f'{path}: CSV row width')
        return header, [dict(zip(header, row)) for row in rows[1:]]

    def artifact(row, label):
        relative = Path(row['file_path'])
        require(not relative.is_absolute() and '..' not in relative.parts, f'{label}: nonlocal artifact path')
        p = root / relative
        require(p.is_file(), f'{label}: missing {relative}')
        if p.is_file():
            data = p.read_bytes()
            require(len(data) == int(row['bytes']), f'{label}: length mismatch')
            require(hashlib.sha256(data).hexdigest() == row['sha256'], f'{label}: digest mismatch')

    ignored = {'.cache', '.git', 'static-analysis-work', '__pycache__'}
    markdown = [p for p in root.rglob('*.md')
                if not set(p.relative_to(root).parts) & ignored
                and not p.is_relative_to(root / 'sources/originals')]
    links = 0
    fragments = 0
    for p in markdown:
        for match in re.finditer(r'\[[^\]\n]*\]\((<[^>]+>|[^\s)]+)(?:\s+"[^"]*")?\)', p.read_text()):
            target = match[1].strip('<>')
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc:
                continue
            links += 1
            local = (p.parent / unquote(parsed.path)).resolve() if parsed.path else p
            require(local.is_relative_to(root) and local.exists(), f'{p.relative_to(root)}: broken local link {target}')
            if parsed.fragment and local.is_file() and local.suffix == '.md':
                fragments += 1
                anchors = set()
                duplicates = {}
                for title in re.findall(r'^#{1,6}\s+(.+?)\s*#*$', local.read_text(), re.M):
                    slug = re.sub(r'[^\w\- ]', '', title.lower()).replace(' ', '-')
                    count = duplicates.get(slug, 0)
                    duplicates[slug] = count + 1
                    anchors.add(slug + (f'-{count}' if count else ''))
                require(unquote(parsed.fragment) in anchors,
                        f'{p.relative_to(root)}: missing Markdown anchor {target}')
    counts.update(markdown_files=len(markdown), local_links=links, markdown_fragments=fragments)
    chapters = sorted((root / 'docs').glob('[0-9][0-9]_*.md'))
    require(len(chapters) == 11, 'require exactly eleven research chapters')
    readme = (root / 'README.md').read_text()
    for p in chapters:
        require(p.relative_to(root).as_posix() in readme, f'README missing chapter {p.name}')

    all_csv = [p for p in root.rglob('*.csv') if not set(p.relative_to(root).parts) & ignored]
    for p in all_csv:
        csv_rows(p)
    header, roms = csv_rows(root / 'inventory/roms.csv')
    _, cards = csv_rows(root / 'inventory/cards.csv')
    _, packages = csv_rows(root / 'inventory/vendor_packages.csv')
    _, tests = csv_rows(root / 'inventory/test_log.csv')
    for row in tests:
        require(all(row[field].strip() for field in ('test_id', 'experiment_id', 'result', 'log_path')),
                'test_log.csv: actual run rows need IDs, a result and an evidence path')
        log_path = Path(row['log_path'])
        require(not log_path.is_absolute() and '..' not in log_path.parts,
                f'test_log.csv: nonlocal evidence path {row["log_path"]}')
        require((root / log_path).is_file(),
                f'test_log.csv: missing run evidence {row["log_path"]}')
    template = root / 'bios/_template'
    th, tr = csv_rows(template / 'manifest.csv')
    require(th == header and not tr, 'template manifest header/rows mismatch')
    for kind in ('original', 'official', 'modified'):
        require(sorted(p.name for p in (template / kind).iterdir()) == ['.gitkeep'], f'template {kind} changed')
    card_ids = {c['card_id'] for c in cards}
    require(len(card_ids) == len(cards), 'duplicate card IDs')
    union = []
    for card in cards:
        cp = root / card['card_record_path']
        require(cp.is_file() and cp.parent.name == card['card_id'], 'card record path/ID mismatch')
        mh, mr = csv_rows(cp.parent / 'manifest.csv')
        require(mh == header, f'{card["card_id"]}: manifest header mismatch')
        require(all(row['card_id'] == card['card_id'] for row in mr), 'manifest contains another card')
        require(card['stock_rom_sha256'] in {r['sha256'] for r in mr}, 'stock digest absent from card manifest')
        union.extend(mr)
    require(sorted(union, key=lambda r: r['rom_id']) == sorted(roms, key=lambda r: r['rom_id']),
            'ROM inventory differs from card manifests')
    require(len({r['rom_id'] for r in roms}) == len(roms), 'duplicate ROM ID')
    for row in roms:
        require(row['card_id'] in card_ids, 'ROM refers to unknown card')
        artifact(row, row['rom_id'])
    for row in packages:
        artifact(row, row['artifact_id'])
        if row['artifact_role'] == 'firmware_payload':
            require(row['parent_sha256'] in {r['sha256'] for r in packages if r['artifact_role'] == 'vendor_package'},
                    'unassociated payload parent package missing')
    # Example files may be hypothetical; their parent artifact directory must exist in the template.
    for p in markdown:
        for kind in re.findall(r'bios/r9700-asus-001/(original|official|modified)/', p.read_text()):
            require((template / kind).is_dir(), f'{p}: example does not match template')

    source_index = (root / 'sources/README.md').read_text()
    source_rows = re.findall(
        r'^\|\s*(N|R1|R2)\s*\|\s*\[[^]]+\]\(([^)]+)\)\s*\|\s*(\d+)\s*\|\s*`([0-9a-f]{64})`\s*\|$',
        source_index, re.M)
    require({row[0] for row in source_rows} == {'N', 'R1', 'R2'},
            'sources/README.md: expected hashes for N, R1 and R2')
    for source_id, target, expected_bytes, expected_sha256 in source_rows:
        relative = Path(unquote(target))
        require(not relative.is_absolute() and '..' not in relative.parts,
                f'{source_id}: source path must stay within sources/')
        p = root / 'sources' / relative
        require(p.is_file(), f'{source_id}: missing preserved source {relative}')
        if p.is_file():
            data = p.read_bytes()
            require(len(data) == int(expected_bytes), f'{source_id}: preserved source length mismatch')
            require(hashlib.sha256(data).hexdigest() == expected_sha256,
                    f'{source_id}: preserved source digest mismatch')
    counts.update(chapters=len(chapters), csv_files=len(all_csv), cards=len(cards), roms=len(roms),
                  vendor_artifacts=len(packages), preserved_sources=len(source_rows))
    return {'valid': not errors, 'counts': counts, 'errors': errors}


if __name__ == '__main__':
    try:
        result = check()
        print(json.dumps(result, indent=2))
        sys.exit(0 if result['valid'] else 1)
    except (OSError, ValueError, KeyError, csv.Error) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
