#!/usr/bin/env python3
"""Prepare an isolated, hash-pinned Radiance 1.9.0 TP4 trial source tree."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

PINNED = {
    'libr4d/r4d_selftest.cpp': 'b4e30e11864549eb9f3d8bf48511738ae8862e8da381f7e0bfff38a13e12d216',
    'libr4d/r4d_gdn_chunk_scan_k128_v128_c64_bf16.hip': 'b36561e7c4dce9132f0b9d9796a28b0e10146265dc2212fbc9c30e05e379518f',
}
ROOT = Path(__file__).resolve().parents[1]
MANIFEST_SHA256 = 'b3c676a083e7e16afbb87f1a0a15c6ca5ef6b77c5bd744354a53c220c84f9627'


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f'expected exactly one source anchor: {old[:80]}')
    return text.replace(old, new, 1)


def specialize_gdn(scan):
    """Instantiate both wave counts; specialize only the measured TP4 geometry."""
    scan = replace_once(scan, '''#ifndef R4D_TP4_SCAN_NW
#define R4D_TP4_SCAN_NW 8
#endif
#define NW R4D_TP4_SCAN_NW''', '// NW is a kernel template parameter: retain the stock eight-wave fallback.')
    scan = replace_once(scan, '''#if NW == 8
#define NTV 2
#elif NW == 16
#define NTV 1
#else
#error "R4D_TP4_SCAN_NW must be 8 or 16"
#endif''', '#define NTV (16 / NW)')
    scan = replace_once(scan, '''#if NW == 8
#define SKT 2
#else
#define SKT 1
#endif''', '#define SKT (16 / NW)')
    scan = replace_once(scan, 'template <int SDT, bool H0 = true, bool HT = true>',
                        'template <int NW, int SDT, bool H0 = true, bool HT = true>')
    scan = replace_once(scan, '''#if NW == 8
  const int mt = w >> 1, ntb = (w & 1) * 2;
#else
  const int mt = w >> 2, ntb = w & 3;
#endif''', '  const int mt = w / (NW / 4), ntb = (w % (NW / 4)) * NTV;')
    scan = replace_once(scan, 'dim3 grid(V / BV, H, N), blk(NTHR);', 'dim3 grid(V / BV, H, N);')
    scan = replace_once(scan, '#define CS_LAUNCH(SDTC, H0C, HTC)', '#define CS_LAUNCH(NWC, SDTC, H0C, HTC)')
    scan = replace_once(scan, '(r4d_gdn_chunk_scan_kernel<SDTC, H0C, HTC>), grid, blk, 0,',
                        '(r4d_gdn_chunk_scan_kernel<NWC, SDTC, H0C, HTC>), grid, dim3(NWC * 32), 0,')
    scan = replace_once(scan, '#define CS_PICK(SDTC)', '#define CS_PICK(NWC, SDTC)')
    for h0, ht in [('true', 'true'), ('true', 'false'), ('false', 'true'), ('false', 'false')]:
        scan = replace_once(scan, f'CS_LAUNCH(SDTC, {h0}, {ht})', f'CS_LAUNCH(NWC, SDTC, {h0}, {ht})')
    scan = replace_once(scan, '  if (state_fp16) CS_PICK(1); else CS_PICK(0);', '''  // Measured on TP4 Flash-Next: one sequence, twelve value/four key heads,
  // with retained state. Preserve the stock schedule for every other geometry.
  if (N == 1 && H == 12 && Hg == 4 && h0 && ht) {
    if (state_fp16) CS_PICK(16, 1); else CS_PICK(16, 0);
  } else {
    if (state_fp16) CS_PICK(8, 1); else CS_PICK(8, 0);
  }''')
    return scan


def specialize_moe(moe):
    """Change measured TP4 shapes only, preserving every explicit test pin."""
    start = moe.index('static int moe_gemm_launch(')
    end = moe.index('extern "C" int64_t r4d_rad_moe_gemm_q_scratch')
    prefix, suffix = moe[:start], moe[end:]
    moe = moe[start:end]
    moe = replace_once(moe, '''    const uint32_t ny = (uint32_t)(N / 64);
    const int form = g_moe_prefill_form;''', '''    const uint32_t ny = (uint32_t)(N / 64);
    // EXP-0003: resident Flash-Next TP4, compact regular expert classes.
    bool tp4_shape = W4 == 2 && ncls == 4 && top_k == 10 &&
                     (n_expert == 512 || n_expert == 510 || n_expert == 508) &&
                     wdt && !std::strcmp(wdt, "w4nl64a8h");
    int wide_classes = 0;
    for (int q = 0; q < ncls; ++q) {
        const bool wide = a_sorted ? Kc[q] == 256 : Nc[q] == 512;
        wide_classes += wide;
        tp4_shape = tp4_shape && (a_sorted ? Nc[q] == 2560 && (Kc[q] == 128 || wide)
                                                        : Kc[q] == 2560 && (Nc[q] == 256 || wide));
    }
    tp4_shape = tp4_shape && wide_classes == 1 && parts == (a_sorted ? 1 : 2);
    const bool tp4_group8 = tp4_shape && a_sorted && T >= 5120 && T <= 20480 &&
                           g_moe_prefill_form == 0 && g_moe_down_dec_pin == 0 &&
                           g_moe_down_tile_pin == 0;
    const int form = tp4_group8 ? 2 : g_moe_prefill_form;''')
    moe = replace_once(moe, '        const long long g2 = r4d_moe_down_dec_g(T);',
                        '        const long long g2 = tp4_group8 ? 8 : r4d_moe_down_dec_g(T);')
    moe = replace_once(moe, '            bool fk2 = r4d_moe_gu_fk256<W4>(T, a_sorted);', '''            bool fk2 = r4d_moe_gu_fk256<W4>(T, a_sorted);
            if (tp4_shape && !a_sorted && T <= 650 && g_moe_fk_pin == 0) fk2 = true;''')
    return prefix + moe + suffix


def prepare(source, destination, gdn_specialization=False, moe_specialization=False):
    source, destination = source.resolve(), destination.resolve()
    if destination.exists() or source == destination or source in destination.parents:
        raise ValueError('destination must be a fresh directory outside the source')
    manifest = json.loads((ROOT / 'experiments/EXP-0002/build-1.9.0/build-provenance.json').read_text())['source_files_sha256']
    encoded = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()
    if hashlib.sha256(encoded).hexdigest() != MANIFEST_SHA256:
        raise ValueError('upstream source manifest identity changed')
    files = {str(p.relative_to(source)) for p in source.rglob('*') if p.is_file()}
    if files != set(manifest) or any(p.is_symlink() for p in source.rglob('*')):
        raise ValueError('source tree file set differs from pristine archive')
    for name, wanted in manifest.items():
        if hashlib.sha256((source / name).read_bytes()).hexdigest() != wanted:
            raise ValueError(f'not the pinned pristine v1.9.0 source: {name}')
    cpp = (source / 'libr4d/r4d_selftest.cpp').read_text()
    payload = (ROOT / 'patches/radiance-v1.9.0/tp4_trials.inc').read_text()
    cpp = replace_once(cpp, 'int main(int argc, char** argv) {', '''#ifdef RAD_HAVE_HIP
#include "tp4_trials.inc"
#endif

int main(int argc, char** argv) {
#ifdef RAD_HAVE_HIP
    if (argc > 2 && !std::strncmp(argv[2], "--tp4-", 6))
        return tp4_main(argc, argv);
#endif''')
    scan_name = 'libr4d/r4d_gdn_chunk_scan_k128_v128_c64_bf16.hip'
    scan = (source / scan_name).read_text()
    scan = replace_once(scan, '#define NW    8', '''#ifndef R4D_TP4_SCAN_NW
#define R4D_TP4_SCAN_NW 8
#endif
#define NW R4D_TP4_SCAN_NW''')
    scan = replace_once(scan, '#define NTV   2                 // n tiles per wave in the main / V\' / O loops', '''#if NW == 8
#define NTV 2
#elif NW == 16
#define NTV 1
#else
#error "R4D_TP4_SCAN_NW must be 8 or 16"
#endif''')
    scan = replace_once(scan, '#define SKT   2', '''#if NW == 8
#define SKT 2
#else
#define SKT 1
#endif
//''')
    scan = replace_once(scan,
        '  const int mt = w >> 1, ntb = (w & 1) * 2;                 // [BT][BV]: 2 tiles/wave',
        '''#if NW == 8
  const int mt = w >> 1, ntb = (w & 1) * 2;
#else
  const int mt = w >> 2, ntb = w & 3;
#endif''')
    scan = replace_once(scan,
        '  const int kt0 = (w >> 1) * 2, vt0 = (w & 1) * 2;           // 2 x 2',
        '  const int kt0 = (w >> 1) * SKT, vt0 = (w & 1) * SVT;')
    if gdn_specialization:
        scan = specialize_gdn(scan)
    moe_name = 'libr4d/r4d_moe.hip'
    moe = specialize_moe((source / moe_name).read_text()) if moe_specialization else None
    # All edits are prepared before creating output, so unknown source fails closed.
    shutil.copytree(source, destination)
    (destination / 'libr4d/r4d_selftest.cpp').write_text(cpp)
    (destination / 'libr4d/tp4_trials.inc').write_text(payload)
    (destination / scan_name).write_text(scan)
    changes = ['libr4d/r4d_selftest.cpp', 'libr4d/tp4_trials.inc', scan_name]
    if moe is not None:
        (destination / moe_name).write_text(moe)
        changes.append(moe_name)
    manifest = {'upstream_commit': '685ec5bd858a31e90ba0431e844e3353c8c266fc',
                'original_sha256': manifest, 'source_manifest_sha256': MANIFEST_SHA256,
                'prepared_sha256': {p: hashlib.sha256((destination / p).read_bytes()).hexdigest()
                                    for p in changes},
                'default_scan_waves': 8, 'production_dispatch_changed': gdn_specialization or moe_specialization,
                'gdn_specialization': 'N=1 H=12 Hg=4 h0+ht: NW16' if gdn_specialization else None,
                'moe_specialization': 'TP4 GU FK256 T<=650; down G8 5120<=T<=20480' if moe_specialization else None}
    (destination / 'TP4_PREPARATION.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--destination', required=True, type=Path)
    parser.add_argument('--gdn-specialization', action='store_true')
    parser.add_argument('--moe-specialization', action='store_true')
    args = parser.parse_args()
    manifest = prepare(args.source, args.destination, args.gdn_specialization, args.moe_specialization)
    print(json.dumps({'destination': str(args.destination),
                      'verified_upstream_files': len(manifest['original_sha256']),
                      'prepared_sha256': manifest['prepared_sha256']}, indent=2))


if __name__ == '__main__':
    main()
