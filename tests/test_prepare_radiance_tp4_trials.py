"""Offline source-integrity and tile-ownership checks; no GPU runtime is loaded."""
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('prepare_tp4', ROOT / 'tools/prepare_radiance_tp4_trials.py')
prepare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prepare)
SOURCE = Path(os.environ.get('RADIANCE_190_SOURCE', ROOT / '.cache/tp4-trials/upstream-v1.9.0'))


@unittest.skipUnless(SOURCE.is_dir(), 'requires the retained pinned Radiance 1.9.0 source archive')
class PreparationTest(unittest.TestCase):
    def test_change_outside_patch_files_refuses_before_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'source'
            shutil.copytree(SOURCE, source)
            file = source / 'libr4d/r4d_ar_entry.hip'
            file.write_bytes(file.read_bytes() + b'\n// unexpected change\n')
            destination = Path(tmp) / 'must-not-exist'
            with self.assertRaisesRegex(ValueError, 'not the pinned pristine'):
                prepare.prepare(source, destination)
            self.assertFalse(destination.exists())

    def test_fresh_output_and_deterministic_preparation_preserve_input(self):
        before = {p: hashlib.sha256((SOURCE / p).read_bytes()).hexdigest() for p in prepare.PINNED}
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp) / 'a', Path(tmp) / 'b'
            ma = prepare.prepare(SOURCE, a)
            mb = prepare.prepare(SOURCE, b)
            self.assertEqual(ma, mb)
            self.assertEqual(len(ma['original_sha256']), 1051)
            self.assertEqual(ma['default_scan_waves'], 8)
            with self.assertRaisesRegex(ValueError, 'fresh directory'):
                prepare.prepare(SOURCE, a)
            for name in ma['prepared_sha256']:
                self.assertEqual((a / name).read_bytes(), (b / name).read_bytes())
        self.assertEqual(before, {p: hashlib.sha256((SOURCE / p).read_bytes()).hexdigest() for p in prepare.PINNED})

    @unittest.skipUnless(shutil.which('c++'), 'host C++ compiler required for ownership proof')
    def test_compiled_scan_wave_and_prefetch_ownership(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            prepare.prepare(SOURCE, directory / 'source')
            scan = (directory / 'source/libr4d/r4d_gdn_chunk_scan_k128_v128_c64_bf16.hip').read_text()
            geometry = scan[scan.index('#define BT'):scan.index('struct Smem')]
            mappings = scan[scan.index('#if NW == 8\n  const int mt'):scan.index('#define PFW')]
            prefetch = scan[scan.index('#define PFW'):scan.index('  // Do not change: staged rows')]
            code = '''#include <set>
#include <utility>
#include <cassert>
struct uint4 { unsigned x, y, z, w; };
#define __builtin_amdgcn_readfirstlane(x) (x)
''' + geometry + '''
int main() {
  std::set<std::pair<int,int>> main_tiles, state_tiles, k_cells, v_cells;
  for (int w=0; w<NW; ++w) {
''' + mappings + '''
    for (int i=0; i<NTV; ++i) {
      assert(mt>=0 && mt<4 && ntb+i>=0 && ntb+i<4);
      assert(main_tiles.emplace(mt,ntb+i).second);
    }
    for (int i=0; i<SKT; ++i) for(int j=0; j<SVT; ++j) {
      assert(kt0+i>=0 && kt0+i<8 && vt0+j>=0 && vt0+j<4);
      assert(state_tiles.emplace(kt0+i,vt0+j).second);
    }
  }
  assert(main_tiles.size()==16 && state_tiles.size()==32);
  for (int tid=0; tid<NTHR; ++tid) {
''' + prefetch + '''
    for(int u=0;u<NKB;++u) for(int j=0;j<PFW;++j) {
      const int r=kr0+KRU*u,c=kc+j;
      assert(r>=0 && r<BT && c>=0 && c<KD);
      assert(k_cells.emplace(r,c).second);
    }
    for(int u=0;u<NVB;++u) for(int j=0;j<PFW;++j) {
      const int r=vr0+VRU*u,c=vc+j;
      assert(r>=0 && r<BT && c>=0 && c<BV);
      assert(v_cells.emplace(r,c).second);
    }
  }
  assert(k_cells.size()==BT*KD && v_cells.size()==BT*BV);
}
'''
            file = directory / 'ownership.cpp'
            file.write_text(code)
            for waves in [8, 16]:
                binary = directory / f'ownership-{waves}'
                result = subprocess.run(['c++', '-std=c++17', f'-DR4D_TP4_SCAN_NW={waves}',
                                         str(file), '-o', str(binary)], capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                subprocess.run([str(binary)], check=True, timeout=5)


if __name__ == '__main__':
    unittest.main()
