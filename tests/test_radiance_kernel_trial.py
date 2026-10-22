"""Exercise GPU-trial supervision with CPU children and synthetic monitoring only."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import radiance_kernel_trial as trial


class KernelTrialTest(unittest.TestCase):
    def test_deadline_kills_term_ignoring_grandchild_after_leader_exits(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            pidfile = directory / 'grandchild.pid'
            grandchild = ('import signal,time,os,pathlib; signal.signal(signal.SIGTERM,signal.SIG_IGN); '
                         f'pathlib.Path({str(pidfile)!r}).write_text(str(os.getpid())); time.sleep(30)')
            leader = ('import subprocess,sys,time; subprocess.Popen([sys.executable,"-c",'
                      f'{grandchild!r}]); time.sleep(30)')
            began = time.monotonic()
            with self.assertRaises(subprocess.TimeoutExpired):
                trial.supervise_process([sys.executable, '-c', leader], directory / 'log', .5)
            self.assertLess(time.monotonic() - began, 5)
            self.assertTrue(pidfile.exists())
            proc = Path('/proc') / pidfile.read_text()
            if proc.exists():
                self.assertIn((proc / 'stat').read_text().rsplit(')', 1)[1].split()[0], ['Z', 'X'])

    def test_no_window_confirmation_refuses_before_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'absent'
            result = subprocess.run([sys.executable, str(ROOT / 'tools/radiance_kernel_trial.py'),
                'run', '--manifest', 'absent.json', '--out', str(out), '--stopped-server-pid', '1'],
                capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('confirm the exclusive window', result.stderr)
            self.assertFalse(out.exists())

    def test_changed_input_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / 'input'
            file.write_text('original')
            data = {'inputs_sha256': {str(file): hashlib.sha256(file.read_bytes()).hexdigest()},
                    'commands': [{'label': 'synthetic', 'argv': [str(file)], 'timeout_seconds': 2}]}
            manifest = Path(tmp) / 'manifest.json'
            manifest.write_text(json.dumps(data))
            trial.manifest_inputs(manifest)
            file.write_text('changed')
            with self.assertRaisesRegex(ValueError, 'input changed'):
                trial.manifest_inputs(manifest)

    def test_monitor_failure_terminates_cpu_child_and_retains_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            out = directory / 'out'
            out.mkdir()
            pidfile = directory / 'child.pid'
            code = 'import os,time,pathlib; pathlib.Path(' + repr(str(pidfile)) + ').write_text(str(os.getpid())); time.sleep(30)'
            python = str(Path(sys.executable).resolve())
            data = {'inputs_sha256': {python: trial.sha256(Path(python))},
                    'commands': [{'label': 'sleeping CPU mock', 'argv': [python, '-c', code], 'timeout_seconds': 10}]}
            manifest = directory / 'manifest.json'
            manifest.write_text(json.dumps(data))
            args = types.SimpleNamespace(out=out, manifest=manifest, seconds=5,
                stopped_server_pid=2147483647, exclusive_window_confirmed=True)
            count = 0
            def sensors():
                nonlocal count
                count += 1
                if count > 1:
                    raise RuntimeError('synthetic GPU fault')
                return {'synthetic': {}}
            log = types.SimpleNamespace(returncode=0, stdout='', stderr='')
            with patch.object(trial, 'read_telemetry', sensors), \
                 patch.object(trial, 'host_identity', return_value={'boot': 'synthetic'}), \
                 patch.object(trial.subprocess, 'run', return_value=log):
                with self.assertRaisesRegex(RuntimeError, 'kernel command'):
                    trial.worker(args)
            state = json.loads((out / 'status.json').read_text())
            self.assertEqual(state['status'], 'incomplete')
            self.assertEqual(state['completed_commands'], 0)
            self.assertIn('synthetic GPU fault', (out / 'monitor-failure.json').read_text())
            self.assertTrue(pidfile.exists())
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pidfile.read_text()), 0)


if __name__ == '__main__':
    unittest.main()
