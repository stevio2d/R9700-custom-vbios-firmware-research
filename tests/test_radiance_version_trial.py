"""Host-only tests: never contact the real server or import a GPU runtime."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('radiance_trial', ROOT / 'tools/radiance_version_trial.py')
trial = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trial)


class TrialTest(unittest.TestCase):
    def test_missing_window_confirmation_refuses_before_network_or_output(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / 'must-not-exist'
            proc = subprocess.run([sys.executable, str(ROOT / 'tools/radiance_version_trial.py'),
                'run', '--version', '1.6.0', '--corpus', d, '--out', str(out),
                '--betterbench-root', d, '--pid', '1'],
                capture_output=True, text=True, timeout=5)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn('operator must first confirm', proc.stderr)
            self.assertFalse(out.exists())

    def test_child_is_terminated_at_deadline_and_partial_log_retained(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / 'child.log'
            began = time.monotonic()
            with self.assertRaises(TimeoutError):
                trial.bounded_child([sys.executable, '-u', '-c',
                    'import time; print("partial"); time.sleep(30)'], log, 0.15)
            self.assertLess(time.monotonic() - began, 5)
            self.assertIn('partial', log.read_text())

    def test_fault_guard_terminates_client(self):
        with tempfile.TemporaryDirectory() as d:
            def fault():
                raise RuntimeError('synthetic fault')
            with self.assertRaisesRegex(RuntimeError, 'synthetic fault'):
                trial.bounded_child([sys.executable, '-c', 'import time; time.sleep(30)'],
                                    Path(d) / 'log', 20, fault)

    def test_partial_suite_cannot_pass(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'result.json'
            good = {'ok': True, 'finish_reason': 'stop', 'prompt_tokens': 10,
                    'completion_tokens': 16, 'decode_tps': 100, 'wall_ms': 170, 'ttft_ms': 10}
            data = {'single_stream': {str(i): [good] * 12 for i in range(8)},
                    'prefill': [{'target_depth': n, 'raw_requests': [good] * 6}
                                for n in (2000, 8000, 16000, 32000, 64000)],
                    'concurrency': [{'level': n, 'requests': 32, 'ok': 32, 'raw_requests': [good] * 32}
                                    for n in (1, 2, 4, 8)]}
            p.write_text(json.dumps(data))
            trial.validate_result(p)
            data['prefill'][-1]['raw_requests'].pop()
            p.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, 'prefill samples'):
                trial.validate_result(p)

    def test_missing_usage_or_finish_cannot_pass(self):
        good = {'ok': True, 'finish_reason': 'stop', 'prompt_tokens': 10,
                'completion_tokens': 16, 'decode_tps': 100, 'wall_ms': 170, 'ttft_ms': 10}
        for key in ('finish_reason', 'prompt_tokens', 'completion_tokens'):
            row = dict(good)
            del row[key]
            with self.assertRaisesRegex(ValueError, 'incomplete response'):
                trial.validate_sample(row)
        row = dict(good, decode_tps=float('nan'))
        with self.assertRaisesRegex(ValueError, 'invalid response metric'):
            trial.validate_sample(row)

    def test_one_token_prefill_is_valid_without_a_decode_interval(self):
        row = {'ok': True, 'category': 'prefill', 'finish_reason': 'stop',
               'prompt_tokens': 64000, 'completion_tokens': 1, 'decode_tps': None,
               'pp_tps': 7000, 'wall_ms': 9200, 'ttft_ms': 9150}
        trial.validate_sample(row)
        with self.assertRaisesRegex(ValueError, 'incomplete response'):
            trial.validate_sample(dict(row, category='code'))

    def test_all_workers_require_window_confirmation(self):
        with tempfile.TemporaryDirectory() as d:
            proc = subprocess.run([sys.executable, str(ROOT / 'tools/radiance_version_trial.py'),
                '_suite', '--corpus', d, '--out', str(Path(d) / 'absent'),
                '--betterbench-root', d, '--config', 'absent', '--repeat', '0'],
                capture_output=True, text=True, timeout=5)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn('operator must first confirm', proc.stderr)

    def test_monitor_requires_four_gpus_and_honors_advertised_critical(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for bdf in trial.BDFS:
                hw = root / bdf / 'hwmon/hwmon0'
                hw.mkdir(parents=True)
                (hw / 'temp1_input').write_text('70000')
                (hw / 'temp1_crit').write_text('100000')
            self.assertEqual(set(trial.read_telemetry(root)), set(trial.BDFS))
            (root / trial.BDFS[-1] / 'hwmon/hwmon0/temp1_input').write_text('100001')
            with self.assertRaisesRegex(RuntimeError, 'reached advertised critical'):
                trial.read_telemetry(root)

    def test_quality_requires_complete_nonempty_responses(self):
        class Handler(BaseHTTPRequestHandler):
            finish_reason = 'stop'
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                reply = {'choices': [{'message': {'content': body['messages'][0]['content']},
                                      'finish_reason': self.finish_reason}]}
                data = json.dumps(reply).encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        endpoint = f'http://127.0.0.1:{server.server_port}'
        try:
            rows = trial.quality(endpoint, 'mock', time.monotonic() + 10)
            self.assertEqual(len(rows), len(trial.PROBES))
            self.assertEqual([r['text'] for r in rows], trial.PROBES)
            Handler.finish_reason = 'length'
            with self.assertRaisesRegex(ValueError, 'incomplete'):
                trial.quality(endpoint, 'mock', time.monotonic() + 10)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == '__main__':
    unittest.main()
