#!/usr/bin/env python3
"""Bounded matched BetterBench trials; never start, stop, or reconfigure a server.

Run only after the operator releases an exclusive GPU window. Preparation and
offline comparison need no GPU. BetterBench is imported only in a suite child.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import random
import re
import signal
import subprocess
import sys
import threading
import time
import types
import urllib.request


CONFIG = {
    'greedy': True, 'seed': 9700, 'temperature': 0.0,
    'warmup': 2, 'runs_per_category': 12,
    'unique_nonce': True, 'run_single_stream': True,
    'run_prefill': True, 'prefill_depths': [2000, 8000, 16000, 32000, 64000],
    'prefill_warmup': 2, 'prefill_runs': 6, 'prefill_max_tokens': 16,
    'run_concurrency': True, 'concurrency_levels': [1, 2, 4, 8],
    'concurrency_requests': 32, 'max_model_len': 262144, 'timeout_s': 120,
    'extra_body': {'chat_template_kwargs': {'enable_thinking': False}},
}
PROBES = [
    'Reply with only the integer result of 17 + 25.',
    'Return only a JSON object with keys "name" and "count", values "r9700" and 4.',
    'Reply with only the Python expression that reverses a list named xs using slicing.',
    'Sort these integers ascending and reply with only a comma-separated list: 9, 1, 5, 3.',
    'Reply with only the capital city of Australia.',
    'Translate "good morning" into French. Reply with only the translation.',
]
BDFS = ['0000:03:00.0', '0000:06:00.0', '0000:83:00.0', '0000:86:00.0']


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def benchmark_fingerprint(root, corpus):
    files = sorted(set((root / 'betterbench').rglob('*.py')) |
                   set(corpus.rglob('*.jsonl')) | {root / 'pyproject.toml'})
    return {str(p.resolve()): sha256(p) for p in files}


def server_fingerprint(pid):
    proc = Path('/proc') / str(pid)
    mappings = set()
    for line in (proc / 'maps').read_text().splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) == 6 and fields[5].startswith('/') and '.so' in fields[5]:
            mappings.add(fields[5])
    command = (proc / 'cmdline').read_bytes().decode().split('\0')[:-1]
    model = Path(command[command.index('--model') + 1]).resolve()
    st = model.stat()
    return {'exe_path': str((proc / 'exe').resolve()), 'exe_sha256': sha256(proc / 'exe'),
            'cmdline': command, 'model': {'path': str(model), 'bytes': st.st_size,
                'mtime_ns': st.st_mtime_ns, 'inode': st.st_ino, 'device': st.st_dev},
            'start_ticks': (proc / 'stat').read_text().rsplit(')', 1)[1].split()[19],
            'libraries': {p: sha256(Path(p)) for p in sorted(mappings)}}


def read_telemetry(sysfs=Path('/sys/bus/pci/devices')):
    rows = {}
    for bdf in BDFS:
        dev = sysfs / bdf
        sensors = {}
        for hw in (dev / 'hwmon').glob('hwmon*'):
            for p in sorted(hw.glob('temp*_input')):
                stem = p.name.removesuffix('_input')
                label = (hw / (stem + '_label'))
                crit = hw / (stem + '_crit')
                value = int(p.read_text())
                limit = int(crit.read_text()) if crit.is_file() else None
                sensors[stem] = {'label': label.read_text().strip() if label.exists() else stem,
                                 'millidegrees_c': value, 'critical_millidegrees_c': limit}
                if limit is not None and value >= limit:
                    raise RuntimeError(f'{bdf} {stem}={value} mC reached advertised critical={limit} mC')
            for name in ('power1_average', 'power1_cap', 'fan1_input'):
                p = hw / name
                if p.is_file():
                    sensors[name] = p.read_text().strip()
        if not sensors or not any(isinstance(v, dict) and v['critical_millidegrees_c'] is not None
                                  for v in sensors.values()):
            raise RuntimeError(f'{bdf}: temperature/critical telemetry unavailable')
        for name in ('gpu_busy_percent', 'mem_busy_percent', 'mem_info_vram_used',
                     'mem_info_vram_total', 'pp_dpm_sclk', 'pp_dpm_mclk'):
            p = dev / name
            if p.is_file():
                sensors[name] = p.read_text().strip()
        rows[bdf] = sensors
    return rows


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def get_json(endpoint, path, payload=None, timeout=5):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(endpoint.rstrip('/') + path, data=data,
                                 headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.load(response)


def quality(endpoint, model, deadline):
    records = []
    for prompt in PROBES:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('trial deadline reached during correctness probes')
        body = {'model': model, 'messages': [{'role': 'user', 'content': prompt}],
                'temperature': 0, 'seed': 9700, 'max_tokens': 128, 'stream': False,
                'chat_template_kwargs': {'enable_thinking': False}}
        reply = get_json(endpoint, '/v1/chat/completions', body, min(120, remaining))
        choice = reply['choices'][0]
        text = choice['message']['content']
        if not isinstance(text, str) or not text.strip() or choice.get('finish_reason') != 'stop':
            raise ValueError('incomplete or empty correctness probe')
        records.append({'request': body, 'response': reply, 'text': text,
                        'text_sha256': hashlib.sha256(text.encode()).hexdigest()})
    return records


def suite(args):
    if not args.exclusive_window_confirmed:
        raise ValueError('operator must first confirm the exclusive window')
    sys.path.insert(0, str(args.betterbench_root))
    # A fresh child isolates the nonce generator, recorder, and imported CLI.
    from betterbench import client, runner
    from betterbench.cli import main as bb_main
    phase = 0

    def make_rng():
        nonlocal phase
        phase += 1
        return random.Random(970000 + args.repeat * 100 + phase)

    # BetterBench's --seed controls sampling, but its nonce RNG normally uses
    # OS entropy. Replace only this module's RNG factory in this isolated child.
    runner.random = types.SimpleNamespace(Random=make_rng)
    original = client.stream_chat_sync
    lock = threading.Lock()
    with (args.out / 'requests.jsonl').open('x') as evidence:
        def capture(endpoint, model, messages, **kwargs):
            request = {k: v for k, v in kwargs.items() if k != 'api_key'}
            request.update(model=model, messages=messages)
            canonical = json.dumps(request, sort_keys=True, separators=(',', ':'))
            result = original(endpoint, model, messages, **kwargs)
            # Retain the original visible-window rate, and measure decode to
            # response completion so invisible trailing tokens cannot inflate it.
            result.visible_decode_tps = result.decode_tps
            if result.ok and result.completion_tokens and result.ttft_ms is not None:
                duration_ms = result.wall_ms - result.ttft_ms
                if duration_ms > 0 and result.completion_tokens > 1:
                    result.decode_tps = (result.completion_tokens - 1) * 1000 / duration_ms
            with lock:
                evidence.write(json.dumps({'request': request,
                    'request_sha256': hashlib.sha256(canonical.encode()).hexdigest(),
                    'result': result.as_dict()}) + '\n')
                evidence.flush()
            validate_sample(result.as_dict())
            return result

        client.stream_chat_sync = capture
        os.environ['BETTERBENCH_NO_UPDATE_CHECK'] = '1'
        bb_main(['run', '--endpoint', args.endpoint.rstrip('/') + '/v1',
                 '--model', args.model, '--config', str(args.config),
                 '--corpus', str(args.corpus), '--no-update-check',
                 '--out', str(args.out / 'results.json')])


def validate_sample(row):
    prefill = row.get('category') == 'prefill'
    if (not row.get('ok') or row.get('finish_reason') not in ('stop', 'length') or
            not isinstance(row.get('prompt_tokens'), int) or row['prompt_tokens'] <= 0 or
            not isinstance(row.get('completion_tokens'), int) or
            row['completion_tokens'] < (1 if prefill else 2)):
        raise ValueError('incomplete response: finish reason and token usage required')
    for key in ('pp_tps' if prefill else 'decode_tps', 'ttft_ms', 'wall_ms'):
        value = row.get(key)
        if not isinstance(value, (float, int)) or not math.isfinite(value) or value <= 0:
            raise ValueError(f'invalid response metric: {key}')


def validate_result(path):
    data = json.loads(path.read_text())
    if len(data.get('single_stream', {})) != 8:
        raise ValueError('expected all eight decode categories')
    for rows in data['single_stream'].values():
        if len(rows) != CONFIG['runs_per_category'] or not all(r.get('ok') for r in rows):
            raise ValueError('incomplete or failed decode samples')
    if [r['target_depth'] for r in data.get('prefill', [])] != CONFIG['prefill_depths']:
        raise ValueError('incomplete prefill sweep')
    for row in data['prefill']:
        raw = row.get('raw_requests', [])
        if len(raw) != CONFIG['prefill_runs'] or not all(r.get('ok') for r in raw):
            raise ValueError('incomplete or failed prefill samples')
    if [r['level'] for r in data.get('concurrency', [])] != CONFIG['concurrency_levels']:
        raise ValueError('incomplete concurrency sweep')
    for row in data['concurrency']:
        if row['requests'] != CONFIG['concurrency_requests'] or row['ok'] != row['requests']:
            raise ValueError('incomplete or failed concurrency samples')
        if len(row.get('raw_requests', [])) != row['requests']:
            raise ValueError('missing concurrency request evidence')
    for rows in data['single_stream'].values():
        for row in rows:
            validate_sample(row)
    for group in data['prefill'] + data['concurrency']:
        for row in group['raw_requests']:
            validate_sample(row)
    return data


def bounded_child(command, log, seconds, guard=lambda: None, new_session=True):
    if seconds <= 0:
        raise TimeoutError('trial deadline reached')
    with log.open('x') as output:
        child = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT,
                                 start_new_session=new_session)
        def terminate():
            try:
                if new_session:
                    os.killpg(child.pid, signal.SIGTERM)
                else:
                    child.terminate()
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                if new_session:
                    os.killpg(child.pid, signal.SIGKILL)
                else:
                    child.kill()
                child.wait(timeout=3)
        try:
            deadline = time.monotonic() + seconds
            while child.poll() is None:
                guard()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('trial deadline reached')
                try:
                    child.wait(timeout=min(1, remaining))
                except subprocess.TimeoutExpired:
                    pass
            rc = child.returncode
        except BaseException:
            terminate()
            raise
        if rc:
            terminate()
    if rc:
        raise RuntimeError(f'BetterBench child exited {rc}; see {log}')


def run(args):
    if not args.exclusive_window_confirmed:
        raise ValueError('operator must first confirm the exclusive window')
    if not 1 <= args.seconds <= 1680:
        raise ValueError('deadline must be 1..1680 seconds (28 minutes)')
    if not args.corpus.is_dir():
        raise ValueError('corpus directory missing')
    # The supervisor reserved this fresh directory before spawning this worker.
    started = time.monotonic()
    deadline = started + args.seconds
    state = {'status': 'running', 'version_expected': args.version,
             'started_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
             'deadline_seconds': args.seconds, 'completed_repeats': 0}
    write_json(args.out / 'status.json', state)
    last_check = 0.0
    monitor_stop = threading.Event()
    monitor_error = []

    def guard():
        nonlocal last_check
        sensors = read_telemetry()
        with (args.out / 'telemetry.jsonl').open('a') as output:
            output.write(json.dumps({'utc': time.time(), 'gpus': sensors}) + '\n')
        if time.monotonic() - last_check < 3:
            return
        last_check = time.monotonic()
        result = subprocess.run(['journalctl', '-k', '--since', state['started_utc'],
                                 '--no-pager', '-q'], capture_output=True, text=True, timeout=5)
        (args.out / 'kernel-window.log').write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError('kernel log unavailable; measurement stopped')
        pattern = (r'amdgpu.*(GPU reset|GPU fault|GPU hang|ring .*timeout|MES.*failed|'
                   r'page fault|VM_L2_PROTECTION_FAULT)|HW Exception by GPU|GPU HANG|'
                   r'pcieport.*(Timeout|Uncorrect|fatal)')
        if re.search(pattern, result.stdout, re.I):
            raise RuntimeError('new GPU/PCIe error; stop and inspect kernel-window.log')

    def interrupt(signum, frame):
        raise RuntimeError('monitor stopped trial: ' + str(monitor_error[-1]))

    def monitor():
        while not monitor_stop.wait(1):
            try:
                guard()
            except Exception as error:
                monitor_error.append(str(error))
                write_json(args.out / 'monitor-failure.json', {'error': str(error)})
                os.kill(os.getpid(), signal.SIGUSR1)
                return

    old_handler = signal.signal(signal.SIGUSR1, interrupt)
    thread = threading.Thread(target=monitor, daemon=True)

    try:
        guard()
        frozen = benchmark_fingerprint(args.betterbench_root, args.corpus)
        write_json(args.out / 'benchmark-inputs.json', frozen)
        identity = server_fingerprint(args.pid)
        write_json(args.out / 'server-before.json', identity)
        thread.start()
        # Hash the real container within the independently bounded window.
        # Its stat identity is checked again after the trial, without a second
        # 122 GB read that would spend the measurement budget on file I/O.
        write_json(args.out / 'model.json', dict(identity['model'],
            sha256=sha256(Path(identity['model']['path']))))
        version = get_json(args.endpoint, '/version')
        write_json(args.out / 'version.json', version)
        if version.get('version') != args.version:
            raise ValueError(f'wrong running version: {version}')
        health = get_json(args.endpoint, '/health')
        write_json(args.out / 'health-before.json', health)
        if health.get('status') != 'ok' or health.get('in_flight') != 0:
            raise ValueError('server must be healthy and idle before trial')
        write_json(args.out / 'config.json', CONFIG)
        before = quality(args.endpoint, args.model, deadline)
        write_json(args.out / 'quality-before.json', before)
        for repeat in range(3):
            target = args.out / f'repeat-{repeat + 1}'
            target.mkdir()
            command = [sys.executable, str(Path(__file__).resolve()), '_suite',
                       '--endpoint', args.endpoint, '--model', args.model,
                       '--config', str(args.out / 'config.json'), '--corpus', str(args.corpus),
                       '--out', str(target), '--repeat', str(repeat),
                       '--betterbench-root', str(args.betterbench_root), '--exclusive-window-confirmed']
            if benchmark_fingerprint(args.betterbench_root, args.corpus) != frozen:
                raise ValueError('BetterBench source/corpus changed during trial')
            bounded_child(command, target / 'betterbench.log', deadline - time.monotonic(),
                          new_session=False)
            validate_result(target / 'results.json')
            state['completed_repeats'] += 1
            write_json(args.out / 'status.json', state)
        after = quality(args.endpoint, args.model, deadline)
        write_json(args.out / 'quality-after.json', after)
        if [r['text'] for r in before] != [r['text'] for r in after]:
            raise ValueError('deterministic responses changed within the same version')
        health = get_json(args.endpoint, '/health')
        write_json(args.out / 'health-after.json', health)
        if health.get('status') != 'ok' or health.get('in_flight') != 0:
            raise ValueError('server not healthy and idle after trial')
        if time.monotonic() > deadline:
            raise TimeoutError('trial exceeded its deadline')
        final = server_fingerprint(args.pid)
        write_json(args.out / 'server-after.json', final)
        if final != identity or benchmark_fingerprint(args.betterbench_root, args.corpus) != frozen:
            raise ValueError('server or benchmark inputs changed during trial')
        state['status'] = 'completed'
    except BaseException as error:
        state.update(status='incomplete', error=str(error))
        raise
    finally:
        monitor_stop.set()
        if thread.ident is not None:
            thread.join(timeout=6)
        signal.signal(signal.SIGUSR1, old_handler)
        state['elapsed_seconds'] = time.monotonic() - started
        write_json(args.out / 'status.json', state)


def supervise(args):
    if not args.exclusive_window_confirmed:
        raise ValueError('operator must first confirm the exclusive window')
    if not 1 <= args.seconds <= 1680:
        raise ValueError('deadline must be 1..1680 seconds (28 minutes)')
    args.out.mkdir(parents=True, exist_ok=False)
    command = [sys.executable, str(Path(__file__).resolve()), '_run',
               '--endpoint', args.endpoint, '--model', args.model, '--version', args.version,
               '--corpus', str(args.corpus), '--out', str(args.out), '--pid', str(args.pid),
               '--seconds', str(args.seconds), '--betterbench-root', str(args.betterbench_root),
               '--exclusive-window-confirmed']
    started = time.monotonic()
    try:
        # All network calls, probes, monitors and suites are in this process
        # group. A trickling HTTP response cannot extend this independent clock.
        bounded_child(command, args.out / 'supervisor.log', args.seconds)
    except BaseException as error:
        path = args.out / 'status.json'
        state = json.loads(path.read_text()) if path.is_file() else {}
        state.update(status='incomplete', supervisor_error=str(error),
                     elapsed_seconds=time.monotonic() - started)
        write_json(path, state)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    for mode in ('run', '_run', '_suite'):
        p = sub.add_parser(mode)
        p.add_argument('--endpoint', default='http://127.0.0.1:8001')
        p.add_argument('--model', default='Qwen3.8-Flash-Next')
        p.add_argument('--corpus', type=Path, required=True)
        p.add_argument('--betterbench-root', type=lambda x: Path(x).resolve(), required=True)
        p.add_argument('--out', type=lambda x: Path(x).resolve(), required=True)
        p.add_argument('--exclusive-window-confirmed', action='store_true')
        if mode != '_suite':
            p.add_argument('--version', required=True)
            p.add_argument('--pid', type=int, required=True)
            p.add_argument('--seconds', type=int, default=1680)
        else:
            p.add_argument('--repeat', type=int, required=True)
            p.add_argument('--config', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        {'run': supervise, '_run': run, '_suite': suite}[args.mode](args)
    except Exception as error:
        parser.exit(1, f'{error}\n')


if __name__ == '__main__':
    main()
