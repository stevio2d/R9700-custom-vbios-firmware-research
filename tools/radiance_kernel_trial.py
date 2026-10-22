#!/usr/bin/env python3
"""Run a reviewed GPU command manifest under an independent 28-minute supervisor."""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import time

from radiance_version_trial import bounded_child, read_telemetry, sha256, write_json

FAULT = (r'amdgpu.*(GPU reset|GPU fault|GPU hang|ring .*timeout|MES.*failed|page fault|'
         r'VM_L2_PROTECTION_FAULT)|HW Exception by GPU|GPU HANG|pcieport.*(Timeout|Uncorrect|fatal)')


def group_running(pgid):
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            fields = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
            if int(fields[2]) == pgid and fields[0] not in ('Z', 'X'):
                return True
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            pass
    return False


def supervise_process(command, log, seconds):
    """Bound and clean up the entire session, independently of leader exit."""
    if seconds <= 0:
        raise TimeoutError('kernel trial deadline reached')
    with log.open('x') as output:
        child = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT,
                                 start_new_session=True)
        try:
            rc = child.wait(timeout=seconds)
            if rc:
                raise RuntimeError(f'kernel worker exited {rc}')
            if group_running(child.pid):
                raise RuntimeError('kernel worker left a running descendant')
        except BaseException:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
            # Always kill remaining group members even if the leader exited on TERM.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
            end = time.monotonic() + 3
            while group_running(child.pid) and time.monotonic() < end:
                time.sleep(.05)
            if group_running(child.pid):
                raise RuntimeError('kernel process group is still running after SIGKILL; stop and inspect')
            raise


def manifest_inputs(path):
    data = json.loads(path.read_text())
    if not 1 <= len(data['commands']) <= 300:
        raise ValueError('expected 1..300 reviewed commands')
    for row in data['commands']:
        if (not isinstance(row['argv'], list) or not row['argv'] or
                not all(isinstance(s, str) and s and '\0' not in s for s in row['argv']) or
                not 1 <= row['timeout_seconds'] <= 600 or
                row['argv'][0] not in data['inputs_sha256']):
            raise ValueError('invalid command or unpinned executable')
    check_inputs(data)
    return data


def check_inputs(data):
    for name, expected in data['inputs_sha256'].items():
        if sha256(Path(name)) != expected:
            raise ValueError(f'input changed: {name}')


def host_identity():
    result = subprocess.run(['modinfo', '-n', 'amdgpu'], check=True,
                            capture_output=True, text=True, timeout=5)
    module = Path(result.stdout.strip()).resolve()
    return {'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'kernel': os.uname().release, 'installed_module_path': str(module),
            'installed_module_sha256': sha256(module),
            'loaded_srcversion': Path('/sys/module/amdgpu/srcversion').read_text().strip(),
            'module_source_provenance_qualified': False}


def worker(args):
    if not args.exclusive_window_confirmed:
        raise ValueError('operator must confirm the exclusive window')
    started = time.monotonic()
    deadline = started + args.seconds
    state = {'status': 'running', 'completed_commands': 0,
             'started_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
             'deadline_seconds': args.seconds}
    write_json(args.out / 'status.json', state)
    stop = threading.Event()
    errors = []
    last_log = 0
    def guard():
        nonlocal last_log
        sensors = read_telemetry()
        with (args.out / 'telemetry.jsonl').open('a') as f:
            f.write(json.dumps({'utc': time.time(), 'gpus': sensors}) + '\n')
        if time.monotonic() - last_log < 3:
            return
        last_log = time.monotonic()
        log = subprocess.run(['journalctl', '-k', '--since', state['started_utc'],
                              '--no-pager', '-q'], capture_output=True, text=True, timeout=5)
        (args.out / 'kernel.log').write_text(log.stdout + log.stderr)
        if log.returncode or re.search(FAULT, log.stdout, re.I):
            raise RuntimeError('new GPU/PCIe fault or unavailable kernel monitoring')
    def interrupt(signum, frame):
        raise RuntimeError('monitor stopped trial: ' + str(errors[-1]))
    def monitor():
        while not stop.wait(1):
            try:
                guard()
            except Exception as error:
                errors.append(str(error))
                write_json(args.out / 'monitor-failure.json', {'error': str(error)})
                os.kill(os.getpid(), signal.SIGUSR1)
                return
    old = signal.signal(signal.SIGUSR1, interrupt)
    thread = threading.Thread(target=monitor, daemon=True)
    try:
        if Path(f'/proc/{args.stopped_server_pid}').exists():
            raise ValueError('serving process still exists; stop it in the confirmed exclusive window first')
        manifest = manifest_inputs(args.manifest)
        write_json(args.out / 'manifest.json', manifest)
        write_json(args.out / 'environment.json', {k: v for k, v in os.environ.items()
            if k in ('ROCR_VISIBLE_DEVICES', 'LD_LIBRARY_PATH', 'ROCM_PATH', 'HIP_PATH')})
        guard()
        thread.start()
        identity = host_identity()
        write_json(args.out / 'host-before.json', identity)
        for i, command in enumerate(manifest['commands']):
            check_inputs(manifest)
            seconds = min(command['timeout_seconds'], deadline - time.monotonic())
            state['active_command'] = i
            write_json(args.out / 'status.json', state)
            print(f'command {i + 1}/{len(manifest["commands"])}: {command["label"]}', flush=True)
            try:
                bounded_child(command['argv'], args.out / f'command-{i:03d}.log', seconds,
                              new_session=False)
            except BaseException as error:
                raise RuntimeError(f'kernel command {i} ({command["label"]}) failed; inspect retained log') from error
            state['completed_commands'] += 1
            write_json(args.out / 'status.json', state)
        check_inputs(manifest)
        final = host_identity()
        write_json(args.out / 'host-after.json', final)
        if final != identity or time.monotonic() > deadline:
            raise ValueError('driver/boot identity changed or deadline reached')
        guard()
        if errors:
            raise RuntimeError(errors[-1])
        state['status'] = 'completed'
    except BaseException as error:
        state.update(status='incomplete', error=str(error))
        raise
    finally:
        stop.set()
        if thread.ident is not None:
            thread.join(timeout=6)
        signal.signal(signal.SIGUSR1, old)
        state['elapsed_seconds'] = time.monotonic() - started
        write_json(args.out / 'status.json', state)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['run', '_worker'])
    parser.add_argument('--manifest', type=lambda p: Path(p).resolve(), required=True)
    parser.add_argument('--out', type=lambda p: Path(p).resolve(), required=True)
    parser.add_argument('--seconds', type=int, default=1680)
    parser.add_argument('--stopped-server-pid', type=int, required=True)
    parser.add_argument('--exclusive-window-confirmed', action='store_true')
    args = parser.parse_args()
    if not args.exclusive_window_confirmed or not 1 <= args.seconds <= 1680:
        parser.error('operator must confirm the exclusive window; deadline is 1..1680 seconds')
    if args.stopped_server_pid <= 0:
        parser.error('a real stopped serving PID is required')
    if args.mode == '_worker':
        worker(args)
        return
    args.out.mkdir(parents=True, exist_ok=False)
    command = [sys.executable, str(Path(__file__).resolve()), '_worker',
        '--manifest', str(args.manifest), '--out', str(args.out), '--seconds', str(args.seconds),
        '--stopped-server-pid', str(args.stopped_server_pid), '--exclusive-window-confirmed']
    def interrupted(signum, frame):
        raise RuntimeError('supervisor interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    started = time.monotonic()
    try:
        # Worker, its monitor, and every command share a killable process group.
        supervise_process(command, args.out / 'supervisor.log', args.seconds)
    except BaseException as error:
        path = args.out / 'status.json'
        state = json.loads(path.read_text()) if path.exists() else {}
        state.update(status='incomplete', supervisor_error=str(error),
                     elapsed_seconds=time.monotonic() - started)
        write_json(path, state)
        raise RuntimeError('kernel trial incomplete; inspect status.json and command logs') from error


if __name__ == '__main__':
    main()
