#!/usr/bin/env python3
"""Summarize completed version trials offline; never contact a model or GPU."""
import argparse
from collections import Counter
from datetime import datetime
import hashlib
import json
from pathlib import Path
from statistics import median

from radiance_version_trial import validate_result, validate_sample


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_requests(rows, config, category_count):
    expected = (category_count * (config['warmup'] + config['runs_per_category']) +
                len(config['prefill_depths']) * (config['prefill_warmup'] + config['prefill_runs']) +
                len(config['concurrency_levels']) * config['concurrency_requests'])
    if len(rows) != expected:
        raise ValueError(f'expected {expected} recorded requests, found {len(rows)}')
    for row in rows:
        canonical = json.dumps(row['request'], sort_keys=True, separators=(',', ':'))
        if hashlib.sha256(canonical.encode()).hexdigest() != row['request_sha256']:
            raise ValueError('recorded request hash does not match its definition')
        validate_sample(row['result'])


def load_trial(root):
    def read(name):
        return json.loads((root / name).read_text())
    status = read('status.json')
    if status.get('status') != 'completed' or status.get('completed_repeats') != 3:
        raise ValueError(f'{root}: trial is incomplete')
    metrics, repeats, requests, configs = {}, [], [], []
    for i in range(1, 4):
        directory = root / f'repeat-{i}'
        data = validate_result(directory / 'results.json')
        weights = data['config']['weights']
        rates = {k: median(r['decode_tps'] for r in rows)
                 for k, rows in data['single_stream'].items()}
        values = {'weighted_decode': sum(weights[k] * rates[k] for k in weights) / sum(weights.values())}
        values.update({f'prefill_{r["target_depth"]}': median(r['pp_tps']) for r in data['prefill']})
        values.update({f'concurrency_{r["level"]}': r['aggregate_tps'] for r in data['concurrency']})
        for key, value in values.items():
            metrics.setdefault(key, []).append(value)
        rows = [json.loads(line) for line in (directory / 'requests.jsonl').read_text().splitlines()]
        validate_requests(rows, data['config'], len(data['single_stream']))
        requests.append(rows)
        configs.append(data['config'])
        start = datetime.strptime(data['env']['timestamp'], '%Y-%m-%dT%H:%M:%S%z').timestamp()
        finish = (directory / 'results.json').stat().st_mtime
        repeats.append({'repeat': i, 'started_epoch': start, 'finished_epoch': finish,
                        'elapsed_seconds_from_retained_mtime': finish - start,
                        'recorded_requests_including_warmups': len(rows), 'metrics': values})
    for key, values in metrics.items():
        metrics[key] = {'values': values, 'median': median(values), 'min': min(values), 'max': max(values)}
    temperatures, fans = {}, {}
    kernel = (root / 'kernel-window.log').read_text()
    for line in (root / 'telemetry.jsonl').read_text().splitlines():
        row = json.loads(line)
        for bdf, sensors in row['gpus'].items():
            for key, value in sensors.items():
                if key.startswith('temp'):
                    label = f'{bdf}/{value["label"]}'
                    temperatures[label] = max(temperatures.get(label, 0), value['millidegrees_c'] / 1000)
            if 'fan1_input' in sensors:
                values = fans.setdefault(bdf, [])
                values.append(int(sensors['fan1_input']))
    summary = {'version': read('version.json'), 'status': status, 'metrics': metrics,
               'repeats': repeats, 'max_temperatures_c': temperatures,
               'fan_rpm_range': {k: [min(v), max(v)] for k, v in fans.items()},
               'kernel_window_log_empty': not kernel.strip(),
               'model': read('model.json'), 'config': read('config.json'),
               'benchmark_inputs': read('benchmark-inputs.json'),
               'effective_repeat_configs': configs,
               'probe_texts_before': [r['text'] for r in read('quality-before.json')],
               'probe_texts_after': [r['text'] for r in read('quality-after.json')],
               'probe_usage_before': [r['response']['usage'] for r in read('quality-before.json')],
               'probe_usage_after': [r['response']['usage'] for r in read('quality-after.json')],
               'evidence_sha256': {str(p.relative_to(root)): digest(p) for p in sorted(root.rglob('*'))
                                   if p.is_file()}}
    return summary, requests


def compare(baseline, candidate, a_requests, b_requests):
    checks = {
        'same_model_sha256': baseline['model']['sha256'] == candidate['model']['sha256'],
        'same_benchmark_config': baseline['config'] == candidate['config'],
        'same_effective_repeat_configs': baseline['effective_repeat_configs'] == candidate['effective_repeat_configs'],
        'same_benchmark_sources_and_corpus': baseline['benchmark_inputs'] == candidate['benchmark_inputs'],
        'same_probe_texts': baseline['probe_texts_before'] == candidate['probe_texts_before'] ==
                            baseline['probe_texts_after'] == candidate['probe_texts_after'],
        'same_probe_usage_before': baseline['probe_usage_before'] == candidate['probe_usage_before'],
        'same_probe_usage_after': baseline['probe_usage_after'] == candidate['probe_usage_after'],
    }
    for i, (left, right) in enumerate(zip(a_requests, b_requests), 1):
        checks[f'repeat_{i}_same_request_multiset'] = (
            Counter(r['request_sha256'] for r in left) == Counter(r['request_sha256'] for r in right))
    qualified = all(checks.values())
    rows = []
    for key, a in baseline['metrics'].items():
        b = candidate['metrics'][key]
        change = 100 * (b['median'] / a['median'] - 1)
        rows.append({'metric': key, 'baseline': a, 'candidate': b, 'delta_percent': change,
                     'gain_above_2pct_and_observed_range': qualified and change > 2 and b['min'] > a['max'],
                     'regression_above_5pct_and_observed_range': qualified and change < -5 and b['max'] < a['min']})
    return {'matching_checks': checks, 'comparison_qualified': qualified, 'metrics': rows}


def markdown(a, b, comparison):
    lines = ['# Matched Radiance release comparison', '',
             ('Matching checks passed.' if comparison['comparison_qualified'] else
              '**UNQUALIFIED: matching checks failed. Numerical differences cannot justify promotion.**'), '',
             f'Baseline {a["version"]["version"]}: {a["status"]["elapsed_seconds"] / 60:.2f} minutes. '
             f'Candidate {b["version"]["version"]}: {b["status"]["elapsed_seconds"] / 60:.2f} minutes.', '',
             'Three repetitions per version. Rates are tok/s; ranges are the minimum and maximum '
             'of the three suite values, not confidence intervals.', '',
             '| Metric | 1.6.0 median (range) | 1.9.0 median (range) | Change | Clear gain |',
             '|---|---:|---:|---:|---|']
    for row in comparison['metrics']:
        av, bv = row['baseline'], row['candidate']
        lines.append(f'| {row["metric"]} | {av["median"]:.1f} ({av["min"]:.1f}–{av["max"]:.1f}) '
                     f'| {bv["median"]:.1f} ({bv["min"]:.1f}–{bv["max"]:.1f}) '
                     f'| {row["delta_percent"]:+.2f}% '
                     f'| {("yes" if row["gain_above_2pct_and_observed_range"] else "no") if comparison["comparison_qualified"] else "unqualified"} |')
    lines.extend(['', 'Matching checks:', ''])
    lines.extend(f'- {name}: {"pass" if value else "FAIL"}' for name, value in comparison['matching_checks'].items())
    lines.extend(['', 'The response probes are a narrow regression check. This comparison does '
                  'not establish general output quality, restart variability or a causal kernel bottleneck. '
                  'No release is automatically selected by this report.', ''])
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--candidate', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--markdown', type=Path)
    args = parser.parse_args()
    a, ar = load_trial(args.baseline)
    result = {'baseline': a}
    if args.candidate:
        b, br = load_trial(args.candidate)
        result.update(candidate=b, comparison=compare(a, b, ar, br))
        if args.markdown:
            args.markdown.write_text(markdown(a, b, result['comparison']))
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'versions': [a['version']['version']] +
                     ([result['candidate']['version']['version']] if args.candidate else []),
                     'output': str(args.out)}))


if __name__ == '__main__':
    main()
