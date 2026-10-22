"""Offline evidence-integrity checks for the release comparison report."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import summarize_radiance_trials as report


class SummaryTest(unittest.TestCase):
    def test_truncated_or_tampered_request_evidence_is_rejected(self):
        config = {'warmup': 0, 'runs_per_category': 1, 'prefill_depths': [],
                  'prefill_warmup': 0, 'prefill_runs': 0,
                  'concurrency_levels': [], 'concurrency_requests': 0}
        request = {'messages': [{'role': 'user', 'content': 'original'}]}
        row = {'request': request,
               'request_sha256': hashlib.sha256(json.dumps(request, sort_keys=True,
                   separators=(',', ':')).encode()).hexdigest(),
               'result': {'ok': True, 'finish_reason': 'stop', 'prompt_tokens': 4,
                          'completion_tokens': 3, 'decode_tps': 100,
                          'ttft_ms': 10, 'wall_ms': 30}}
        report.validate_requests([row], config, 1)
        with self.assertRaisesRegex(ValueError, 'expected 1 recorded requests'):
            report.validate_requests([], config, 1)
        row['request']['messages'][0]['content'] = 'changed'
        with self.assertRaisesRegex(ValueError, 'hash does not match'):
            report.validate_requests([row], config, 1)

    def test_usage_difference_blocks_gain_verdict(self):
        baseline = {'version': {'version': '1.6.0'}, 'status': {'elapsed_seconds': 60},
                    'model': {'sha256': 'same'}, 'config': {}, 'benchmark_inputs': {},
                    'effective_repeat_configs': [{}] * 3,
                    'probe_texts_before': ['same'], 'probe_texts_after': ['same'],
                    'probe_usage_before': [{'completion_tokens': 3}],
                    'probe_usage_after': [{'completion_tokens': 3}],
                    'metrics': {'weighted_decode': {'median': 100, 'min': 99, 'max': 101}}}
        candidate = copy.deepcopy(baseline)
        candidate['version']['version'] = '1.9.0'
        candidate['metrics']['weighted_decode'] = {'median': 120, 'min': 119, 'max': 121}
        requests = [[{'request_sha256': 'same'}]] * 3
        matched = report.compare(baseline, candidate, requests, requests)
        self.assertTrue(matched['comparison_qualified'])
        self.assertTrue(matched['metrics'][0]['gain_above_2pct_and_observed_range'])
        candidate['probe_usage_before'][0]['completion_tokens'] = 4
        comparison = report.compare(baseline, candidate, requests, requests)
        self.assertFalse(comparison['comparison_qualified'])
        self.assertFalse(comparison['metrics'][0]['gain_above_2pct_and_observed_range'])
        rendered = report.markdown(baseline, candidate, comparison)
        self.assertIn('UNQUALIFIED', rendered)
        self.assertNotIn('| yes |', rendered)


if __name__ == '__main__':
    unittest.main()
