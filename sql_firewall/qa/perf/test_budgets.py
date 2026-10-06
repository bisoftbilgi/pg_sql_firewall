#!/usr/bin/env python3
"""Offline regressions for incomplete runs, final windows and audit accounting."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

EVALUATOR = Path(__file__).with_name('budgets.py')


class BudgetTests(unittest.TestCase):
    def evaluate(self, duration=1800, total=180000, loss=0, caught='yes', written=None, anon='1000->1000', only='p4p7'):
        with tempfile.TemporaryDirectory(prefix='sqlfw-budget-') as name:
            run = Path(name)
            (run / 'pgbench').mkdir()
            (run / 'manifest.txt').write_text(
                f'perf_only={only}\nshared_memory_size_A=552MB\nshared_memory_size_B=568MB\n'
                f'long_consumer_anon_kb={anon}\nserver_errors=0\n'
                f'long_loss_delta={loss},0,0\nlong_caught_up={caught}\n'
                f'long_published_delta=180000\nlong_written={180000-loss if written is None else written}\n')
            (run / 'results.csv').write_text(
                'config,workload,clients,rate,duration,tps,act_skipped,act_rejected,act_publish_failed,act_lag_p99_s,failed\n'
                'E,W1,8,2000,300,2000,0,0,0,0.1,0\n')
            (run / 'long_samples.csv').write_text(
                'activity_rows,skipped\n1000,0\n1000,0\n')
            lines = [f'progress: {t}.0 s, 100.0 tps' for t in range(60, duration, 60)]
            (run / 'pgbench/long.out').write_text('\n'.join(lines) +
                f'\nduration: {duration} s\nnumber of transactions actually processed: {total}\n'
                'number of failed transactions: 0\n')
            result = subprocess.run([sys.executable, str(EVALUATOR), str(run)], text=True, capture_output=True)
            return result.returncode, result.stdout

    def test_complete_stable_run(self):
        status, output = self.evaluate()
        self.assertEqual(status, 0, output)
        self.assertIn('| P7 | PASS | 30 min', output)
        self.assertIn('| P7.audit | PASS |', output)

    def test_final_unprinted_minute_changes_final_window(self):
        # 29 minutes at 100 TPS, final minute at 400 TPS. Old evaluation
        # sees only 100 TPS lines and incorrectly passes the drift criterion.
        status, output = self.evaluate(total=198000)
        self.assertEqual(status, 1, output)
        self.assertIn('100.00/160.00 (+60.0%', output)

    def test_ten_minute_run_cannot_pass_thirty_minute_gate(self):
        status, output = self.evaluate(duration=600, total=60000)
        self.assertEqual(status, 1, output)
        self.assertIn('requires at least 1800s', output)

    def test_terminal_audit_loss_is_separate_failure(self):
        status, output = self.evaluate(loss=5)
        self.assertEqual(status, 1, output)
        self.assertIn('| P7 | PASS |', output)
        self.assertIn('| P7.audit | FAIL | terminal losses 5', output)

    def test_pending_backlog_is_not_pass(self):
        status, output = self.evaluate(caught='no')
        self.assertEqual(status, 1, output)
        self.assertIn('caught up False', output)

    def test_missing_records_are_not_hidden_by_zero_loss(self):
        status, output = self.evaluate(written=179990)
        self.assertEqual(status, 1, output)
        self.assertIn('accounting consistent False', output)

    def test_memory_decrease_does_not_fail_growth_budget(self):
        status, output = self.evaluate(anon='2000->1000')
        self.assertEqual(status, 0, output)
        self.assertIn('RSS growth -1.0 MB', output)

    def test_absent_memory_measurement_is_not_zero_growth(self):
        status, output = self.evaluate(anon='')
        self.assertEqual(status, 1, output)
        self.assertIn('RSS growth unavailable', output)

    def test_p7_only_does_not_claim_p4_was_measured(self):
        status, output = self.evaluate(only='p7')
        self.assertEqual(status, 0, output)
        self.assertIn('| P4 | NOT MEASURED | PERF_ONLY=p7 run |', output)
        self.assertIn('| P7 | PASS |', output)


if __name__ == '__main__':
    unittest.main()
