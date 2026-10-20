import json
import sys
import unittest
from chip import ChipProcess


class ChipProcessTests(unittest.TestCase):
    def process(self, source, timeout=3):
        process = ChipProcess([sys.executable, '-u', '-c', source],
                              dict(sod='YQ==', dg1='YQ==', dg2='YQ==', dg14='YQ=='), timeout=timeout)
        self.addCleanup(process.close)
        return process

    def test_json_line_exchange_and_successful_exit(self):
        source = '''import sys,json
assert set(json.loads(sys.stdin.readline())) == {'sod','dg1','dg2','dg14'}
print(json.dumps({'type':'command','sequence':0,'command':'AKQMAAI/AA=='}))
assert json.loads(sys.stdin.readline()) == {'sequence':0,'response':'kAA='}
print('{"type":"verified"}')
'''
        process = self.process(source)
        self.assertEqual(0, process.next()['sequence'])
        self.assertEqual({'type':'verified'}, process.next('kAA=', 0))
        self.assertTrue(process.closed)

    def test_success_without_exchange_is_rejected(self):
        process = self.process('input(); print(\'{"type":"verified"}\')')
        with self.assertRaises(ValueError): process.next()
        self.assertTrue(process.closed)

    def test_bad_sequence_duplicate_fields_and_output_limit(self):
        for output in ['{"type":"command","sequence":2,"command":"AAAAAA=="}',
                       '{"type":"command","type":"verified"}', 'x'*8193,
                       '{"type":"rejected"}', '[]']:
            process = self.process('input(); print('+repr(output)+')')
            with self.subTest(output=output[:60]),self.assertRaises(ValueError): process.next()
            self.assertTrue(process.closed)

    def test_error_exit_after_verified_is_not_success(self):
        process = self.process('''import sys
input();print('{"type":"command","sequence":0,"command":"AAAAAA=="}')
input();print('{"type":"verified"}');sys.exit(2)''')
        process.next()
        with self.assertRaises(ValueError): process.next('kAA=', 0)
        self.assertTrue(process.closed)

    def test_response_limit_and_replay_kill_process(self):
        for response,sequence in [('AA==',0),('kAA=',1),('kAA=',True),('A'*6000,0)]:
            process = self.process('input();print(\'{"type":"command","sequence":0,"command":"AAAAAA=="}\');input()')
            process.next()
            with self.subTest(sequence=sequence),self.assertRaises(ValueError):process.next(response,sequence)
            self.assertTrue(process.closed)

    def test_timeout_and_cancellation_reap_children(self):
        process = self.process('import time;input();time.sleep(10)', timeout=0.2)
        with self.assertRaises((ValueError,OSError)):process.next()
        self.assertIsNotNone(process.process.poll())
        other = self.process('input();input()')
        other.close();other.close()
        self.assertIsNotNone(other.process.poll())

    def test_capacity_is_bounded_and_released(self):
        active = [self.process('input();input()') for _ in range(4)]
        with self.assertRaises(ValueError):self.process('input()')
        active[0].close()
        replacement = self.process('input();input()')
        replacement.close()
