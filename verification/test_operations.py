import math
import unittest
from evaluate_biometrics import evaluate
from monitor import update

class OperationsTests(unittest.TestCase):
    def test_alert_debounce_and_recovery(self):
        state={}
        for expected in (False,False,True,False):
            state,changed=update(state,False);self.assertEqual(expected,changed)
        state,changed=update(state,True);self.assertTrue(changed);self.assertFalse(state['alert'])
        self.assertFalse(update(state,True)[1])

    def rows(self):
        return [{'sample':str(i),'subject':str(i),'partition':'evaluation','kind':kind,'score':str(score)} for i,(kind,score) in enumerate(
            [('genuine',.8),('impostor',.7),('bona_fide',.6),('attack',.2)])]

    def test_fixed_holdout_metrics_and_nonzero_uncertainty(self):
        result=evaluate(self.rows(),.5,.5)['metrics']
        self.assertEqual(1,result['FMR']['errors']);self.assertEqual(0,result['APCER']['errors'])
        self.assertGreater(result['APCER']['wilson95'][1],0)
        self.assertEqual(4,sum(m['samples'] for m in result.values()))

    def test_leakage_duplicates_missing_classes_and_invalid_scores_fail(self):
        for changes in ({'score':'NaN'},{'score':'2'},{'kind':'unknown'}):
            rows=self.rows();rows[0].update(changes)
            with self.assertRaises(ValueError):evaluate(rows,.5,.5)
        rows=self.rows();rows.append(dict(rows[0]))
        with self.assertRaises(ValueError):evaluate(rows,.5,.5)
        rows=self.rows();rows.append(dict(rows[0],sample='extra',partition='calibration'))
        with self.assertRaises(ValueError):evaluate(rows,.5,.5)
        with self.assertRaises(ValueError):evaluate(self.rows()[:-1],.5,.5)
        with self.assertRaises(ValueError):evaluate(self.rows(),math.nan,.5)

if __name__=='__main__':unittest.main()
