import copy
import unittest
import metadata_guard as guard

def fixture(code):
    records=[{'table':{'family':'inet','name':guard.TABLE}},
             {'chain':{'family':'inet','table':guard.TABLE,'name':'output','type':'filter','hook':'output','prio':-10,'policy':'accept'}}]
    for family,address in guard.ADDRESSES.items():
        records.append({'rule':{'family':'inet','table':guard.TABLE,'chain':'output','expr':[
            {'match':{'op':'==','left':{'payload':{'protocol':family,'field':'daddr'}},'right':address}},
            {'match':{'op':'!=','left':{'meta':{'key':'skuid'}},'right':0}},
            {'counter':{'packets':0,'bytes':0}},
            {'reject':{'type':'icmpx','expr':code}}]}})
    return {'nftables':records}

class MetadataTests(unittest.TestCase):
    def test_symbolic_and_numeric_admin_prohibited(self):
        for code in ('admin-prohibited',3):
            with self.subTest(code=code):guard.verify(fixture(code))

    def test_missing_ipv6_or_weakened_uid_condition_rejected(self):
        for change in ('ipv6','uid','destination','accept','wrong_code'):
            value=fixture(3)
            rule=value['nftables'][-1]['rule']
            if change=='ipv6':value['nftables'].pop()
            elif change=='uid':rule['expr'][1]['match']['op']='=='
            elif change=='destination':rule['expr'][0]['match']['right']='::1'
            elif change=='accept':rule['expr'][-1]={'accept':None}
            else:rule['expr'][-1]['reject']['expr']=1
            with self.subTest(change=change),self.assertRaises(ValueError):guard.verify(value)

if __name__=='__main__':unittest.main()

