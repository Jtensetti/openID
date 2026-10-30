"""Idle expiry uses synthetic documents and a transport double, without biometrics."""
import threading
import unittest
import weakref
from unittest.mock import Mock

from identity import VerifiedDocument
from native import NativeSessions
from test_chip_fixture import ChipFixture,capture_ready,fixture_order,signed


class NativeRetentionTests(unittest.TestCase):
    def setUp(self):
        self.now=100
        self.attest=Mock()
        self.attest.check.side_effect=lambda op,**kw:({'publicKey':'synthetic-key'} if op=='attestation'
            else {'signCount':kw['signCount']+1})
        self.native=NativeSessions(self.attest,lambda _:VerifiedDocument(b'SYNTHETIC_PORTRAIT',{}),None,None,
            clock=lambda:self.now,chip_factory=ChipFixture,pose_order=fixture_order,cleanup_interval=.01)
        self.addCleanup(self.native.close)

    def registered(self):
        started=self.native.start()
        return self.native.register({'id':started['id'],'keyId':'synthetic','attestation':'synthetic'})

    def chip(self,registered):
        return self.native.begin_chip(signed(registered['id'],registered|dict(sod='YQ==',dg1='YQ==',dg2='YQ==',dg14='YQ==')))

    def document_released(self,ident):
        released=threading.Event()
        ref=weakref.ref(self.native.pending[ident]['document'],lambda _:released.set())
        return ref,released

    def test_idle_capture_releases_document_without_another_request(self):
        registered=self.registered();ident=registered['id']
        capture_ready(self.native,registered,dict(sod='YQ==',dg1='YQ==',dg2='YQ==',dg14='YQ=='))
        ref,released=self.document_released(ident)
        self.now+=300
        self.assertTrue(released.wait(3),'idle expired portrait still referenced')
        self.assertIsNone(ref());self.assertNotIn(ident,self.native.pending)

    def test_idle_chip_deadline_closes_transport_and_releases_document(self):
        registered=self.registered();ident=registered['id'];self.chip(registered)
        chip=self.native.pending[ident]['chip'];ref,released=self.document_released(ident)
        self.now+=75
        self.assertTrue(released.wait(3),'idle expired chip still retained its document')
        # The document is released before bounded child-process cleanup completes.
        with self.native.session_lock:self.assertTrue(chip.closed)
        self.assertIsNone(ref());self.assertNotIn(ident,self.native.pending)

    def test_live_capture_is_kept_and_close_stops_sweeper_and_releases_it(self):
        registered=self.registered();ident=registered['id'];self.chip(registered)
        ref,released=self.document_released(ident)
        self.now+=74;self.native.expire()
        self.assertIsNotNone(ref());self.assertFalse(released.is_set())
        self.native.close()
        self.assertTrue(released.wait(1));self.assertFalse(self.native.sweeper.is_alive())
        self.native.close()
        with self.assertRaisesRegex(ValueError,'closed'):self.native.start()

    def test_slow_attestation_and_passport_check_cannot_reinsert_expired_sessions(self):
        started=self.native.start()
        def slow_attestation(*args,**kw):self.now+=300;return {'publicKey':'synthetic-key'}
        self.attest.check.side_effect=slow_attestation
        with self.assertRaisesRegex(ValueError,'expired'):
            self.native.register({'id':started['id'],'keyId':'synthetic','attestation':'synthetic'})
        self.assertNotIn(started['id'],self.native.pending)
        self.attest.check.side_effect=lambda op,**kw:({'publicKey':'synthetic-key'} if op=='attestation'
            else {'signCount':kw['signCount']+1})
        registered=self.registered()
        def slow_passport(_):self.now+=300;return VerifiedDocument(b'SYNTHETIC_PORTRAIT',{})
        self.native.passport=slow_passport
        self.native.chip_factory=Mock()
        with self.assertRaisesRegex(ValueError,'expired'):self.chip(registered)
        self.native.chip_factory.assert_not_called();self.assertNotIn(registered['id'],self.native.pending)

    def test_expiry_during_first_chip_command_closes_child_before_rejecting(self):
        registered=self.registered();child=ChipFixture(None);original=child.next
        def delayed_command(*args):self.now+=300;return original(*args)
        child.next=delayed_command;self.native.chip_factory=lambda _:child
        with self.assertRaisesRegex(ValueError,'expired'):self.chip(registered)
        self.assertTrue(child.closed);self.assertNotIn(registered['id'],self.native.pending)

    def test_cleanup_waits_for_chip_operation_and_cannot_clear_its_live_state(self):
        registered=self.registered();ident=registered['id'];first=self.chip(registered)
        child=self.native.pending[ident]['chip'];entered=threading.Event();release=threading.Event()
        original=child.next;result=[]
        def blocked(*args):
            entered.set()
            if not release.wait(3):raise TimeoutError('synthetic transport')
            self.assertFalse(child.closed)
            return original(*args)
        child.next=blocked
        def step():
            try:result.append(self.native.chip_step(dict(id=ident,chipToken=first['chipToken'],sequence=0,response='kAA=')))
            except Exception as error:result.append(error)
        worker=threading.Thread(target=step);worker.start()
        try:
            self.assertTrue(entered.wait(2));self.now+=300
            ref,released=self.document_released(ident)
            self.assertFalse(released.wait(.05));self.assertFalse(child.closed)
        finally:release.set();worker.join(timeout=3)
        self.assertFalse(worker.is_alive());self.assertEqual(1,len(result))
        self.assertIsInstance(result[0],ValueError)
        self.assertTrue(released.wait(2));self.assertIsNone(ref());self.assertNotIn(ident,self.native.pending)

    def test_one_failed_transport_cleanup_does_not_retain_other_sessions(self):
        registered=self.registered();ident=registered['id'];self.chip(registered)
        other=self.registered();self.chip(other)
        child=self.native.pending[ident]['chip']
        child.close=Mock(side_effect=RuntimeError('synthetic close error'))
        ref,released=self.document_released(other['id'])
        with self.native.session_lock,self.assertLogs('native',level='ERROR'):
            self.now+=300;self.native.expire()
        self.assertEqual({},self.native.pending);self.assertTrue(released.wait(1));self.assertIsNone(ref())


if __name__=='__main__':unittest.main()
