import unittest
from probe import sp_ready


class ReadinessTests(unittest.TestCase):
    def test_actual_sp_html_marker_and_rejected_states(self):
        wrapper=lambda value: b"<!doctype html><html lang='sv'><head><title>openID</title></head><body><main>"+value+b"</main></body></html>"
        self.assertTrue(sp_ready(wrapper(b'READY')))
        for body in (wrapper(b'STORAGE_UNAVAILABLE'),wrapper(b'SYNTHETIC_ONLY: READY'),
                     wrapper(b'NOT_READY'),b'READY',wrapper(b'READY')+wrapper(b'READY'),
                     b'<main>READY'):
            with self.subTest(body=body):self.assertFalse(sp_ready(body))


if __name__=='__main__':unittest.main()
