from copy import deepcopy
from datetime import date, datetime, timezone
import unittest

from age_eligibility import eligible_over_18


def profile(birth='081108', expiry='2030-12-31', **extra):
    # Synthetic fields shaped like an authenticated stored passport profile.
    return {'birthDateMrz': birth, 'documentExpires': expiry, **extra}


class AgeEligibilityTests(unittest.TestCase):
    def test_eighteenth_birthday_boundary(self):
        value = profile()
        self.assertIs(False, eligible_over_18(value, today=date(2026, 11, 7)))
        self.assertIs(True, eligible_over_18(value, today=date(2026, 11, 8)))
        self.assertIs(True, eligible_over_18(value, today=date(2026, 11, 9)))

    def test_ambiguous_century_does_not_promote_a_possible_minor(self):
        # 1910 and 2010 share an MRZ date. Even an actual 116-year-old is denied.
        self.assertIs(False, eligible_over_18(profile('101108'), today=date(2026, 11, 8)))
        self.assertIs(False, eligible_over_18(profile('261108'), today=date(2026, 11, 8)))
        self.assertIs(True, eligible_over_18(profile('900101'), today=date(2026, 11, 8)))

    def test_future_matching_date_is_not_a_possible_birth_date(self):
        # A verified birth date cannot be tomorrow; the preceding century is
        # the youngest possible date. On the birthday itself a newborn is possible.
        value = profile('261109')
        self.assertIs(True, eligible_over_18(value, today=date(2026, 11, 8)))
        self.assertIs(False, eligible_over_18(value, today=date(2026, 11, 9)))

    def test_new_century_changes_the_youngest_possible_date_conservatively(self):
        value = profile('000101', '2101-01-01')
        self.assertIs(True, eligible_over_18(value, today=date(2099, 12, 31)))
        self.assertIs(False, eligible_over_18(value, today=date(2100, 1, 1)))

    def test_leap_day_threshold_waits_until_march_in_non_leap_year(self):
        value = profile('080229')
        self.assertIs(False, eligible_over_18(value, today=date(2026, 2, 28)))
        self.assertIs(True, eligible_over_18(value, today=date(2026, 3, 1)))

    def test_non_leap_century_is_skipped_without_rewriting_february_29(self):
        value = profile('000229', '2201-01-01')
        self.assertIs(True, eligible_over_18(value, today=date(2100, 2, 28)))
        self.assertIs(True, eligible_over_18(value, today=date(2100, 3, 1)))
        # The nearest earlier valid matching date can be several centuries away.
        self.assertIs(True, eligible_over_18(value, today=date(1900, 3, 1)))

    def test_leap_century_does_not_skip_a_possible_minor(self):
        value = profile('000229', '2030-12-31')
        self.assertIs(False, eligible_over_18(value, today=date(2000, 2, 29)))
        self.assertIs(False, eligible_over_18(value, today=date(2018, 2, 28)))
        self.assertIs(True, eligible_over_18(value, today=date(2018, 3, 1)))

    def test_document_expiry_is_conservative_on_the_expiry_day(self):
        value = profile('900101', '2026-11-08')
        self.assertIs(True, eligible_over_18(value, today=date(2026, 11, 7)))
        self.assertIs(False, eligible_over_18(value, today=date(2026, 11, 8)))
        self.assertIs(False, eligible_over_18(value, today=date(2026, 11, 9)))

    def test_malformed_birth_dates_are_rejected(self):
        for birth in (None, 81108, True, '', '20081108', '081108\n', '081108 ',
                      '08-1108', '０８１１０８', '081332', '080000', '080230',
                      '090229', '900229'):
            with self.subTest(birth=birth), self.assertRaises(ValueError):
                eligible_over_18(profile(birth), today=date(2026, 11, 8))

    def test_malformed_expiry_is_rejected_even_for_a_minor(self):
        for expiry in (None, 20301231, True, '', '301231', '2030-2-01',
                       '2030-12-31\n', '2030-12-31T00:00:00Z',
                       '2030-02-29', '2100-02-29', '0000-01-01'):
            with self.subTest(expiry=expiry), self.assertRaises(ValueError):
                eligible_over_18(profile('101108', expiry), today=date(2026, 11, 8))

    def test_missing_fields_and_untrusted_clock_types_are_rejected(self):
        for value in (None, [], '081108', {}, {'birthDateMrz': '081108'},
                      {'documentExpires': '2030-12-31'}):
            with self.subTest(profile=value), self.assertRaises(ValueError):
                eligible_over_18(value, today=date(2026, 11, 8))
        for today in (None, '2026-11-08', 1794096000, True,
                      datetime(2026, 11, 8, tzinfo=timezone.utc)):
            with self.subTest(today=today), self.assertRaises(ValueError):
                eligible_over_18(profile(), today=today)

    def test_no_possible_nonfuture_calendar_date_is_rejected(self):
        with self.assertRaises(ValueError):
            eligible_over_18(profile('020101'), today=date(1, 1, 1))

    def test_person_number_and_unverified_extra_claims_do_not_override_mrz(self):
        value = profile('101108', passportPersonalNumber='190001010000',
                        birthDate='1900-01-01', age_over_18=True, age=126)
        original = deepcopy(value)
        result = eligible_over_18(value, today=date(2026, 11, 8))
        self.assertIs(False, result)
        self.assertIs(type(result), bool)
        self.assertEqual(original, value)


if __name__ == '__main__':
    unittest.main()
