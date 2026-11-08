"""Conservative 18+ eligibility from an authenticated stored passport profile.

This policy is not identity or credential verification. The caller must obtain
the profile from the authenticated profile store, enforce active credential and
current evidence/revocation checks, and choose the service's trusted UTC date.
Never call it on passport fields supplied by a relying party or a browser.
"""

from collections.abc import Mapping
from datetime import date
import re


def eligible_over_18(profile, *, today):
    """Return only whether every possible, nonfuture MRZ birth date is 18+.

    MRZ dates contain a two-digit year. The most recent calendar-valid matching
    date on or before today gives a conservative lower bound, not the person's
    actual birth date. Earlier matching centuries cannot make a person younger.
    This can decline an adult over 100 whose MRZ date also fits a minor.

    A 29 February birth reaches the threshold on 1 March in a non-leap year.
    The document must expire after today; expiry today is conservatively denied.
    Invalid/missing fields raise ValueError. No personal number is interpreted,
    and no inferred date, age, or other identity attribute is returned.
    """
    if not isinstance(profile, Mapping) or type(today) is not date:
        raise ValueError('authenticated profile and trusted calendar date required')

    birth = profile.get('birthDateMrz')
    expiry = profile.get('documentExpires')
    if not isinstance(birth, str) or re.fullmatch(r'[0-9]{6}', birth) is None:
        raise ValueError('invalid MRZ birth date')
    if not isinstance(expiry, str) or re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}', expiry) is None:
        raise ValueError('invalid document expiry')

    year, month, day = int(birth[:2]), int(birth[2:4]), int(birth[4:])
    try:
        # The 2000 century includes every possible MMDD for each two-digit YY,
        # including 000229. This validates syntax, not the actual birth century.
        date(2000 + year, month, day)
        expires = date.fromisoformat(expiry)
    except ValueError:
        raise ValueError('invalid passport calendar date') from None

    youngest = None
    for century in range(today.year // 100, -1, -1):
        candidate_year = century * 100 + year
        if candidate_year < 1:
            continue
        try:
            candidate = date(candidate_year, month, day)
        except ValueError:
            # Century years such as 1900 and 2100 do not have 29 February.
            continue
        if candidate <= today:
            youngest = candidate
            break
    if youngest is None:
        raise ValueError('MRZ birth date has no possible nonfuture date')

    threshold_year = youngest.year + 18
    old_enough = (today.year > threshold_year or
                  (today.year == threshold_year and
                   (today.month, today.day) >= (youngest.month, youngest.day)))
    return expires > today and old_enough
