"""The computer's time zone: Windows rules, POSIX strings, the CLDR mapping and local -> UTC conversion."""
import lzma
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest

from app.forensic.registry import control_sets, open_hive
from app.forensic.timezone import PosixZone, Rule, local_to_utc, posix_string, read_time_zone, tzinfo_for, valid_zone
from app.forensic.windows_zones import WINDOWS_TO_IANA

US_EASTERN = dict(bias=300, standard_bias=0, daylight_bias=-60,
                  standard=Rule(month=11, week=1, weekday=0, minutes=120), daylight=Rule(month=3, week=2, weekday=0, minutes=120))


def test_rules_find_the_right_sunday():
    assert Rule(3, 2, 0, 120).date(2026) == datetime(2026, 3, 8, 2)     # second Sunday of March 2026
    assert Rule(11, 1, 0, 120).date(2026) == datetime(2026, 11, 1, 2)   # first Sunday of November
    assert Rule(10, 5, 0, 180).date(2026) == datetime(2026, 10, 25, 3)  # last Sunday of October (EU)
    assert Rule(2, 5, 0, 0).date(2024) == datetime(2024, 2, 25)         # "last" in a leap-year February


def test_posix_strings_from_windows_rules():
    assert posix_string(**US_EASTERN) == 'STD5DST4,M3.2.0/2:00:00,M11.1.0/2:00:00'
    assert posix_string(-330, 0, 0, None, None) == 'STD-5:30'          # India: no daylight saving
    assert posix_string(-600, 0, -60, Rule(4, 1, 0, 180), Rule(10, 1, 0, 120)) == 'STD-10DST-11,M10.1.0/2:00:00,M4.1.0/3:00:00'


@pytest.mark.parametrize('posix,iana', [
    ('STD5DST4,M3.2.0/2:00:00,M11.1.0/2:00:00', 'America/New_York'),
    ('STD-10DST-11,M10.1.0/2:00:00,M4.1.0/3:00:00', 'Australia/Sydney'),   # southern hemisphere
    ('STD-5:30', 'Asia/Kolkata'),
])
def test_posix_zone_matches_the_iana_zone_all_year(posix, iana):
    """Every half hour of 2026, in both directions, the hive-rule fallback agrees with the tz database."""
    pz, zi = PosixZone(posix), ZoneInfo(iana)
    t = datetime(2026, 1, 1, tzinfo=timezone.utc)
    while t.year == 2026:
        assert t.astimezone(pz).replace(tzinfo=None) == t.astimezone(zi).replace(tzinfo=None), t
        local = t.astimezone(zi).replace(tzinfo=None)
        assert local.replace(tzinfo=pz).astimezone(timezone.utc) == local.replace(tzinfo=zi, fold=0).astimezone(timezone.utc), local
        t += timedelta(minutes=30)


def test_local_to_utc_follows_daylight_saving():
    assert local_to_utc(datetime(2026, 9, 1, 5, 41, 2), 'America/New_York') == datetime(2026, 9, 1, 9, 41, 2, tzinfo=timezone.utc)
    assert local_to_utc(datetime(2026, 1, 15, 10, 30), 'America/New_York') == datetime(2026, 1, 15, 15, 30, tzinfo=timezone.utc)
    assert local_to_utc(datetime(2026, 1, 15, 10, 30), 'UTC') == datetime(2026, 1, 15, 10, 30, tzinfo=timezone.utc)
    # The repeated hour when clocks go back is read as its first (daylight) occurrence.
    assert local_to_utc(datetime(2026, 11, 1, 1, 30), 'America/New_York') == datetime(2026, 11, 1, 5, 30, tzinfo=timezone.utc)
    assert tzinfo_for('STD5DST4,M3.2.0/2:00:00,M11.1.0/2:00:00').utcoffset(datetime(2026, 7, 1)) == timedelta(hours=-4)


def test_zone_validation():
    assert valid_zone('UTC') and valid_zone('America/New_York') and valid_zone('Asia/Kolkata')
    assert valid_zone('STD5DST4,M3.2.0/2:00:00,M11.1.0/2:00:00')
    assert not valid_zone('Mars/Olympus') and not valid_zone("'; drop") and not valid_zone('') and not valid_zone(None)


def test_cldr_mapping_resolves_to_installed_zones():
    assert WINDOWS_TO_IANA['Eastern Standard Time'] == 'America/New_York'
    assert WINDOWS_TO_IANA['India Standard Time'] in ('Asia/Calcutta', 'Asia/Kolkata')
    missing = [w for w, z in WINDOWS_TO_IANA.items() if not valid_zone(z)]
    assert not missing, missing  # tzdata and tzdata-legacy must cover every CLDR zone


def test_time_zone_from_a_real_windows_7_system_hive(tmp_path):
    hive = tmp_path / 'SYSTEM'
    hive.write_bytes(lzma.decompress((__import__('pathlib').Path(__file__).parent / 'fixtures' / 'SYSTEM.xz').read_bytes()))
    reg = open_hive(hive)
    tz = read_time_zone(reg, control_sets(reg)[0])
    assert tz is not None and tz.active_bias == 240           # the hive's own ActiveTimeBias (UTC-4)
    assert tz.zone and valid_zone(tz.zone)
    assert local_to_utc(datetime(2011, 4, 3, 21, 15, 5), tz.zone) == datetime(2011, 4, 4, 1, 15, 5, tzinfo=timezone.utc)
