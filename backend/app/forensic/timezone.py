"""The computer's time zone, read from its SYSTEM hive, and conversion of the local times Windows stores.

FAT file systems, setupapi.dev.log and a few other sources record local time without saying which zone. The
SYSTEM hive does: ControlSet\\Control\\TimeZoneInformation holds the Windows zone name (TimeZoneKeyName), the
standard/daylight offsets and the daylight-saving start and end rules. DFIP turns that into a zone name that both
the Sleuth Kit (`fls -z`) and Python understand:

  * the IANA zone that Unicode CLDR maps the Windows zone to (e.g. Eastern Standard Time -> America/New_York),
    which also carries the zone's historical rule changes; or, when the Windows zone has no mapping (a custom
    zone),
  * a POSIX TZ string built exactly from the hive's own rules (e.g. STD5DST4,M3.2.0/2:00:00,M11.1.0/2:00:00).

Local times in the repeated hour when clocks go back are ambiguous; they are read as the first (daylight)
occurrence, as the C library does.
"""
from __future__ import annotations
import re
import struct
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone, tzinfo
from functools import lru_cache

from .registry import signed_dword, values
from .windows_zones import WINDOWS_TO_IANA

UTC = 'UTC'


@dataclass
class Rule:
    """A recurring transition: the `week`-th (5 = last) `weekday` (0 = Sunday) of `month`, at `minutes` local time."""
    month: int
    week: int
    weekday: int
    minutes: int

    def date(self, year: int) -> datetime:
        first = datetime(year, self.month, 1)
        day = 1 + (self.weekday - (first.weekday() + 1) % 7) % 7  # first matching weekday (Python Monday=0)
        day += 7 * (self.week - 1)
        while day > 31 or (datetime(year, self.month, 1) + timedelta(days=day - 1)).month != self.month:
            day -= 7  # week 5 means "the last one in the month"
        return datetime(year, self.month, day) + timedelta(minutes=self.minutes)


def _systemtime_rule(raw) -> Rule | None:
    """A TimeZoneInformation StandardStart/DaylightStart SYSTEMTIME (16 bytes) as a recurring rule, or None."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) < 16:
        try:
            raw = bytes.fromhex(raw) if isinstance(raw, str) else None
        except ValueError:
            raw = None
    if not raw or len(raw) < 16:
        return None
    year, month, weekday, day, hour, minute, _sec, _ms = struct.unpack('<8H', bytes(raw[:16]))
    if month == 0 or year != 0:  # no daylight saving, or a one-off absolute date (not used for recurring rules)
        return None
    return Rule(month=month, week=day, weekday=weekday, minutes=hour * 60 + minute)


def _posix_offset(minutes_west: int) -> str:
    sign = '-' if minutes_west < 0 else ''
    h, m = divmod(abs(minutes_west), 60)
    return f'{sign}{h}' + (f':{m:02d}' if m else '')


def _posix_rule(rule: Rule) -> str:
    h, m = divmod(rule.minutes, 60)
    return f'M{rule.month}.{rule.week}.{rule.weekday}/{h}:{m:02d}:00'


def posix_string(bias: int, standard_bias: int, daylight_bias: int, standard: Rule | None, daylight: Rule | None) -> str:
    """POSIX TZ for Windows offsets (UTC = local + bias, in minutes) and daylight-saving rules."""
    std = f'STD{_posix_offset(bias + standard_bias)}'
    if not standard or not daylight:
        return std
    return f'{std}DST{_posix_offset(bias + daylight_bias)},{_posix_rule(daylight)},{_posix_rule(standard)}'


@dataclass
class ComputerTimeZone:
    key_name: str | None
    standard_name: str | None
    daylight_name: str | None
    bias: int
    standard_bias: int
    daylight_bias: int
    active_bias: int | None
    dynamic_dst_disabled: bool
    standard_start: Rule | None
    daylight_start: Rule | None

    @property
    def iana(self) -> str | None:
        name = WINDOWS_TO_IANA.get(self.key_name or '')
        return name if name and is_known_zone(name) else None

    @property
    def posix(self) -> str:
        return posix_string(self.bias, self.standard_bias, self.daylight_bias, self.standard_start, self.daylight_start)

    @property
    def zone(self) -> str:
        """The zone DFIP converts with: the mapped IANA zone, else the hive's exact rules as POSIX TZ."""
        return self.iana or self.posix

    def to_dict(self) -> dict:
        d = asdict(self)
        d.update(iana=self.iana, posix=self.posix, zone=self.zone)
        return d


def read_time_zone(reg, control_set: str) -> ComputerTimeZone | None:
    """TimeZoneInformation of one control set of a regipy SYSTEM hive, or None when the key is absent."""
    try:
        v = values(reg.get_key(f'\\{control_set}\\Control\\TimeZoneInformation'))
    except Exception:
        return None
    if 'Bias' not in v:
        return None
    return ComputerTimeZone(
        key_name=(v.get('TimeZoneKeyName') or None), standard_name=v.get('StandardName'), daylight_name=v.get('DaylightName'),
        bias=signed_dword(v.get('Bias')) or 0, standard_bias=signed_dword(v.get('StandardBias')) or 0,
        daylight_bias=signed_dword(v.get('DaylightBias')) or 0, active_bias=signed_dword(v.get('ActiveTimeBias')),
        dynamic_dst_disabled=bool(v.get('DynamicDaylightTimeDisabled')),
        standard_start=_systemtime_rule(v.get('StandardStart')), daylight_start=_systemtime_rule(v.get('DaylightStart')))


# ------------------------------------------------------------------------------------------- conversions
@lru_cache(maxsize=1)
def _iana_zones() -> frozenset:
    from zoneinfo import available_timezones
    return frozenset(available_timezones())


def is_known_zone(name: str) -> bool:
    return name == UTC or name in _iana_zones()


_POSIX_RE = re.compile(r'^STD(-?\d+)(?::(\d\d))?(?:DST(-?\d+)(?::(\d\d))?,M(\d+)\.(\d)\.(\d)/(\d+):(\d\d):\d\d,M(\d+)\.(\d)\.(\d)/(\d+):(\d\d):\d\d)?$')


def _minutes(hours: str, mins: str | None) -> int:
    """'5' -> 300, '-5:30' -> -330 (POSIX offsets are minutes west of UTC)."""
    total = abs(int(hours)) * 60 + int(mins or 0)
    return -total if hours.startswith('-') else total


class PosixZone(tzinfo):
    """The POSIX TZ strings `posix_string` builds (standard offset, optional daylight offset and M-rules)."""

    def __init__(self, spec: str):
        m = _POSIX_RE.match(spec)
        if not m:
            raise ValueError(f'Unsupported time zone: {spec}')
        self.spec = spec
        self.std = timedelta(minutes=-_minutes(m.group(1), m.group(2)))
        if m.group(3) is not None:
            self.dst_offset = timedelta(minutes=-_minutes(m.group(3), m.group(4)))
            g = [int(x) for x in m.groups()[4:]]
            self.start = Rule(g[0], g[1], g[2], g[3] * 60 + g[4])
            self.end = Rule(g[5], g[6], g[7], g[8] * 60 + g[9])
        else:
            self.dst_offset = None

    @staticmethod
    def _between(t, start, end) -> bool:
        return start <= t < end if start < end else not (end <= t < start)  # southern hemisphere: DST spans New Year

    def _in_dst(self, local: datetime) -> bool:
        """Whether a wall-clock time is daylight time. Times in the skipped hour count as standard time and times
        in the repeated hour as daylight time (the first occurrence), as Python's zoneinfo does with fold=0."""
        if self.dst_offset is None:
            return False
        naive = local.replace(tzinfo=None)
        start = self.start.date(naive.year) + (self.dst_offset - self.std)
        return self._between(naive, start, self.end.date(naive.year))

    def utcoffset(self, dt):
        return self.dst_offset if self._in_dst(dt) else self.std

    def dst(self, dt):
        return (self.dst_offset - self.std) if self._in_dst(dt) else timedelta(0)

    def tzname(self, dt):
        return 'DST' if self._in_dst(dt) else 'STD'

    def fromutc(self, dt):
        naive = dt.replace(tzinfo=None)
        if self.dst_offset is not None:
            start = self.start.date(naive.year) - self.std       # transitions as UTC instants
            end = self.end.date(naive.year) - self.dst_offset
            if self._between(naive, start, end):
                return (naive + self.dst_offset).replace(tzinfo=self)
        return (naive + self.std).replace(tzinfo=self)


def tzinfo_for(zone: str | None) -> tzinfo:
    """A tzinfo for a zone DFIP uses: 'UTC', an IANA name or a POSIX string from `posix_string`."""
    if not zone or zone == UTC:
        return timezone.utc
    if is_known_zone(zone):
        from zoneinfo import ZoneInfo
        return ZoneInfo(zone)
    return PosixZone(zone)


def local_to_utc(local: datetime, zone: str | None) -> datetime:
    """A naive local time as an aware UTC datetime (ambiguous times: the first, daylight, occurrence)."""
    return local.replace(tzinfo=tzinfo_for(zone), fold=0).astimezone(timezone.utc)


def valid_zone(zone: str | None) -> bool:
    """True for 'UTC', an IANA zone name or a POSIX string DFIP itself produced."""
    if not zone or len(zone) > 64:
        return False
    if is_known_zone(zone):
        return True
    try:
        PosixZone(zone)
        return True
    except ValueError:
        return False
