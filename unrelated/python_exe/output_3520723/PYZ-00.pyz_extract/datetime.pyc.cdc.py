
__doc__ = 'Concrete date/time and related types.\n\nSee http://www.iana.org/time-zones/repository/tz-link.html for\ntime zone and DST data sources.\n'
__all__ = ('date', 'datetime', 'time', 'timedelta', 'timezone', 'tzinfo', 'MINYEAR', 'MAXYEAR')
import time as _time
import math as _math
import sys
from operator import index as _index

def _cmp(x, y):
    if x == y:
        return 0
    if None > y:
        return 1

MINYEAR = 1
MAXYEAR = 9999
_MAXORDINAL = 3652059
_DAYS_IN_MONTH = [
    -1,
    31,
    28,
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31]
_DAYS_BEFORE_MONTH = [
    -1]
dbm = 0
del dbm
del dim

def _is_leap(year):
    '''year -> 1 if leap year, else 0.'''
    if not year % 4 == 0 and year % 100 != 0:
        pass
    return year % 400 == 0


def _days_before_year(year):
    '''year -> number of days before January 1st of year.'''
    y = year - 1
    return (y * 365 + y // 4 - y // 100) + y // 400


def _days_in_month(year, month):
    '''year, month -> number of days in that month in that year.'''
    pass
# WARNING: Decompyle incomplete


def _days_before_month(year, month):
    '''year, month -> number of days in year preceding first day of month.'''
    pass
# WARNING: Decompyle incomplete


def _ymd2ord(year, month, day):
    '''year, month, day -> ordinal, considering 01-Jan-0001 as day 1.'''
    pass
# WARNING: Decompyle incomplete

_DI400Y = _days_before_year(401)
_DI100Y = _days_before_year(101)
_DI4Y = _days_before_year(5)
# WARNING: Decompyle incomplete
