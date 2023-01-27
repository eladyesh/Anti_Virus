
__doc__ = 'Concrete date/time and related types.\n\nSee http://www.iana.org/time-zones/repository/tz-link.html for\ntime zone and DST data sources.\n'
__all__ = ('date', 'datetime', 'time', 'timedelta', 'timezone', 'tzinfo', 'MINYEAR', 'MAXYEAR')
import time as _time
import math as _math
import sys

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
# WARNING: Decompyle incomplete
