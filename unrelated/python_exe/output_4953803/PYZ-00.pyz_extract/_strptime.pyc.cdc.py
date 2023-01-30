
'''Strptime-related classes and functions.

CLASSES:
    LocaleTime -- Discovers and stores locale-specific time information
    TimeRE -- Creates regexes for pattern matching a string of text containing
                time information

FUNCTIONS:
    _getlang -- Figure out what language is being used for the locale
    strptime -- Calculates the time struct represented by the passed-in string

'''
import time
import locale
import calendar
from re import compile as re_compile
from re import IGNORECASE
from re import escape as re_escape
from datetime import date as datetime_date, timedelta as datetime_timedelta, timezone as datetime_timezone
from _thread import allocate_lock as _thread_allocate_lock
__all__ = []

def _getlang():
    return locale.getlocale(locale.LC_TIME)


class LocaleTime(object):
    '''Stores and handles locale-specific information related to time.

    ATTRIBUTES:
        f_weekday -- full weekday names (7-item list)
        a_weekday -- abbreviated weekday names (7-item list)
        f_month -- full month names (13-item list; dummy value in [0], which
                    is added by code)
        a_month -- abbreviated month names (13-item list, dummy value in
                    [0], which is added by code)
        am_pm -- AM/PM representation (2-item list)
        LC_date_time -- format string for date/time representation (string)
        LC_date -- format string for date representation (string)
        LC_time -- format string for time representation (string)
        timezone -- daylight- and non-daylight-savings timezone representation
                    (2-item list of sets)
        lang -- Language used by instance (2-item tuple)
    '''
    
    def __init__(self):
        '''Set all attributes.

        Order of methods called matters for dependency reasons.

        The locale language is set at the offset and then checked again before
        exiting.  This is to make sure that the attributes were not set with a
        mix of information from more than one locale.  This would most likely
        happen when using threads where one thread calls a locale-dependent
        function while another thread changes the locale while the function in
        the other thread is still running.  Proper coding would call for
        locks to prevent changing the locale while locale-dependent code is
        running.  The check here is done in case someone does not think about
        doing this.

        Only other possible issue is if someone changed the timezone and did
        not call tz.tzset .  That is an issue for the programmer, though,
        since changing the timezone is worthless without that call.

        '''
        self.lang = _getlang()
        self.__calc_weekday()
        self.__calc_month()
        self.__calc_am_pm()
        self.__calc_timezone()
        self.__calc_date_time()
        if _getlang() != self.lang:
            raise ValueError('locale changed during initialization')
        if None.tzname != self.tzname or time.daylight != self.daylight:
            raise ValueError('timezone changed during initialization')

    
    def __calc_weekday(self):
        a_weekday = (lambda .0: [ calendar.day_abbr[i].lower() for i in .0 ])(range(7))
        f_weekday = (lambda .0: [ calendar.day_name[i].lower() for i in .0 ])(range(7))
        self.a_weekday = a_weekday
        self.f_weekday = f_weekday

    
    def __calc_month(self):
        a_month = (lambda .0: [ calendar.month_abbr[i].lower() for i in .0 ])(range(13))
        f_month = (lambda .0: [ calendar.month_name[i].lower() for i in .0 ])(range(13))
        self.a_month = a_month
        self.f_month = f_month

    
    def __calc_am_pm(self):
        am_pm = []
        self.am_pm = am_pm

    
    def __calc_date_time(self):
        time_tuple = time.struct_time((1999, 3, 17, 22, 44, 55, 2, 76, 0))
        date_time = [
            None,
            None,
            None]
        date_time[0] = time.strftime('%c', time_tuple).lower()
        date_time[1] = time.strftime('%x', time_tuple).lower()
        date_time[2] = time.strftime('%X', time_tuple).lower()
        replacement_pairs = [
            ('%', '%%'),
            (self.f_weekday[2], '%A'),
            (self.f_month[3], '%B'),
            (self.a_weekday[2], '%a'),
            (self.a_month[3], '%b'),
            (self.am_pm[1], '%p'),
            ('1999', '%Y'),
            ('99', '%y'),
            ('22', '%H'),
            ('44', '%M'),
            ('55', '%S'),
            ('76', '%j'),
            ('17', '%d'),
            ('03', '%m'),
            ('3', '%m'),
            ('2', '%w'),
            ('10', '%I')]
        replacement_pairs.extend((lambda .0: [ (tz, '%Z') for tz_values in .0 for tz in tz_values ])(self.timezone))
        for offset, directive in ((0, '%c'), (1, '%x'), (2, '%X')):
            current_format = date_time[offset]
            time_tuple = time.struct_time((1999, 1, 3, 1, 1, 1, 6, 3, 0))
            U_W = '%W'
        U_W = '%U'
        date_time[offset] = current_format.replace('11', U_W)
        continue
        self.LC_date_time = date_time[0]
        self.LC_date = date_time[1]
        self.LC_time = date_time[2]

    
    def __calc_timezone(self):
        pass
    # WARNING: Decompyle incomplete



class TimeRE(dict):
    '''Handle conversion from format directives to regexes.'''
    
    def __init__(self = None, locale_time = None):
        '''Create keys/values.

        Order of execution is important for dependency reasons.

        '''
        if locale_time:
            self.locale_time = locale_time
        else:
            self.locale_time = LocaleTime()
        base = super()
    # WARNING: Decompyle incomplete

    
    def __seqToRE(self, to_convert, directive):
        """Convert a list to a regex string for matching a directive.

        Want possible matching values to be from longest to shortest.  This
        prevents the possibility of a match occurring for a value that also
        a substring of a larger value that should have matched (e.g., 'abc'
        matching when 'abcdef' should have been the match).

        """
        to_convert = sorted(to_convert, len, True, **('key', 'reverse'))
        for value in to_convert:
            return None
            regex = '|'.join((lambda .0: pass# WARNING: Decompyle incomplete
)(to_convert))
            regex = '(?P<%s>%s' % (directive, regex)
            return '%s)' % regex

    
    def pattern(self, format):
        '''Return regex pattern for the format string.

        Need to make sure that any characters that might be interpreted as
        regex syntax are escaped.

        '''
        processed_format = ''
        regex_chars = re_compile('([\\\\.^$*+?\\(\\){}\\[\\]|])')
        format = regex_chars.sub('\\\\\\1', format)
        whitespace_replacement = re_compile('\\s+')
        format = whitespace_replacement.sub('\\\\s+', format)
        if '%' in format:
            directive_index = format.index('%') + 1
            processed_format = '%s%s%s' % (processed_format, format[:directive_index - 1], self[format[directive_index]])
            format = format[directive_index + 1:]
            if not '%' in format:
                return '%s%s' % (processed_format, format)

    
    def compile(self, format):
        '''Return a compiled re object for the format string.'''
        return re_compile(self.pattern(format), IGNORECASE)

    __classcell__ = None

_cache_lock = _thread_allocate_lock()
_TimeRE_cache = TimeRE()
_CACHE_MAX_SIZE = 5
_regex_cache = { }

def _calc_julian_from_U_or_W(year, week_of_year, day_of_week, week_starts_Mon):
    '''Calculate the Julian day based on the year, week of the year, and day of
    the week, with week_start_day representing whether the week of the year
    assumes the week starts on Sunday or Monday (6 or 0).'''
    first_weekday = datetime_date(year, 1, 1).weekday()
    if not week_starts_Mon:
        first_weekday = (first_weekday + 1) % 7
        day_of_week = (day_of_week + 1) % 7
    week_0_length = (7 - first_weekday) % 7
    if week_of_year == 0:
        return 1 + day_of_week - first_weekday
    days_to_week = None + 7 * (week_of_year - 1)
    return 1 + days_to_week + day_of_week


def _calc_julian_from_V(iso_year, iso_week, iso_weekday):
    '''Calculate the Julian day based on the ISO 8601 year, week, and weekday.
    ISO weeks start on Mondays, with week 01 being the week containing 4 Jan.
    ISO week days range from 1 (Monday) to 7 (Sunday).
    '''
    correction = datetime_date(iso_year, 1, 4).isoweekday() + 3
    ordinal = iso_week * 7 + iso_weekday - correction
    if ordinal < 1:
        ordinal += datetime_date(iso_year, 1, 1).toordinal()
        iso_year -= 1
        ordinal -= datetime_date(iso_year, 1, 1).toordinal()
    return (iso_year, ordinal)


def _strptime(data_string, format = ('%a %b %d %H:%M:%S %Y',)):
    '''Return a 2-tuple consisting of a time struct and an int containing
    the number of microseconds based on the input string and the
    format string.'''
    global _TimeRE_cache
    pass
# WARNING: Decompyle incomplete


def _strptime_time(data_string, format = ('%a %b %d %H:%M:%S %Y',)):
    '''Return a time struct based on the input string and the
    format string.'''
    tt = _strptime(data_string, format)[0]
    return time.struct_time(tt[:time._STRUCT_TM_ITEMS])


def _strptime_datetime(cls, data_string, format = ('%a %b %d %H:%M:%S %Y',)):
    '''Return a class cls instance based on the input string and the
    format string.'''
    (tt, fraction, gmtoff_fraction) = _strptime(data_string, format)
    (tzname, gmtoff) = tt[-2:]
    args = tt[:6] + (fraction,)
    if gmtoff is not None:
        tzdelta = datetime_timedelta(gmtoff, gmtoff_fraction, **('seconds', 'microseconds'))
        if tzname:
            tz = datetime_timezone(tzdelta, tzname)
        else:
            tz = datetime_timezone(tzdelta)
        args += (tz,)
# WARNING: Decompyle incomplete

