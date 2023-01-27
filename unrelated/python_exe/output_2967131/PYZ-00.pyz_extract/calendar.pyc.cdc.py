
'''Calendar printing functions

Note when comparing these calendars to the ones printed by cal(1): By
default, these calendars have Monday as the first day of the week, and
Sunday as the last (the European convention). Use setfirstweekday() to
set the first day of the week (0=Monday, 6=Sunday).'''
import sys
import datetime
import locale as _locale
from itertools import repeat
__all__ = [
    'IllegalMonthError',
    'IllegalWeekdayError',
    'setfirstweekday',
    'firstweekday',
    'isleap',
    'leapdays',
    'weekday',
    'monthrange',
    'monthcalendar',
    'prmonth',
    'month',
    'prcal',
    'calendar',
    'timegm',
    'month_name',
    'month_abbr',
    'day_name',
    'day_abbr',
    'Calendar',
    'TextCalendar',
    'HTMLCalendar',
    'LocaleTextCalendar',
    'LocaleHTMLCalendar',
    'weekheader']
error = ValueError

class IllegalMonthError(ValueError):
    
    def __init__(self, month):
        self.month = month

    
    def __str__(self):
        return 'bad month number %r; must be 1-12' % self.month



class IllegalWeekdayError(ValueError):
    
    def __init__(self, weekday):
        self.weekday = weekday

    
    def __str__(self):
        return 'bad weekday number %r; must be 0 (Monday) to 6 (Sunday)' % self.weekday


January = 1
February = 2
mdays = [
    0,
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

class _localized_month:
    _months = (lambda .0: [ datetime.date(2001, i + 1, 1).strftime for i in .0 ])(range(12))
    _months.insert(0, (lambda x: ''))
    
    def __init__(self, format):
        self.format = format

    
    def __getitem__(self, i):
        funcs = self._months[i]
        if isinstance(i, slice):
            return (lambda .0 = None: [ f(self.format) for f in .0 ])(funcs)
        return None(self.format)

    
    def __len__(self):
        return 13



class _localized_day:
    _days = (lambda .0: [ datetime.date(2001, 1, i + 1).strftime for i in .0 ])(range(7))
    
    def __init__(self, format):
        self.format = format

    
    def __getitem__(self, i):
        funcs = self._days[i]
        if isinstance(i, slice):
            return (lambda .0 = None: [ f(self.format) for f in .0 ])(funcs)
        return None(self.format)

    
    def __len__(self):
        return 7


day_name = _localized_day('%A')
day_abbr = _localized_day('%a')
month_name = _localized_month('%B')
month_abbr = _localized_month('%b')
(MONDAY, TUESDAY, WEDNESDAY, THURSDAY, FRIDAY, SATURDAY, SUNDAY) = range(7)

def isleap(year):
    '''Return True for leap years, False for non-leap years.'''
    if not year % 4 == 0 and year % 100 != 0:
        return year % 400 == 0


def leapdays(y1, y2):
    '''Return number of leap years in range [y1, y2).
       Assume y1 <= y2.'''
    y1 -= 1
    y2 -= 1
    return (y2 // 4 - y1 // 4 - y2 // 100 - y1 // 100) + (y2 // 400 - y1 // 400)


def weekday(year, month, day):
    '''Return weekday (0-6 ~ Mon-Sun) for year, month (1-12), day (1-31).'''
    year = None if not year <= year or year <= datetime.MAXYEAR else 2000 + year % 400
    return datetime.date(year, month, day).weekday()


def monthrange(year, month):
    '''Return weekday (0-6 ~ Mon-Sun) and number of days (28-31) for
       year, month.'''
    raise None if not month <= month or month <= 12 else IllegalMonthError(month)
    day1 = weekday(year, month, 1)
    if month == February:
        ndays = mdays[month] + isleap(year)
        return (day1, ndays)


def _monthlen(year, month):
    if month == February:
        return mdays[month] + isleap(year)


def _prevmonth(year, month):
    if month == 1:
        return (year - 1, 12)
    return (None, month - 1)


def _nextmonth(year, month):
    if month == 12:
        return (year + 1, 1)
    return (None, month + 1)


class Calendar(object):
    """
    Base calendar class. This class doesn't do any formatting. It simply
    provides data to subclasses.
    """
    
    def __init__(self, firstweekday = (0,)):
        self.firstweekday = firstweekday

    
    def getfirstweekday(self):
        return self._firstweekday % 7

    
    def setfirstweekday(self, firstweekday):
        self._firstweekday = firstweekday

    firstweekday = property(getfirstweekday, setfirstweekday)
    
    def iterweekdays(self):
        '''
        Return an iterator for one week of weekday numbers starting with the
        configured first one.
        '''
        for i in range(self.firstweekday, self.firstweekday + 7):
            yield i % 7

    
    def itermonthdates(self, year, month):
        '''
        Return an iterator for one month. The iterator will yield datetime.date
        values and will always iterate through complete weeks, so it will yield
        dates outside the specified month.
        '''
        pass

    
    def itermonthdays(self, year, month):
        '''
        Like itermonthdates(), but will yield day numbers. For days outside
        the specified month the day number is 0.
        '''
        (day1, ndays) = monthrange(year, month)
        days_before = (day1 - self.firstweekday) % 7
    # WARNING: Decompyle incomplete

    
    def itermonthdays2(self, year, month):
        '''
        Like itermonthdates(), but will yield (day number, weekday number)
        tuples. For days outside the specified month the day number is 0.
        '''
        pass

    
    def itermonthdays3(self, year, month):
        '''
        Like itermonthdates(), but will yield (year, month, day) tuples.  Can be
        used for dates outside of datetime.date range.
        '''
        (day1, ndays) = monthrange(year, month)
        days_before = (day1 - self.firstweekday) % 7
        days_after = (self.firstweekday - day1 - ndays) % 7
        (y, m) = _prevmonth(year, month)
        end = _monthlen(y, m) + 1
        for d in range(end - days_before, end):
            yield (y, m, d)
            for d in None(None, ndays + 1):
                yield (year, month, d)
                (y, m) = None(None, month)
                for d in range(1, days_after + 1):
                    yield (y, m, d)

    
    def itermonthdays4(self, year, month):
        '''
        Like itermonthdates(), but will yield (year, month, day, day_of_week) tuples.
        Can be used for dates outside of datetime.date range.
        '''
        pass

    
    def monthdatescalendar(self, year, month):
        """
        Return a matrix (list of lists) representing a month's calendar.
        Each row represents a week; week entries are datetime.date values.
        """
        dates = list(self.itermonthdates(year, month))
        return (lambda .0 = None: [ dates[i:i + 7] for i in .0 ])(range(0, len(dates), 7))

    
    def monthdays2calendar(self, year, month):
        """
        Return a matrix representing a month's calendar.
        Each row represents a week; week entries are
        (day number, weekday number) tuples. Day numbers outside this month
        are zero.
        """
        days = list(self.itermonthdays2(year, month))
        return (lambda .0 = None: [ days[i:i + 7] for i in .0 ])(range(0, len(days), 7))

    
    def monthdayscalendar(self, year, month):
        """
        Return a matrix representing a month's calendar.
        Each row represents a week; days outside this month are zero.
        """
        days = list(self.itermonthdays(year, month))
        return (lambda .0 = None: [ days[i:i + 7] for i in .0 ])(range(0, len(days), 7))

    
    def yeardatescalendar(self, year, width = (3,)):
        '''
        Return the data for the specified year ready for formatting. The return
        value is a list of month rows. Each month row contains up to width months.
        Each month contains between 4 and 6 weeks and each week contains 1-7
        days. Days are datetime.date objects.
        '''
        months = (lambda .0 = None: [ self.monthdatescalendar(year, i) for i in .0 ])(range(January, January + 12))
        return (lambda .0 = None: [ months[i:i + width] for i in .0 ])(range(0, len(months), width))

    
    def yeardays2calendar(self, year, width = (3,)):
        '''
        Return the data for the specified year ready for formatting (similar to
        yeardatescalendar()). Entries in the week lists are
        (day number, weekday number) tuples. Day numbers outside this month are
        zero.
        '''
        months = (lambda .0 = None: [ self.monthdays2calendar(year, i) for i in .0 ])(range(January, January + 12))
        return (lambda .0 = None: [ months[i:i + width] for i in .0 ])(range(0, len(months), width))

    
    def yeardayscalendar(self, year, width = (3,)):
        '''
        Return the data for the specified year ready for formatting (similar to
        yeardatescalendar()). Entries in the week lists are day numbers.
        Day numbers outside this month are zero.
        '''
        months = (lambda .0 = None: [ self.monthdayscalendar(year, i) for i in .0 ])(range(January, January + 12))
        return (lambda .0 = None: [ months[i:i + width] for i in .0 ])(range(0, len(months), width))



class TextCalendar(Calendar):
    '''
    Subclass of Calendar that outputs a calendar as a simple plain text
    similar to the UNIX program cal.
    '''
    
    def prweek(self, theweek, width):
        '''
        Print a single week (no newline).
        '''
        print(self.formatweek(theweek, width), '', **('end',))

    
    def formatday(self, day, weekday, width):
        '''
        Returns a formatted day.
        '''
        return None if day == 0 else s.center(width)

    
    def formatweek(self, theweek, width):
        '''
        Returns a single week in a string (no newline).
        '''
        return None((lambda .0 = None: pass)(theweek))

    
    def formatweekday(self, day, width):
        '''
        Returns a formatted week day name.
        '''
        return None[names if width >= 9 else day][:width].center(width)

    
    def formatweekheader(self, width):
        '''
        Return a header for a week.
        '''
        return None((lambda .0 = None: pass)(self.iterweekdays()))

    
    def formatmonthname(self, theyear, themonth, width, withyear = (True,)):
        '''
        Return a formatted month name.
        '''
        s = month_name[themonth]
        if withyear:
            s = '%s %r' % (s, theyear)
            return s.center(width)

    
    def prmonth(self, theyear, themonth, w, l = (0, 0)):
        """
        Print a month's calendar.
        """
        print(self.formatmonth(theyear, themonth, w, l), '', **('end',))

    
    def formatmonth(self, theyear, themonth, w, l = (0, 0)):
        """
        Return a month's calendar string (multi-line).
        """
        w = max(2, w)
        l = max(1, l)
        s = self.formatmonthname(theyear, themonth, 7 * (w + 1) - 1)
        s = s.rstrip()
        s += '\n' * l
        s += self.formatweekheader(w).rstrip()
        s += '\n' * l
        for week in self.monthdays2calendar(theyear, themonth):
            s += self.formatweek(week, w).rstrip()
            s += '\n' * l

    
    def formatyear(self, theyear, w, l, c, m = (2, 1, 6, 3)):
        """
        Returns a year's calendar as a multi-line string.
        """
        w = max(2, w)
        l = max(1, l)
        c = max(2, c)
        colwidth = (w + 1) * 7 - 1
        v = []
        a = v.append
        a(repr(theyear).center(colwidth * m + c * (m - 1)).rstrip())
        a('\n' * l)
        header = self.formatweekheader(w)
        for i, row in enumerate(self.yeardays2calendar(theyear, m)):
            months = range(m * i + 1, min(m * (i + 1) + 1, 13))
            a('\n' * l)
            names = (lambda .0 = None: pass)(months)
            a(formatstring(names, colwidth, c).rstrip())
            a('\n' * l)
            headers = (lambda .0 = None: pass)(months)
            a(formatstring(headers, colwidth, c).rstrip())
            a('\n' * l)
            height = max((lambda .0: pass)(row))
            for j in range(height):
                weeks = []
                for cal in row:
                    weeks.append('')
                weeks.append(self.formatweek(cal[j], w))
                [ '' ]([ self.formatweek(cal[j], w) ](weeks, colwidth, c).rstrip())
                a('\n' * l)
                return [ '\n' * l ].join(v)

    
    def pryear(self, theyear, w, l, c, m = (0, 0, 6, 3)):
        """Print a year's calendar."""
        print(self.formatyear(theyear, w, l, c, m), '', **('end',))



class HTMLCalendar(Calendar):
    '''
    This calendar returns complete HTML pages.
    '''
    cssclasses = [
        'mon',
        'tue',
        'wed',
        'thu',
        'fri',
        'sat',
        'sun']
    cssclasses_weekday_head = cssclasses
    cssclass_noday = 'noday'
    cssclass_month_head = 'month'
    cssclass_month = 'month'
    cssclass_year_head = 'year'
    cssclass_year = 'year'
    
    def formatday(self, day, weekday):
        '''
        Return a day as a table cell.
        '''
        if day == 0:
            return '<td class="%s">&nbsp;</td>' % self.cssclass_noday
        return None % (self.cssclasses[weekday], day)

    
    def formatweek(self, theweek):
        '''
        Return a complete week as a table row.
        '''
        s = None((lambda .0 = None: pass)(theweek))
        return '<tr>%s</tr>' % s

    
    def formatweekday(self, day):
        '''
        Return a weekday name as a table header.
        '''
        return '<th class="%s">%s</th>' % (self.cssclasses_weekday_head[day], day_abbr[day])

    
    def formatweekheader(self):
        '''
        Return a header for a week as a table row.
        '''
        s = None((lambda .0 = None: pass)(self.iterweekdays()))
        return '<tr>%s</tr>' % s

    
    def formatmonthname(self, theyear, themonth, withyear = (True,)):
        '''
        Return a month name as a table row.
        '''
        return None if withyear else '<tr><th colspan="7" class="%s">%s</th></tr>' % (self.cssclass_month_head, s)

    
    def formatmonth(self, theyear, themonth, withyear = (True,)):
        '''
        Return a formatted month as a table.
        '''
        v = []
        a = v.append
        a('<table border="0" cellpadding="0" cellspacing="0" class="%s">' % self.cssclass_month)
        a('\n')
        a(self.formatmonthname(theyear, themonth, withyear, **('withyear',)))
        a('\n')
        a(self.formatweekheader())
        a('\n')
        for week in self.monthdays2calendar(theyear, themonth):
            a(self.formatweek(week))
            a('\n')
            [ self.formatweek(week) ]([ '\n' ])
            a('\n')
            return ''.join(v)

    
    def formatyear(self, theyear, width = (3,)):
        '''
        Return a formatted year as a table of tables.
        '''
        v = []
        a = v.append
        width = max(width, 1)
        a('<table border="0" cellpadding="0" cellspacing="0" class="%s">' % self.cssclass_year)
        a('\n')
        a('<tr><th colspan="%d" class="%s">%s</th></tr>' % (width, self.cssclass_year_head, theyear))
        for i in range(January, January + 12, width):
            months = range(i, min(i + width, 13))
            a('<tr>')
            a('</table>')
            return ''.join(v)

    
    def formatyearpage(self, theyear, width, css, encoding = (3, 'calendar.css', None)):
        '''
        Return a formatted year as a complete HTML page.
        '''
        if encoding is None:
            encoding = sys.getdefaultencoding()
            v = []
            a = v.append
        a('<?xml version="1.0" encoding="%s"?>\n' % encoding)
        a('<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">\n')
        a('<html>\n')
        a('<head>\n')
        a('<meta http-equiv="Content-Type" content="text/html; charset=%s" />\n' % encoding)
        if css is not None:
            a('<link rel="stylesheet" type="text/css" href="%s" />\n' % css)
            a('<title>Calendar for %d</title>\n' % theyear)
            a('</head>\n')
            a('<body>\n')
            a(self.formatyear(theyear, width))
            a('</body>\n')
            a('</html>\n')
            return ''.join(v).encode(encoding, 'xmlcharrefreplace')



class different_locale:
    
    def __init__(self, locale):
        self.locale = locale

    
    def __enter__(self):
        self.oldlocale = _locale.getlocale(_locale.LC_TIME)
        _locale.setlocale(_locale.LC_TIME, self.locale)

    
    def __exit__(self, *args):
        _locale.setlocale(_locale.LC_TIME, self.oldlocale)



class LocaleTextCalendar(TextCalendar):
    '''
    This class can be passed a locale name in the constructor and will return
    month and weekday names in the specified locale. If this locale includes
    an encoding all strings containing month and weekday names will be returned
    as unicode.
    '''
    
    def __init__(self, firstweekday, locale = (0, None)):
        TextCalendar.__init__(self, firstweekday)
        if locale is None:
            locale = _locale.getdefaultlocale()
            self.locale = locale
            return None

    
    def formatweekday(self, day, width):
        pass
    # WARNING: Decompyle incomplete

    
    def formatmonthname(self, theyear, themonth, width, withyear = (True,)):
        pass
    # WARNING: Decompyle incomplete



class LocaleHTMLCalendar(HTMLCalendar):
    '''
    This class can be passed a locale name in the constructor and will return
    month and weekday names in the specified locale. If this locale includes
    an encoding all strings containing month and weekday names will be returned
    as unicode.
    '''
    
    def __init__(self, firstweekday, locale = (0, None)):
        HTMLCalendar.__init__(self, firstweekday)
        if locale is None:
            locale = _locale.getdefaultlocale()
            self.locale = locale
            return None

    
    def formatweekday(self, day):
        pass
    # WARNING: Decompyle incomplete

    
    def formatmonthname(self, theyear, themonth, withyear = (True,)):
        pass
    # WARNING: Decompyle incomplete


c = TextCalendar()
firstweekday = c.getfirstweekday

def setfirstweekday(firstweekday):
    raise None if not firstweekday <= firstweekday or firstweekday <= SUNDAY else IllegalWeekdayError(firstweekday)
    c.firstweekday = firstweekday

monthcalendar = c.monthdayscalendar
prweek = c.prweek
week = c.formatweek
weekheader = c.formatweekheader
prmonth = c.prmonth
month = c.formatmonth
calendar = c.formatyear
prcal = c.pryear
_colwidth = 20
_spacing = 6

def format(cols, colwidth, spacing = (_colwidth, _spacing)):
    '''Prints multi-column formatting for year calendars'''
    print(formatstring(cols, colwidth, spacing))


def formatstring(cols, colwidth, spacing = (_colwidth, _spacing)):
    '''Returns a string formatted from n strings, centered within n columns.'''
    spacing *= ' '
    return None((lambda .0 = None: pass)(cols))

EPOCH = 1970
_EPOCH_ORD = datetime.date(EPOCH, 1, 1).toordinal()

def timegm(tuple):
    '''Unrelated but handy function to calculate Unix timestamp from GMT.'''
    (year, month, day, hour, minute, second) = tuple[:6]
    days = (datetime.date(year, month, 1).toordinal() - _EPOCH_ORD) + day - 1
    hours = days * 24 + hour
    minutes = hours * 60 + minute
    seconds = minutes * 60 + second
    return seconds


def main(args):
    import argparse
    parser = argparse.ArgumentParser()
    textgroup = parser.add_argument_group('text only arguments')
    htmlgroup = parser.add_argument_group('html only arguments')
    textgroup.add_argument('-w', '--width', int, 2, 'width of date column (default 2)', **('type', 'default', 'help'))
    textgroup.add_argument('-l', '--lines', int, 1, 'number of lines for each week (default 1)', **('type', 'default', 'help'))
    textgroup.add_argument('-s', '--spacing', int, 6, 'spacing between months (default 6)', **('type', 'default', 'help'))
    textgroup.add_argument('-m', '--months', int, 3, 'months per row (default 3)', **('type', 'default', 'help'))
    htmlgroup.add_argument('-c', '--css', 'calendar.css', 'CSS to use for page', **('default', 'help'))
    parser.add_argument('-L', '--locale', None, 'locale to be used from month and weekday names', **('default', 'help'))
    parser.add_argument('-e', '--encoding', None, 'encoding to use for output', **('default', 'help'))
    parser.add_argument('-t', '--type', 'text', ('text', 'html'), 'output type (text or html)', **('default', 'choices', 'help'))
    parser.add_argument('year', '?', int, 'year number (1-9999)', **('nargs', 'type', 'help'))
    parser.add_argument('month', '?', int, 'month number (1-12, text only)', **('nargs', 'type', 'help'))
    options = parser.parse_args(args[1:])
# WARNING: Decompyle incomplete

if __name__ == '__main__':
    main(sys.argv)
    return None
