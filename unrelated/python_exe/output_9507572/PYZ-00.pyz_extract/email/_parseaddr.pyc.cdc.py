
'''Email address parsing code.

Lifted directly from rfc822.py.  This should eventually be rewritten.
'''
__all__ = [
    'mktime_tz',
    'parsedate',
    'parsedate_tz',
    'quote']
import time
import calendar
SPACE = ' '
EMPTYSTRING = ''
COMMASPACE = ', '
_monthnames = [
    'jan',
    'feb',
    'mar',
    'apr',
    'may',
    'jun',
    'jul',
    'aug',
    'sep',
    'oct',
    'nov',
    'dec',
    'january',
    'february',
    'march',
    'april',
    'may',
    'june',
    'july',
    'august',
    'september',
    'october',
    'november',
    'december']
_daynames = [
    'mon',
    'tue',
    'wed',
    'thu',
    'fri',
    'sat',
    'sun']
_timezones = {
    'UT': 0,
    'UTC': 0,
    'GMT': 0,
    'Z': 0,
    'AST': -400,
    'ADT': -300,
    'EST': -500,
    'EDT': -400,
    'CST': -600,
    'CDT': -500,
    'MST': -700,
    'MDT': -600,
    'PST': -800,
    'PDT': -700 }

def parsedate_tz(data):
    '''Convert a date string to a time tuple.

    Accounts for military timezones.
    '''
    res = _parsedate_tz(data)
    if not res:
        return None
    if None[9] is None:
        res[9] = 0
        return tuple(res)


def _parsedate_tz(data):
    '''Convert date to extended time tuple.

    The last (additional) element is the time zone offset in seconds, except if
    the timezone was specified as -0000.  In that case the last element is
    None.  This indicates a UTC timestamp that explicitly declaims knowledge of
    the source timezone, as opposed to a +0000 timestamp that indicates the
    source timezone really was UTC.

    '''
    if not data:
        return None
    data = None.split()
    if data[0].endswith(',') or data[0].lower() in _daynames:
        del data[0]
# WARNING: Decompyle incomplete


def parsedate(data):
    '''Convert a time string to a time tuple.'''
    t = parsedate_tz(data)
    if isinstance(t, tuple):
        return t[:9]
    return None


def mktime_tz(data):
    '''Turn a 10-tuple as returned by parsedate_tz() into a POSIX timestamp.'''
    if data[9] is None:
        return time.mktime(data[:8] + (-1,))
    t = None.timegm(data)
    return t - data[9]


def quote(str):
    '''Prepare string to be used in a quoted string.

    Turns backslash and double quote characters into quoted pairs.  These
    are the only characters that need to be quoted inside a quoted string.
    Does not add the surrounding double quotes.
    '''
    return str.replace('\\', '\\\\').replace('"', '\\"')


class AddrlistClass:
    '''Address parser class by Ben Escoto.

    To understand what this class does, it helps to have a copy of RFC 2822 in
    front of you.

    Note: this class interface is deprecated and may be removed in the future.
    Use email.utils.AddressList instead.
    '''
    
    def __init__(self, field):
        """Initialize a new instance.

        `field' is an unparsed address header field, containing
        one or more addresses.
        """
        self.specials = '()<>@,:;."[]'
        self.pos = 0
        self.LWS = ' \t'
        self.CR = '\r\n'
        self.FWS = self.LWS + self.CR
        self.atomends = self.specials + self.LWS + self.CR
        self.phraseends = self.atomends.replace('.', '')
        self.field = field
        self.commentlist = []

    
    def gotonext(self):
        '''Skip white space and extract comments.'''
        wslist = []
        if self.pos < len(self.field):
            if self.field[self.pos] in self.LWS + '\n\r':
                if self.field[self.pos] not in '\n\r':
                    wslist.append(self.field[self.pos])
                    self.pos += 1
                    continue
                    if self.field[self.pos] == '(':
                        self.commentlist.append(self.getcomment())
                        continue
                    
                    return EMPTYSTRING.join(wslist)

    
    def getaddrlist(self):
        '''Parse all addresses.

        Returns a list containing all of the addresses.
        '