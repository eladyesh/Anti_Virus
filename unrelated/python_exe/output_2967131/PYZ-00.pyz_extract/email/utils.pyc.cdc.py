
'''Miscellaneous utilities.'''
__all__ = [
    'collapse_rfc2231_value',
    'decode_params',
    'decode_rfc2231',
    'encode_rfc2231',
    'formataddr',
    'formatdate',
    'format_datetime',
    'getaddresses',
    'make_msgid',
    'mktime_tz',
    'parseaddr',
    'parsedate',
    'parsedate_tz',
    'parsedate_to_datetime',
    'unquote']
import os
import re
import time
import random
import socket
import datetime
import urllib.parse as urllib
from email._parseaddr import quote
from email._parseaddr import AddressList as _AddressList
from email._parseaddr import mktime_tz
from email._parseaddr import parsedate, parsedate_tz, _parsedate_tz
from email.charset import Charset
COMMASPACE = ', '
EMPTYSTRING = ''
UEMPTYSTRING = ''
CRLF = '\r\n'
TICK = "'"
specialsre = re.compile('[][\\\\()<>@,:;".]')
escapesre = re.compile('[\\\\"]')

def _has_surrogates(s):
    '''Return True if s contains surrogate-escaped binary data.'''
    pass
# WARNING: Decompyle incomplete


def _sanitize(string):
    original_bytes = string.encode('utf-8', 'surrogateescape')
    return original_bytes.decode('utf-8', 'replace')


def formataddr(pair, charset = ('utf-8',)):
    """The inverse of parseaddr(), this takes a 2-tuple of the form
    (realname, email_address) and returns the string value suitable
    for an RFC 2822 From, To or Cc header.

    If the first element of pair is false, then the second element is
    returned unmodified.

    The optional charset is the character set that is used to encode
    realname in case realname is not ASCII safe.  Can be an instance of str or
    a Charset-like object which has a header_encode method.  Default is
    'utf-8'.
    """
    (name, address) = pair
    address.encode('ascii')
# WARNING: Decompyle incomplete


def getaddresses(fieldvalues):
    '''Return a list of (REALNAME, EMAIL) for each fieldvalue.'''
    all = COMMASPACE.join(fieldvalues)
    a = _AddressList(all)
    return a.addresslist


def _format_timetuple_and_zone(timetuple, zone):
    return '%s, %02d %s %04d %02d:%02d:%02d %s' % ([
        'Mon',
        'Tue',
        'Wed',
        'Thu',
        'Fri',
        'Sat',
        'Sun'][timetuple[6]], timetuple[2], [
        'Jan',
        'Feb',
        'Mar',
        'Apr',
        'May',
        'Jun',
        'Jul',
        'Aug',
        'Sep',
        'Oct',
        'Nov',
        'Dec'][timetuple[1] - 1], timetuple[0], timetuple[3], timetuple[4], timetuple[5], zone)


def formatdate(timeval, localtime, usegmt = (None, False, False)):
    '''Returns a date string as specified by RFC 2822, e.g.:

    Fri, 09 Nov 2001 01:08:47 -0000

    Optional timeval if given is a floating point time value as accepted by
    gmtime() and localtime(), otherwise the current time is used.

    Optional localtime is a flag that when True, interprets timeval, and
    returns a date relative to the local timezone instead of UTC, properly
    taking daylight savings time into account.

    Optional argument usegmt means that the timezone is written out as
    an ascii string, not numeric one (so "GMT" instead of "+0000"). This
    is needed for HTTP, and is only used when localtime==False.
    '''
    if timeval is None:
        timeval = time.time()
        if localtime or usegmt:
            dt = datetime.datetime.fromtimestamp(timeval, datetime.timezone.utc)
        else:
            dt = datetime.datetime.utcfromtimestamp(timeval)
            if localtime:
                dt = dt.astimezone()
                usegmt = False
                return format_datetime(dt, usegmt)


def format_datetime(dt, usegmt = (False,)):
    """Turn a datetime into a date string as specified in RFC 2822.

    If usegmt is True, dt must be an aware datetime with an offset of zero.  In
    this case 'GMT' will be rendered instead of the normal +0000 required by
    RFC2822.  This is to support HTTP headers involving date stamps.
    """
    now = dt.timetuple()
    if usegmt:
        if dt.tzinfo is None or dt.tzinfo != datetime.timezone.utc:
            raise ValueError('usegmt option requires a UTC datetime')
        zone = None
    elif dt.tzinfo is None:
        zone = '-0000'
    else:
        zone = dt.strftime('%z')
        return _format_timetuple_and_zone(now, zone)


def make_msgid(idstring, domain = (None, None)):
    """Returns a string suitable for RFC 2822 compliant Message-ID, e.g:

    <142480216486.20800.16526388040877946887@nightshade.la.mastaler.com>

    Optional idstring if given is a string used to strengthen the
    uniqueness of the message id.  Optional domain if given provides the
    portion of the message id after the '@'.  It defaults to the locally
    defined hostname.
    """
    timeval = int(time.time() * 100)
    pid = os.getpid()
    randint = random.getrandbits(64)
    if idstring is None:
        idstring = ''
    else:
        idstring = '.' + idstring
        if domain is None:
            domain = socket.getfqdn()
            msgid = '<%d.%d.%d%s@%s>' % (timeval, pid, randint, idstring, domain)
            return msgid


def parsedate_to_datetime(data):
    pass
# WARNING: Decompyle incomplete


def parseaddr(addr):
    """
    Parse addr into its constituent realname and email address parts.

    Return a tuple of realname and email address, unless the parse fails, in
    which case return a 2-tuple of ('', '').
    """
    addrs = _AddressList(addr).addresslist
    if not addrs:
        return ('', '')
    return None[0]


def unquote(str):
    '''Remove quotes from a string.'''
    if len(str) > 1:
        if str.startswith('"') and str.endswith('"'):
            return str[1:-1].replace('\\\\', '\\').replace('\\"', '"')
        if None.startswith('<') and str.endswith('>'):
            return str[1:-1]
        return None


def decode_rfc2231(s):
    '''Decode string according to RFC 2231'''
    parts = s.split(TICK, 2)
    if len(parts) <= 2:
        return (None, None, s)


def encode_rfc2231(s, charset, language = (None, None)):
    '''Encode string according to RFC 2231.

    If neither charset nor language is given, then s is returned as-is.  If
    charset is given but not language, the string is encoded using the empty
    string for language.
    '''
    if not charset:
        s = urllib.parse.quote(s, '', 'ascii', **('safe', 'encoding'))
        if charset is None and language is None:
            return s
        if None is None:
            language = ''
            return "%s'%s'%s" % (charset, language, s)

rfc2231_continuation = re.compile('^(?P<name>\\w+)\\*((?P<num>[0-9]+)\\*?)?$', re.ASCII)

def decode_params(params):
    '''Decode parameters list according to RFC 2231.

    params is a sequence of 2-tuples containing (param name, string value).
    '''
    new_params = [
        params[0]]
    rfc2231_params = { }
    new_params.append((name, '"%s"' % quote(value)))
    continue
    if rfc2231_params:
        for name, continuations in rfc2231_params.items():
            value = []
            extended = False
            continuations.sort()
            for num, s, encoded in continuations:
                s = urllib.parse.unquote(s, 'latin-1', **('encoding',))
                extended = True
                value.append(s)
            value = quote(EMPTYSTRING.join(value))
            (charset, language, value) = decode_rfc2231(value)
            new_params.append((name, (charset, language, '"%s"' % value)))
            [ (name, (charset, language, '"%s"' % value)) ]((name, '"%s"' % value))


def collapse_rfc2231_value(value, errors, fallback_charset = ('replace', 'us-ascii')):
    if isinstance(value, tuple) or len(value) != 3:
        return unquote(value)
    (charset, language, text) = None
# WARNING: Decompyle incomplete


def localtime(dt, isdst = (None, -1)):
    '''Return local time as an aware datetime object.

    If called without arguments, return current time.  Otherwise *dt*
    argument should be a datetime instance, and it is converted to the
    local time zone according to the system time zone database.  If *dt* is
    naive (that is, dt.tzinfo is None), it is assumed to be in local time.
    In this case, a positive or zero value for *isdst* causes localtime to
    presume initially that summer time (for example, Daylight Saving Time)
    is or is not (respectively) in effect for the specified time.  A
    negative value for *isdst* causes the localtime() function to attempt
    to divine whether summer time is in effect for the specified time.

    '''
    if dt is None:
        return datetime.datetime.now(datetime.timezone.utc).astimezone()
    if None.tzinfo is not None:
        return dt.astimezone()
    tm = None.timetuple()[:-1] + (isdst,)
    seconds = time.mktime(tm)
    localtm = time.localtime(seconds)
# WARNING: Decompyle incomplete

