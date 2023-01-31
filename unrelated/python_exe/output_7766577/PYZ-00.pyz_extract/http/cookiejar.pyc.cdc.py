
"""HTTP cookie handling for web clients.

This module has (now fairly distant) origins in Gisle Aas' Perl module
HTTP::Cookies, from the libwww-perl library.

Docstrings, comments and debug strings in this code refer to the
attributes of the HTTP cookie system as cookie-attributes, to distinguish
them clearly from Python attributes.

Class diagram (note that BSDDBCookieJar and the MSIE* classes are not
distributed with the Python standard library, but are available from
http://wwwsearch.sf.net/):

                        CookieJar____
                        /     \\      \\
            FileCookieJar      \\      \\
             /    |   \\         \\      \\
 MozillaCookieJar | LWPCookieJar \\      \\
                  |               |      \\
                  |   ---MSIEBase |       \\
                  |  /      |     |        \\
                  | /   MSIEDBCookieJar BSDDBCookieJar
                  |/
               MSIECookieJar

"""
__all__ = [
    'Cookie',
    'CookieJar',
    'CookiePolicy',
    'DefaultCookiePolicy',
    'FileCookieJar',
    'LWPCookieJar',
    'LoadError',
    'MozillaCookieJar']
import os
import copy
import datetime
import re
import time
import urllib.parse as urllib
import urllib.request as urllib
import threading as _threading
import http.client as http
from calendar import timegm
debug = False
logger = None

def _debug(*args):
    global logger
    if not debug:
        return None
    if not None:
        import logging
        logger = logging.getLogger('http.cookiejar')
# WARNING: Decompyle incomplete

HTTPONLY_ATTR = 'HTTPOnly'
HTTPONLY_PREFIX = '#HttpOnly_'
DEFAULT_HTTP_PORT = str(http.client.HTTP_PORT)
NETSCAPE_MAGIC_RGX = re.compile('#( Netscape)? HTTP Cookie File')
MISSING_FILENAME_TEXT = 'a filename was not supplied (nor was the CookieJar instance initialised with one)'
NETSCAPE_HEADER_TEXT = '# Netscape HTTP Cookie File\n# http://curl.haxx.se/rfc/cookie_spec.html\n# This is a generated file!  Do not edit.\n\n'

def _warn_unhandled_exception():
    import io
    import warnings
    import traceback
    f = io.StringIO()
    traceback.print_exc(None, f)
    msg = f.getvalue()
    warnings.warn('http.cookiejar bug!\n%s' % msg, 2, **('stacklevel',))

EPOCH_YEAR = 1970

def _timegm(tt):
    (year, month, mday, hour, min, sec) = tt[:6]
    if year >= EPOCH_YEAR:
        if month <= month or month <= 12:
            pass
        else:
            1
            return None
        if mday <= mday or mday <= 31:
            pass
        else:
            1
            return None
        if hour <= hour or hour <= 24:
            pass
        else:
            1
            return None
        if min <= min or min <= 59:
            pass
        else:
            1
            return None
        if sec <= sec or sec <= 61:
            return timegm(tt)
        return None

DAYS = [
    'Mon',
    'Tue',
    'Wed',
    'Thu',
    'Fri',
    'Sat',
    'Sun']
MONTHS = [
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
    'Dec']
MONTHS_LOWER = []

def time2isoz(t = (None,)):
    '''Return a string representing time in seconds since epoch, t.

    If the function is called without an argument, it will use the current
    time.

    The format of the returned string is like "YYYY-MM-DD hh:mm:ssZ",
    representing Universal Time (UTC, aka GMT).  An example of this format is:

    1994-11-24 08:49:37Z

    '''
    if t is None:
        dt = datetime.datetime.utcnow()
    else:
        dt = datetime.datetime.utcfromtimestamp(t)
    return '%04d-%02d-%02d %02d:%02d:%02dZ' % (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)


def time2netscape(t = (None,)):
    '''Return a string representing time in seconds since epoch, t.

    If the function is called without an argument, it will use the current
    time.

    The format of the returned string is like this:

    Wed, DD-Mon-YYYY HH:MM:SS GMT

    '''
    if t is None:
      