
__all__ = [
    'Charset',
    'add_alias',
    'add_charset',
    'add_codec']
from functools import partial
import email.base64mime as email
import email.quoprimime as email
from email import errors
from email.encoders import encode_7or8bit
QP = 1
BASE64 = 2
SHORTEST = 3
RFC2047_CHROME_LEN = 7
DEFAULT_CHARSET = 'us-ascii'
UNKNOWN8BIT = 'unknown-8bit'
EMPTYSTRING = ''
# WARNING: Decompyle incomplete
