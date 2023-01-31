
'''Header encoding and decoding functionality.'''
__all__ = [
    'Header',
    'decode_header',
    'make_header']
import re
import binascii
import email.quoprimime as email
import email.base64mime as email
from email.errors import HeaderParseError
from email import charset as _charset
Charset = _charset.Charset
NL = '\n'
SPACE = ' '
BSPACE = b' '
SPACE8 = '        '
EMPTYSTRING = ''
MAXLINELEN = 78
FWS = ' \t'
USASCII = Charset('us-ascii')
UTF8 = Charset('utf-8')
ecre = re.compile('\n  =\\?                   # literal =?\n  (?P<charset>[^?]*?)   # non-greedy up to the next ? is the charset\n  \\?                    # literal ?\n  (?P<encoding>[qQbB])  # either a "q" or a "b", case insensitive\n  \\?                    # literal ?\n  (?P<encoded>.*?)      # non-greedy up to the next ?= is the encoded string\n  \\?=                   # literal ?=\n  ', re.VERBOSE | re.MULTILINE)
fcre = re.compile('[\\041-\\176]+:$')
_embedded_header = re.compile('\\n[^ \\t]+:')
_max_append = email.quoprimime._max_append

def decode_header(header):
    '''Decode a message header value without converting charset.

    Returns a list of (string, charset) pairs containing each of the decoded
    parts of the header.  Charset is None for non-encoded parts of the header,
    otherwise a lower-case string containing the name of the character set
    specified in the encoded string.

    header may be a string that may or may not contain RFC2047 encoded words,
    or it may be a Header object.

    An email.errors.HeaderParseError may be raised when certain decoding error
    occurs (e.g. a base64 decoding exception).
    '''
    if hasattr(header, '_chunks'):
        return (lambda .0: [ (_charset._encode(string, str(charset)), str(charset)) for string, charset in .0 ])(header._chunks)
    if not None.search(header):
        return [
            (header, None)]
    words = None
    droplist = []
    decoded_words = []
    if encoding == 'q':
        word = email.quoprimime.header_decode(encoded_string)
        decoded_words.append((word, charset))
        continue
# WARNING: Decompyle incomplete


def make_header(decoded_seq, maxlinelen, header_name, continuation_ws = (None, None, ' ')):
    '''Create a Header from a sequence of pairs as returned by decode_header()

    decode_header() takes a header value string and returns a sequence of
    pairs of the format (decoded_string, charset) where charset is the string
    name of the character set.

    This function takes one of those sequence of pairs and returns a Header
    instance.  Optional maxlinelen, header_name, and continuation_ws are as in
    the Header constructor.
    '''
    h = Header(maxlinelen, header_name, continuation_ws, **('maxlinelen', 'header_name', 'continuation_ws'))
    return h


class Header:
    
    def __init__(self, s, charset, maxlinelen, header_name, continuation_ws, errors = (None, None, None, None, ' ', 'strict')):
        """Create a MIME-compliant header that can contain many character sets.

        Optional s is the initial header value.  If None, the initial header
        value is not set.  You can later append to the header with .append()
        method calls.  s may be a byte string or a Unicode string, but see the
        .append() documentation for semantics.

        Optional charset serves two purposes: it has the same meaning as the
        charset argument to the .append() method.  It also sets the default
        character set for all subsequent .append() calls that omit the charset
        argument.  If charset is not provided in the constructor, the us-ascii
        charset is used both as s's initial charset and as the default for
        subsequent .append() calls.

        The maximum line length can be specified explicitly via maxlinelen. For
        splitting the first line to a shorter value (to account for the field
        header which isn't included in s, e.g. `Subject') pass in the name of
        the field in header_name.  The default maxlinelen is 78