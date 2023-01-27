
''' Routines for manipulating RFC2047 encoded words.

This is currently a package-private API, but will be considered for promotion
to a public API if there is demand.

'''
import re
import base64
import binascii
import functools
from string import ascii_letters, digits
from email import errors
__all__ = [
    'decode_q',
    'encode_q',
    'decode_b',
    'encode_b',
    'len_q',
    'len_b',
    'decode',
    'encode']
_q_byte_subber = functools.partial(re.compile(b'=([a-fA-F0-9]{2})').sub, (lambda m: bytes.fromhex(m.group(1).decode())))

def decode_q(encoded):
    encoded = encoded.replace(b'_', b' ')
    return (_q_byte_subber(encoded), [])


class _QByteMap(dict):
    safe = b'-!*+/' + ascii_letters.encode('ascii') + digits.encode('ascii')
    
    def __missing__(self, key):
        if key in self.safe:
            self[key] = chr(key)
        else:
            self[key] = '={:02X}'.format(key)
            return self[key]


_q_byte_map = _QByteMap()
_q_byte_map[ord(' ')] = '_'

def encode_q(bstring):
    return ''.join((lambda .0: pass)(bstring))


def len_q(bstring):
    return sum((lambda .0: pass)(bstring))


def decode_b(encoded):
    pad_err = len(encoded) % 4
# WARNING: Decompyle incomplete


def encode_b(bstring):
    return base64.b64encode(bstring).decode('ascii')


def len_b(bstring):
    (groups_of_3, leftover) = divmod(len(bstring), 3)
    return groups_of_3 * 4 if leftover else 4 + 0

_cte_decoders = {
    'q': decode_q,
    'b': decode_b }

def decode(ew):
    """Decode encoded word and return (string, charset, lang, defects) tuple.

    An RFC 2047/2243 encoded word has the form:

        =?charset*lang?cte?encoded_string?=

    where '*lang' may be omitted but the other parts may not be.

    This function expects exactly such a string (that is, it does not check the
    syntax and may raise errors if the string is not well formed), and returns
    the encoded_string decoded first from its Content Transfer Encoding and
    then from the resulting bytes into unicode using the specified charset.  If
    the cte-decoded string does not successfully decode using the specified
    character set, a defect is added to the defects list and the unknown octets
    are replaced by the unicode 'unknown' character \\uFDFF.

    The specified charset and language are returned.  The default for language,
    which is rarely if ever encountered, is the empty string.

    """
    (_, charset, cte, cte_string, _) = ew.split('?')
    (charset, _, lang) = charset.partition('*')
    cte = cte.lower()
    bstring = cte_string.encode('ascii', 'surrogateescape')
    (bstring, defects) = _cte_decoders[cte](bstring)
# WARNING: Decompyle incomplete

_cte_encoders = {
    'q': encode_q,
    'b': encode_b }
_cte_encode_length = {
    'q': len_q,
    'b': len_b }

def encode(string, charset, encoding, lang = ('utf-8', None, '')):
    """Encode string using the CTE encoding that produces the shorter result.

    Produces an RFC 2047/2243 encoded word of the form:

        =?charset*lang?cte?encoded_string?=

    where '*lang' is omitted unless the 'lang' parameter is given a value.
    Optional argument charset (defaults to utf-8) specifies the charset to use
    to encode the string to binary before CTE encoding it.  Optional argument
    'encoding' is the cte specifier for the encoding that should be used ('q'
    or 'b'); if it is None (the default) the encoding which produces the
    shortest encoded sequence is used, except that 'q' is preferred if it is up
    to five characters longer.  Optional argument 'lang' (default '') gives the
    RFC 2243 language string to specify in the encoded word.

    """
    if charset == 'unknown-8bit':
        bstring = string.encode('ascii', 'surrogateescape')
    else:
        bstring = string.encode(charset)
        if encoding is None:
            qlen = _cte_encode_length['q'](bstring)
            blen = _cte_encode_length['b'](bstring)
            encoded = _cte_encoders[encoding](bstring)
            if lang:
                lang = '*' + lang
                return '=?{}{}?{}?{}?='.format(charset, lang, encoding, encoded)

