
'''Base16, Base32, Base64 (RFC 3548), Base85 and Ascii85 data encodings'''
import re
import struct
import binascii
__all__ = [
    'encode',
    'decode',
    'encodebytes',
    'decodebytes',
    'b64encode',
    'b64decode',
    'b32encode',
    'b32decode',
    'b32hexencode',
    'b32hexdecode',
    'b16encode',
    'b16decode',
    'b85encode',
    'b85decode',
    'a85encode',
    'a85decode',
    'standard_b64encode',
    'standard_b64decode',
    'urlsafe_b64encode',
    'urlsafe_b64decode']
bytes_types = (bytes, bytearray)

def _bytes_from_decode_data(s):
    pass
# WARNING: Decompyle incomplete


def b64encode(s, altchars = (None,)):
    """Encode the bytes-like object s using Base64 and return a bytes object.

    Optional altchars should be a byte string of length 2 which specifies an
    alternative alphabet for the '+' and '/' characters.  This allows an
    application to e.g. generate url or filesystem safe Base64 strings.
    """
    encoded = binascii.b2a_base64(s, False, **('newline',))
# WARNING: Decompyle incomplete


def b64decode(s, altchars, validate = (None, False)):
    """Decode the Base64 encoded bytes-like object or ASCII string s.

    Optional altchars must be a bytes-like object or ASCII string of length 2
    which specifies the alternative alphabet used instead of the '+' and '/'
    characters.

    The result is returned as a bytes object.  A binascii.Error is raised if
    s is incorrectly padded.

    If validate is False (the default), characters that are neither in the
    normal base-64 alphabet nor the alternative alphabet are discarded prior
    to the padding check.  If validate is True, these non-alphabet characters
    in the input result in a binascii.Error.
    """
    s = _bytes_from_decode_data(s)
# WARNING: Decompyle incomplete


def standard_b64encode(s):
    '''Encode bytes-like object s using the standard Base64 alphabet.

    The result is returned as a bytes object.
    '''
    return b64encode(s)


def standard_b64decode(s):
    '''Decode bytes encoded with the standard Base64 alphabet.

    Argument s is a bytes-like object or ASCII string to decode.  The result
    is returned as a bytes object.  A binascii.Error is raised if the input
    is incorrectly padded.  Characters that are not in the standard alphabet
    are discarded prior to the padding check.
    '''
    return b64decode(s)

_urlsafe_encode_translation = bytes.maketrans(b'+/', b'-_')
_urlsafe_decode_translation = bytes.maketrans(b'-_', b'+/')

def urlsafe_b64encode(s):
    """Encode bytes using the URL- and filesystem-safe Base64 alphabet.

    Argument s is a bytes-like object to encode.  The result is returned as a
    bytes object.  The alphabet uses '-' instead of '+' and '_' instead of
    '/'.
    """
    return b64encode(s).translate(_urlsafe_encode_translation)


def urlsafe_b64decode(s):
    """Decode bytes using the URL- and filesystem-safe Base64 alphabet.

    Argument s is a bytes-like object or ASCII string to decode.  The result
    is returned as a bytes object.  A binascii.Error is raised if the input
    is incorrectly padded.  Characters that are not in the URL-safe base-64
    alphabet, and are not a plus '+' or slash '/', are discarded prior to the
    padding check.

    The alphabet uses '-' instead of '+' and '_' instead of '/'.
    """
    s = _bytes_from_decode_data(s)
    s = s.translate(_urlsafe_decode_translation)
    return b64decode(s)

_B32_ENCODE_DOCSTRING = '\nEncode the bytes-like objects using {encoding} and return a bytes object.\n'
_B32_DECODE_DOCSTRING = '\nDecode the {encoding} encoded bytes-like object or ASCII string s.\n\nOptional casefold is a flag specifying whether a lowercase alphabet is\nacceptable as input.  For security purposes, the default is False.\n{extra_args}\nThe result is returned as a bytes object.  A binascii.Error is raised if\nthe input is incorrectly padded or if there are non-alphabet\ncharacters present in the input.\n'
_B32_DECODE_MAP01_DOCSTRING = '\nRFC 3548 allows for optional mapping of the digit 0 (zero) to the\nletter O (oh), and for optional mapping of the digit 1 (one) to\neither the letter I (eye) or letter L (el).  The optional argument\nmap01 when not None, specifies which letter the digit 1 should be\nmapped to (when map01 is not None, the digit 0 is always mapped to\nthe letter O).  For security purposes the default is None, so that\n0 and 1 are not allowed in the input.\n'
_b32alphabet = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
_b32hexalphabet = b'0123456789ABCDEFGHIJKLMNOPQRSTUV'
_b32tab2 = { }
_b32rev = { }

def _b32encode(alphabet, s):
    if alphabet not in _b32tab2:
        b32tab = (lambda .0: [ bytes((i,)) for i in .0 ])(alphabet)
        _b32tab2[alphabet] = (lambda .0 = None: [ a + b for a in .0 for b in b32tab ])(b32tab)
        b32tab = None
    if not isinstance(s, bytes_types):
        s = memoryview(s).tobytes()
    leftover = len(s) % 5
    if leftover:
        s = s + b'\x00' * (5 - leftover)
    encoded = bytearray()
    from_bytes = int.from_bytes
    b32tab2 = _b32tab2[alphabet]
    if leftover == 1:
        encoded[-6:] = b'======'
        return bytes(encoded)
    if None == 2:
        encoded[-4:] = b'===='
        return bytes(encoded)
    if None == 3:
        encoded[-3:] = b'==='
        return bytes(encoded)
    if None == 4:
        encoded[-1:] = b'='
    return bytes(encoded)


def _b32decode(alphabet, s, casefold, map01 = (False, None)):
    if alphabet not in _b32rev:
        _b32rev[alphabet] = (lambda .0: pass# WARNING: Decompyle incomplete
)(enumerate(alphabet))
    s = _bytes_from_decode_data(s)
    if len(s) % 8:
        raise binascii.Error('Incorrect padding')
# WARNING: Decompyle incomplete


def b32encode(s):
    return _b32encode(_b32alphabet, s)

b32encode.__doc__ = _B32_ENCODE_DOCSTRING.format('base32', **('encoding',))

def b32decode(s, casefold, map01 = (False, None)):
    return _b32decode(_b32alphabet, s, casefold, map01)

b32decode.__doc__ = _B32_DECODE_DOCSTRING.format('base32', _B32_DECODE_MAP01_DOCSTRING, **('encoding', 'extra_args'))

def b32hexencode(s):
    return _b32encode(_b32hexalphabet, s)

b32hexencode.__doc__ = _B32_ENCODE_DOCSTRING.format('base32hex', **('encoding',))

def b32hexdecode(s, casefold = (False,)):
    return _b32decode(_b32hexalphabet, s, casefold)

b32hexdecode.__doc__ = _B32_DECODE_DOCSTRING.format('base32hex', '', **('encoding', 'extra_args'))

def b16encode(s):
    '''Encode the bytes-like object s using Base16 and return a bytes object.
    '''
    return binascii.hexlify(s).upper()


def b16decode(s, casefold = (False,)):
    '''Decode the Base16 encoded bytes-like object or ASCII string s.

    Optional casefold is a flag specifying whether a lowercase alphabet is
    acceptable as input.  For security purposes, the default is False.

    The result is returned as a bytes object.  A binascii.Error is raised if
    s is incorrectly padded or if there are non-alphabet characters present
    in the input.
    '''
    s = _bytes_from_decode_data(s)
    if casefold:
        s = s.upper()
    if re.search(b'[^0-9A-F]', s):
        raise binascii.Error('Non-base16 digit found')
    return None.unhexlify(s)

_a85chars = None
_a85chars2 = None
_A85START = b'<~'
_A85END = b'~>'

def _85encode(b, chars, chars2, pad, foldnuls, foldspaces = (False, False, False)):
    if not isinstance(b, bytes_types):
        b = memoryview(b).tobytes()
    padding = -len(b) % 4
    if padding:
        b = b + b'\x00' * padding
    words = struct.Struct('!%dI' % len(b) // 4).unpack(b)
    chunks = (lambda .0 = None: for word in .0:
passcontinueb'z'[b'y' if foldspaces and word == 538976288 else chars2[word // 614125] + chars2[word // 85 % 7225] + chars[word % 85]])(words)
    if not padding and pad:
        if chunks[-1] == b'z':
            chunks[-1] = chars[0] * 5
        chunks[-1] = chunks[-1][:-padding]
    return b''.join(chunks)


def a85encode(b = None, *, foldspaces, wrapcol, pad, adobe):
    '''Encode bytes-like object b using Ascii85 and return a bytes object.

    foldspaces is an optional flag 