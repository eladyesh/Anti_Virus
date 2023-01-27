
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

_b32alphabet = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
_b32tab2 = None
_b32rev = None

def b32encode(s):
    '''Encode the bytes-like object s using Base32 and return a bytes object.
    '''
    global _b32tab2
    if _b32tab2 is None:
        b32tab = (lambda .0: [ bytes((i,)) for i in .0 ])(_b32alphabet)
        _b32tab2 = (lambda .0 = None: [ a + b for a in .0 for b in b32tab ])(b32tab)
        b32tab = None
        if not isinstance(s, bytes_types):
            s = memoryview(s).tobytes()
            leftover = len(s) % 5
            if leftover:
                s = s + b'\x00' * (5 - leftover)
                encoded = bytearray()
                from_bytes = int.from_bytes
                b32tab2 = _b32tab2
                for i in range(0, len(s), 5):
                    c = from_bytes(s[i:i + 5], 'big')
                    encoded += b32tab2[c >> 30] + b32tab2[c >> 20 & 1023] + b32tab2[c >> 10 & 1023] + b32tab2[c & 1023]
                if leftover == 1:
                    encoded[-6:] = b'======'
                elif leftover == 2:
                    encoded[-4:] = b'===='
                elif leftover == 3:
                    encoded[-3:] = b'==='
                elif leftover == 4:
                    encoded[-1:] = b'='
                    return bytes(encoded)


def b32decode(s, casefold, map01 = (False, None)):
    '''Decode the Base32 encoded bytes-like object or ASCII string s.

    Optional casefold is a flag specifying whether a lowercase alphabet is
    acceptable as input.  For security purposes, the default is False.

    RFC 3548 allows for optional mapping of the digit 0 (zero) to the
    letter O (oh), and for optional mapping of the digit 1 (one) to
    either the letter I (eye) or letter L (el).  The optional argument
    map01 when not None, specifies which letter the digit 1 should be
    mapped to (when map01 is not None, the digit 0 is always mapped to
    the letter O).  For security purposes the default is None, so that
    0 and 1 are not allowed in the input.

    The result is returned as a bytes object.  A binascii.Error is raised if
    the input is incorrectly padded or if there are non-alphabet
    characters present in the input.
    '''
    global _b32rev
    pass
# WARNING: Decompyle incomplete


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
passif foldspaces and word == 538976288:
passb'y')(words)
    if not padding and pad:
        if chunks[-1] == b'z':
            chunks[-1] = chars[0] * 5
            chunks[-1] = chunks[-1][:-padding]
            return b''.join(chunks)


def a85encode(b = None, *, foldspaces, wrapcol, pad, adobe):
    '''Encode bytes-like object b using Ascii85 and return a bytes object.

    foldspaces is an optional flag that uses the special short sequence \'y\'
    instead of 4 consecutive spaces (ASCII 0x20) as supported by \'btoa\'. This
    feature is not supported by the "standard" Adobe encoding.

    wrapcol controls whether the output should have newline (b\'\\n\') characters
    added to it. If this is non-zero, each output line will be at most this
    many characters long.

    pad controls whether the input is padded to a multiple of 4 before
    encoding. Note that the btoa implementation always pads.

    adobe controls whether the encoded byte sequence is framed with <~ and ~>,
    which is used by the Adobe implementation.
    '''
    global _a85chars, _a85chars2
    if _a85chars2 is None:
        _a85chars = (lambda .0: [ bytes((i,)) for i in .0 ])(range(33, 118))
        _a85chars2 = (lambda .0: [ a + b for a in .0 for b in _a85chars ])(_a85chars)
        result = _85encode(b, _a85chars, _a85chars2, pad, True, foldspaces)
        if adobe:
            result = _A85START + result
            if wrapcol:
                wrapcol = max(2, 1 if adobe else wrapcol)
                chunks = (lambda .0 = None: [ result[i:i + wrapcol] for i in .0 ])(range(0, len(result), wrapcol))
                if adobe and len(chunks[-1]) + 2 > wrapcol:
                    chunks.append(b'')
                    result = b'\n'.join(chunks)
                    if adobe:
                        result += _A85END
                        return result


def a85decode(b = None, *, foldspaces, adobe, ignorechars):
    '''Decode the Ascii85 encoded bytes-like object or ASCII string b.

    foldspaces is a flag that specifies whether the \'y\' short sequence should be
    accepted as shorthand for 4 consecutive spaces (ASCII 0x20). This feature is
    not supported by the "standard" Adobe encoding.

    adobe controls whether the input sequence is in Adobe Ascii85 format (i.e.
    is framed with <~ and ~>).

    ignorechars should be a byte string containing characters to ignore from the
    input. This should only contain whitespace characters, and by default
    contains all whitespace characters in ASCII.

    The result is returned as a bytes object.
    '''
    b = _bytes_from_decode_data(b)
    if adobe:
        if not b.endswith(_A85END):
            raise ValueError('Ascii85 encoded byte sequences must end with {!r}'.format(_A85END))
        if None.startswith(_A85START):
            b = b[2:-2]
        else:
            b = b[:-2]
            packI = struct.Struct('!I').pack
        decoded = []
        decoded_append = decoded.append
        curr = []
        curr_append = curr.append
        curr_clear = curr.clear
        for x in b + b'uuuu':
            pass
        33
# WARNING: Decompyle incomplete

_b85alphabet = b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~'
_b85chars = None
_b85chars2 = None
_b85dec = None

def b85encode(b, pad = (False,)):
    """Encode bytes-like object b in base85 format and return a bytes object.

    If pad is true, the input is padded with b'\\0' so its length is a multiple of
    4 bytes before encoding.
    """
    global _b85chars, _b85chars2
    if _b85chars2 is None:
        _b85chars = (lambda .0: [ bytes((i,)) for i in .0 ])(_b85alphabet)
        _b85chars2 = (lambda .0: [ a + b for a in .0 for b in _b85chars ])(_b85chars)
        return _85encode(b, _b85chars, _b85chars2, pad)


def b85decode(b):
    '''Decode the base85-encoded bytes-like object or ASCII string b

    The result is returned as a bytes object.
    '''
    global _b85dec
    if _b85dec is None:
        _b85dec = [
            None] * 256
        for i, c in enumerate(_b85alphabet):
            _b85dec[c] = i
        b = _bytes_from_decode_data(b)
        padding = -len(b) % 5
        b = b + b'~' * padding
        out = []
    packI = struct.Struct('!I').pack
# WARNING: Decompyle incomplete

MAXLINESIZE = 76
MAXBINSIZE = (MAXLINESIZE // 4) * 3

def encode(input, output):
    '''Encode a file; input and output are binary files.'''
    s = input.read(MAXBINSIZE)
    if not s:
        pass
    elif len(s) < MAXBINSIZE:
        ns = input.read(MAXBINSIZE - len(s))
        if not ns:
            pass
        else:
            s += ns
        line = binascii.b2a_base64(s)
        output.write(line)
        continue
        return None


def decode(input, output):
    '''Decode a file; input and output are binary files.'''
    line = input.readline()
    if not line:
        pass
    else:
        s = binascii.a2b_base64(line)
        output.write(s)


def _input_type_check(s):
    pass
# WARNING: Decompyle incomplete


def encodebytes(s):
    '''Encode a bytestring into a bytes object containing multiple lines
    of base-64 data.'''
    _input_type_check(s)
    pieces = []
    return b''.join(pieces)


def decodebytes(s):
    '''Decode a bytestring of base-64 data into a bytes object.'''
    _input_type_check(s)
    return binascii.a2b_base64(s)


def main():
    '''Small main program'''
    import sys
    import getopt
# WARNING: Decompyle incomplete


def test():
    s0 = b'Aladdin:open sesame'
    print(repr(s0))
    s1 = encodebytes(s0)
    print(repr(s1))
    s2 = decodebytes(s1)
    print(repr(s2))
# WARNING: Decompyle incomplete

if __name__ == '__main__':
    main()
    return None
