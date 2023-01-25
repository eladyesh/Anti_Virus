
__doc__ = 'Conversions to/from quoted-printable transport encoding as per RFC 1521.'
__all__ = [
    'encode',
    'decode',
    'encodestring',
    'decodestring']
ESCAPE = b'='
MAXLINESIZE = 76
HEX = b'0123456789ABCDEF'
EMPTYSTRING = b''
# WARNING: Decompyle incomplete
