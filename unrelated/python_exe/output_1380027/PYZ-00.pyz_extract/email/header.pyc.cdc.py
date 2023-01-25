
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
    continue
    droplist = []
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
        the field in header_name.  The default maxlinelen is 78 as recommended
        by RFC 2822.

        continuation_ws must be RFC 2822 compliant folding whitespace (usually
        either a space or a hard tab) which will be prepended to continuation
        lines.

        errors is passed through to the .append() call.
        """
        if charset is None:
            charset = USASCII
        elif not isinstance(charset, Charset):
            charset = Charset(charset)
            self._charset = charset
            self._continuation_ws = continuation_ws
            self._chunks = []
            if s is not None:
                self.append(s, charset, errors)
                if maxlinelen is None:
                    maxlinelen = MAXLINELEN
                    self._maxlinelen = maxlinelen
                    if header_name is None:
                        self._headerlen = 0
                    else:
                        self._headerlen = len(header_name) + 2
                        return None

    
    def __str__(self):
        '''Return the string value of the header.'''
        self._normalize()
        uchunks = []
        lastcs = None
        lastspace = None
        for string, charset in self._chunks:
            nextcs = charset
            original_bytes = string.encode('ascii', 'surrogateescape')
            string = original_bytes.decode('ascii', 'replace')
            hasspace = self._nonctext(string[0])
            uchunks.append(SPACE)
            nextcs = None
        if not nextcs not in (None, 'us-ascii') and lastspace:
            uchunks.append(SPACE)
            if string:
                lastspace = self._nonctext(string[-1])
                lastcs = nextcs
                uchunks.append(string)
                continue
                return EMPTYSTRING.join(uchunks)

    
    def __eq__(self, other):
        return other == str(self)

    
    def append(self, s, charset, errors = (None, 'strict')):
        """Append a string to the MIME header.

        Optional charset, if given, should be a Charset instance or the name
        of a character set (which will be converted to a Charset instance).  A
        value of None (the default) means that the charset given in the
        constructor is used.

        s may be a byte string or a Unicode string.  If it is a byte string
        (i.e. isinstance(s, str) is false), then charset is the encoding of
        that byte string, and a UnicodeError will be raised if the string
        cannot be decoded with that charset.  If s is a Unicode string, then
        charset is a hint specifying the character set of the characters in
        the string.  In either case, when producing an RFC 2822 compliant
        header using RFC 2047 rules, the string will be encoded using the
        output codec of the charset.  If the string cannot be encoded to the
        output codec, a UnicodeError will be raised.

        Optional `errors' is passed as the errors argument to the decode
        call if s is a byte string.
        """
        if charset is None:
            charset = self._charset
    # WARNING: Decompyle incomplete

    
    def _nonctext(self, s):
        '''True if string s is not a ctext character of RFC822.
        '''
        if not s.isspace():
            return s in ('(', ')', '\\')

    
    def encode(self, splitchars, maxlinelen, linesep = (';, \t', None, '\n')):
        '''Encode a message header into an RFC-compliant format.

        There are many issues involved in converting a given string for use in
        an email header.  Only certain character sets are readable in most
        email clients, and as header strings can only contain a subset of
        7-bit ASCII, care must be taken to properly convert and encode (with
        Base64 or quoted-printable) header strings.  In addition, there is a
        75-character length limit on any given encoded header field, so
        line-wrapping must be performed, even with double-byte character sets.

        Optional maxlinelen specifies the maximum length of each generated
        line, exclusive of the linesep string.  Individual lines may be longer
        than maxlinelen if a folding point cannot be found.  The first line
        will be shorter by the length of the header name plus ": " if a header
        name was specified at Header construction time.  The default value for
        maxlinelen is determined at header construction time.

        Optional splitchars is a string containing characters which should be
        given extra weight by the splitting algorithm during normal header
        wrapping.  This is in very rough support of RFC 2822\'s `higher level
        syntactic breaks\':  split points preceded by a splitchar are preferred
        during line splitting, with the characters preferred in the order in
        which they appear in the string.  Space and tab may be included in the
        string to indicate whether preference should be given to one over the
        other as a split point when other split chars do not appear in the line
        being split.  Splitchars does not affect RFC 2047 encoded lines.

        Optional linesep is a string to be used to separate the lines of
        the value.  The default value is the most useful for typical
        Python applications, but it can be set to \\r\\n to produce RFC-compliant
        line separators when needed.
        '''
        self._normalize()
        if maxlinelen is None:
            maxlinelen = self._maxlinelen
            if maxlinelen == 0:
                maxlinelen = 1000000
                formatter = _ValueFormatter(self._headerlen, maxlinelen, self._continuation_ws, splitchars)
                lastcs = None
                hasspace = None
                lastspace = None
        for string, charset in self._chunks:
            hasspace = self._nonctext(string[0])
            formatter.add_transition()
        if not charset not in (None, 'us-ascii') and lastspace:
            formatter.add_transition()
            if string:
                lastspace = self._nonctext(string[-1])
                lastcs = charset
                hasspace = False
                lines = string.splitlines()
                if lines:
                    formatter.feed('', lines[0], charset)
                else:
                    formatter.feed('', '', charset)
                    for line in lines[1:]:
                        formatter.newline()
                        formatter.feed(self._continuation_ws, ' ' + line.lstrip(), charset)
                    sline = line.lstrip()
                    fws = line[:len(line) - len(sline)]
                    formatter.feed(fws, sline, charset)
            elif len(lines) > 1:
                formatter.newline()
                continue
                if self._chunks:
                    formatter.add_transition()
                    value = formatter._str(linesep)
                    if _embedded_header.search(value):
                        raise HeaderParseError('header value appears to contain an embedded header: {!r}'.format(value))
                    return string

    
    def _normalize(self):
        chunks = []
        last_charset = None
        last_chunk = []
        if last_charset is not None:
            chunks.append((SPACE.join(last_chunk), last_charset))
            last_chunk = [
                string]
            last_charset = charset
            continue
            if last_chunk:
                chunks.append((SPACE.join(last_chunk), last_charset))
                self._chunks = chunks
                return None



class _ValueFormatter:
    
    def __init__(self, headerlen, maxlen, continuation_ws, splitchars):
        self._maxlen = maxlen
        self._continuation_ws = continuation_ws
        self._continuation_ws_len = len(continuation_ws)
        self._splitchars = splitchars
        self._lines = []
        self._current_line = _Accumulator(headerlen)

    
    def _str(self, linesep):
        self.newline()
        return linesep.join(self._lines)

    
    def __str__(self):
        return self._str(NL)

    
    def newline(self):
        end_of_line = self._current_line.pop()
    # WARNING: Decompyle incomplete

    
    def add_transition(self):
        self._current_line.push(' ', '')

    
    def feed(self, fws, string, charset):
        if charset.header_encoding is None:
            self._ascii_split(fws, string, self._splitchars)
            return None
        encoded_lines = None.header_encode_lines(string, self._maxlengths())
    # WARNING: Decompyle incomplete

    
    def _maxlengths(self):
        yield self._maxlen - len(self._current_line)
        yield self._maxlen - self._continuation_ws_len

    
    def _ascii_split(self, fws, string, splitchars):
        parts = re.split('([' + FWS + ']+)', fws + string)
    # WARNING: Decompyle incomplete

    
    def _append_chunk(self, fws, string):
        self._current_line.push(fws, string)
        if len(self._current_line) > self._maxlen:
            for ch in self._splitchars:
                for i in range(self._current_line.part_count() - 1, 0, -1):
                    fws = self._current_line[i][0]
                prevpart = self._current_line[i - 1][1]
                (fws, part) = None._current_line.pop()
                self.newline()
                fws = ' '
                self._current_line.push(fws, part)
                return None
                remainder = self._current_line.pop_from(i)
                self._lines.append(str(self._current_line))
                self._current_line.reset(remainder)
                return None



class _Accumulator(list):
    
    def __init__(self = None, initial_size = None):
        self._initial_size = initial_size
        super().__init__()

    
    def push(self, fws, string):
        self.append((fws, string))

    
    def pop_from(self, i = (0,)):
        popped = self[i:]
        self[i:] = []
        return popped

    
    def pop(self = None):
        if self.part_count() == 0:
            return ('', '')
        return None().pop()

    
    def __len__(self):
        return sum((lambda .0: pass)(self), self._initial_size)

    
    def __str__(self):
        return EMPTYSTRING.join((lambda .0: pass)(self))

    
    def reset(self, startval = (None,)):
        if startval is None:
            startval = []
            self[:] = startval
        self._initial_size = 0

    
    def is_onlyws(self):
        if not self._initial_size == 0 and not self:
            return str(self).isspace()

    
    def part_count(self = None):
        return super().__len__()

    __classcell__ = None

