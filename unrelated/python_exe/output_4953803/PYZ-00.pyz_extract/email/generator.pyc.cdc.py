
'''Classes to generate plain text from a message object tree.'''
__all__ = [
    'Generator',
    'DecodedGenerator',
    'BytesGenerator']
import re
import sys
import time
import random
from copy import deepcopy
from io import StringIO, BytesIO
from email.utils import _has_surrogates
UNDERSCORE = '_'
NL = '\n'
NLCRE = re.compile('\\r\\n|\\r|\\n')
fcre = re.compile('^From ', re.MULTILINE)

class Generator:
    '''Generates output from a Message object tree.

    This basic generator writes the message to the given file object as plain
    text.
    '''
    
    def __init__(self, outfp = None, mangle_from_ = (None, None), maxheaderlen = {
        'policy': None }, *, policy):
        """Create the generator for message flattening.

        outfp is the output file-like object for writing the message to.  It
        must have a write() method.

        Optional mangle_from_ is a flag that, when True (the default if policy
        is not set), escapes From_ lines in the body of the message by putting
        a `>' in front of them.

        Optional maxheaderlen specifies the longest length for a non-continued
        header.  When a header line is longer (in characters, with tabs
        expanded to 8 spaces) than maxheaderlen, the header will split as
        defined in the Header class.  Set maxheaderlen to zero to disable
        header wrapping.  The default is 78, as recommended (but not required)
        by RFC 2822.

        The policy keyword specifies a policy object that controls a number of
        aspects of the generator's operation.  If no policy is specified,
        the policy associated with the Message object passed to the
        flatten method is used.

        """
        if mangle_from_ is None:
            mangle_from_ = True if policy is None else policy.mangle_from_
        self._fp = outfp
        self._mangle_from_ = mangle_from_
        self.maxheaderlen = maxheaderlen
        self.policy = policy

    
    def write(self, s):
        self._fp.write(s)

    
    def flatten(self, msg, unixfrom, linesep = (False, None)):
        """Print the message object tree rooted at msg to the output file
        specified when the Generator instance was created.

        unixfrom is a flag that forces the printing of a Unix From_ delimiter
        before the first object in the message tree.  If the original message
        has no From_ delimiter, a `standard' one is crafted.  By default, this
        is False to inhibit the printing of any From_ delimiter.

        Note that for subobjects, no From_ line is printed.

        linesep specifies the characters used to indicate a new line in
        the output.  The default value is determined by the policy specified
        when the Generator instance was created or, if none was specified,
        from the policy associated with the msg.

        """
        policy = msg.policy if self.policy is None else self.policy
        if linesep is not None:
            policy = policy.clone(linesep, **('linesep',))
        if self.maxheaderlen is not None:
            policy = policy.clone(self.maxheaderlen, **('max_line_length',))
        self._NL = policy.linesep
        self._encoded_NL = self._encode(self._NL)
        self._EMPTY = ''
        self._encoded_EMPTY = self._encode(self._EMPTY)
        old_gen_policy = self.policy
        old_msg_policy = msg.policy
    # WARNING: Decompyle incomplete

    
    def clone(self, fp):
        '''Clone this generator with the exact same options.'''
        return self.__class__(fp, self._mangle_from_, None, self.policy, **('policy',))

    
    def _new_buffer(self):
        return StringIO()

    
    def _encode(self, s):
        return s

    
    def _write_lines(self, lines):
        if not lines:
            return None
        lines = None.split(lines)
        if lines[-1]:
            self.write(lines[-1])
            return None
        return [ self._NL for line in lines[:-1] ]

    
    def _write(self, msg):
        oldfp = self._fp
    # WARNING: Decompyle incomplete

    
    def _dispatch(self, msg):
        main = msg.get_content_maintype()
        sub = msg.get_content_subtype()
        specific = UNDERSCORE.join((main, sub)).replace('-', '_')
        meth = getattr(self, '_handle_' + specific, None)
        if meth is None:
            generic = main.replace('-', '_')
            meth = getattr(self, '_handle_' + generic, None)
            if meth is None:
                meth = self._writeBody
        meth(msg)

    
    def _write_headers(self, msg):
        self.write(self._NL)

    
    def _handle_text(self, msg):
        payload = msg.get_payload()
        if payload is None:
            return None
        if not None(payload, str):
            raise TypeError('string payload expected: %s' % type(payload))
        if None(msg._payload):
            charset = msg.get_param('charset')
            if charset is not None:
                msg = deepcopy(msg)
                del msg['content-transfer-encoding']
                msg.set_payload(payload, charset)
                payload = msg.get_payload()
                self._munge_cte = (msg['content-transfer-encoding'], msg['content-type'])
        if self._mangle_from_:
            payload = fcre.sub('>From ', payload)
        self._write_lines(payload)

    _writeBody = _handle_text
    
    def _handle_multipart(self, msg):
        msgtexts = []
        subparts = msg.get_payload()
        if subparts is None:
            subparts = []
        elif isinstance(subparts, str):
            self.write(subparts)
            return None
        if not isinstance(subparts, list):
            subparts = [
                subparts]
        boundary = msg.get_boundary()
        self.write('--' + boundary + self._NL)
        if msgtexts:
            self._fp.write(msgtexts.pop(0))
        self.write(self._NL + '--' + boundary + '--' + self._NL)
        if msg.epilogue is not None:
            self._write_lines(epilogue)
            return None
        return [ body_part for body_part in msgtexts ]

    
    def _handle_multipart_signed(self, msg):
        p = self.policy
        self.policy = p.clone(0, **('max_line_length',))
    # WARNING: Decompyle incomplete

    
    def _handle_message_delivery_status(self, msg):
        blocks = []
        blocks.append(text)
        continue
        self._fp.write(self._encoded_NL.join(blocks))

    
    def _handle_message(self, msg):
        s = self._new_buffer()
        g = self.clone(s)
        payload = msg._payload
        if isinstance(payload, list):
            g.flatten(msg.get_payload(0), False, self._NL, **('unixfrom', 'linesep'))
            payload = s.getvalue()
        else:
            payload = self._encode(payload)
        self._fp.write(payload)

    
    def _make_boundary(cls, text = (None,)):
        token = random.randrange(sys.maxsize)
        boundary = '===============' + _fmt % token + '=='
        if text is None:
            return boundary
        b = None
        counter = 0
        cre = cls._compile_re('^--' + re.escape(b) + '(--)?$', re.MULTILINE)
        if not cre.search(text):
            return b
        b = None + '.' + str(counter)
        counter += 1
        continue

    _make_boundary = classmethod(_make_boundary)
    
    def _compile_re(cls, s, flags):
        return re.compile(s, flags)

    _compile_re = classmethod(_compile_re)


class BytesGenerator(Generator):
    '''Generates a bytes version of a Message object tree.

    Functionally identical to the base Generator except that the output is
    bytes and not string.  When surrogates were used in the input to encode
    bytes, these are decoded back to bytes for output.  If the policy has
    cte_type set to 7bit, then the message is transformed such that the
    non-ASCII bytes are properly content transfer encoded, using the charset
    unknown-8bit.

    The outfp object must accept bytes in its write method.
    '''
    
    def write(self, s):
        self._fp.write(s.encode('ascii', 'surrogateescape'))

    
    def _new_buffer(self):
        return BytesIO()

    
    def _encode(self, s):
        return s.encode('ascii')

    
    def _write_headers(self, msg):
        self.write(self._NL)

    
    def _handle_text(self = None, msg = None):
        if msg._payload is None:
            return None
        if not None(msg._payload) and self.policy.cte_type == '7bit':
            if self._mangle_from_:
                msg._payload = fcre.sub('>From ', msg._payload)
            self._write_lines(msg._payload)
            return None
        None(BytesGenerator, self)._handle_text(msg)

    _writeBody = _handle_text
    
    def _compile_re(cls, s, flags):
        return re.compile(s.encode('ascii'), flags)

    _compile_re = classmethod(_compile_re)
    __classcell__ = None

_FMT = '[Non-text (%(type)s) part of message omitted, filename %(filename)s]'

class DecodedGenerator(Generator):
    '''Generates a text representation of a message.

    Like the Generator base class, except that non-text parts are substituted
    with a format string representing the part.
    '''
    
    def __init__(self, outfp, mangle_from_ = None, maxheaderlen = (None, None, None), fmt = {
        'policy': None }, *, policy):
        """Like Generator.__init__() except that an additional optional
        argument is allowed.

        Walks through all subparts of a message.  If the subpart is of main
        type `text', then it prints the decoded payload of the subpart.

        Otherwise, fmt is a format string that is used instead of the message
        payload.  fmt is expanded with the following keywords (in
        %(keyword)s format):

        type       : Full MIME type of the non-text part
        maintype   : Main MIME type of the non-text part
        subtype    : Sub-MIME type of the non-text part
        filename   : Filename of the non-text part
        description: Description associated with the non-text part
        encoding   : Content transfer encoding of the non-text part

        The default value for fmt is None, meaning

        [Non-text (%(type)s) part of message omitted, filename %(filename)s]
        """
        Generator.__init__(self, outfp, mangle_from_, maxheaderlen, policy, **('policy',))
        if fmt is None:
            self._fmt = _FMT
            return None
        self._fmt = None

    
    def _dispatch(self, msg):
        if maintype == 'multipart':
            continue
        print(self._fmt % {
            'type': part.get_content_type(),
            'maintype': part.get_content_maintype(),
            'subtype': part.get_content_subtype(),
            'filename': part.get_filename('[no filename]'),
            'description': part.get('Content-Description', '[no description]'),
            'encoding': part.get('Content-Transfer-Encoding', '[no encoding]') }, self, **('file',))
        continue


_width = len(repr(sys.maxsize - 1))
_fmt = '%%0%dd' % _width
_make_boundary = Generator._make_boundary
