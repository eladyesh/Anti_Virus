
"""FeedParser - An email feed parser.

The feed parser implements an interface for incrementally parsing an email
message, line by line.  This has advantages for certain applications, such as
those reading email messages off a socket.

FeedParser.feed() is the primary interface for pushing new data into the
parser.  It returns when there's nothing more it can do with the available
data.  When you have no more data to push into the parser, call .close().
This completes the parsing and returns the root message object.

The other advantage of this parser is that it will never raise a parsing
exception.  Instead, when it finds something unexpected, it adds a 'defect' to
the current message.  Defects are just instances that live on the message
object's .defects attribute.
"""
__all__ = [
    'FeedParser',
    'BytesFeedParser']
import re
from email import errors
from email._policybase import compat32
from collections import deque
from io import StringIO
NLCRE = re.compile('\\r\\n|\\r|\\n')
NLCRE_bol = re.compile('(\\r\\n|\\r|\\n)')
NLCRE_eol = re.compile('(\\r\\n|\\r|\\n)\\Z')
NLCRE_crack = re.compile('(\\r\\n|\\r|\\n)')
headerRE = re.compile('^(From |[\\041-\\071\\073-\\176]*:|[\\t ])')
EMPTYSTRING = ''
NL = '\n'
NeedMoreData = object()

class BufferedSubFile(object):
    '''A file-ish object that can have new data loaded into it.

    You can also push and pop line-matching predicates onto a stack.  When the
    current predicate matches the current line, a false EOF response
    (i.e. empty string) is returned instead.  This lets the parser adhere to a
    simple abstraction -- it parses until EOF closes the current message.
    '''
    
    def __init__(self):
        self._partial = StringIO('', **('newline',))
        self._lines = deque()
        self._eofstack = []
        self._closed = False

    
    def push_eof_matcher(self, pred):
        self._eofstack.append(pred)

    
    def pop_eof_matcher(self):
        return self._eofstack.pop()

    
    def close(self):
        self._partial.seek(0)
        self.pushlines(self._partial.readlines())
        self._partial.seek(0)
        self._partial.truncate()
        self._closed = True

    
    def readline(self):
        if not self._lines:
            if self._closed:
                return ''
            return None
        line = None._lines.popleft()
        for ateof in reversed(self._eofstack):
            self._lines.appendleft(line)
            [ line ]
            return ''

    
    def unreadline(self, line):
        pass
    # WARNING: Decompyle incomplete

    
    def push(self, data):
        '''Push some new data into this object.'''
        self._partial.write(data)
        if '\n' not in data and '\r' not in data:
            return None
        None._partial.seek(0)
        parts = self._partial.readlines()
        self._partial.seek(0)
        self._partial.truncate()
        if not parts[-1].endswith('\n'):
            self._partial.write(parts.pop())
            self.pushlines(parts)
            return None

    
    def pushlines(self, lines):
        self._lines.extend(lines)

    
    def __iter__(self):
        return self

    
    def __next__(self):
        line = self.readline()
        if line == '':
            raise StopIteration



class FeedParser:
    '''A feed-style parser of email.'''
    
    def __init__(self = None, _factory = (None,), *, policy):
        """_factory is called with no arguments to create a new message obj

        The policy keyword specifies a policy object that controls a number of
        aspects of the parser's operation.  The default policy maintains
        backward compatibility.

        """
        self.policy = policy
        self._old_style_factory = False
        if _factory is None:
            if policy.message_factory is None:
                Message = Message
                import email.message
                self._factory = Message
            else:
                self._factory = policy.message_factory