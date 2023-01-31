
__doc__ = 'A lexical analyzer class for simple shell-like syntaxes.'
import os
import re
import sys
from collections import deque
from io import StringIO
__all__ = [
    'shlex',
    'split',
    'quote',
    'join']

class shlex:
    '''A lexical analyzer class for simple shell-like syntaxes.'''
    
    def __init__(self, instream, infile, posix, punctuation_chars = (None, None, False, False)):
        if isinstance(instream, str):
            instream = StringIO(instream)
        if instream is not None:
            self.instream = instream
            self.infile = infile
        else:
            self.instream = sys.stdin
            self.infile = None
        self.posix = posix
        if posix:
            self.eof = None
        else:
            self.eof = ''
        self.commenters = '#'
        self.wordchars = 'abcdfeghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_'
        if self.posix:
            self.wordchars += '\xc3\x9f\xc3\xa0\xc3\xa1\xc3\xa2\xc3\xa3\xc3\xa4\xc3\xa5\xc3\xa6\xc3\xa7\xc3\xa8\xc3\xa9\xc3\xaa\xc3\xab\xc3\xac\xc3\xad\xc3\xae\xc3\xaf\xc3\xb0\xc3\xb1\xc3\xb2\xc3\xb3\xc3\xb4\xc3\xb5\xc3\xb6\xc3\xb8\xc3\xb9\xc3\xba\xc3\xbb\xc3\xbc\xc3\xbd\xc3\xbe\xc3\xbf\xc3\x80\xc3\x81\xc3\x82\xc3\x83\xc3\x84\xc3\x85\xc3\x86\xc3\x87\xc3\x88\xc3\x89\xc3\x8a\xc3\x8b\xc3\x8c\xc3\x8d\xc3\x8e\xc3\x8f\xc3\x90\xc3\x91\xc3\x92\xc3\x93\xc3\x94\xc3\x95\xc3\x96\xc3\x98\xc3\x99\xc3\x9a\xc3\x9b\xc3\x9c\xc3\x9d\xc3\x9e'
        self.whitespace = ' \t\r\n'
        self.whitespace_split = False
        self.quotes = '\'"'
        self.escape = '\\'
        self.escapedquotes = '"'
        self.state = ' '
        self.pushback = deque()
        self.lineno = 1
        self.debug = 0
        self.token = ''
        self.filestack = deque()
        self.source = None
        self._punctuation_chars = punctuation_chars
        if punctuation_chars:
            self._pushback_chars = deque()
            self.wordchars += '~-./*?='
            t = self.wordchars.maketrans(dict.fromkeys(punctuation_chars))
            self.wordchars = self.wordchars.translate(t)
            return None
        return None if not punctuation_chars else self

    
    def punctuation_chars(self):
        return self._punctuation_chars

    punctuation_chars = property(punctuation_chars)
    
    def push_token(self, tok):
        '''Push a token onto the stack popped by the get_token method'''
        if self.debug >= 1:
            print('shlex: pushing token ' + repr(tok))
        self.pushback.appendleft(tok)

    
    def push_source(self, newstream, newfile = (None,)):
        """Push an input source onto the lexer's input source stack."""
        if isinstance(newstream, str):
            newstream = StringIO(newstream)
        self.filestack.appendleft((self.infile, self.instream, self.lineno))
        self.infile = newfile
        self.instream = newstream
        self.lineno = 1
        if self.debug:
            if newfile is not None:
                print('shlex: pushing to file %s' % (self.infile,))
                return None
            None('shlex: pushing to stream %s' % (self.instream,))
            return None

    
    def pop_source(self):
        '''Pop the input source stack.'''
        self.instream.close()
        (self.infile, self.instream, self.lineno) = self.filestack.popleft()
        if self.debug:
            print('shlex: popping to %s, line %d' % (self.instream, self.lineno))
        self.state = ' '

    
    def get_token(self):
        """Get a token from the input stream (or from stack if it's nonempty)"""
        if self.pushback:
            tok = self.pushback.popleft()
            if self.debug >= 1:
                print('shlex: popping token ' + repr(tok))
            return tok
        raw = None.read_token()
        if self.source is not None and raw == self.source:
            spec = self.sourcehook(self.read_token())
            if spec:
                (newfile, newstream) = spec
                self.push_source(newstream, newfile)
            raw = self.get_token()
            if raw == self.source or raw == self.eof:
                if not self.filestack:
                    return self.eof
                None.pop_source()
                raw = self.get_token()
                if raw == self.eof or self.debug >= 1:
                    if raw != self.eof:
                        print('shlex: token=' + repr(raw))
                        return raw
                    None('shlex: token=EOF')
        return raw

    
    def read_token(self):
        quoted = False
        escapedstate = ' '
        if self.punctuation_chars and self._pushback_chars:
            nextchar = self._pushback_chars.pop()
        else:
            nextchar = self.instream.read(1)
        continue
        result = self.token
        self.token = ''
        if self.posix and quoted and result == '':
            result = None
        if self.debug > 1:
            if result:
                print('shlex: raw token=' + repr(result))
                return result
            None if not nextchar else None if nextchar == '\n' else self if not nextchar else self if not nextchar else self if self.state is None else self if nextchar in self.commenters else self('shlex: raw token=EOF')
        return result

    
    def sourcehook(self, newfile):
        '''Hook called on a filename to be sourced.'''
        if newfile[0] == '"':
            newfile = newfile[1:-1]
        if not isinstance(self.infile, str) and os.path.isabs(newfile):
            newfile = os.path.join(os.path.dirname(self.infile), newfile)
        return (newfile, open(newfile, 'r'))

    
    def error_leader(self, infile, lineno = (None, None)):
        '''Emit a C-compiler-like, Emacs-friendly error-message leader.'''
        if infile is None:
            infile = self.infile
        if lineno is None:
            lineno = self.lineno
        return '"%s", line %d: ' % (infile, lineno)

    
    def __iter__(self):
        return self

    
    def __next__(self):
        token = self.get_token()
        if token == self.eof:
            raise StopIteration



def split(s, comments, posix = (False, True)):
    '''Split the string *s* using shell-like syntax.'''
    if s is None:
        import warnings
        warnings.warn("Passing None for 's' to shlex.split() is deprecated.", DeprecationWarning, 2, **('stacklevel',))
    lex = shlex(s, posix, **('posix',))
    lex.whitespace_split = True
    if not comments:
        lex.commenters = ''
    return list(lex)


def join(split_command):
    '''Return a shell-escaped string from *split_command*.'''
    return ' '.join((lambda .0: pass# WARNING: Decompyle incomplete
)(split_command))

_find_unsafe = re.compile('[^\\w@%+=:,./-]', re.ASCII).search

def quote(s):
    '''Return a shell-escaped version of the string *s*.'''
    if not s:
        return "''"
    if None(s) is None:
        return s
    return None + s.replace("'", '\'"\'"\'') + "'"


def _print_tokens(lexer):
    tt = lexer.get_token()
    if not tt:
        return None
    None('Token: ' + repr(tt))
    continue

# WARNING: Decompyle incomplete
