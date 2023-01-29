
'''Text wrapping and filling.
'''
import re
__all__ = [
    'TextWrapper',
    'wrap',
    'fill',
    'dedent',
    'indent',
    'shorten']
_whitespace = '\t\n\x0b\x0c\r '

class TextWrapper:
    '''
    Object for wrapping/filling text.  The public interface consists of
    the wrap() and fill() methods; the other methods are just there for
    subclasses to override in order to tweak the default behaviour.
    If you want to completely replace the main wrapping algorithm,
    you\'ll probably have to override _wrap_chunks().

    Several instance attributes control various aspects of wrapping:
      width (default: 70)
        the maximum width of wrapped lines (unless break_long_words
        is false)
      initial_indent (default: "")
        string that will be prepended to the first line of wrapped
        output.  Counts towards the line\'s width.
      subsequent_indent (default: "")
        string that will be prepended to all lines save the first
        of wrapped output; also counts towards each line\'s width.
      expand_tabs (default: true)
        Expand tabs in input text to spaces before further processing.
        Each tab will become 0 .. \'tabsize\' spaces, depending on its position
        in its line.  If false, each tab is treated as a single character.
      tabsize (default: 8)
        Expand tabs in input text to 0 .. \'tabsize\' spaces, unless
        \'expand_tabs\' is false.
      replace_whitespace (default: true)
        Replace all whitespace characters in the input text by spaces
        after tab expansion.  Note that if expand_tabs is false and
        replace_whitespace is true, every tab will be converted to a
        single space!
      fix_sentence_endings (default: false)
        Ensure that sentence-ending punctuation is always followed
        by two spaces.  Off by default because the algorithm is
        (unavoidably) imperfect.
      break_long_words (default: true)
        Break words longer than \'width\'.  If false, those words will not
        be broken, and some lines might be longer than \'width\'.
      break_on_hyphens (default: true)
        Allow breaking hyphenated words. If true, wrapping will occur
        preferably on whitespaces and right after hyphens part of
        compound words.
      drop_whitespace (default: true)
        Drop leading and trailing whitespace from lines.
      max_lines (default: None)
        Truncate wrapped lines.
      placeholder (default: \' [...]\')
        Append to the last line of truncated text.
    '''
    unicode_whitespace_trans = { }
    uspace = ord(' ')
    word_punct = '[\\w!"\\\'&.,?]'
    letter = '[^\\d\\W]'
    whitespace = '[%s]' % re.escape(_whitespace)
    nowhitespace = '[^' + whitespace[1:]
    wordsep_re = re.compile('\n        ( # any whitespace\n          %(ws)s+\n        | # em-dash between words\n          (?<=%(wp)s) -{2,} (?=\\w)\n        | # word, possibly hyphenated\n          %(nws)s+? (?:\n            # hyphenated word\n              -(?: (?<=%(lt)s{2}-) | (?<=%(lt)s-%(lt)s-))\n              (?= %(lt)s -? %(lt)s)\n            | # end of word\n              (?=%(ws)s|\\Z)\n            | # em-dash\n              (?<=%(wp)s) (?=-{2,}\\w)\n            )\n        )' % {
        'wp': word_punct,
        'lt': letter,
        'ws': whitespace,
        'nws': nowhitespace }, re.VERBOSE)
    del word_punct
    del letter
    del nowhitespace
    wordsep_simple_re = re.compile('(%s+)' % whitespace)
    del whitespace
    sentence_end_re = re.compile('[a-z][\\.\\!\\?][\\"\\\']?\\Z')
    
    def __init__(self, width, initial_indent, subsequent_indent, expand_tabs, replace_whitespace, fix_sentence_endings, break_long_words, drop_whitespace = None, break_on_hyphens = (70, '', '', True, True, False, True, True, True, 8), tabsize = {
        'max_lines': None,
        'placeholder': ' [...]' }, *, max_lines, placeholder):
        self.width = width
        self.initial_indent = initial_indent
        self.subsequent_indent = subsequent_indent
        self.expand_tabs = expand_tabs
        self.replace_whitespace = replace_whitespace
        self.fix_sentence_endings = fix_sentence_endings
        self.break_long_words = break_long_words
        self.drop_whitespace = drop_whitespace
        self.break_on_hyphens = break_on_hyphens
        self.tabsize = tabsize
        self.max_lines = max_lines
        self.placeholder = placeholder

    
    def _munge_whitespace(self, text):
        '''_munge_whitespace(text : string) -> string

        Munge whitespace in text: expand tabs and convert all other
        whitespace characters to spaces.  Eg. " foo\\tbar\\n\\nbaz"
        becomes " foo    bar  baz".
        '''
        if self.expand_tabs:
            text = text.expandtabs(self.tabsize)
        if self.replace_whitespace:
            text = text.translate(self.unicode_whitespace_trans)
        return text

    
    def _split(self, text):
        """_split(text : string) -> [string]

        Split the text to wrap into indivisible chunks.  Chunks are
        not quite the same as words; see _wrap_chunks() for full
        details.  As an example, the text
          Look, goof-ball -- use the -b option!
        breaks into the following chunks:
          'Look,', ' ', 'goof-', 'ball', ' ', '--', ' ',
          'use', ' ', 'the', ' ', '-b', ' ', 'option!'
        if break_on_hyphens is True, or in:
          'Look,', ' ', 'goof-ball', ' ', '--', ' ',
          'use', ' ', 'the', ' ', '-b', ' ', option!'
        otherwise.
        """
        if self.break_on_hyphens is True:
            chunks = self.wordsep_re.split(text)
        else:
            chunks = self.wordsep_simple_re.split(text)
        chunks = (lambda .0: [ c for c in .0 if c ])(chunks)
        return chunks

    
    def _fix_sentence_endings(self, chunks):
        '''_fix_sentence_endings(chunks : [string])

        Correct for sentence endings buried in \'chunks\'.  Eg. when the
        original text contains "... foo.\\nBar ...", munge_whitespace()
        and split() will convert that to [..., "foo.", " ", "Bar", ...]
        which has one too few spaces; this method simply changes the one
        space to two.
        '''
        i = 0
        patsearch = self.sentence_end_re.search
        if i < len(chunks) - 1:
            if chunks[i + 1] == ' ' and patsearch(chunks[i]):
                chunks[i + 1] = '  '
                i += 2
            else:
                i += 1
            if not i < len(chunks) - 1:
                return None
            return None

    
    def _handle_long_word(self, reversed_chunks, cur_line, cur_len, width):
        '''_handle_long_word(chunks : [string],
                             cur_line : [string],
                             cur_len : int, width : int)

        Handle a chunk of text (most likely a word, not whitespace) that
        is too long to fit in any line.
        '''
        if width < 1:
            space_left = 1
        else:
            space_left = width - cur_len
        if self.break_long_words:
            end = space_left
            chunk = reversed_chunks[-1]
            if self.break_on_hyphens and len(chunk) > space_left:
                hyphen = chunk.rfind('-', 0, space_left)
                if hyphen > 0 and any((lambda .0: pass# WARNING: Decompyle incomplete
)(chunk[:hyphen])):
                    end = hyphen + 1
            cur_line.append(chunk[:end])
            reversed_chunks[-1] = chunk[end:]
            return None
        if not None:
            cur_line.append(reversed_chunks.pop())
            return None

    
    def _wrap_chunks(self, chunks):
        '''_wrap_chunks(chunks : [string]) -> [string]

        Wrap a sequence of text chunks and return a list of lines of
        length \'self.width\' or less.  (If \'break_long_words\' is false,
        some lines may be longer than this.)  Chunks correspond roughly
        to words and the whitespace between them: each chunk is
        indivisible (modulo \'break_long_words\'), but a line break can
        come between any two chunks.  Chunks should not have internal
        whitespace; ie. a chunk is either all whitespace or a "word".
        Whitespace chunks will be removed from the beginning and end of
        lines, but apart from that whitespace is preserved.
        '''
        lines = []
        if self.width <= 0:
            raise ValueError('invalid width %r (must be > 0)' % self.width)
        if None.max_lines is not None:
            if self.max_lines > 1:
                indent = self.subsequent_indent
            else:
                indent = self.initial_indent
            if len(indent) + len(self.placeholder.lstrip()) > self.width:
                raise ValueError('placeholder too large for max width')
            None.reverse()
            if chunks:
                cur_line = []
                cur_len = 0
                if lines:
                    indent = self.subsequent_indent
                else:
                    indent = self.initial_indent
                width = self.width - len(indent)
                if self.drop_whitespace and chunks[-1].strip() == '' and lines:
                    del chunks[-1]
                if chunks:
                    l = len(chunks[-1])
                    if cur_len + l <= width:
                        cur_line.append(chunks.pop())
                        cur_len += l
                    
                elif (chunks or chunks) and len(chunks[-1]) > width:
                    self._handle_long_word(chunks, cur_line, cur_len, width)
                    cur_len = sum(map(len, cur_line))
                if self.drop_whitespace and cur_line and cur_line[-1].strip() == '':
                    cur_len -= len(cur_line[-1])
                    del cur_line[-1]
                if cur_line:
                    if not self.max_lines is None and len(lines) + 1 < self.max_lines:
                        if (chunks or self.drop_whitespace) and len(chunks) == 1 and chunks[0].strip() and cur_len <= width:
                            lines.append(indent + ''.join(cur_line))
                        elif cur_line:
                            if cur_line[-1].strip() and cur_len + len(self.placeholder) <= width:
                                cur_line.append(self.placeholder)
                                lines.append(indent + ''.join(cur_line))
                                return lines
                            None -= len(cur_line[-1])
                            del cur_line[-1]
                            if cur_line or lines:
                                prev_line = lines[-1].rstrip()
                                if len(prev_line) + len(self.placeholder) <= self.width:
                                    lines[-1] = prev_line + self.placeholder
                                    return lines
                                None.append(indent + self.placeholder.lstrip())
                                return lines
                            if not None:
                                return lines

    
    def _split_chunks(self, text):
        text = self._munge_whitespace(text)
        return self._split(text)

    
    def wrap(self, text):
        """wrap(text : string) -> [string]

        Reformat the single paragraph in 'text' so it fits in lines of
        no more than 'self.width' columns, and return a list of wrapped
        lines.  Tabs in 'text' are expanded with string.expandtabs(),
        and all other whitespace characters (including newline) are
        converted to space.
        """
        chunks = self._split_chunks(text)
        if self.fix_sentence_endings:
            self._fix_sentence_endings(chunks)
        return self._wrap_chunks(chunks)

    
    def fill(self, text):
        """fill(text : string) -> string

        Reformat the single paragraph in 'text' to fit in lines of no
        more than 'self.width' columns, and return a new string
        containing the entire wrapped paragraph.
        """
        return '\n'.join(self.wrap(text))



def wrap(text, width = (70,), **kwargs):
    """Wrap a single paragraph of text, returning a list of wrapped lines.

    Reformat the single paragraph in 'text' so it fits in lines of no
    more than 'width' columns, and return a list of wrapped lines.  By
    default, tabs in 'text' are expanded with string.expandtabs(), and
    all other whitespace characters (including newline) are converted to
    space.  See TextWrapper class for available keyword args to customize
    wrapping behaviour.
    """
    pass
# WARNING: Decompyle incomplete


def fill(text, width = (70,), **kwargs):
    """Fill a single paragraph of text, returning a new string.

    Reformat the single paragraph in 'text' to fit in lines of no more
    than 'width' columns, and return a new string containing the entire
    wrapped paragraph.  As with wrap(), tabs are expanded and other
    whitespace characters converted to space.  See TextWrapper class for
    available keyword args to customize wrapping behaviour.
    """
    pass
# WARNING: Decompyle incomplete


def shorten(text, width, **kwargs):
    '''Collapse and truncate the given text to fit in the given width.

    The text first has its whitespace collapsed.  If it then fits in
    the *width*, it is returned as is.  Otherwise, as many words
    as possible are joined and then the placeholder is appended::

        >>> textwrap.shorten("Hello  world!", width=12)
        \'Hello world!\'
        >>> textwrap.shorten("Hello  world!", width=11)
        \'Hello [...]\'
    '''
    pass
# WARNING: Decompyle incomplete

_whitespace_only_re = re.compile('^[ \t]+$', re.MULTILINE)
_leading_whitespace_re = re.compile('(^[ \t]*)(?:[^ \t\n])', re.MULTILINE)

def dedent(text):
    '''Remove any common leading whitespace from every line in `text`.

    This can be used to make triple-quoted strings line up with the left
    edge of the display, while still presenting them in the source code
    in indented form.

    Note that tabs and spaces are both treated as whitespace, but they
    are not equal: the lines "  hello" and "\\thello" are
    considered to have no common leading whitespace.

    Entirely blank lines are normalized to a newline character.
    '''
    margin = None
    text = _whitespace_only_re.sub('', text)
    indents = _leading_whitespace_re.findall(text)
    if indent.startswith(margin):
        continue
    if margin.startswith(indent):
        margin = indent
        continue
    continue
    continue
    if margin:
        text = re.sub('(?m)^' + margin, '', text)
    return text


def indent(text, prefix, predicate = (None,)):
    """Adds 'prefix' to the beginning of selected lines in 'text'.

    If 'predicate' is provided, 'prefix' will only be added to the lines
    where 'predicate(line)' is True. If 'predicate' is not provided,
    it will default to adding 'prefix' to all non-empty lines that do not
    consist solely of whitespace characters.
    """
    if predicate is None:
        
        def predicate(line):
            return line.strip()

    
    def prefixed_lines():
        pass
    # WARNING: Decompyle incomplete

    return ''.join(prefixed_lines())

if __name__ == '__main__':
    print(dedent('Hello there.\n  This is indented.'))
    return None
