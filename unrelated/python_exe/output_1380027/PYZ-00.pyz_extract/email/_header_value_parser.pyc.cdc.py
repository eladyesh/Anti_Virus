
'''Header value parser implementing various email-related RFC parsing rules.

The parsing methods defined in this module implement various email related
parsing rules.  Principal among them is RFC 5322, which is the followon
to RFC 2822 and primarily a clarification of the former.  It also implements
RFC 2047 encoded word decoding.

RFC 5322 goes to considerable trouble to maintain backward compatibility with
RFC 822 in the parse phase, while cleaning up the structure on the generation
phase.  This parser supports correct RFC 5322 generation by tagging white space
as folding white space only when folding is allowed in the non-obsolete rule
sets.  Actually, the parser is even more generous when accepting input than RFC
5322 mandates, following the spirit of Postel\'s Law, which RFC 5322 encourages.
Where possible deviations from the standard are annotated on the \'defects\'
attribute of tokens that deviate.

The general structure of the parser follows RFC 5322, and uses its terminology
where there is a direct correspondence.  Where the implementation requires a
somewhat different structure than that used by the formal grammar, new terms
that mimic the closest existing terms are used.  Thus, it really helps to have
a copy of RFC 5322 handy when studying this code.

Input to the parser is a string that has already been unfolded according to
RFC 5322 rules.  According to the RFC this unfolding is the very first step, and
this parser leaves the unfolding step to a higher level message parser, which
will have already detected the line breaks that need unfolding while
determining the beginning and end of each header.

The output of the parser is a TokenList object, which is a list subclass.  A
TokenList is a recursive data structure.  The terminal nodes of the structure
are Terminal objects, which are subclasses of str.  These do not correspond
directly to terminal objects in the formal grammar, but are instead more
practical higher level combinations of true terminals.

All TokenList and Terminal objects have a \'value\' attribute, which produces the
semantically meaningful value of that part of the parse subtree.  The value of
all whitespace tokens (no matter how many sub-tokens they may contain) is a
single space, as per the RFC rules.  This includes \'CFWS\', which is herein
included in the general class of whitespace tokens.  There is one exception to
the rule that whitespace tokens are collapsed into single spaces in values: in
the value of a \'bare-quoted-string\' (a quoted-string with no leading or
trailing whitespace), any whitespace that appeared between the quotation marks
is preserved in the returned value.  Note that in all Terminal strings quoted
pairs are turned into their unquoted values.

All TokenList and Terminal objects also have a string value, which attempts to
be a "canonical" representation of the RFC-compliant form of the substring that
produced the parsed subtree, including minimal use of quoted pair quoting.
Whitespace runs are not collapsed.

Comment tokens also have a \'content\' attribute providing the string found
between the parens (including any nested comments) with whitespace preserved.

All TokenList and Terminal objects have a \'defects\' attribute which is a
possibly empty list all of the defects found while creating the token.  Defects
may appear on any token in the tree, and a composite list of all defects in the
subtree is available through the \'all_defects\' attribute of any node.  (For
Terminal notes x.defects == x.all_defects.)

Each object in a parse tree is called a \'token\', and each has a \'token_type\'
attribute that gives the name from the RFC 5322 grammar that it represents.
Not all RFC 5322 nodes are produced, and there is one non-RFC 5322 node that
may be produced: \'ptext\'.  A \'ptext\' is a string of printable ascii characters.
It is returned in place of lists of (ctext/quoted-pair) and
(qtext/quoted-pair).

XXX: provide complete list of token types.
'''
import re
import sys
import urllib
from string import hexdigits
from operator import itemgetter
from email import _encoded_words as _ew
from email import errors
from email import utils
WSP = set(' \t')
CFWS_LEADER = WSP | set('(')
SPECIALS = set('()<>@,:;.\\"[]')
ATOM_ENDS = SPECIALS | WSP
DOT_ATOM_ENDS = ATOM_ENDS - set('.')
PHRASE_ENDS = SPECIALS - set('."(')
TSPECIALS = (SPECIALS | set('/?=')) - set('.')
TOKEN_ENDS = TSPECIALS | WSP
ASPECIALS = TSPECIALS | set("*'%")
ATTRIBUTE_ENDS = ASPECIALS | WSP
EXTENDED_ATTRIBUTE_ENDS = ATTRIBUTE_ENDS - set('%')

def quote_string(value):
    return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"') + '"'

rfc2047_matcher = re.compile("\n   =\\?            # literal =?\n   [^?]*          # charset\n   \\?             # literal ?\n   [qQbB]         # literal 'q' or 'b', case insensitive\n   \\?             # literal ?\n  .*?             # encoded word\n  \\?=             # literal ?=\n", re.VERBOSE | re.MULTILINE)

class TokenList(list):
    token_type = None
    syntactic_break = True
    ew_combine_allowed = True
    
    def __init__(self = None, *args, **kw):
        pass
    # WARNING: Decompyle incomplete

    
    def __str__(self):
        return ''.join((lambda .0: pass)(self))

    
    def __repr__(self = None):
        return '{}({})'.format(self.__class__.__name__, super().__repr__())

    
    def value(self):
        return ''.join((lambda .0: pass)(self))

    value = property(value)
    
    def all_defects(self):
        return sum((lambda .0: pass)(self), self.defects)

    all_defects = property(all_defects)
    
    def startswith_fws(self):
        return self[0].startswith_fws()

    
    def as_ew_allowed(self):
        '''True if all top level tokens of this part may be RFC2047 encoded.'''
        return all((lambda .0: pass)(self))

    as_ew_allowed = property(as_ew_allowed)
    
    def comments(self):
        comments = []
        return comments

    comments = property(comments)
    
    def fold(self, *, policy):
        return _refold_parse_tree(self, policy, **('policy',))

    
    def pprint(self, indent = ('',)):
        print(self.ppstr(indent, **('indent',)))

    
    def ppstr(self, indent = ('',)):
        return '\n'.join(self._pp(indent, **('indent',)))

    
    def _pp(self, indent = ('',)):
        yield '{}{}/{}('.format(indent, self.__class__.__name__, self.token_type)
    # WARNING: Decompyle incomplete

    __classcell__ = None


class WhiteSpaceTokenList(TokenList):
    
    def value(self):
        return ' '

    value = property(value)
    
    def comments(self):
        return (lambda .0: [ x.content for x in .0 if x.token_type == 'comment' ])(self)

    comments = property(comments)


class UnstructuredTokenList(TokenList):
    token_type = 'unstructured'


class Phrase(TokenList):
    token_type = 'phrase'


class Word(TokenList):
    token_type = 'word'


class CFWSList(WhiteSpaceTokenList):
    token_type = 'cfws'


class Atom(TokenList):
    token_type = 'atom'


class Token(TokenList):
    token_type = 'token'
    encode_as_ew = False


class EncodedWord(TokenList):
    token_type = 'encoded-word'
    cte = None
    charset = None
    lang = None


class QuotedString(TokenList):
    token_type = 'quoted-string'
    
    def content(self):
        pass

    content = property(content)
    
    def quoted_value(self):
        res = []
        res.append(x.value)
        continue
        return ''.join(res)

    quoted_value = property(quoted_value)
    
    def stripped_value(self):
        pass

    stripped_value = property(stripped_value)


class BareQuotedString(QuotedString):
    token_type = 'bare-quoted-string'
    
    def __str__(self):
        return quote_string(''.join((lambda .0: pass)(self)))

    
    def value(self):
        return ''.join((lambda .0: pass)(self))

    value = property(value)


class Comment(WhiteSpaceTokenList):
    token_type = 'comment'
    
    def __str__(self):
        return None(None([
            None,
            (lambda .0 = None: [ self.quote(x) for x in .0 ])(self),
            [
                ')']], []))

    
    def quote(self, value):
        if value.token_type == 'comment':
            return str(value)
        return None(value).replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')

    
    def content(self):
        return ''.join((lambda .0: pass)(self))

    content = property(content)
    
    def comments(self):
        return [
            self.content]

    comments = property(comments)


class AddressList(TokenList):
    token_type = 'address-list'
    
    def addresses(self):
        return (lambda .0: [ x for x in .0 if x.token_type == 'address' ])(self)

    addresses = property(addresses)
    
    def mailboxes(self):
        return sum((lambda .0: pass)(self), [])

    mailboxes = property(mailboxes)
    
    def all_mailboxes(self):
        return sum((lambda .0: pass)(self), [])

    all_mailboxes = property(all_mailboxes)


class Address(TokenList):
    token_type = 'address'
    
    def display_name(self):
        if self[0].token_type == 'group':
            return self[0].display_name

    display_name = property(display_name)
    
    def mailboxes(self):
        if self[0].token_type == 'mailbox':
            return [
                self[0]]
        if None[0].token_type == 'invalid-mailbox':
            return []
        return None[0].mailboxes

    mailboxes = property(mailboxes)
    
    def all_mailboxes(self):
        if self[0].token_type == 'mailbox':
            return [
                self[0]]
        if None[0].token_type == 'invalid-mailbox':
            return [
                self[0]]
        return None[0].all_mailboxes

    all_mailboxes = property(all_mailboxes)


class MailboxList(TokenList):
    token_type = 'mailbox-list'
    
    def mailboxes(self):
        return (lambda .0: [ x for x in .0 if x.token_type == 'mailbox' ])(self)

    mailboxes = property(mailboxes)
    
    def all_mailboxes(self):
        return (lambda .0: [ x for x in .0 if x.token_type in ('mailbox', 'invalid-mailbox') ])(self)

    all_mailboxes = property(all_mailboxes)


class GroupList(TokenList):
    token_type = 'group-list'
    
    def mailboxes(self):
        if self or self[0].token_type != 'mailbox-list':
            return []
        return None[0].mailboxes

    mailboxes = property(mailboxes)
    
    def all_mailboxes(self):
        if self or self[0].token_type != 'mailbox-list':
            return []
        return None[0].all_mailboxes

    all_mailboxes = property(all_mailboxes)


class Group(TokenList):
    token_type = 'group'
    
    def mailboxes(self):
        if self[2].token_type != 'group-list':
            return []
        return None[2].mailboxes

    mailboxes = property(mailboxes)
    
    def all_mailboxes(self):
        if self[2].token_type != 'group-list':
            return []
        return None[2].all_mailboxes

    all_mailboxes = property(all_mailboxes)
    
    def display_name(self):
        return self[0].display_name

    display_name = property(display_name)


class NameAddr(TokenList):
    token_type = 'name-addr'
    
    def display_name(self):
        if len(self) == 1:
            return None
        return None[0].display_name

    display_name = property(display_name)
    
    def local_part(self):
        return self[-1].local_part

    local_part = property(local_part)
    
    def domain(self):
        return self[-1].domain

    domain = property(domain)
    
    def route(self):
        return self[-1].route

    route = property(route)
    
    def addr_spec(self):
        return self[-1].addr_spec

    addr_spec = property(addr_spec)


class AngleAddr(TokenList):
    token_type = 'angle-addr'
    
    def local_part(self):
        pass

    local_part = property(local_part)
    
    def domain(self):
        pass

    domain = property(domain)
    
    def route(self):
        pass

    route = property(route)
    
    def addr_spec(self):
        return '<>'

    addr_spec = property(addr_spec)


class ObsRoute(TokenList):
    token_type = 'obs-route'
    
    def domains(self):
        return (lambda .0: [ x.domain for x in .0 if x.token_type == 'domain' ])(self)

    domains = property(domains)


class Mailbox(TokenList):
    token_type = 'mailbox'
    
    def display_name(self):
        if self[0].token_type == 'name-addr':
            return self[0].display_name

    display_name = property(display_name)
    
    def local_part(self):
        return self[0].local_part

    local_part = property(local_part)
    
    def domain(self):
        return self[0].domain

    domain = property(domain)
    
    def route(self):
        if self[0].token_type == 'name-addr':
            return self[0].route

    route = property(route)
    
    def addr_spec(self):
        return self[0].addr_spec

    addr_spec = property(addr_spec)


class InvalidMailbox(TokenList):
    token_type = 'invalid-mailbox'
    
    def display_name(self):
        pass

    display_name = property(display_name)
    local_part = domain = route = addr_spec = display_name


class Domain(TokenList):
    token_type = 'domain'
    as_ew_allowed = False
    
    def domain(self = None):
        return ''.join(super().value.split())

    domain = None(domain)
    __classcell__ = None


class DotAtom(TokenList):
    token_type = 'dot-atom'


class DotAtomText(TokenList):
    token_type = 'dot-atom-text'
    as_ew_allowed = True


class NoFoldLiteral(TokenList):
    token_type = 'no-fold-literal'
    as_ew_allowed = False


class AddrSpec(TokenList):
    token_type = 'addr-spec'
    as_ew_allowed = False
    
    def local_part(self):
        return self[0].local_part

    local_part = property(local_part)
    
    def domain(self):
        if len(self) < 3:
            return None
        return None[-1].domain

    domain = property(domain)
    
    def value(self):
        if len(self) < 3:
            return self[0].value
        return None[0].value.rstrip() + self[1].value + self[2].value.lstrip()

    value = property(value)
    
    def addr_spec(self):
        nameset = set(self.local_part)
        if None is not self.domain if len(nameset) > len(nameset - DOT_ATOM_ENDS) else None:
            return lp + '@' + self.domain

    addr_spec = property(addr_spec)


class ObsLocalPart(TokenList):
    token_type = 'obs-local-part'
    as_ew_allowed = False


class DisplayName(Phrase):
    token_type = 'display-name'
    ew_combine_allowed = False
    
    def display_name(self):
        res = TokenList(self)
        if len(res) == 0:
            return res.value
        if None[0].token_type == 'cfws':
            res.pop(0)
        elif res[0][0].token_type == 'cfws':
            res[0] = TokenList(res[0][1:])
            if res[-1].token_type == 'cfws':
                res.pop()
            elif res[-1][-1].token_type == 'cfws':
                res[-1] = TokenList(res[-1][:-1])
                return res.value

    display_name = property(display_name)
    
    def value(self = None):
        quote = False
        if self.defects:
            quote = True
        else:
            for x in self:
                quote = True
            if len(self) != 0 and quote:
                pre = post = ''
                if self[0].token_type == 'cfws' or self[0][0].token_type == 'cfws':
                    pre = ' '
                    if self[-1].token_type == 'cfws' or self[-1][-1].token_type == 'cfws':
                        post = ' '
                        return pre + quote_string(self.display_name) + post
                    return None().value
                return None

    value = None(value)
    __classcell__ = None


class LocalPart(TokenList):
    token_type = 'local-part'
    as_ew_allowed = False
    
    def value(self):
        if self[0].token_type == 'quoted-string':
            return self[0].quoted_value
        return None[0].value

    value = property(value)
    
    def local_part(self):
        res = [
            DOT]
        last = DOT
        last_is_tl = False
        for tok in self[0] + [
            DOT]:
            res[-1] = TokenList(last[:-1])
            is_tl = isinstance(tok, TokenList)
            res.append(TokenList(tok[1:]))
        res.append(tok)
        last = res[-1]
        last_is_tl = is_tl
        continue
        res = TokenList(res[1:-1])
        return res.value

    local_part = property(local_part)


class DomainLiteral(TokenList):
    token_type = 'domain-literal'
    as_ew_allowed = False
    
    def domain(self = None):
        return ''.join(super().value.split())

    domain = None(domain)
    
    def ip(self):
        pass

    ip = property(ip)
    __classcell__ = None


class MIMEVersion(TokenList):
    token_type = 'mime-version'
    major = None
    minor = None


class Parameter(TokenList):
    token_type = 'parameter'
    sectioned = False
    extended = False
    charset = 'us-ascii'
    
    def section_number(self):
        if self.sectioned:
            return self[1].number

    section_number = property(section_number)
    
    def param_value(self):
        for token in self:
            return token.stripped_value
            for token in token:
                for token in token:
                    return token.stripped_value
                    return ''

    param_value = property(param_value)


class InvalidParameter(Parameter):
    token_type = 'invalid-parameter'


class Attribute(TokenList):
    token_type = 'attribute'
    
    def stripped_value(self):
        pass

    stripped_value = property(stripped_value)


class Section(TokenList):
    token_type = 'section'
    number = None


class Value(TokenList):
    token_type = 'value'
    
    def stripped_value(self):
        token = self[0]
        if token.token_type == 'cfws':
            token = self[1]
            if token.token_type.endswith(('quoted-string', 'attribute', 'extended-attribute')):
                return token.stripped_value
            return None.value

    stripped_value = property(stripped_value)


class MimeParameters(TokenList):
    token_type = 'mime-parameters'
    syntactic_break = False
    
    def params(self):
        params = { }
    # WARNING: Decompyle incomplete

    params = property(params)
    
    def __str__(self):
        params = []
        params.append(name)
        continue
        params = '; '.join(params)
        if params:
            return ' ' + params
        return [ '{}={}'.format(name, quote_string(value)) for name, value in self.params if value ]



class ParameterizedHeaderValue(TokenList):
    syntactic_break = False
    
    def params(self):
        return { }

    params = property(params)


class ContentType(ParameterizedHeaderValue):
    token_type = 'content-type'
    as_ew_allowed = False
    maintype = 'text'
    subtype = 'plain'


class ContentDisposition(ParameterizedHeaderValue):
    token_type = 'content-disposition'
    as_ew_allowed = False
    content_disposition = None


class ContentTransferEncoding(TokenList):
    token_type = 'content-transfer-encoding'
    as_ew_allowed = False
    cte = '7bit'


class HeaderLabel(TokenList):
    token_type = 'header-label'
    as_ew_allowed = False


class MsgID(TokenList):
    token_type = 'msg-id'
    as_ew_allowed = False
    
    def fold(self, policy):
        return str(self) + policy.linesep



class MessageID(MsgID):
    token_type = 'message-id'


class InvalidMessageID(MessageID):
    token_type = 'invalid-message-id'


class Header(TokenList):
    token_type = 'header'


class Terminal(str):
    as_ew_allowed = True
    ew_combine_allowed = True
    syntactic_break = True
    
    def __new__(cls = None, value = None, token_type = None):
        self = super().__new__(cls, value)
        self.token_type = token_type
        self.defects = []
        return self

    
    def __repr__(self = None):
        return '{}({})'.format(self.__class__.__name__, super().__repr__())

    
    def pprint(self):
        print(self.__class__.__name__ + '/' + self.token_type)

    
    def all_defects(self):
        return list(self.defects)

    all_defects = property(all_defects)
    
    def _pp(self = None, indent = None):
        if not self.defects:
            pass
        else:
            return [
                indent(self.__class__.__name__, self.token_type, super().__repr__(), '', ' {}'.format(self.defects))]

    
    def pop_trailing_ws(self):
        pass

    
    def comments(self):
        return []

    comments = property(comments)
    
    def __getnewargs__(self):
        return (str(self), self.token_type)

    __classcell__ = None


class WhiteSpaceTerminal(Terminal):
    
    def value(self):
        return ' '

    value = property(value)
    
    def startswith_fws(self):
        return True



class ValueTerminal(Terminal):
    
    def value(self):
        return self

    value = property(value)
    
    def startswith_fws(self):
        return False



class EWWhiteSpaceTerminal(WhiteSpaceTerminal):
    
    def value(self):
        return ''

    value = property(value)
    
    def __str__(self):
        return ''



def _InvalidEwError():
    '''_InvalidEwError'''
    __doc__ = 'Invalid encoded word found while parsing headers.'

_InvalidEwError = <NODE:26>(_InvalidEwError, '_InvalidEwError', errors.HeaderParseError)
DOT = ValueTerminal('.', 'dot')
ListSeparator = ValueTerminal(',', 'list-separator')
RouteComponentMarker = ValueTerminal('@', 'route-component-marker')
_wsp_splitter = re.compile('([{}]+)'.format(''.join(WSP))).split
_non_atom_end_matcher = re.compile('[^{}]+'.format(re.escape(''.join(ATOM_ENDS)))).match
_non_printable_finder = re.compile('[\\x00-\\x20\\x7F]').findall
_non_token_end_matcher = re.compile('[^{}]+'.format(re.escape(''.join(TOKEN_ENDS)))).match
_non_attribute_end_matcher = re.compile('[^{}]+'.format(re.escape(''.join(ATTRIBUTE_ENDS)))).match
_non_extended_attribute_end_matcher = re.compile('[^{}]+'.format(re.escape(''.join(EXTENDED_ATTRIBUTE_ENDS)))).match

def _validate_xtext(xtext):
    '''If input token contains ASCII non-printables, register a defect.'''
    non_printables = _non_printable_finder(xtext)
    if non_printables:
        xtext.defects.append(errors.NonPrintableDefect(non_printables))
        if utils._has_surrogates(xtext):
            xtext.defects.append(errors.UndecodableBytesDefect('Non-ASCII characters found in header token'))
            return None


def _get_ptext_to_endchars(value, endchars):
    '''Scan printables/quoted-pairs until endchars and return unquoted ptext.

    This function turns a run of qcontent, ccontent-without-comments, or
    dtext-with-quoted-printables into a single string by unquoting any
    quoted printables.  It returns the string, the remaining value, and
    a flag that is True iff there were any quoted printables decoded.

    '''
    pass
# WARNING: Decompyle incomplete


def get_fws(value):
    """FWS = 1*WSP

    This isn't the RFC definition.  We're using fws to represent tokens where
    folding can be done, but when we are parsing the *un*folding has already
    been done so we don't need to watch out for CRLF.

    """
    newvalue = value.lstrip()
    fws = WhiteSpaceTerminal(value[:len(value) - len(newvalue)], 'fws')
    return (fws, newvalue)


def get_encoded_word(value):
    ''' encoded-word = "=?" charset "?" encoding "?" encoded-text "?="

    '''
    ew = EncodedWord()
    if not value.startswith('=?'):
        raise errors.HeaderParseError('expected encoded word but found {}'.format(value))
# WARNING: Decompyle incomplete


def get_unstructured(value):
    """unstructured = (*([FWS] vchar) *WSP) / obs-unstruct
       obs-unstruct = *((*LF *CR *(obs-utext) *LF *CR)) / FWS)
       obs-utext = %d0 / obs-NO-WS-CTL / LF / CR

       obs-NO-WS-CTL is control characters except WSP/CR/LF.

    So, basically, we have printable runs, plus control characters or nulls in
    the obsolete syntax, separated by whitespace.  Since RFC 2047 uses the
    obsolete syntax in its specification, but requires whitespace on either
    side of the encoded words, I can see no reason to need to separate the
    non-printable-non-whitespace from the printable runs if they occur, so we
    parse this into xtext tokens separated by WSP tokens.

    Because an 'unstructured' value must by definition constitute the entire
    value, this 'get' routine does not return a remaining value, only the
    parsed TokenList.

    """
    unstructured = UnstructuredTokenList()
# WARNING: Decompyle incomplete


def get_qp_ctext(value):
    """ctext = <printable ascii except \\ ( )>

    This is not the RFC ctext, since we are handling nested comments in comment
    and unquoting quoted-pairs here.  We allow anything except the '()'
    characters, but if we find any ASCII other than the RFC defined printable
    ASCII, a NonPrintableDefect is added to the token's defects list.  Since
    quoted pairs are converted to their unquoted values, what is returned is
    a 'ptext' token.  In this case it is a WhiteSpaceTerminal, so it's value
    is ' '.

    """
    (ptext, value, _) = _get_ptext_to_endchars(value, '()')
    ptext = WhiteSpaceTerminal(ptext, 'ptext')
    _validate_xtext(ptext)
    return (ptext, value)


def get_qcontent(value):
    """qcontent = qtext / quoted-pair

    We allow anything except the DQUOTE character, but if we find any ASCII
    other than the RFC defined printable ASCII, a NonPrintableDefect is
    added to the token's defects list.  Any quoted pairs are converted to their
    unquoted values, so what is returned is a 'ptext' token.  In this case it
    is a ValueTerminal.

    """
    (ptext, value, _) = _get_ptext_to_endchars(value, '"')
    ptext = ValueTerminal(ptext, 'ptext')
    _validate_xtext(ptext)
    return (ptext, value)


def get_atext(value):
    """atext = <matches _atext_matcher>

    We allow any non-ATOM_ENDS in atext, but add an InvalidATextDefect to
    the token's defects list if we find non-atext characters.
    """
    m = _non_atom_end_matcher(value)
    if not m:
        raise errors.HeaderParseError("expected atext but found '{}'".format(value))
    atext = None.group()
    value = value[len(atext):]
    atext = ValueTerminal(atext, 'atext')
    _validate_xtext(atext)
    return (atext, value)


def get_bare_quoted_string(value):
    '''bare-quoted-string = DQUOTE *([FWS] qcontent) [FWS] DQUOTE

    A quoted-string without the leading or trailing white space.  Its
    value is the text between the quote marks, with whitespace
    preserved and quoted pairs decoded.
    '''
    if value[0] != '"':
        raise errors.HeaderParseError('expected \'"\' but found \'{}\''.format(value))
    bare_quoted_string = None()
    value = value[1:]
# WARNING: Decompyle incomplete


def get_comment(value):
    '''comment = "(" *([FWS] ccontent) [FWS] ")"
       ccontent = ctext / quoted-pair / comment

    We handle nested comments here, and quoted-pair in our qp-ctext routine.
    '''
    if value and value[0] != '(':
        raise errors.HeaderParseError("expected '(' but found '{}'".format(value))
    comment = None()
    value = value[1:]
    if value and value[0] != ')':
        if value[0] in WSP:
            (token, value) = get_fws(value)
        elif value[0] == '(':
            (token, value) = get_comment(value)
        else:
            (token, value) = get_qp_ctext(value)
            comment.append(token)
        if not value:
            comment.defects.append(errors.InvalidHeaderDefect('end of header inside comment'))
            return (comment, value)
        return (None, value[1:])


def get_cfws(value):
    '''CFWS = (1*([FWS] comment) [FWS]) / FWS

    '''
    cfws = CFWSList()
    if value and value[0] in CFWS_LEADER:
        if value[0] in WSP:
            (token, value) = get_fws(value)
        else:
            (token, value) = get_comment(value)
            cfws.append(token)
        return (cfws, value)


def get_quoted_string(value):
    """quoted-string = [CFWS] <bare-quoted-string> [CFWS]

    'bare-quoted-string' is an intermediate class defined by this
    parser and not by the RFC grammar.  It is the quoted string
    without any attached CFWS.
    """
    quoted_string = QuotedString()
    if value and value[0] in CFWS_LEADER:
        (token, value) = get_cfws(value)
        quoted_string.append(token)
        (token, value) = get_bare_quoted_string(value)
        quoted_string.append(token)
        if va