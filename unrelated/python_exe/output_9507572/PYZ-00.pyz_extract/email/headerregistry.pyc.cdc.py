
"""Representing and manipulating email headers via custom objects.

This module provides an implementation of the HeaderRegistry API.
The implementation is designed to flexibly follow RFC5322 rules.

Eventually HeaderRegistry will be a public API, but it isn't yet,
and will probably change some before that happens.

"""
from types import MappingProxyType
from email import utils
from email import errors
from email import _header_value_parser as parser

class Address:
    
    def __init__(self, display_name, username, domain, addr_spec = ('', '', '', None)):
        """Create an object representing a full email address.

        An address can have a 'display_name', a 'username', and a 'domain'.  In
        addition to specifying the username and domain separately, they may be
        specified together by using the addr_spec keyword *instead of* the
        username and domain keywords.  If an addr_spec string is specified it
        must be properly quoted according to RFC 5322 rules; an error will be
        raised if it is not.

        An Address object has display_name, username, domain, and addr_spec
        attributes, all of which are read-only.  The addr_spec and the string
        value of the object are both quoted according to RFC5322 rules, but
        without any Content Transfer Encoding.

        """
        inputs = ''.join(filter(None, (display_name, username, domain, addr_spec)))
        if '\r' in inputs or '\n' in inputs:
            raise ValueError('invalid arguments; address parts cannot contain CR or LF')
        if None is not None:
            if username or domain:
                raise TypeError('addrspec specified when username and/or domain also specified')
            (a_s, rest) = None.get_addr_spec(addr_spec)
            if rest:
                raise ValueError("Invalid addr_spec; only '{}' could be parsed from '{}'".format(a_s, addr_spec))
            if None.all_defects:
                raise a_s.all_defects[0]
            username = None.local_part
            domain = a_s.domain
            self._display_name = display_name
            self._username = username
            self._domain = domain
            return None

    
    def display_name(self):
        return self._display_name

    display_name = property(display_name)
    
    def username(self):
        return self._username

    username = property(username)
    
    def domain(self):
        return self._domain

    domain = property(domain)
    
    def addr_spec(self):
        '''The addr_spec (username@domain) portion of the address, quoted
        according to RFC 5322 rules, but with no Content Transfer Encoding.
        '''
        lp = self.username
        if not parser.DOT_ATOM_ENDS.isdisjoint(lp):
            lp = parser.quote_string(lp)
            if self.domain:
                return lp + '@' + self.domain
            if not None:
                return '<>'
            return None

    addr_spec = property(addr_spec)
    
    def __repr__(self):
        return '{}(display_name={!r}, username={!r}, domain={!r})'.format(self.__class__.__name__, self.display_name, self.username, self.domain)

    
    def __str__(self):
        disp = self.display_name
        if not parser.SPECIALS.isdisjoint(disp):
            disp = parser.quote_string(disp)
            if disp:
                return '' if self.addr_spec == '<>' else '{} <{}>'.format(disp, addr_spec)
            return None.addr_spec

    
    def __eq__(self, other):
        if not isinstance(other, Address):
            return NotImplemented
        if None.display_name == other.display_name and self.username == other.username:
            return self.domain == other.domain



class Group:
    
    def __init__(self, display_name, addresses = (None, None)):
        '''Create an object representing an address group.

        An address group consists of a display_name followed by colon and a
        list of addresses (see Address) terminated by a semi-colon.  The Group
        is created by specifying a display_name and a possibly empty list of
        Address objects.  A Group can also be used to represent a single
        address that is not in a group, which is convenient when manipulating
        lists that are a combination of Groups and individual Addresses.  In
        this case the display_name should be set to None.  In particular, the
        string representation of a Group whose display_name is None is the same
        as the Address object, if there is one and only one Address object in
        the addresses list.

        '''
        self._display_name = display_name

    
    def display_name(self):
        return self._display_name

    display_name = property(display_name)
    
    def addresses(self):
        return self._addresses

    addresses = property(addresses)
    
    def __repr__(self):
        return '{}(display_name={!r}, addresses={!r}'.format(self.__class__.__name__, self.display_name, self.addresses)

    
    def __str__(self):
        if self.display_name is None and len(self.addresses) == 1:
            return str(self.addresses[0])
        disp = None.display_name
        if not disp is not None and parser.SPECIALS.isdisjoint(disp):
            disp = parser.quote_string(disp)
            adrstr = ', '.join((lambda .0: pass)(self.addresses))
            return '{}:{};'.format(disp, adrstr)

    
    def __eq__(self, other):
        if not isinstance(other, Group):
            return NotImplemented
        if None.display_name == other.display_name:
            return self.addresses == other.addresses



class BaseHeader(str):
    """Base class for message headers.

    Implements generic behavior and provides tools for subclasses.

    A subclass must define a classmethod named 'parse' that takes an unfolded
    value string and a dictionary as its arguments.  The dictionary will
    contain one key, 'defects', initialized to an empty list.  After the call
    the dictionary must contain two additional keys: parse_tree, set to the
    parse tree obtained from parsing the header, and 'decoded', set to the
    string value of the idealized representation of the data from the value.
    (That is, encoded words are decoded, and values that have canonical
    representations are so represented.)

    The defects key is intended to collect parsing defects, which the message
    parser will subsequently dispose of as appropriate.  The parser should not,
    insofar as practical, raise any errors.  Defects should be added to the
    list instead.  The standard header parsers register defects for RFC
    compliance issues, for obsolete RFC syntax, and for unrecoverable parsing
    errors.

    The parse method may add additional keys to the dictionary.  In this case
    the subclass must define an 'init' method, which will be passed the
    dictionary as its keyword arguments.  The method should use (usually by
    setting them as the value of similarly named attributes) and remove all the
    extra keys added by its parse method, and then use super to call its parent
    class with the remaining arguments and keywords.

    The subclass should also make sure that a 'max_count' attribute is defined
    that is either None or 1. XXX: need to better define this API.

    """
    
    def __new__(cls, name, value):
        kwds = {
            'defects': [] }
        cls.parse(value, kwds)
    # WARNING: Decompyle incomplete

    
    def init(self, name, *, parse_tree, defects):
        self._name = name
        self._parse_tree = parse_tree
        self._defects = defects

    
    def name(self):
        return self._name

    name = property(name)
    
    def defects(self):
        return tuple(self._defects)

    defects = property(defects)
    
    def __reduce__(self):
        return (_reconstruct_header, (self.__class__.__name__, self.__class__.__bases__, str(self)), self.__dict__)

    
    def _reconstruct(cls, value):
        return str.__new__(cls, value)

    _reconstruct = classmethod(_reconstruct)
    
    def fold(self, *, policy):
        '''Fold header according to policy.

        The parsed representation of the header is folded according to
        RFC5322 rules, as modified by the policy.  If the parse tree
        contains surrogateescaped bytes, the bytes are CTE encoded using
        the charset \'unknown-8bit".

        Any non-ASCII characters in the parse tree are CTE encoded using
        charset utf-8. XXX: make this a policy setting.

        The returned value is an ASCII-only string possibly containing linesep
        characters, and ending with a linesep character.  The string includes
        the header name and the \': \' separator.

        '''
        header = parser.Header([
            parser.HeaderLabel([
                parser.ValueTerminal(self.name, 'header-name'),
                parser.ValueTerminal(':', 'header-sep')])])
        if self._parse_tree:
            header.append(parser.CFWSList([
                parser.WhiteSpaceTerminal(' ', 'fws')]))
            header.append(self._parse_tree)
            return header.fold(policy, **('policy',))



def _reconstruct_header(cls_name, bases, value):
    return type(cls_name, bases, { })._reconstruct(value)


class UnstructuredHeader:
    max_count = None
    value_parser = staticmethod(parser.get_unstructured)
    
    def parse(cls, value, kwds):
        kwds['parse_tree'] = cls.value_parser(value)
        kwds['decoded'] = str(kwds['parse_tree'])

    parse = classmethod(parse)


class UniqueUnstructuredHeader(UnstructuredHeader):
    max_count = 1


class DateHeader:
    """Header whose value consists of a single timestamp.

    Provides an additional attribute, datetime, which is either an aware
    datetime using a timezone, or a naive datetime if the timezone
    in the input string is -0000.  Also accepts a datetime as input.
    The 'value' attribute is the normalized form of the timestamp,
    which means it is the output of format_datetime on the datetime.
    """
    max_count = None
    value_parser = staticmethod(parser.get_unstructured)
    
    def parse(cls, value, kwds):
        if not value:
            kwds['defects'].append(errors.HeaderMissingRequiredValue())
            kwds['datetime'] = None
            kwds['decoded'] = ''
            kwds['parse_tree'] = parser.TokenList()
            return None
        if None(value, str):
            value = utils.parsedate_to_datetime(value)
            kwds['datetime'] = value
            kwds['decoded'] = utils.format_datetime(kwds['datetime'])
            kwds['parse_tree'] = cls.value_parser(kwds['decoded'])
            return None

    parse = classmethod(parse)
    
    def init(self = None, *args, **kw):
        self._datetime = kw.pop('datetime')
    # WARNING: Decompyle incomplete

    
    def datetime(self):
        return self._datetime

    datetime = property(datetime)
    __classcell__ = None


class UniqueDateHeader(DateHeader):
    max_count = 1


class AddressHeader:
    max_count = None
    
    def value_parser(value):
        (address_list, value) = parser.get_address_list(value)
    # WARNING: Decompyle incomplete

    value_parser = staticmethod(value_parser)
    
    def parse(cls, value, kwds):
        if isinstance(value, str):
            kwds['parse_tree'] = address_list = cls.value_parser(value)
            groups = []
            for addr in address_list.addresses:
                groups.append(Group(addr.display_name, (lambda .0: [ Address('', '', '') for mb in .0 if mb.domain ])(addr.all_mailboxes)))
            defects = list(address_list.all_defects)
        elif not hasattr(value, '__iter__'):
            value = [
                value]
            groups = (lambda .0: for item in .0:
passcontinueGroup(None, [
item])[item])(value)
            defects = []
            kwds['groups'] = groups
            kwds['defects'] = defects
            kwds['decoded'] = ', '.join((lambda .0: [ str(item) for item in .0 ])(groups))
            if 'parse_tree' not in kwds:
                kwds['parse_tree'] = cls.value_parser(kwds['decoded'])
                return None

    parse = classmethod(parse)
    
    def init(self = None, *args, **kw):
        self._groups = tuple(kw.pop('groups'))
        self._addresses = None
    # WARNING: Decompyle incomplete

    
    def groups(self):
        return self._groups

    groups = property(groups)
    
    def addresses(self):
        if self._addresses is None:
            self._addresses = tuple((lambda .0: for group in .0:
for address in group.addresses:
addressNone)(self._groups))
            return self._addresses

    addresses = property(addresses)
    __classcell__ = None


class UniqueAddressHeader(AddressHeader):
    max_count = 1


class SingleAddressHeader(AddressHeader):
    
    def address(self):
        if len(self.addresses) != 1:
            raise ValueError('value of single address header {} is not a single address'.format(self.name))
        return None.addresses[0]

    address = property(address)


class UniqueSingleAddressHeader(SingleAddressHeader):
    max_count = 1


class MIMEVersionHeader:
    max_count = 1
    value_parser = staticmethod(parser.parse_mime_version)
    
    def parse(cls, value, kwds):
        kwds['parse_tree'] = parse_tree = cls.value_parser(value)
        kwds['decoded'] = str(parse_tree)
        kwds['defects'].extend(parse_tree.all_defects)
        parse_tree.major[kwds if parse_tree.minor is None else 'major'] = None
        kwds['minor'] = parse_tree.minor
        if parse_tree.minor is not None:
            kwds['version'] = '{}.{}'.format(kwds['major'], kwds['minor'])
        else:
            kwds['version'] = None
            return None

    parse = classmethod(parse)
    
    def init(self = None, *args, **kw):
        self._version = kw.pop('version')
        self._major = kw.pop('major')
        self._minor = kw.pop('minor')
    # WARNING: Decompyle incomplete

    
    def major(self):
        return self._major

    major = property(major)
    
    def minor(self):
        return self._minor

    minor = property(minor)
    
    def version(self):
        return self._version

    version = property(version)
    __classcell__ = None


class ParameterizedMIMEHeader:
    max_count = 1
    
    def parse(cls, value, kwds):
        kwds['parse_tree'] = parse_tree = cls.value_parser(value)
        kwds['decoded'] = str(parse_tree)
        kwds['defects'].extend(parse_tree.all_defects)
        if parse_tree.params is None:
            kwds['params'] = { }
        else:
            kwds['params'] = (lambda .0: pass# WARNING: Decompyle incomplete
)(parse_tree.params)
            return None

    parse = classmethod(parse)
    
    def init(self = None, *args, **kw):
        self._params = kw.pop('params')
    # WARNING: Decompyle incomplete

    
    def params(self):
        return MappingProxyType(self._params)

    params = property(params)
    __classcell__ = None


class ContentTypeHeader(ParameterizedMIMEHeader):
    value_parser = staticmethod(parser.parse_content_type_header)
    
    def init(self = None, *args, **kw):
        pass
    # WARNING: Decompyle incomplete

    
    def maintype(self):
        return self._maintype

    maintype = property(maintype)
    
    def subtype(self):
        return self._subtype

    subtype = property(subtype)
    
    def content_type(self):
        return self.maintype + '/' + self.subtype

    content_type = property(content_type)
    __classcell__ = None


class ContentDispositionHeader(ParameterizedMIMEHeader):
    value_parser = staticmethod(parser.parse_content_disposition_header)
    
    def init(self = None, *args, **kw):
        pass
    # WARNING: Decompyle incomplete

    
    def content_disposition(self):
        return self._content_disposition

    content_disposition = property(content_disposition)
    __classcell__ = None


class ContentTransferEncodingHeader:
    max_count = 1
    value_parser = staticmethod(parser.parse_content_transfer_encoding_header)
    
    def parse(cls, value, kwds):
        kwds['parse_tree'] = parse_tree = cls.value_parser(value)
        kwds['decoded'] = str(parse_tree)
        kwds['defects'].extend(parse_tree.all_defects)

    parse = classmethod(parse)
    
    def init(self = None, *args, **kw):
        pass
    # WARNING: Decompyle incomplete

    
    def cte(self):
        return self._cte

    cte = property(cte)
    __classcell__ = None


class MessageIDHeader:
    max_count = 1
    value_parser = staticmethod(parser.parse_message_id)
    
    def parse(cls, value, kwds):
        kwds['parse_tree'] = parse_tree = cls.value_parser(value)
        kwds['decoded'] = str(parse_tree)
        kwds['defects'].extend(parse_tree.all_defects)

    parse = classmethod(parse)

_default_header_map = {
    'subject': UniqueUnstructuredHeader,
    'date': UniqueDateHeader,
    'resent-date': DateHeader,
    'orig-date': UniqueDateHeader,
    'sender': UniqueSingleAddressHeader,
    'resent-sender': SingleAddressHeader,
    'to': UniqueAddressHeader,
    'resent-to': AddressHeader,
    'cc': UniqueAddressHeader,
    'resent-cc': AddressHeader,
    'bcc': UniqueAddressHeader,
    'resent-bcc': AddressHeader,
    'from': UniqueAddressHeader,
    'resent-from': AddressHeader,
    'reply-to': UniqueAddressHeader,
    'mime-version': MIMEVersionHeader,
    'content-type': ContentTypeHeader,
    'content-disposition': ContentDispositionHeader,
    'content-transfer-encoding': ContentTransferEncodingHeader,
    'message-id': MessageIDHeader }

class HeaderRegistry:
    '''A header_factory and header registry.'''
    
    def __init__(self, base_class, default_class, use_default_map = (BaseHeader, UnstructuredHeader, True)):
        '''Create a header_factory that works with the Policy API.

        base_class is the class that will be the last class in the created
        header class\'s __bases__ list.  default_class is the class that will be
        used if "name" (see __call__) does not appear in the registry.
        use_default_map controls whether or not the default mapping of names to
        specialized classes is copied in to the registry when the factory is
        created.  The default is True.

        '''
        self.registry = { }
        self.base_class = base_class
        self.default_class = default_class
        if use_default_map:
            self.registry.update(_default_header_map)
            return None

    
    def map_to_type(self, name, cls):
        '''Register cls as the specialized class for handling "name" headers.

        '''
        self.registry[name.lower()] = cls

    
    def __getitem__(self, name):
        cls = self.registry.get(name.lower(), self.default_class)
        return type('_' + cls.__name__, (cls, self.base_class), { })

    
    def __call__(self, name, value):
        """Create a header instance for header 'name' from 'value'.

        Creates a header instance by creating a specialized class for parsing
        and representing the specified header by combining the factory
        base_class with a specialized class from the registry or the
        default_class, and passing the name and value to the constructed
        class's constructor.

        """
        return self[name](name, value)


