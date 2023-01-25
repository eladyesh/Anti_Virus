
'''Configuration file parser.

A configuration file consists of sections, lead by a "[section]" header,
and followed by "name: value" entries, with continuations and such in
the style of RFC 822.

Intrinsic defaults can be specified by passing them into the
ConfigParser constructor as a dictionary.

class:

ConfigParser -- responsible for parsing a list of
                    configuration files, and managing the parsed database.

    methods:

    __init__(defaults=None, dict_type=_default_dict, allow_no_value=False,
             delimiters=(\'=\', \':\'), comment_prefixes=(\'#\', \';\'),
             inline_comment_prefixes=None, strict=True,
             empty_lines_in_values=True, default_section=\'DEFAULT\',
             interpolation=<unset>, converters=<unset>):
        Create the parser. When `defaults\' is given, it is initialized into the
        dictionary or intrinsic defaults. The keys must be strings, the values
        must be appropriate for %()s string interpolation.

        When `dict_type\' is given, it will be used to create the dictionary
        objects for the list of sections, for the options within a section, and
        for the default values.

        When `delimiters\' is given, it will be used as the set of substrings
        that divide keys from values.

        When `comment_prefixes\' is given, it will be used as the set of
        substrings that prefix comments in empty lines. Comments can be
        indented.

        When `inline_comment_prefixes\' is given, it will be used as the set of
        substrings that prefix comments in non-empty lines.

        When `strict` is True, the parser won\'t allow for any section or option
        duplicates while reading from a single source (file, string or
        dictionary). Default is True.

        When `empty_lines_in_values\' is False (default: True), each empty line
        marks the end of an option. Otherwise, internal empty lines of
        a multiline option are kept as part of the value.

        When `allow_no_value\' is True (default: False), options without
        values are accepted; the value presented for these is None.

        When `default_section\' is given, the name of the special section is
        named accordingly. By default it is called ``"DEFAULT"`` but this can
        be customized to point to any other valid section name. Its current
        value can be retrieved using the ``parser_instance.default_section``
        attribute and may be modified at runtime.

        When `interpolation` is given, it should be an Interpolation subclass
        instance. It will be used as the handler for option value
        pre-processing when using getters. RawConfigParser objects don\'t do
        any sort of interpolation, whereas ConfigParser uses an instance of
        BasicInterpolation. The library also provides a ``zc.buildbot``
        inspired ExtendedInterpolation implementation.

        When `converters` is given, it should be a dictionary where each key
        represents the name of a type converter and each value is a callable
        implementing the conversion from string to the desired datatype. Every
        converter gets its corresponding get*() method on the parser object and
        section proxies.

    sections()
        Return all the configuration section names, sans DEFAULT.

    has_section(section)
        Return whether the given section exists.

    has_option(section, option)
        Return whether the given option exists in the given section.

    options(section)
        Return list of configuration options for the named section.

    read(filenames, encoding=None)
        Read and parse the iterable of named configuration files, given by
        name.  A single filename is also allowed.  Non-existing files
        are ignored.  Return list of successfully read files.

    read_file(f, filename=None)
        Read and parse one configuration file, given as a file object.
        The filename defaults to f.name; it is only used in error
        messages (if f has no `name\' attribute, the string `<???>\' is used).

    read_string(string)
        Read configuration from a given string.

    read_dict(dictionary)
        Read configuration from a dictionary. Keys are section names,
        values are dictionaries with keys and values that should be present
        in the section. If the used dictionary type preserves order, sections
        and their keys will be added in order. Values are automatically
        converted to strings.

    get(section, option, raw=False, vars=None, fallback=_UNSET)
        Return a string value for the named option.  All % interpolations are
        expanded in the return values, based on the defaults passed into the
        constructor and the DEFAULT section.  Additional substitutions may be
        provided using the `vars\' argument, which must be a dictionary whose
        contents override any pre-existing defaults. If `option\' is a key in
        `vars\', the value from `vars\' is used.

    getint(section, options, raw=False, vars=None, fallback=_UNSET)
        Like get(), but convert value to an integer.

    getfloat(section, options, raw=False, vars=None, fallback=_UNSET)
        Like get(), but convert value to a float.

    getboolean(section, options, raw=False, vars=None, fallback=_UNSET)
        Like get(), but convert value to a boolean (currently case
        insensitively defined as 0, false, no, off for False, and 1, true,
        yes, on for True).  Returns False or True.

    items(section=_UNSET, raw=False, vars=None)
        If section is given, return a list of tuples with (name, value) for
        each option in the section. Otherwise, return a list of tuples with
        (section_name, section_proxy) for each section, including DEFAULTSECT.

    remove_section(section)
        Remove the given file section and all its options.

    remove_option(section, option)
        Remove the given option from the given section.

    set(section, option, value)
        Set the given option.

    write(fp, space_around_delimiters=True)
        Write the configuration state in .ini format. If
        `space_around_delimiters\' is True (the default), delimiters
        between keys and values are surrounded by spaces.
'''
from collections.abc import MutableMapping
from collections import ChainMap as _ChainMap
import functools
import io
import itertools
import os
import re
import sys
import warnings
__all__ = [
    'NoSectionError',
    'DuplicateOptionError',
    'DuplicateSectionError',
    'NoOptionError',
    'InterpolationError',
    'InterpolationDepthError',
    'InterpolationMissingOptionError',
    'InterpolationSyntaxError',
    'ParsingError',
    'MissingSectionHeaderError',
    'ConfigParser',
    'SafeConfigParser',
    'RawConfigParser',
    'Interpolation',
    'BasicInterpolation',
    'ExtendedInterpolation',
    'LegacyInterpolation',
    'SectionProxy',
    'ConverterMapping',
    'DEFAULTSECT',
    'MAX_INTERPOLATION_DEPTH']
_default_dict = dict
DEFAULTSECT = 'DEFAULT'
MAX_INTERPOLATION_DEPTH = 10

class Error(Exception):
    '''Base class for ConfigParser exceptions.'''
    
    def __init__(self, msg = ('',)):
        self.message = msg
        Exception.__init__(self, msg)

    
    def __repr__(self):
        return self.message

    __str__ = __repr__


class NoSectionError(Error):
    '''Raised when no section matches a requested option.'''
    
    def __init__(self, section):
        Error.__init__(self, 'No section: %r' % (section,))
        self.section = section
        self.args = (section,)



class DuplicateSectionError(Error):
    '''Raised when a section is repeated in an input source.

    Possible repetitions that raise this exception are: multiple creation
    using the API or in strict parsers when a section is found more than once
    in a single input file, string or dictionary.
    '''
    
    def __init__(self, section, source, lineno = (None, None)):
        msg = [
            repr(section),
            ' already exists']
        if source is not None:
            message = [
                'While reading from ',
                repr(source)]
            None(Error.__init__, self(''.join if lineno is not None else msg))
            self.section = section
            self.source = source
            self.lineno = lineno
            self.args = (section, source, lineno)
            return None



class DuplicateOptionError(Error):
    '''Raised by strict parsers when an option is repeated in an input source.

    Current implementation raises this exception only when an option is found
    more than once in a single file, string or dictionary.
    '''
    
    def __init__(self, section, option, source, lineno = (None, None)):
        msg = [
            repr(option),
            ' in section ',
            repr(section),
            ' already exists']
        if source is not None:
            message = [
                'While reading from ',
                repr(source)]
            None(Error.__init__, self(''.join if lineno is not None else msg))
            self.section = section
            self.option = option
            self.source = source
            self.lineno = lineno
            self.args = (section, option, source, lineno)
            return None



class NoOptionError(Error):
    '''A requested option was not found.'''
    
    def __init__(self, option, section):
        Error.__init__(self, 'No option %r in section: %r' % (option, section))
        self.option = option
        self.section = section
        self.args = (option, section)



class InterpolationError(Error):
    '''Base class for interpolation-related exceptions.'''
    
    def __init__(self, option, section, msg):
        Error.__init__(self, msg)
        self.option = option
        self.section = section
        self.args = (option, section, msg)



class InterpolationMissingOptionError(InterpolationError):
    '''A string substitution required a setting which was not available.'''
    
    def __init__(self, option, section, rawval, reference):
        msg = 'Bad value substitution: option {!r} in section {!r} contains an interpolation key {!r} which is not a valid option name. Raw value: {!r}'.format(option, section, reference, rawval)
        InterpolationError.__init__(self, option, section, msg)
        self.reference = reference
        self.args = (option, section, rawval, reference)



class InterpolationSyntaxError(InterpolationError):
    '''Raised when the source text contains invalid syntax.

    Current implementation raises this exception when the source text into
    which substitutions are made does not conform to the required syntax.
    '''
    pass


class InterpolationDepthError(InterpolationError):
    '''Raised when substitutions are nested too deeply.'''
    
    def __init__(self, option, section, rawval):
        msg = 'Recursion limit exceeded in value substitution: option {!r} in section {!r} contains an interpolation key which cannot be substituted in {} steps. Raw value: {!r}'.format(option, section, MAX_INTERPOLATION_DEPTH, rawval)
        InterpolationError.__init__(self, option, section, msg)
        self.args = (option, section, rawval)



class ParsingError(Error):
    '''Raised when a configuration file does not follow legal syntax.'''
    
    def __init__(self, source, filename = (None, None)):
        if filename and source:
            raise ValueError("Cannot specify both `filename' and `source'. Use `source'.")
        if not filename and source:
            raise ValueError("Required argument `source' not given.")
        if filename:
            source = filename
            Error.__init__(self, 'Source contains parsing errors: %r' % source)
            self.source = source
            self.errors = []
            self.args = (source,)
            return None

    
    def filename(self):
        """Deprecated, use `source'."""
        warnings.warn("The 'filename' attribute will be removed in future versions.  Use 'source' instead.", DeprecationWarning, 2, **('stacklevel',))
        return self.source

    filename = property(filename)
    
    def filename(self, value):
        """Deprecated, user `source'."""
        warnings.warn("The 'filename' attribute will be removed in future versions.  Use 'source' instead.", DeprecationWarning, 2, **('stacklevel',))
        self.source = value

    filename = filename.setter(filename)
    
    def append(self, lineno, line):
        self.errors.append((lineno, line))
        self.message += '\n\t[line %2d]: %s' % (lineno, line)



class MissingSectionHeaderError(ParsingError):
    '''Raised when a key-value pair is found before any section header.'''
    
    def __init__(self, filename, lineno, line):
        Error.__init__(self, 'File contains no section headers.\nfile: %r, line: %d\n%r' % (filename, lineno, line))
        self.source = filename
        self.lineno = lineno
        self.line = line
        self.args = (filename, lineno, line)


_UNSET = object()

class Interpolation:
    '''Dummy interpolation that passes the value through with no changes.'''
    
    def before_get(self, parser, section, option, value, defaults):
        return value

    
    def before_set(self, parser, section, option, value):
        return value

    
    def before_read(self, parser, section, option, value):
        return value

    
    def before_write(self, parser, section, option, value):
        return value



class BasicInterpolation(Interpolation):
    '''Interpolation as implemented in the classic ConfigParser.

    The option values can contain format strings which refer to other values in
    the same section, or values in the special default section.

    For example:

        something: %(dir)s/whatever

    would resolve the "%(dir)s" to the value of dir.  All reference
    expansions are done late, on demand. If a user needs to use a bare % in
    a configuration file, she can escape it by writing %%. Other % usage
    is considered a user error and raises `InterpolationSyntaxError\'.'''
    _KEYCRE = re.compile('%\\(([^)]+)\\)s')
    
    def before_get(self, parser, section, option, value, defaults):
        L = []
        self._interpolate_some(parser, option, L, value, section, defaults, 1)
        return ''.join(L)

    
    def before_set(self, parser, section, option, value):
        tmp_value = value.replace('%%', '')
        tmp_value = self._KEYCRE.sub('', tmp_value)
        if '%' in tmp_value:
            raise ValueError('invalid interpolation syntax in %r at position %d' % (value, tmp_value.find('%')))

    
    def _interpolate_some(self, parser, option, accum, rest, section, map, depth):
        rawval = parser.get(section, option, True, rest, **('raw', 'fallback'))
        if depth > MAX_INTERPOLATION_DEPTH:
            raise InterpolationDepthError(option, section, rawval)
    # WARNING: Decompyle incomplete



class ExtendedInterpolation(Interpolation):
    """Advanced variant of interpolation, supports the syntax used by
    `zc.buildout'. Enables interpolation between sections."""
    _KEYCRE = re.compile('\\$\\{([^}]+)\\}')
    
    def before_get(self, parser, section, option, value, defaults):
        L = []
        self._interpolate_some(parser, option, L, value, section, defaults, 1)
        return ''.join(L)

    
    def before_set(self, parser, section, option, value):
        tmp_value = value.replace('$$', '')
        tmp_value = self._KEYCRE.sub('', tmp_value)
        if '$' in tmp_value:
            raise ValueError('invalid interpolation syntax in %r at position %d' % (value, tmp_value.find('$')))

    
    def _interpolate_some(self, parser, option, accum, rest, section, map, depth):
        rawval = parser.get(section, option, True, rest, **('raw', 'fallback'))
        if depth > MAX_INTERPOLATION_DEPTH:
            raise InterpolationDepthError(option, section, rawval)
    # WARNING: Decompyle incomplete



class LegacyInterpolation(Interpolation):
    '''Deprecated interpolation used in old versions of ConfigParser.
    Use BasicInterpolation or ExtendedInterpolation instead.'''
    _KEYCRE = re.compile('%\\(([^)]*)\\)s|.')
    
    def before_get(self, parser, section, option, value, vars):
        rawval = value
        depth = MAX_INTERPOLATION_DEPTH
    # WARNING: Decompyle incomplete

    
    def before_set(self, parser, section, option, value):
        return value

    
    def _interpolation_replace(match, parser):
        s = match.group(1)
        if s is None:
            return match.group()
        return None % parser.optionxform(s)

    _interpolation_replace = staticmethod(_interpolation_replace)


class RawConfigParser(MutableMapping):
    '''ConfigParser that does not do interpolation.'''
    _SECT_TMPL = '\n        \\[                                 # [\n        (?P<header>[^]]+)                  # very permissive!\n        \\]                                 # ]\n        '
    _OPT_TMPL = '\n        (?P<option>.*?)                    # very permissive!\n        \\s*(?P<vi>{delim})\\s*              # any number of space/tab,\n                                           # followed by any of the\n                                           # allowed delimiters,\n                                           # followed by any space/tab\n        (?P<value>.*)$                     # everything up to eol\n        '
    _OPT_NV_TMPL = '\n        (?P<option>.*?)                    # very permissive!\n        \\s*(?:                             # any number of space/tab,\n        (?P<vi>{delim})\\s*                 # optionally followed by\n                                           # any of the allowed\n                                           # delimiters, followed by any\n                                           # space/tab\n        (?P<value>.*))?$                   # everything up to eol\n        '
    _DEFAULT_INTERPOLATION = Interpolation()
    SECTCRE = re.compile(_SECT_TMPL, re.VERBOSE)
    OPTCRE = re.compile(_OPT_TMPL.format('=|:', **('delim',)), re.VERBOSE)
    OPTCRE_NV = re.compile(_OPT_NV_TMPL.format('=|:', **('delim',)), re.VERBOSE)
    NONSPACECRE = re.compile('\\S')
    BOOLEAN_STATES = {
        '1': True,
        'yes': True,
        'true': True,
        'on': True,
        '0': False,
        'no': False,
        'false': False,
        'off': False }
    
    def __init__(self, defaults = None, dict_type = (None, _default_dict, False), allow_no_value = {
        'delimiters': ('=', ':'),
        'comment_prefixes': ('#', ';'),
        'inline_comment_prefixes': None,
        'strict': True,
        'empty_lines_in_values': True,
        'default_section': DEFAULTSECT,
        'interpolation': _UNSET,
        'converters': _UNSET }, *, delimiters, comment_prefixes, inline_comment_prefixes, strict, empty_lines_in_values, default_section, interpolation, converters):
        self._dict = dict_type
        self._sections = self._dict()
        self._defaults = self._dict()
        self._converters = ConverterMapping(self)
        self._proxies = self._dict()
        self._proxies[default_section] = SectionProxy(self, default_section)
        self._delimiters = tuple(delimiters)
        if delimiters == ('=', ':'):
            if allow_no_value:
                pass
            else:
                self._optcre = self.OPTCRE
        else:
            d = '|'.join((lambda .0: pass)(delimiters))
            if allow_no_value:
                self._optcre = re.compile(self._OPT_NV_TMPL.format(d, **('delim',)), re.VERBOSE)
            else:
                self._optcre = re.compile(self._OPT_TMPL.format(d, **('delim',)), re.VERBOSE)
                if not comment_prefixes:
                    self._comment_prefixes = tuple(())
                    if not inline_comment_prefixes:
                        self._inline_comment_prefixes = tuple(())
                        self._strict = strict
                        self._allow_no_value = allow_no_value
                        self._empty_lines_in_values = empty_lines_in_values
                        self.default_section = default_section
                        self._interpolation = interpolation
                        if self._interpolation is _UNSET:
                            self._interpolation = self._DEFAULT_INTERPOLATION
                            if self._interpolation is None:
                                self._interpolation = Interpolation()
                                if converters is not _UNSET:
                                    self._converters.update(converters)
                                    if defaults:
                                        self._read_defaults(defaults)
                                        return None

    
    def defaults(self):
        return self._defaults

    
    def sections(self):
        '''Return a list of section names, excluding [DEFAULT]'''
        return list(self._sections.keys())

    
    def add_section(self, section):
        '''Create a new section in the configuration.

        Raise DuplicateSectionError if a section by the specified name
        already exists. Raise ValueError if name is DEFAULT.
        '''
        if section == self.default_section:
            raise ValueError('Invalid section name: %r' % section)
        if None in self._sections:
            raise DuplicateSectionError(section)
        self._sections[section] = None._dict()
        self._proxies[section] = SectionProxy(self, section)

    
    def has_section(self, section):
        '''Indicate whether the named section is present in the configuration.

        The DEFAULT section is not acknowledged.
        '''
        return section in self._sections

    
    def options(self, section):
        '''Return a list of option names for the given section name.'''
        pass
    # WARNING: Decompyle incomplete

    
    def read(self, filenames, encoding = (None,)):
        """Read and parse a filename or an iterable of filenames.

        Files that cannot be opened are silently ignored; this is
        designed so that you can specify an iterable of potential
        configuration file locations (e.g. current directory, user's
        home directory, systemwide directory), and all existing
        configuration files in the iterable will be read.  A single
        filename may also be given.

        Return list of successfully read files.
        """
        pass
    # WARNING: Decompyle incomplete

    
    def read_file(self, f, source = (None,)):
        """Like read() but the argument must be a file-like object.

        The `f' argument must be iterable, returning one line at a time.
        Optional second argument is the `source' specifying the name of the
        file being read. If not given, it is taken from f.name. If `f' has no
        `name' attribute, `<???>' is used.
        """
        pass
    # WARNING: Decompyle incomplete

    
    def read_string(self, string, source = ('<string>',)):
        '''Read configuration from a given string.'''
        sfile = io.StringIO(string)
        self.read_file(sfile, source)

    
    def read_dict(self, dictionary, source = ('<dict>',)):
        """Read configuration from a dictionary.

        Keys are section names, values are dictionaries with keys and values
        that should be present in the section. If the used dictionary type
        preserves order, sections and their keys will be added in order.

        All types held in the dictionary are converted to strings during
        reading, including section names, option names and keys.

        Optional second argument is the `source' specifying the name of the
        dictionary being read.
        """
        elements_added = set()
    # WARNING: Decompyle incomplete

    
    def readfp(self, fp, filename = (None,)):
        '''Deprecated, use read_file instead.'''
        warnings.warn("This method will be removed in future versions.  Use 'parser.read_file()' instead.", DeprecationWarning, 2, **('stacklevel',))
        self.read_file(fp, filename, **('source',))

    
    def get(self, section = None, option = {
        'raw': False,
        'vars': None,
        'fallback': _UNSET }, *, raw, vars, fallback):
        """Get an option value for a given section.

        If `vars' is provided, it must be a dictionary. The option is looked up
        in `vars' (if provided), `section', and in `DEFAULTSECT' in that order.
        If the key is not found and `fallback' is provided, it is used as
        a fallback value. `None' can be provided as a `fallback' value.

        If interpolation is enabled and the optional argument `raw' is False,
        all interpolations are expanded in the return values.

        Arguments `raw', `vars', and `fallback' are keyword only.

        The section DEFAULT is special.
        """
        pass
    # WARNING: Decompyle incomplete

    
    def _get(self, section, conv, option, **kwargs):
        pass
    # WARNING: Decompyle incomplete

    
    def _get_conv(self, section, option = None, conv = {
        'raw': False,
        'vars': None,
        'fallback': _UNSET }, *, raw, vars, fallback, **kwargs):
        pass
    # WARNING: Decompyle incomplete

    
    def getint(self, section = None, option = {
        'raw': False,
        'vars': None,
        'fallback': _UNSET }, *, raw, vars, fallback, **kwargs):
        pass
    # WARNING: Decompyle incomplete

    
    def getfloat(self, section = None, option = {
        'raw': False,
        'vars': None,
        'fallback': _UNSET }, *, raw, vars, fallback, **kwargs):
        pass
    # WARNING: Decompyle incomplete

    
    def getboolean(self, section = None, option = {
        'raw': False,
        'vars': None,
        'fallback': _UNSET }, *, raw, vars, fallback, **kwargs):
        pass
    # WARNING: Decompyle incomplete

    
    def items(self = None, section = None, raw = None, vars = None):
        """Return a list of (name, value) tuples for each option in a section.

        All % interpolations are expanded in the return values, based on the
        defaults passed into the constructor, unless the optional argument
        `raw' is true.  Additional substitutions may be provided using the
        `vars' argument, which must be a dictionary whose contents overrides
        any pre-existing defaults.

        The section DEFAULT is special.
        """
        if section is _UNSET:
            return super().items()
        d = None._defaults.copy()
    # WARNING: Decompyle incomplete

    
    def popitem(self):
        '''Remove a section from the parser and return it as
        a (section_name, section_proxy) tuple. If no section is present, raise
        KeyError.

        The section DEFAULT is never returned because it cannot be removed.
        '''
        for key in self.sections():
            value = self[key]
            del self[key]
            return (key, value)
            raise KeyError
            return None

    
    def optionxform(self, optionstr):
        return optionstr.lower()

    
    def has_option(self, section, option):
        """Check for the existence of a given option in a given section.
        If the specified `section' is None or an empty string, DEFAULT is
        assumed. If the specified `section' does not exist, returns False."""
        if section or section == self.default_section:
            option = self.optionxform(option)
            return option in self._defaults
        if None not in self._sections:
            return False
        option = None.optionxform(option)
        if not option in self._sections[section]:
            return option in self._defaults
        return option in self._sections[section]

    
    def set(self, section, option, value = (None,)):
        '''Set an option.'''
        pass
    # WARNING: Decompyle incomplete

    
    def write(self, fp, space_around_delimiters = (True,)):
        """Write an .ini-format representation of the configuration state.

        If `space_around_delimiters' is True (the default), delimiters
        between keys and values are surrounded by spaces.

        Please note that comments in the original configuration file are not
        preserved when writing the configuration back.
        """
        if space_around_delimiters:
            d = ' {} '.format(self._delimiters[0])
        else:
            d = self._delimiters[0]
            if self._defaults:
                self._write_section(fp, self.default_section, self._defaults.items(), d)
                for section in self._sections:
                    self._write_section(fp, section, self._sections[section].items(), d)
                return None

    
    def _write_section(self, fp, section_name, section_items, delimiter):
        """Write a single section to the specified `fp'."""
        fp.write('[{}]\n'.format(section_name))
        for key, value in section_items:
            value = self._interpolation.before_write(self, section_name, key, value)
            value = delimiter + str(value).replace('\n', '\n\t')
        value = ''
        fp.write('{}{}\n'.format(key, value))
        continue
        fp.write('\n')

    
    def remove_option(self, section, option):
        '''Remove an option.'''
        if section or section == self.default_section:
            sectdict = self._defaults
    # WARNING: Decompyle incomplete

    
    def remove_section(self, section):
        '''Remove a file section.'''
        existed = section in self._sections
        if existed:
            del self._sections[section]
            del self._proxies[section]
            return existed

    
    def __getitem__(self, key):
        if not key != self.default_section and self.has_section(key):
            raise KeyError(key)
        return None._proxies[key]

    
    def __setitem__(self, key, value):
        if key in self and self[key] is value:
            return None
        if None == self.default_section:
            self._defaults.clear()
        elif key in self._sections:
            self._sections[key].clear()
            self.read_dict({
                key: value })
            return None

    
    def __delitem__(self, key):
        if key == self.default_section:
            raise ValueError('Cannot remove the default section.')
        if not None.has_section(key):
            raise KeyError(key)
        None.remove_section(key)

    
    def __contains__(self, key):
        if not key == self.default_section:
            return self.has_section(key)

    
    def __len__(self):
        return len(self._sections) + 1

    
    def __iter__(self):
        return itertools.chain((self.default_section,), self._sections.keys())

    
    def _read(self, fp, fpname):
        """Parse a sectioned configuration file.

        Each section in a configuration file contains a header, indicated by
        a name in square brackets (`[]'), plus key/value options, indicated by
        `name' and `value' delimited with a specific substring (`=' or `:' by
        default).

        Values can span multiple lines, as long as they are indented deeper
        than the first line of the value. Depending on the parser's mode, blank
        lines may be treated as parts of multiline values or ignored.

        Configuration files may include comments, prefixed by specific
        characters (`#' and `;' by default). Comments may appear on their own
        in an otherwise empty line or may be entered in lines holding values or
        section names. Please note that comments get stripped off when reading configuration files.
        """
        elements_added = set()
        cursect = None
        sectname = None
        optname = None
        lineno = 0
        indent_level = 0
        e = None
        first_nonspace = self.NONSPACECRE.search(line)
        if cursect is not None and optname and cur_indent_level > indent_level:
            cursect[optname].append(value)
            continue
            indent_level = cur_indent_level
            mo = self.SECTCRE.match(value)
            if mo:
                sectname = mo.group('header')
                if sectname in self._sections:
                    if self._strict and sectname in elements_added:
                        raise DuplicateSectionError(sectname, fpname, lineno)
                    cursect = [ '' for lineno, line in enumerate(fp, 1, **('start',)) if inline_prefixes for prefix in self._comment_prefixes if cursect[optname] is not None ] if first_nonspace else first_nonspace.start()._sections[sectname]
                    elements_added.add(sectname)
                elif sectname == self.default_section:
                    cursect = self._defaults
                else:
                    cursect = self._dict()
                    self._sections[sectname] = cursect
                    self._proxies[sectname] = SectionProxy(self, sectname)
                    elements_added.add(sectname)
                    optname = None
                if cursect is None:
                    raise MissingSectionHeaderError(fpname, lineno, line)
                mo = self._optcre.match(value)
                if mo:
                    (optname, vi, optval) = mo.group('option', 'vi', 'value')
                    if not optname:
                        e = self._handle_error(e, fpname, lineno, line)
                        optname = self.optionxform(optname.rstrip())
                        if self._strict and (sectname, optname) in elements_added:
                            raise DuplicateOptionError(sectname, optname, fpname, lineno)
                        [ '' for lineno, line in enumerate(fp, 1, **('start',)) if inline_prefixes for prefix in self._comment_prefixes if cursect[optname] is not None ] if first_nonspace else first_nonspace.start().add((sectname, optname))
                        if optval is not None:
                            optval = optval.strip()
                            cursect[optname] = [
                                optval]
                        else:
                            cursect[optname] = None
                        e = self._handle_error(e, fpname, lineno, line)
                        continue
                        self._join_multiline_values()
                        if e:
                            raise e
                        return None

    
    def _join_multiline_values(self):
        defaults = (self.default_section, self._defaults)
        all_sections = itertools.chain((defaults,), self._sections.items())

    
    def _read_defaults(self, defaults):
        '''Read the defaults passed in the initializer.
        Note: values can be non-string.'''
        pass

    
    def _handle_error(self, exc, fpname, lineno, line):
        if not exc:
            exc = ParsingError(fpname)
        exc.append(lineno, repr(line))
        return exc

    
    def _unify_values(self, section, vars):
        """Create a sequence of lookups with 'vars' taking priority over
        the 'section' which takes priority over the DEFAULTSECT.

        """
        sectiondict = { }
    # WARNING: Decompyle incomplete

    
    def _convert_to_boolean(self, value):
        '''Return a boolean value translating from other types if necessary.
        '''
        if value.lower() not in self.BOOLEAN_STATES:
            raise ValueError('Not a boolean: %s' % value)
        return None.BOOLEAN_STATES[value.lower()]

    
    def _validate_value_types(self = None, *, section, option, value):
        '''Raises a TypeError for non-string values.

        The only legal non-string value if we allow valueless
        options is None, so we need to check if the value is a
        string if:
        - we do not allow valueless options, or
        - we allow valueless options but the value is not None

        For compatibility reasons this method is not used in classic set()
        for RawConfigParsers. It is invoked in every case for mapping protocol
        access and in ConfigParser.set().
        '''
        if not isinstance(section, str):
            raise TypeError('section names must be strings')
        if not None(option, str):
            raise TypeError('option keys must be strings')
        if not (None._allow_no_value or value) and isinstance(value, str):
            raise TypeError('option values must be strings')

    
    def converters(self):
        return self._converters

    converters = property(converters)
    __classcell__ = None


class ConfigParser(RawConfigParser):
    '''ConfigParser implementing interpolation.'''
    _DEFAULT_INTERPOLATION = BasicInterpolation()
    
    def set(self = None, section = None, option = None, value = None):
        '''Set an option.  Extends RawConfigParser.set by validating type and
        interpolation syntax on the value.'''
        self._validate_value_types(option, value, **('option', 'value'))
        super().set(section, option, value)

    
    def add_section(self = None, section = None):
        '''Create a new section in the configuration.  Extends
        RawConfigParser.add_section by validating if the section name is
        a string.'''
        self._validate_value_types(section, **('section',))
        super().add_section(section)

    
    def _read_defaults(self, defaults):
        '''Reads the defaults passed in the initializer, implicitly converting
        values to strings like the rest of the API.

        Does not perform interpolation for backwards compatibility.
        '''
        pass
    # WARNING: Decompyle incomplete

    __classcell__ = None


class SafeConfigParser(ConfigParser):
    '''ConfigParser alias for backwards compatibility purposes.'''
    
    def __init__(self = None, *args, **kwargs):
        pass
    # WARNING: Decompyle incomplete

    __classcell__ = None


class SectionProxy(MutableMapping):
    '''A proxy for a single section from a parser.'''
    
    def __init__(self, parser, name):
        '''Creates a view on a section of the specified `name` in `parser`.'''
        self._parser = parser
        self._name = name

    
    def __repr__(self):
        return '<Section: {}>'.format(self._name)

    
    def __getitem__(self, key):
        if not self._parser.has_option(self._name, key):
            raise KeyError(key)
        return None._parser.get(self._name, key)

    
    def __setitem__(self, key, value):
        self._parser._validate_value_types(key, value, **('option', 'value'))
        return self._parser.set(self._name, key, value)

    
    def __delitem__(self, key):
        if not self._parser.has_option(self._name, key) or self._parser.remove_option(self._name, key):
            raise KeyError(key)

    
    def __contains__(self, key):
        return self._parser.has_option(self._name, key)

    
    def __len__(self):
        return len(self._options())

    
    def __iter__(self):
        return self._options().__iter__()

    
    def _options(self):
        if self._name != self._parser.default_section:
            return self._parser.options(self._name)
        return None._parser.defaults()

    
    def parser(self):
        return self._parser

    parser = property(parser)
    
    def name(self):
        return self._name

    name = property(name)
    
    def get(self = None, option = (None,), fallback = {
        'raw': False,
        'vars': None,
        '_impl': None }, *, raw, vars, _impl, **kwargs):
        '''Get an option value.

        Unless `fallback` is provided, `None` will be returned if the option
        is not found.

        '''
        if not _impl:
            _impl = self._parser.get
    # WARNING: Decompyle incomplete



class ConverterMapping(MutableMapping):
    '''Enables reuse of get*() methods between the parser and section proxies.

    If a parser class implements a getter directly, the value for the given
    key will be ``None``. The presence of the converter name here enables
    section proxies to find and use the implementation on the parser class.
    '''
    GETTERCRE = re.compile('^get(?P<name>.+)$')
    
    def __init__(self, parser):
        self._parser = parser
        self._data = { }
        self._data[m.group('name')] = None
        continue

    
    def __getitem__(self, key):
        return self._data[key]

    
    def __setitem__(self, key, value):
        pass
    # WARNING: Decompyle incomplete

    
    def __delitem__(self, key):
        pass
    # WARNING: Decompyle incomplete

    
    def __iter__(self):
        return iter(self._data)

    
    def __len__(self):
        return len(self._data)


