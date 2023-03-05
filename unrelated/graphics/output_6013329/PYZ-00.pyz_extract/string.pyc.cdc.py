
'''A collection of string constants.

Public module variables:

whitespace -- a string containing all ASCII whitespace
ascii_lowercase -- a string containing all ASCII lowercase letters
ascii_uppercase -- a string containing all ASCII uppercase letters
ascii_letters -- a string containing all ASCII letters
digits -- a string containing all ASCII decimal digits
hexdigits -- a string containing all ASCII hexadecimal digits
octdigits -- a string containing all ASCII octal digits
punctuation -- a string containing all ASCII punctuation characters
printable -- a string containing all ASCII characters considered printable

'''
__all__ = [
    'ascii_letters',
    'ascii_lowercase',
    'ascii_uppercase',
    'capwords',
    'digits',
    'hexdigits',
    'octdigits',
    'printable',
    'punctuation',
    'whitespace',
    'Formatter',
    'Template']
import _string
whitespace = ' \t\n\r\x0b\x0c'
ascii_lowercase = 'abcdefghijklmnopqrstuvwxyz'
ascii_uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
ascii_letters = ascii_lowercase + ascii_uppercase
digits = '0123456789'
hexdigits = digits + 'abcdef' + 'ABCDEF'
octdigits = '01234567'
punctuation = '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
printable = digits + ascii_letters + punctuation + whitespace

def capwords(s, sep = (None,)):
    '''capwords(s [,sep]) -> string

    Split the argument into words using split, capitalize each
    word using capitalize, and join the capitalized words using
    join.  If the optional second argument sep is absent or None,
    runs of whitespace characters are replaced by a single space
    and leading and trailing whitespace are removed, otherwise
    sep is used to split and join the words.

    '''
    if not sep:
        pass
    return ' '.join((lambda .0: pass# WARNING: Decompyle incomplete
)(s.split(sep)))

import re as _re
from collections import ChainMap as _ChainMap
_sentinel_dict = { }

class Template:
    '''A string class for supporting $-substitutions.'''
    delimiter = '$'
    idpattern = '(?a:[_a-z][_a-z0-9]*)'
    braceidpattern = None
    flags = _re.IGNORECASE
    
    def __init_subclass__(cls = None):
        super().__init_subclass__()
        if 'pattern' in cls.__dict__:
            pattern = cls.pattern
        else:
            delim = _re.escape(cls.delimiter)
            id = cls.idpattern
            if not cls.braceidpattern:
                pass
            bid = cls.idpattern
            pattern = f'''\n            {delim}(?:\n              (?P<escaped>{delim})  |   # Escape sequence of two delimiters\n              (?P<named>{id})       |   # delimiter and a Python identifier\n              {{(?P<braced>{bid})}} |   # delimiter and a braced identifier\n              (?P<invalid>)             # Other ill-formed delimiter exprs\n            )\n            '''
        cls.pattern = _re.compile(pattern, cls.flags | _re.VERBOSE)

    
    def __init__(self, template):
        self.template = template

    
    def _invalid(self, mo):
        i = mo.start('invalid')
        lines = self.template[:i].splitlines(True, **('keepends',))
        if not lines:
            colno = 1
            lineno = 1
        else:
            colno = i - len(''.join(lines[:-1]))
            lineno = len(lines)
        raise ValueError('Invalid placeholder in string: line %d, col %d' % (lineno, colno))

    
    def substitute(self, mapping = (_sentinel_dict,), **kws):
        if mapping is _sentinel_dict:
            mapping = kws
        elif kws:
            mapping = _ChainMap(kws, mapping)
        
        def convert(mo = None):
            if not mo.group('named'):
                pass
            named = mo.group('braced')
            if named is not None:
                return str(mapping[named])
            if None.group('escaped') is not None:
                return self.delimiter
            if None.group('invalid') is not None:
                self._invalid(mo)
            raise ValueError('Unrecognized named group in pattern', self.pattern)

        return self.pattern.sub(convert, self.template)

    
    def safe_substitute(self, mapping = (_sentinel_dict,), **kws):
        if mapping is _sentinel_dict:
            mapping = kws
        elif kws:
            mapping = _ChainMap(kws, mapping)
        
        def convert(mo = None):
            if not mo.group('named'):
                pass
            named = mo.group('braced')
        # WARNING: Decompyle incomplete

        return self.pattern.sub(convert, self.template)

    __classcell__ = None

Template.__init_subclass__()

class Formatter:
    
    def format(self, format_string, *args, **kwargs):
        return self.vformat(format_string, args, kwargs)

    
    def vformat(self, format_string, args, kwargs):
        used_args = set()
        (result, _) = self._vformat(format_string, args, kwargs, used_args, 2)
        self.check_unused_args(used_args, args, kwargs)
        return result

    
    def _vformat(self, format_string, args, kwargs, used_args, recursion_depth, auto_arg_index = (0,)):
        if recursion_depth < 0:
            raise ValueError('Max string recursion exceeded')
        result = None
        for literal_text, field_name, format_spec, conversion in self.parse(format_string):
            result.append(literal_text)
            raise ValueError('cannot switch from manual field specification to automatic field numbering')
            field_name = str(auto_arg_index)
            auto_arg_index += 1
        if field_name.isdigit():
            if auto_arg_index:
                raise ValueError('cannot switch from manual field specification to automatic field numbering')
            auto_arg_index = [ literal_text ]
        (obj, arg_used) = self.get_field(field_name, args, kwargs)
        used_args.add(arg_used)
        obj = self.convert_field(obj, conversion)
        (format_spec, auto_arg_index) = self._vformat(format_spec, args, kwargs, used_args, recursion_depth - 1, auto_arg_index, **('auto_arg_index',))
        result.append(self.format_field(obj, format_spec))
        continue
        return (''.join(result), auto_arg_index)

    
    def get_value(self, key, args, kwargs):
        if isinstance(key, int):
            return args[key]
        return None[key]

    
    def check_unused_args(self, used_args, args, kwargs):
        pass

    
    def format_field(self, value, format_spec):
        return format(value, format_spec)

    
    def convert_field(self, value, conversion):
        if conversion is None:
            return value
        if None == 's':
            return str(value)
        if None == 'r':
            return repr(value)
        if None == 'a':
            return ascii(value)
        raise None('Unknown conversion specifier {0!s}'.format(conversion))

    
    def parse(self, format_string):
        return _string.formatter_parser(format_string)

    
    def get_field(self, field_name, args, kwargs):
        (first, rest) = _string.formatter_field_name_split(field_name)
        obj = self.get_value(first, args, kwargs)
        obj = obj[i]
        continue
        return (obj, first)


