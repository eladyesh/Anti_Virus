
import re
import sys
import copy
import types
import inspect
import keyword
import builtins
import functools
import abc
import _thread
from types import FunctionType, GenericAlias
__all__ = [
    'dataclass',
    'field',
    'Field',
    'FrozenInstanceError',
    'InitVar',
    'KW_ONLY',
    'MISSING',
    'fields',
    'asdict',
    'astuple',
    'make_dataclass',
    'replace',
    'is_dataclass']

class FrozenInstanceError(AttributeError):
    pass


class _HAS_DEFAULT_FACTORY_CLASS:
    
    def __repr__(self):
        return '<factory>'


_HAS_DEFAULT_FACTORY = _HAS_DEFAULT_FACTORY_CLASS()

class _MISSING_TYPE:
    pass

MISSING = _MISSING_TYPE()

class _KW_ONLY_TYPE:
    pass

KW_ONLY = _KW_ONLY_TYPE()
_EMPTY_METADATA = types.MappingProxyType({ })

class _FIELD_BASE:
    
    def __init__(self, name):
        self.name = name

    
    def __repr__(self):
        return self.name


_FIELD = _FIELD_BASE('_FIELD')
_FIELD_CLASSVAR = _FIELD_BASE('_FIELD_CLASSVAR')
_FIELD_INITVAR = _FIELD_BASE('_FIELD_INITVAR')
_FIELDS = '__dataclass_fields__'
_PARAMS = '__dataclass_params__'
_POST_INIT_NAME = '__post_init__'
_MODULE_IDENTIFIER_RE = re.compile('^(?:\\s*(\\w+)\\s*\\.)?\\s*(\\w+)')

class InitVar:
    __slots__ = ('type',)
    
    def __init__(self, type):
        self.type = type

    
    def __repr__(self):
        if isinstance(self.type, type):
            type_name = self.type.__name__
        else:
            type_name = repr(self.type)
        return f'''dataclasses.InitVar[{type_name}]'''

    
    def __class_getitem__(cls, type):
        return InitVar(type)



class Field:
    __slots__ = ('name', 'type', 'default', 'default_factory', 'repr', 'hash', 'init', 'compare', 'metadata', 'kw_only', '_field_type')
    
    def __init__(self, default, default_factory, init, repr, hash, compare, metadata, kw_only):
        self.name = None
        self.type = None
        self.default = default
        self.default_factory = default_factory
        self.init = init
        self.repr = repr
        self.hash = hash
        self.compare = compare
        self.metadata = _EMPTY_METADATA if metadata is None else types.MappingProxyType(metadata)
        self.kw_only = kw_only
        self._field_type = None

    
    def __repr__(self):
        return f'''Field(name={self.name!r},type={self.type!r},default={self.default!r},default_factory={self.default_factory!r},init={self.init!r},repr={self.repr!r},hash={self.hash!r},compare={self.compare!r},metadata={self.metadata!r},kw_only={self.kw_only!r},_field_type={self._field_type})'''

    
    def __set_name__(self, owner, name):
        func = getattr(type(self.default), '__set_name__', None)
        if func:
            func(self.default, owner, name)
            return None

    __class_getitem__ = classmethod(GenericAlias)


class _DataclassParams:
    __slots__ = ('init', 'repr', 'eq', 'order', 'unsafe_hash', 'frozen')
    
    def __init__(self, init, repr, eq, order, unsafe_hash, frozen):
        self.init = init
        self.repr = repr
        self.eq = eq
        self.order = order
        self.unsafe_hash = unsafe_hash
        self.frozen = frozen

    
    def __repr__(self):
        return f'''_DataclassParams(init={self.init!r},repr={self.repr!r},eq={self.eq!r},order={self.order!r},unsafe_hash={self.unsafe_hash!r},frozen={self.frozen!r})'''



def field(*, default, default_factory, init, repr, hash, compare, metadata, kw_only):
    """Return an object to identify dataclass fields.

    default is the default value of the field.  default_factory is a
    0-argument function called to initialize a field's value.  If init
    is true, the field will be a parameter to the class's __init__()
    function.  If repr is true, the field will be included in the
    object's repr().  If hash is true, the field will be included in the
    object's hash().  If compare is true, the field will be used in
    comparison functions.  metadata, if specified, must be a mapping
    which is stored but not otherwise examined by dataclass.  If kw_only
    is true, the field will become a keyword-only parameter to
    __init__().

    It is an error to specify both default and default_factory.
    """
    if default is not MISSING and default_factory is not MISSING:
        raise ValueError('cannot specify both default and default_factory')
    return None(default, default_factory, init, repr, hash, compare, metadata, kw_only)


def _fields_in_init_order(fields):
    return (tuple((lambda .0: pass# WARNING: Decompyle incomplete
)(fields)), tuple((lambda .0: pass# WARNING: Decompyle incomplete
)(fields)))


def _tuple_str(obj_name, fields):
    if not fields:
        return '()'
    return f'''{None((lambda .0 = None: [ f'''{obj_name}.{f.name}''' for f in .0 ])(fields))},)'''


def _recursive_repr(user_function):
    repr_running = set()
    
    def wrapper(self = None):
        key = (id(self), _thread.get_ident())
        if key in repr_running:
            return '...'
        None.add(key)
    # WARNING: Decompyle incomplete

    wrapper = None(wrapper)
    return wrapper


def _create_fn(name, args = None, body = {
    'globals': None,
    'locals': None,
    'return_type': MISSING }, *, globals, locals, return_type):
    if locals is None:
        locals = { }
    if 'BUILTINS' not in locals:
        locals['BUILTINS'] = builtins
    return_annotation = ''
    if return_type is not MISSING:
        locals['_return_type'] = return_type
        return_annotation = '->_return_type'
    args = ','.join(args)
    body = '\n'.join((lambda .0: pass# WARNING: Decompyle incomplete
)(body))
    txt = f''' def {name}({args}){return_annotation}:\n{body}'''
    local_vars = ', '.join(locals.keys())
    txt = f'''def __create_fn__({local_vars}):\n{txt}\n return {name}'''
    ns = { }
    exec(txt, globals, ns)
# WARNING: Decompyle incomplete


def _field_assign(frozen, name, value, self_name):
    if frozen:
        return f'''BUILTINS.object.__setattr__({self_name},{name!r},{value})'''
    return f'''{None}.{name}={value}'''


def _field_init(f, frozen, globals, self_name):
    default_name = f'''_dflt_{f.name}'''
    if f.default_factory is not MISSING:
        if f.init:
            globals[default_name] = f.default_factory
            value = f'''{default_name}() if {f.name} is _HAS_DEFAULT_FACTORY else {f.name}'''
        else:
            globals[default_name] = f.default_factory
            value = f'''{default_name}()'''
    elif f.init:
        if f.default is MISSING:
            value = f.name
        elif f.default is not MISSING:
            globals[default_name] = f.default
            value = f.name
        else:
            return None
        if None._field_type is _FIELD_INITVAR:
            return None
        return None(frozen, f.name, value, self_name)


def _init_param(f):
    if f.default is MISSING and f.default_factory is MISSING:
        default = ''
    elif f.default is not MISSING:
        default = f'''=_dflt_{f.name}'''
    elif f.default_factory is not MISSING:
        default = '=_HAS_DEFAULT_FACTORY'
    return f'''{f.name}:_type_{f.name}{default}'''


def _init_fn(fields, std_fields, kw_only_fields, frozen, has_post_init, self_name, globals):
    seen_default = False
    if seen_default:
        raise TypeError(f'''non-default argument {f.name!r} follows default argument''')
    locals = (lambda .0: pass# WARNING: Decompyle incomplete
)(fields)
    locals.update({
        'MISSING': MISSING,
        '_HAS_DEFAULT_FACTORY': _HAS_DEFAULT_FACTORY })
    body_lines = []
    _init_params = (lambda .0: [ _init_param(f) for f in .0 ])(std_fields)
    if kw_only_fields:
        _init_params += [
            '*']
        _init_params += (lambda .0: [ _init_param(f) for f in .0 ])(kw_only_fields)
    return _create_fn('__init__', [
        self_name] + _init_params, body_lines, locals, globals, None, **('locals', 'globals', 'return_type'))


def _repr_fn(fields, globals):
    fn = _create_fn('__repr__', ('self',), [
        'return self.__class__.__qualname__ + f"(' + ', '.join((lambda .0: [ f'''{f.name}={{self.{f.name}!r}}''' for f in .0 ])(fields)) + ')"'], globals, **('globals',))
    return _recursive_repr(fn)


def _frozen_get_del_attr(cls, fields, globals):
    locals = {
        'cls': cls,
        'FrozenInstanceError': FrozenInstanceError }
    if fields:
        fields_str = '(' + ','.join((lambda .0: pass# WARNING: Decompyle incomplete
)(fields)) + ',)'
    else:
        fields_str = '()'
    return (_create_fn('__setattr__', ('self', 'name', 'value'), (f'''if type(self) is cls or name in {fields_str}:''', ' raise FrozenInstanceError(f"cannot assign to field {name!r}")', 'super(cls, self).__setattr__(name, value)'), locals, globals, **('locals', 'globals')), _create_fn('__delattr__', ('self', 'name'), (f'''if type(self) is cls or name in {fields_str}:''', ' raise FrozenInstanceError(f"cannot delete field {name!r}")', 'super(cls, self).__delattr__(name)'), locals, globals, **('locals', 'globals')))


def _cmp_fn(name, op, self_tuple, other_tuple, globals):
    return _create_fn(name, ('self', 'other'), [
        'if other.__class__ is self.__class__:',
        f''' return {self_tuple}{op}{other_tuple}''',
        'return NotImplemented'], globals, **('globals',))


def _hash_fn(fields, globals):
    self_tuple = _tuple_str('self', fields)
    return _create_fn('__hash__', ('self',), [
        f'''return hash({self_tuple})'''], globals, **('globals',))


def _is_classvar(a_type, typing):
    if a_type is typing.ClassVar and type(a_type) is typing._GenericAlias:
        pass
    return a_type.__origin__ is typing.ClassVar


def _is_initvar(a_type, dataclasses):
    if not a_type is dataclasses.InitVar:
        pass
    return type(a_type) is dataclasses.InitVar


def _is_kw_only(a_type, dataclasses):
    return a_type is dataclasses.KW_ONLY


def _is_type(annotation, cls, a_module, a_type, is_type_predicate):
    match = _MODULE_IDENTIFIER_RE.match(annotation)
    if match:
        ns = None
        module_name = match.group(1)
        if not module_name:
            ns = sys.modules.get(cls.__module__).__dict__
        else:
            module = sys.modules.get(cls.__module__)
            if module and module.__dict__.get(module_name) is a_module:
                ns = sys.modules.get(a_type.__module__).__dict__
        if ns and is_type_predicate(ns.get(match.group(2)), a_module):
            return True
        return None


def _get_field(cls, a_name, a_type, default_kw_only):
    default = getattr(cls, a_name, MISSING)
    if isinstance(default, Field):
        f = default
    elif isinstance(default, types.MemberDescriptorType):
        default = MISSING
    f = field(default, **('default',))
    f.name = a_name
    f.type = a_type
    f._field_type = _FIELD
    typing = sys.modules.get('typing')
    if typing:
        if (_is_classvar(a_type, typing) or isinstance(f.type, str)) and _is_type(f.type, cls, typing, typing.ClassVar, _is_classvar):
            f._field_type = _FIELD_CLASSVAR
    if f._field_type is _FIELD:
        dataclasses = sys.modules[__name__]
        if (_is_initvar(a_type, dataclasses) or isinstance(f.type, str)) and _is_type(f.type, cls, dataclasses, dataclasses.InitVar, _is_initvar):
            f._field_type = _FIELD_INITVAR
    if f._field_type in (_FIELD_CLASSVAR, _FIELD_INITVAR) and f.default_factory is not MISSING:
        raise TypeError(f'''field {f.name} cannot have a default factory''')
# WARNING: Decompyle incomplete


def _set_qualname(cls, value):
    if isinstance(value, FunctionType):
        value.__qualname__ = f'''{cls.__qualname__}.{value.__name__}'''
    return value


def _set_new_attribute(cls, name, value):
    if name in cls.__dict__:
        return True
    None(cls, value)
    setattr(cls, name, value)
    return False


def _hash_set_none(cls, fields, globals):
    pass


def _hash_add(cls, fields, globals):
    flds = (lambda .0: for f in .0:
passif f.hash:
continue[][f])(fields)
    return _set_qualname(cls, _hash_fn(flds, globals))


def _hash_exception(cls, fields, globals):
    raise TypeError(f'''Cannot overwrite attribute __hash__ in class {cls.__name__}''')

# WARNING: Decompyle incomplete
