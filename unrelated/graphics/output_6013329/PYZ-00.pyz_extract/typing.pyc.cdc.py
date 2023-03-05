
__doc__ = '\nThe typing module: Support for gradual typing as defined by PEP 484.\n\nAt large scale, the structure of the module is following:\n* Imports and exports, all public names should be explicitly added to __all__.\n* Internal helper functions: these should never be used in code outside this module.\n* _SpecialForm and its instances (special forms):\n  Any, NoReturn, ClassVar, Union, Optional, Concatenate\n* Classes whose instances can be type arguments in addition to types:\n  ForwardRef, TypeVar and ParamSpec\n* The core of internal generics API: _GenericAlias and _VariadicGenericAlias, the latter is\n  currently only used by Tuple and Callable. All subscripted types like X[int], Union[int, str],\n  etc., are instances of either of these classes.\n* The public counterpart of the generics API consists of two classes: Generic and Protocol.\n* Public helper functions: get_type_hints, overload, cast, no_type_check,\n  no_type_check_decorator.\n* Generic aliases for collections.abc ABCs and few additional protocols.\n* Special types: NewType, NamedTuple, TypedDict.\n* Wrapper submodules for re and io related types.\n'
from abc import abstractmethod, ABCMeta
import collections
import collections.abc as collections
import contextlib
import functools
import operator
import re as stdlib_re
import sys
import types
from types import WrapperDescriptorType, MethodWrapperType, MethodDescriptorType, GenericAlias
__all__ = [
    'Annotated',
    'Any',
    'Callable',
    'ClassVar',
    'Concatenate',
    'Final',
    'ForwardRef',
    'Generic',
    'Literal',
    'Optional',
    'ParamSpec',
    'Protocol',
    'Tuple',
    'Type',
    'TypeVar',
    'Union',
    'AbstractSet',
    'ByteString',
    'Container',
    'ContextManager',
    'Hashable',
    'ItemsView',
    'Iterable',
    'Iterator',
    'KeysView',
    'Mapping',
    'MappingView',
    'MutableMapping',
    'MutableSequence',
    'MutableSet',
    'Sequence',
    'Sized',
    'ValuesView',
    'Awaitable',
    'AsyncIterator',
    'AsyncIterable',
    'Coroutine',
    'Collection',
    'AsyncGenerator',
    'AsyncContextManager',
    'Reversible',
    'SupportsAbs',
    'SupportsBytes',
    'SupportsComplex',
    'SupportsFloat',
    'SupportsIndex',
    'SupportsInt',
    'SupportsRound',
    'ChainMap',
    'Counter',
    'Deque',
    'Dict',
    'DefaultDict',
    'List',
    'OrderedDict',
    'Set',
    'FrozenSet',
    'NamedTuple',
    'TypedDict',
    'Generator',
    'BinaryIO',
    'IO',
    'Match',
    'Pattern',
    'TextIO',
    'AnyStr',
    'cast',
    'final',
    'get_args',
    'get_origin',
    'get_type_hints',
    'is_typeddict',
    'NewType',
    'no_type_check',
    'no_type_check_decorator',
    'NoReturn',
    'overload',
    'ParamSpecArgs',
    'ParamSpecKwargs',
    'runtime_checkable',
    'Text',
    'TYPE_CHECKING',
    'TypeAlias',
    'TypeGuard']

def _type_convert(arg, module = (None,)):
    '''For converting None to type(None), and strings to ForwardRef.'''
    if arg is None:
        return type(None)
    if None(arg, str):
        return ForwardRef(arg, module, **('module',))


def _type_check(arg, msg, is_argument, module = (True, None)):
    '''Check that the argument is a type, and return it (internal helper).

    As a special case, accept None and return type(None) instead. Also wrap strings
    into ForwardRef instances. Consider several corner cases, for example plain
    special forms like Union are not valid, while Union[int, str] is OK, etc.
    The msg argument is a human-readable error message, e.g::

        "Union[arg, ...]: arg should be a type."

    We append the repr() of the actual value (truncated to 100 chars).
    '''
    invalid_generic_forms = (Generic, Protocol)
    if is_argument:
        invalid_generic_forms = invalid_generic_forms + (ClassVar, Final)
    arg = _type_convert(arg, module, **('module',))
    if isinstance(arg, _GenericAlias) and arg.__origin__ in invalid_generic_forms:
        raise TypeError(f'''{arg} is not valid as type argument''')
    if None in (Any, NoReturn):
        return arg
    if None(arg, _SpecialForm) or arg in (Generic, Protocol):
        raise TypeError(f'''Plain {arg} is not valid as type argument''')
    if None(arg, (type, TypeVar, ForwardRef, types.UnionType, ParamSpec)):
        return arg
    if not None(arg):
        raise f'''{msg}'''(f''' Got .100.''')


def _is_param_expr(arg):
    if not arg is ...:
        pass
    return isinstance(arg, (tuple, list, ParamSpec, _ConcatenateGenericAlias))


def _type_repr(obj):
    '''Return the repr() of an object, special-casing types (internal helper).

    If obj is a type, we return a shorter version than the default
    type.__repr__, based on the module and qualified name, which is
    typically enough to uniquely identify a type.  For everything
    else, we fall back on repr(obj).
    '''
    if isinstance(obj, types.GenericAlias):
        return repr(obj)
    if None(obj, type):
        if obj.__module__ == 'builtins':
            return obj.__qualname__
        return f'''{None.__module__}.{obj.__qualname__}'''
    if None is ...:
        return '...'
    if None(obj, types.FunctionType):
        return obj.__name__
    return None(obj)


def _collect_type_vars(types_, typevar_types = (None,)):
    '''Collect all type variable contained
    in types in order of first appearance (lexicographic order). For example::

        _collect_type_vars((T, List[S, T])) == (T, S)
    '''
    if typevar_types is None:
        typevar_types = TypeVar
    tvars = []
    return tuple(tvars)


def _check_generic(cls, parameters, elen):
    '''Check correct count for parameters of a generic cls (internal helper).
    This gives a nice error message in case of count mismatch.
    '''
    if not elen:
        raise TypeError(f'''{cls} is not a generic class''')
    alen = None(parameters)
    if alen != elen:
        raise TypeError(f'''Too {'many' if alen > elen else 'few'} arguments for {cls}; actual {alen}, expected {elen}''')


def _prepare_paramspec_params(cls, params):
    '''Prepares the parameters for a Generic containing ParamSpec
    variables (internal helper).
    '''
    pass
# WARNING: Decompyle incomplete


def _deduplicate(params):
    all_params = set(params)
# WARNING: Decompyle incomplete


def _remove_dups_flatten(parameters):
    '''An internal helper for Union creation and substitution: flatten Unions
    among parameters, then remove duplicates.
    '''
    params = []
    if isinstance(p, tuple) and len(p) > 0 and p[0] is Union:
        params.extend(p[1:])
        continue
    params.append(p)
    continue
    return tuple(_deduplicate(params))


def _flatten_literal_params(parameters):
    '''An internal helper for Literal creation: flatten Literals among parameters'''
    params = []
    params.append(p)
    continue
    return tuple(params)

_cleanups = []

def _tp_cache(func = None, *, typed):
    '''Internal wrapper caching __getitem__ of generic types with a fallback to
    original function for non-hashable arguments.
    '''
    
    def decorator(func = None):
        cached = functools.lru_cache(typed, **('typed',))(func)
        _cleanups.append(cached.cache_clear)
        
        def inner(*args, **kwds):
            pass
        # WARNING: Decompyle incomplete

        inner = None(inner)
        return inner

    if func is not None:
        return decorator(func)


def _eval_type(t, globalns, localns, recursive_guard = (frozenset(),)):
    '''Evaluate all forward references in the given type t.
    For use of globalns and localns see the docstring for get_type_hints().
    recursive_guard is used to prevent prevent infinite recursion
    with recursive ForwardRef.
    '''
    if isinstance(t, ForwardRef):
        return t._evaluate(globalns, localns, recursive_guard)
    if None(t, (_GenericAlias, GenericAlias, types.UnionType)):
        ev_args = None((lambda .0 = None: pass# WARNING: Decompyle incomplete
)(t.__args__))
        if ev_args == t.__args__:
            return t
        if None(t, GenericAlias):
            return GenericAlias(t.__origin__, ev_args)
        if None(t, types.UnionType):
            return functools.reduce(operator.or_, ev_args)
        return None.copy_with(ev_args)


class _Final:
    '''Mixin to prohibit subclassing'''
    __slots__ = ('__weakref__',)
    
    def __init_subclass__(self, *args, **kwds):
        if '_root' not in kwds:
            raise TypeError('Cannot subclass special typing classes')



class _Immutable:
    '''Mixin to indicate that object should not be copied.'''
    __slots__ = ()
    
    def __copy__(self):
        return self

    
    def __deepcopy__(self, memo):
        return self


_SpecialForm = <NODE:26>((lambda : __slots__ = ('_name', '__doc__', '_getitem')
def __init__(self, getitem):
self._getitem = getitemself._name = getitem.__name__self.__doc__ = getitem.__doc__
def __getattr__(self, item):
if item in :
self._nameraise None(item)
def __mro_entries__(self, bases):
raise TypeError(f'''Cannot subclass {self!r}''')
def __repr__(self):
'typing.' + self._name
def __reduce__(self):
self._name
def __call__(self, *args, **kwds):
raise TypeError(f'''Cannot instantiate {self!r}''')
def __or__(self, other):
Union[(self, other)]
def __ror__(self, other):
Union[(other, self)]
def __instancecheck__(self, obj):
raise TypeError(f'''{self} cannot be used with isinstance()''')
def __subclasscheck__(self, cls):
raise TypeError(f'''{self} cannot be used with issubclass()''')
def __getitem__(self, parameters):
self._getitem(self, parameters)__getitem__ = _tp_cache(__getitem__)), '_SpecialForm', _Final, True, **('_root',))
_LiteralSpecialForm = <NODE:26>((lambda : 
def __getitem__(self, parameters):
self._getitem(self, parameters)__getitem__ = _tp_cache(True, **('typed',))(__getitem__)), '_LiteralSpecialForm', _SpecialForm, True, **('_root',))

def Any(self, parameters):
    '''Special type indicating an unconstrained type.

    - Any is compatible with every type.
    - Any assumed to have all methods.
    - All values assumed to be instances of Any.

    Note that all the above statements are true from the point of view of
    static type checkers. At runtime, Any should not be used with instance
    or class checks.
    '''
    raise TypeError(f'''{self} is not subscriptable''')

Any = _SpecialForm(Any)

def NoReturn(self, parameters):
    """Special type indicating functions that never return.
    Example::

      from typing import NoReturn

      def stop() -> NoReturn:
          raise Exception('no way')

    This type is invalid in other positions, e.g., ``List[NoReturn]``
    will fail in static type checkers.
    """
    raise TypeError(f'''{self} is not subscriptable''')

NoReturn = _SpecialForm(NoReturn)

def ClassVar(self, parameters):
    '''Special type construct to mark class variables.

    An annotation wrapped in ClassVar indicates that a given
    attribute is intended to be used as a class variable and
    should not be set on instances of that class. Usage::

      class Starship:
          stats: ClassVar[Dict[str, int]] = {} # class variable
          damage: int = 10                     # instance variable

    ClassVar accepts only types and cannot be further subscribed.

    Note that ClassVar is not a class itself, and should not
    be used with isinstance() or issubclass().
    '''
    item = _type_check(parameters, f'''{self} accepts only single type.''')
    return _GenericAlias(self, (item,))

ClassVar = _SpecialForm(ClassVar)

def Final(self, parameters):
    '''Special typing construct to indicate final names to type checkers.

    A final name cannot be re-assigned or overridden in a subclass.
    For example:

      MAX_SIZE: Final = 9000
      MAX_SIZE += 1  # Error reported by type checker

      class Connection:
          TIMEOUT: Final[int] = 10

      class FastConnector(Connection):
          TIMEOUT = 1  # Error reported by type checker

    There is no runtime checking of these properties.
    '''
    item = _type_check(parameters, f'''{self} accepts only single type.''')
    return _GenericAlias(self, (item,))

Final = _SpecialForm(Final)

def Union(self, parameters):
    '''Union type; Union[X, Y] means either X or Y.

    To define a union, use e.g. Union[int, str].  Details:
    - The arguments must be types and there must be at least one.
    - None as an argument is a special case and is replaced by
      type(None).
    - Unions of unions are flattened, e.g.::

        Union[Union[int, str], float] == Union[int, str, float]

    - Unions of a single argument vanish, e.g.::

        Union[int] == int  # The constructor actually returns int

    - Redundant arguments are skipped, e.g.::

        Union[int, str, int] == Union[int, str]

    - When comparing unions, the argument order is ignored, e.g.::

        Union[int, str] == Union[str, int]

    - You cannot subclass or instantiate a union.
    - You can use Optional[X] as a shorthand for Union[X, None].
    '''
    if parameters == ():
        raise TypeError('Cannot take a Union of no types.')
    if not None(parameters, tuple):
        parameters = (parameters,)
    msg = 'Union[arg, ...]: each arg must be a type.'
    parameters = None((lambda .0 = None: pass# WARNING: Decompyle incomplete
)(parameters))
    parameters = _remove_dups_flatten(parameters)
    if len(parameters) == 1:
        return parameters[0]
    if None(parameters) == 2 and type(None) in parameters:
        return _UnionGenericAlias(self, parameters, 'Optional', **('name',))
    return None(self, parameters)

Union = _SpecialForm(Union)

def Optional(self, parameters):
    '''Optional type.

    Optional[X] is equivalent to Union[X, None].
    '''
    arg = _type_check(parameters, f'''{self} requires a single type.''')
    return Union[(arg, type(None))]

Optional = _SpecialForm(Optional)

def Literal(self, parameters):
    """Special typing form to define literal types (a.k.a. value types).

    This form can be used to indicate to type checkers that the corresponding
    variable or function parameter has a value equivalent to the provided
    literal (or one of several literals):

      def validate_simple(data: Any) -> Literal[True]:  # always returns True
          ...

      MODE = Literal['r', 'rb', 'w', 'wb']
      def open_helper(file: str, mode: MODE) -> str:
          ...

      open_helper('/some/path', 'r')  # Passes type check
      open_helper('/other/path', 'typo')  # Error in type checker

    Literal[...] cannot be subclassed. At runtime, an arbitrary value
    is allowed as type argument to Literal[...], but type checkers may
    impose restrictions.
    """
    if not isinstance(parameters, tuple):
        parameters = (parameters,)
    parameters = _flatten_literal_params(parameters)
# WARNING: Decompyle incomplete

Literal = _LiteralSpecialForm(Literal)

def TypeAlias(self, parameters):
    """Special marker indicating that an assignment should
    be recognized as a proper type alias definition by type
    checkers.

    For example::

        Predicate: TypeAlias = Callable[..., bool]

    It's invalid when used anywhere except as in the example above.
    """
    raise TypeError(f'''{self} is not subscriptable''')

TypeAlias = _SpecialForm(TypeAlias)

def Concatenate(self, parameters):
    '''Used in conjunction with ``ParamSpec`` and ``Callable`` to represent a
    higher order function which adds, removes or transforms parameters of a
    callable.

    For example::

       Callable[Concatenate[int, P], int]

    See PEP 612 for detailed information.
    '''
    if parameters == ():
        raise TypeError('Cannot take a Concatenate of no types.')
    if not None(parameters, tuple):
        parameters = (parameters,)
    if not isinstance(parameters[-1], ParamSpec):
        raise TypeError('The last parameter to Concatenate should be a ParamSpec variable.')
    msg = None
    parameters = None((lambda .0 = None: pass# WARNING: Decompyle incomplete
)(parameters))
    return _ConcatenateGenericAlias(self, parameters)

Concatenate = _SpecialForm(Concatenate)

def TypeGuard(self, parameters):
    '''Special typing form used to annotate the return type of a user-defined
    type guard function.  ``TypeGua