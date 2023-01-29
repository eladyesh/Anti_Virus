
"""Get useful information from live Python objects.

This module encapsulates the interface provided by the internal special
attributes (co_*, im_*, tb_*, etc.) in a friendlier fashion.
It also provides some help for examining source code and class layout.

Here are some of the useful functions provided by this module:

    ismodule(), isclass(), ismethod(), isfunction(), isgeneratorfunction(),
        isgenerator(), istraceback(), isframe(), iscode(), isbuiltin(),
        isroutine() - check object types
    getmembers() - get members of an object that satisfy a given condition

    getfile(), getsourcefile(), getsource() - find an object's source code
    getdoc(), getcomments() - get documentation on an object
    getmodule() - determine the module that an object came from
    getclasstree() - arrange classes so as to represent their hierarchy

    getargvalues(), getcallargs() - get info about function arguments
    getfullargspec() - same, with support for Python 3 features
    formatargvalues() - format an argument spec
    getouterframes(), getinnerframes() - get info about frames
    currentframe() - get the current stack frame
    stack(), trace() - get info about frames on the stack or in a traceback

    signature() - get a Signature object for the callable

    get_annotations() - safely compute an object's annotations
"""
__author__ = ('Ka-Ping Yee <ping@lfw.org>', 'Yury Selivanov <yselivanov@sprymix.com>')
import abc
import ast
import dis
import collections.abc as collections
import enum
import importlib.machinery as importlib
import itertools
import linecache
import os
import re
import sys
import tokenize
import token
import types
import warnings
import functools
import builtins
from operator import attrgetter
from collections import namedtuple, OrderedDict
mod_dict = globals()
TPFLAGS_IS_ABSTRACT = 1048576

def get_annotations(obj = None, *, globals, locals, eval_str):
    '''Compute the annotations dict for an object.

    obj may be a callable, class, or module.
    Passing in an object of any other type raises TypeError.

    Returns a dict.  get_annotations() returns a new dict every time
    it\'s called; calling it twice on the same object will return two
    different but equivalent dicts.

    This function handles several details for you:

      * If eval_str is true, values of type str will
        be un-stringized using eval().  This is intended
        for use with stringized annotations
        ("from __future__ import annotations").
      * If obj doesn\'t have an annotations dict, returns an
        empty dict.  (Functions and methods always have an
        annotations dict; classes, modules, and other types of
        callables may not.)
      * Ignores inherited annotations on classes.  If a class
        doesn\'t have its own annotations dict, returns an empty dict.
      * All accesses to object members and dict values are done
        using getattr() and dict.get() for safety.
      * Always, always, always returns a freshly-created dict.

    eval_str controls whether or not values of type str are replaced
    with the result of calling eval() on those values:

      * If eval_str is true, eval() is called on values of type str.
      * If eval_str is false (the default), values of type str are unchanged.

    globals and locals are passed in to eval(); see the documentation
    for eval() for more information.  If either globals or locals is
    None, this function may replace that value with a context-specific
    default, contingent on type(obj):

      * If obj is a module, globals defaults to obj.__dict__.
      * If obj is a class, globals defaults to
        sys.modules[obj.__module__].__dict__ and locals
        defaults to the obj class namespace.
      * If obj is a callable, globals defaults to obj.__globals__,
        although if obj is a wrapped function (using
        functools.update_wrapper()) it is first unwrapped.
    '''
    if isinstance(obj, type):
        obj_dict = getattr(obj, '__dict__', None)
        if obj_dict and hasattr(obj_dict, 'get'):
            ann = obj_dict.get('__annotations__', None)
            if isinstance(ann, types.GetSetDescriptorType):
                ann = None
            else:
                ann = None
        obj_globals = None
        module_name = getattr(obj, '__module__', None)
        if module_name:
            module = sys.modules.get(module_name, None)
            if module:
                obj_globals = getattr(module, '__dict__', None)
        obj_locals = dict(vars(obj))
        unwrap = obj
    elif isinstance(obj, types.ModuleType):
        ann = getattr(obj, '__annotations__', None)
        obj_globals = getattr(obj, '__dict__')
        obj_locals = None
        unwrap = None
    elif callable(obj):
        ann = getattr(obj, '__annotations__', None)
        obj_globals = getattr(obj, '__globals__', None)
        obj_locals = None
        unwrap = obj
    else:
        raise TypeError(f'''{obj!r} is not a module, class, or callable.''')
    if None is None:
        return { }
    if not None(ann, dict):
        raise ValueError(f'''{obj!r}.__annotations__ is neither a dict nor None''')
    if not None:
        return { }
    if not None:
        return dict(ann)
    if None is not None:
        if hasattr(unwrap, '__wrapped__'):
            unwrap = unwrap.__wrapped__
            continue
        if isinstance(unwrap, functools.partial):
            unwrap = unwrap.func
            continue
        if hasattr(unwrap, '__globals__'):
            obj_globals = unwrap.__globals__
    if globals is None:
        globals = obj_globals
    if locals is None:
        locals = obj_locals
    return_value = (lambda .0 = None: for key, value in .0:
pass# WARNING: Decompyle incomplete
)(ann.items())
    return return_value


def ismodule(object):
    '''Return true if the object is a module.

    Module objects provide these attributes:
        __cached__      pathname to byte compiled file
        __doc__         documentation string
        __file__        filename (missing for built-in modules)'''
    return isinstance(object, types.ModuleType)


def isclass(object):
    '''Return true if the object is a class.

    Class objects provide these attributes:
        __doc__         documentation string
        __module__      name of module in which this class was defined'''
    return isinstance(object, type)


def ismethod(object):
    '''Return true if the object is an instance method.

    Instance method objects provide these attributes:
        __doc__         documentation string
        __name__        name with which this method was defined
        __func__        function object containing implementation of method
        __self__        instance to which this method is bound'''
    return isinstance(object, types.MethodType)


def ismethoddescriptor(object):
    '''Return true if the object is a method descriptor.

    But not if ismethod() or isclass() or isfunction() are true.

    This is new in Python 2.2, and, for example, is true of int.__add__.
    An object passing this test has a __get__ attribute but not a __set__
    attribute, but beyond that the set of attributes varies.  __name__ is
    usually sensible, and __doc__ often is.

    Methods implemented via descriptors that also pass one of the other
    tests return false from the ismethoddescriptor() test, simply because
    the other tests promise more -- you can, e.g., count on having the
    __func__ attribute (etc) when an object passes ismethod().'''
    if isclass(object) and ismethod(object) or isfunction(object):
        return False
    tp = None(object)
    if hasattr(tp, '__get__'):
        pass
    return not hasattr(tp, '__set__')


def isdatadescriptor(object):
    '''Return true if the object is a data descriptor.

    Data descriptors have a __set__ or a __delete__ attribute.  Examples are
    properties (defined in Python) and getsets and members (defined in C).
    Typically, data descriptors will also have __name__ and __doc__ attributes
    (properties, getsets, and members have both of these attributes), but this
    is not guaranteed.'''
    if isclass(object) and ismethod(object) or isfunction(object):
        return False
    tp = None(object)
    if not hasattr(tp, '__set__'):
        pass
    return hasattr(tp, '__delete__')

if hasattr(types, 'MemberDescriptorType'):
    
    def ismemberdescriptor(object):
        '''Return true if the object is a member descriptor.

        Member descriptors are specialized descriptors defined in extension
        modules.'''
        return isinstance(object, types.MemberDescriptorType)

else:
    
    def ismemberdescriptor(object):
        '''Return true if the object is a member descriptor.

        Member descriptors are specialized descriptors defined in extension
        modules.'''
        return False

if hasattr(types, 'GetSetDescriptorType'):
    
    def isgetsetdescriptor(object):
        '''Return true if the object is a getset descriptor.

        getset descriptors are specialized descriptors defined in extension
        modules.'''
        return isinstance(object, types.GetSetDescriptorType)

else:
    
    def isgetsetdescriptor(object):
        '''Return true if the object is a getset descriptor.

        getset descriptors are specialized descriptors defined in extension
        modules.'''
        return False


def isfunction(object):
    '''Return true if the object is a user-defined function.

    Function objects provide these attributes:
        __doc__         documentation string
        __name__        name with which this function was defined
        __code__        code object containing compiled function bytecode
        __defaults__    tuple of any default values for arguments
        __globals__     global namespace in which this function was defined
        __annotations__ dict of parameter annotations
        __kwdefaults__  dict of keyword only parameters with defaults'''
    return isinstance(object, types.FunctionType)


def _has_code_flag(f, flag):
    '''Return true if ``f`` is a function (or a method or functools.partial
    wrapper wrapping a function) whose code object has the given ``flag``
    set in its flags.'''
    if ismethod(f):
        f = f.__func__
        if not ismethod(f):
            f = functools._unwrap_partial(f)
            if not isfunction(f):
                return False
            return None(f.__code__.co_flags & flag)


def isgeneratorfunction(obj):
    '''Return true if the object is a user-defined generator function.

    Generator function objects provide the same attributes as functions.
    See help(isfunction) for a list of attributes.'''
    return _has_code_flag(obj, CO_GENERATOR)


def iscoroutinefunction(obj):
    '''Return true if the object is a coroutine function.

    Coroutine functions are defined with "async def" syntax.
    '''
    return _has_code_flag(obj, CO_COROUTINE)


def isasyncgenfunction(obj):
    '''Return true if the object is an asynchronous generator function.

    Asynchronous generator functions are defined with "async def"
    syntax and have "yield" expressions in their body.
    '''
    return _has_code_flag(obj, CO_ASYNC_GENERATOR)


def isasyncgen(object):
    '''Return true if the object is an asynchronous generator.'''
    return isinstance(object, types.AsyncGeneratorType)


def isgenerator(object):
    '''Return true if the object is a generator.

    Generator objects provide these attributes:
        __iter__        defined to support iteration over container
        close           raises a new GeneratorExit exception inside the
                        generator to terminate the iteration
        gi_code         code object
        gi_frame        frame object or possibly None once the generator has
                        been exhausted
        gi_running      set to 1 when generator is executing, 0 otherwise
        next            return the next item from the container
        send            resumes the generator and "sends" a value that becomes
                        the result of the current yield-expression
        throw           used to raise an exception inside the generator'''
    return isinstance(object, types.GeneratorType)


def iscoroutine(object):
    '''Return true if the object is a coroutine.'''
    return isinstance(object, types.CoroutineType)


def isawaitable(object):
    '''Return true if object can be passed to an ``await`` expression.'''
    if not isinstance(object, types.CoroutineType):
        if not isinstance(object, types.GeneratorType) and bool(object.gi_code.co_flags & CO_ITERABLE_COROUTINE):
            pass
    return isinstance(object, collections.abc.Awaitable)


def istraceback(object):
    '''Return true if the object is a traceback.

    Traceback objects provide these attributes:
        tb_frame        frame object at this level
        tb_lasti        index of last attempted instruction in bytecode
        tb_lineno       current line number in Python source code
        tb_next         next inner traceback object (called by this level)'''
    return isinstance(object, types.TracebackType)


def isframe(object):
    """Return true if the object is a frame object.

    Frame objects provide these attributes:
        f_back          next outer frame object (this frame's caller)
        f_builtins      built-in namespace seen by this frame
        f_code          code object being executed in this frame
        f_globals       global namespace seen by this frame
        f_lasti         index of last attempted instruction in bytecode
        f_lineno        current line number in Python source code
        f_locals        local namespace seen by this frame
        f_trace         tracing function for this frame, or None"""
    return isinstance(object, types.FrameType)


def iscode(object):
    '''Return true if the object is a code object.

    Code objects provide these attributes:
        co_argcount         number of arguments (not including *, ** args
                            or keyword only arguments)
        co_code             string of raw compiled bytecode
        co_cellvars         tuple of names of cell variables
        co_consts           tuple of constants used in the bytecode
        co_filename         name of file in which this code object was created
        co_firstlineno      number of first line in Python source code
        co_flags            bitmap: 1=optimized | 2=newlocals | 4=*arg | 8=**arg
                            | 16=nested | 32=generator | 64=nofree | 128=coroutine
                            | 256=iterable_coroutine | 512=async_generator
        co_freevars         tuple of names of free variables
        co_posonlyargcount  number of positional only arguments
        co_kwonlyargcount   number of keyword only arguments (not including ** arg)
        co_lnotab           encoded mapping of line numbers to bytecode indices
        co_name             name with which this code object was defined
        co_names            tuple of names other than arguments and function locals
        co_nlocals          number of local variables
        co_stacksize        virtual machine stack space required
        co_varnames         tuple of names of arguments and local variables'''
    return isinstance(object, types.CodeType)


def isbuiltin(object):
    '''Return true if the object is a built-in function or method.

    Built-in functions and methods provide these attributes:
        __doc__         documentation string
        __name__        original name of this function or method
        __self__        instance to which a method is bound, or None'''
    return isinstance(object, types.BuiltinFunctionType)


def isroutine(object):
    '''Return true if the object is any kind of function or method.'''
    if not isbuiltin(object) and isfunction(object) and ismethod(object):
        pass
    return ismethoddescriptor(object)


def isabstract(object):
    '''Return true if the object is an abstract base class (ABC).'''
    if not isinstance(object, type):
        return False
    if None.__flags__ & TPFLAGS_IS_ABSTRACT:
        return True
    if not None(type(object), abc.ABCMeta):
        return False
    if None(object, '__abstractmethods__'):
        return False
    return False


def getmembers(object, predicate = (None,)):
    '''Return all members of an object as (name, value) pairs sorted by name.
    Optionally, only return members that satisfy a given predicate.'''
    if isclass(object):
        mro = (object,) + getmro(object)
    else:
        mro = ()
    results = []
    processed = set()
    names = dir(object)
# WARNING: Decompyle incomplete

Attribute = namedtuple('Attribute', 'name kind defining_class object')

def classify_class_attrs(cls):
    """Return list of attribute-descriptor tuples.

    For each name in dir(cls), the return list contains a 4-tuple
    with these elements:

        0. The name (a string).

        1. The kind of attribute this is, one of these strings:
               'class method'    created via classmethod()
               'static method'   created via staticmethod()
               'property'        created via property()
               'method'          any other flavor of method or descriptor
               'data'            not a method

        2. The class which defined this attribute (a class).

        3. The object as obtained by calling getattr; if this fails, or if the
           resulting object does not live anywhere in the class' mro (including
           metaclasses) then the object is looked up in the defining class's
           dict (found by walking the mro).

    If one of the items in dir(cls) is stored in the metaclass it will now
    be discovered and not have None be listed as the class in which it was
    defined.  Any items whose home class cannot be discovered are skipped.
    """
    mro = getmro(cls)
    metamro = getmro(type(cls))
    metamro = tuple((lambda .0: pass# WARNING: Decompyle incomplete
)(metamro))
    class_bases = (cls,) + mro
    all_bases = class_bases + metamro
    names = dir(cls)
    result = []
    processed = set()
# WARNING: Decompyle incomplete


def getmro(cls):
    '''Return tuple of base classes (including cls) in method resolution order.'''
    return cls.__mro__


def unwrap(func = None, *, stop):
    '''Get the object wrapped by *func*.

   Follows the chain of :attr:`__wrapped__` attributes returning the last
   object in the chain.

   *stop* is an optional callback accepting an object in the wrapper chain
   as its sole argument that allows the unwrapping to be terminated early if
   the callback returns a true value. If the callback never returns a true
   value, the last object in the chain is returned as usual. For example,
   :func:`signature` uses this to stop unwrapping if any object in the
   chain has a ``__signature__`` attribute defined.

   :exc:`ValueError` is raised if a cycle is encountered.

    '''
    if stop is None:
        
        def _is_wrapper(f):
            return hasattr(f, '__wrapped__')

    else:
        
        def _is_wrapper(f = None):
            if hasattr(f, '__wrapped__'):
                pass
            return not stop(f)

    f = func
    memo = {
        id(f): f }
    recursion_limit = sys.getrecursionlimit()
    if _is_wrapper(func):
        func = func.__wrapped__
        id_func = id(func)
        if id_func in memo or len(memo) >= recursion_limit:
            raise ValueError('wrapper loop when unwrapping {!r}'.format(f))
        memo[id_func] = None
        if not _is_wrapper(func):
            return func


def indentsize(line):
    '''Return the indent size, in spaces, at the start of a line of text.'''
    expline = line.expandtabs()
    return len(expline) - len(expline.lstrip())


def _findclass(func):
    cls = sys.modules.get(func.__module__)
    if cls is None:
        return None
    if not isclass(cls):
        return None


def _finddoc(obj):
    pass
# WARNING: Decompyle incomplete


def getdoc(object):
    '''Get the documentation string for an object.

    All tabs are expanded to spaces.  To clean up docstrings that are
    indented to line up with blocks of code, any whitespace than can be
    uniformly removed from the seco