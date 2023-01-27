
'''Utilities for with-statement contexts.  See PEP 343.'''
import abc
import sys
import _collections_abc
from collections import deque
from functools import wraps
from types import MethodType, GenericAlias
__all__ = [
    'asynccontextmanager',
    'contextmanager',
    'closing',
    'nullcontext',
    'AbstractContextManager',
    'AbstractAsyncContextManager',
    'AsyncExitStack',
    'ContextDecorator',
    'ExitStack',
    'redirect_stdout',
    'redirect_stderr',
    'suppress']

def AbstractContextManager():
    '''AbstractContextManager'''
    __doc__ = 'An abstract base class for context managers.'
    __class_getitem__ = classmethod(GenericAlias)
    
    def __enter__(self):
        '''Return `self` upon entering the runtime context.'''
        return self

    
    def __exit__(self, exc_type, exc_value, traceback):
        '''Raise any exception triggered within the runtime context.'''
        pass

    __exit__ = abc.abstractmethod(__exit__)
    
    def __subclasshook__(cls, C):
        if cls is AbstractContextManager:
            return _collections_abc._check_methods(C, '__enter__', '__exit__')

    __subclasshook__ = classmethod(__subclasshook__)

AbstractContextManager = <NODE:26>(AbstractContextManager, 'AbstractContextManager', abc.ABC)

def AbstractAsyncContextManager():
    '''AbstractAsyncContextManager'''
    __doc__ = 'An abstract base class for asynchronous context managers.'
    __class_getitem__ = classmethod(GenericAlias)
    
    async def __aenter__(self):
        '''Return `self` upon entering the runtime context.'''
        return self

    
    async def __aexit__(self, exc_type, exc_value, traceback):
        '''Raise any exception triggered within the runtime context.'''
        pass

    __aexit__ = abc.abstractmethod(__aexit__)
    
    def __subclasshook__(cls, C):
        if cls is AbstractAsyncContextManager:
            return _collections_abc._check_methods(C, '__aenter__', '__aexit__')

    __subclasshook__ = classmethod(__subclasshook__)

AbstractAsyncContextManager = <NODE:26>(AbstractAsyncContextManager, 'AbstractAsyncContextManager', abc.ABC)

class ContextDecorator(object):
    '''A base class or mixin that enables context managers to work as decorators.'''
    
    def _recreate_cm(self):
        '''Return a recreated instance of self.

        Allows an otherwise one-shot context manager like
        _GeneratorContextManager to support use as
        a decorator via implicit recreation.

        This is a private interface just for _GeneratorContextManager.
        See issue #11647 for details.
        '''
        return self

    
    def __call__(self, func):
        
        def inner(*args, **kwds):
            pass
        # WARNING: Decompyle incomplete

        inner = None(inner)
        return inner



class _GeneratorContextManagerBase:
    '''Shared functionality for @contextmanager and @asynccontextmanager.'''
    
    def __init__(self, func, args, kwds):
        pass
    # WARNING: Decompyle incomplete



class _GeneratorContextManager(ContextDecorator, AbstractContextManager, _GeneratorContextManagerBase):
    '''Helper for @contextmanager decorator.'''
    
    def _recreate_cm(self):
        return self.__class__(self.func, self.args, self.kwds)

    
    def __enter__(self):
        del self.args
        del self.kwds
        del self.func
    # WARNING: Decompyle incomplete

    
    def __exit__(self, type, value, traceback):
        pass
    # WARNING: Decompyle incomplete



class _AsyncGeneratorContextManager(AbstractAsyncContextManager, _GeneratorContextManagerBase):
    '''Helper for @asynccontextmanager.'''
    
    async def __aenter__(self):
        pass
    # WARNING: Decompyle incomplete

    
    async def __aexit__(self, typ, value, traceback):
        pass
    # WARNING: Decompyle incomplete



def contextmanager(func):
    '''@contextmanager decorator.

    Typical usage:

        @contextmanager
        def some_generator(<arguments>):
            <setup>
            try:
                yield <value>
            finally:
                <cleanup>

    This makes this:

        with some_generator(<arguments>) as <variable>:
            <body>

    equivalent to this:

        <setup>
        try:
            <variable> = <value>
            <body>
        finally:
            <cleanup>
    '''
    
    def helper(*args, **kwds):
        return _GeneratorContextManager(func, args, kwds)

    helper = None(helper)
    return helper


def asynccontextmanager(func):
    '''@asynccontextmanager decorator.

    Typical usage:

        @asynccontextmanager
        async def some_async_generator(<arguments>):
            <setup>
            try:
                yield <value>
            finally:
                <cleanup>

    This makes this:

        async with some_async_generator(<arguments>) as <variable>:
            <body>

    equivalent to this:

        <setup>
        try:
            <variable> = <value>
            <body>
        finally:
            <cleanup>
    '''
    
    def helper(*args, **kwds):
        return _AsyncGeneratorContextManager(func, args, kwds)

    helper = None(helper)
    return helper


class closing(AbstractContextManager):
    '''Context to automatically close something at the end of a block.

    Code like this:

        with closing(<module>.open(<arguments>)) as f:
            <block>

    is equivalent to this:

        f = <module>.open(<arguments>)
        try:
            <block>
        finally:
            f.close()

    '''
    
    def __init__(self, thing):
        self.thing = thing

    
    def __enter__(self):
        return self.thing

    
    def __exit__(self, *exc_info):
        self.thing.close()



class _RedirectStream(AbstractContextManager):
    _stream = None
    
    def __init__(self, new_target):
        self._new_target = new_target
        self._old_targets = []

    
    def __enter__(self):
        self._old_targets.append(getattr(sys, self._stream))
        setattr(sys, self._stream, self._new_target)
        return self._new_target

    
    def __exit__(self, exctype, excinst, exctb):
        setattr(sys, self._stream, self._old_targets.pop())



class redirect_stdout(_RedirectStream):
    """Context manager for temporarily redirecting stdout to another file.

        # How to send help() to stderr
        with redirect_stdout(sys.stderr):
            help(dir)

        # How to write help() to a file
        with open('help.txt', 'w') as f:
            with redirect_stdout(f):
                help(pow)
    """
    _stream = 'stdout'


class redirect_stderr(_RedirectStream):
    '''Context manager for temporarily redirecting stderr to another file.'''
    _stream = 'stderr'


class suppress(AbstractContextManager):
    '''Context manager to suppress specified exceptions

    After the exception is suppressed, execution proceeds with the next
    statement following the with statement.

         with suppress(FileNotFoundError):
             os.remove(somefile)
         # Execution still resumes here if the file was already removed
    '''
    
    def __init__(self, *exceptions):
        self._exceptions = exceptions

    
    def __enter__(self):
        pass

    
    def __exit__(self, exctype, excinst, exctb):
        if exctype is not None:
            return issubclass(exctype, self._exceptions)



class _BaseExitStack:
    '''A base class for ExitStack and AsyncExitStack.'''
    
    def _create_exit_wrapper(cm, cm_exit):
        return MethodType(cm_exit, cm)

    _create_exit_wrapper = staticmethod(_create_exit_wrapper)
    
    def _create_cb_wrapper(callback, *args, **kwds):
        
        def _exit_wrapper(exc_type = None, exc = None, tb = None):
            pass
        # WARNING: Decompyle incomplete

        return _exit_wrapper

    _create_cb_wrapper = staticmethod(_create_cb_wrapper)
    
    def __init__(self):
        self._exit_callbacks = deque()

    
    def pop_all(self):
        '''Preserve the context stack by transferring it to a new instance.'''
        new_stack = type(self)()
        new_stack._exit_callbacks = self._exit_callbacks
        self._exit_callbacks = deque()
        return new_stack

    
    def push(self, exit):
        '''Registers a callback with the standard __exit__ method signature.

        Can suppress exceptions the same way __exit__ method can.
        Also accepts any object with an __exit__ method (registering a call
        to the method instead of the object itself).
        '''
        _cb_type = type(exit)
    # WARNING: Decompyle incomplete

    
    def enter_context(self, cm):
        '''Enters the supplied context manager.

        If successful, also pushes its __exit__ method as a callback and
        returns the result of the __enter__ method.
        '''
        _cm_type = type(cm)
        _exit = _cm_type.__exit__
        result = _cm_type.__enter__(cm)
        self._push_cm_exit(cm, _exit)
        return result

    
    def callback(self, callback, *args, **kwds):
        '''Registers an arbitrary callback and arguments.

        Cannot suppress exceptions.
        '''
        pass
    # WARNING: Decompyle incomplete

    
    def _push_cm_exit(self, cm, cm_exit):
        '''Helper to correctly register callbacks to __exit__ methods.'''
        _exit_wrapper = self._create_exit_wrapper(cm, cm_exit)
        self._push_exit_callback(_exit_wrapper, True)

    
    def _push_exit_callback(self, callback, is_sync = (True,)):
        self._exit_callbacks.append((is_sync, callback))



class ExitStack(AbstractContextManager, _BaseExitStack):
    '''Context manager for dynamic management of a stack of exit callbacks.

    For example:
        with ExitStack() as stack:
            files = [stack.enter_context(open(fname)) for fname in filenames]
            # All opened files will automatically be closed at the end of
            # the with statement, even if attempts to open files later
            # in the list raise an exception.
    '''
    
    def __enter__(self):
        return self

    
    def __exit__(self, *exc_details):
        received_exc = exc_details[0] is not None
        frame_exc = sys.exc_info()[1]
        
        def _fix_exception_context(new_exc = None, old_exc = None):
            exc_context = new_exc.__context__
            if exc_context is old_exc:
                return None
            if not None is None:
                if exc_context is frame_exc:
                    pass
                else:
                    new_exc = exc_context
                new_exc.__context__ = old_exc
                return None

        suppressed_exc = False
        pending_raise = False
    # WARNING: Decompyle incomplete

    
    def close(self):
        '''Immediately unwind the context stack.'''
        self.__exit__(None, None, None)



class AsyncExitStack(AbstractAsyncContextManager, _BaseExitStack):
    '''Async context manager for dynamic management of a stack of exit
    callbacks.

    For example:
        async with AsyncExitStack() as stack:
            connections = [await stack.enter_async_context(get_connection())
                for i in range(5)]
            # All opened connections will automatically be released at the
            # end of the async with statement, even if attempts to open a
            # connection later in the list raise an exception.
    '''
    
    def _create_async_exit_wrapper(cm, cm_exit):
        return MethodType(cm_exit, cm)

    _create_async_exit_wrapper = staticmethod(_create_async_exit_wrapper)
    
    def _create_async_cb_wrapper(callback, *args, **kwds):
        
        async def _exit_wrapper(exc_type = None, exc = None, tb = None):
            pass
        # WARNING: Decompyle incomplete

        return _exit_wrapper

    _create_async_cb_wrapper = staticmethod(_create_async_cb_wrapper)
    
    async def enter_async_context(self, cm):
        '''Enters the supplied async context manager.

        If successful, also pushes its __aexit__ method as a callback and
        returns the result of the __aenter__ method.
        '''
        _cm_type = type(cm)
        _exit = _cm_type.__aexit__
        await _cm_type.__aenter__(cm)
        result = <NODE:27>
        self._push_async_cm_exit(cm, _exit)
        return result

    
    def push_async_exit(self, exit):
        '''Registers a coroutine function with the standard __aexit__ method
        signature.

        Can suppress exceptions the same way __aexit__ method can.
        Also accepts any object with an __aexit__ method (registering a call
        to the method instead of the object itself).
        '''
        _cb_type = type(exit)
    # WARNING: Decompyle incomplete

    
    def push_async_callback(self, callback, *args, **kwds):
        '''Registers an arbitrary coroutine function and arguments.

        Cannot suppress exceptions.
        '''
        pass
    # WARNING: Decompyle incomplete

    
    async def aclose(self):
        '''Immediately unwind the context stack.'''
        await self.__aexit__(None, None, None)

    
    def _push_async_cm_exit(self, cm, cm_exit):
        '''Helper to correctly register coroutine function to __aexit__
        method.'''
        _exit_wrapper = self._create_async_exit_wrapper(cm, cm_exit)
        self._push_exit_callback(_exit_wrapper, False)

    
    async def __aenter__(self):
        return self

    
    async def __aexit__(self, *exc_details):
        received_exc = exc_details[0] is not None
        frame_exc = sys.exc_info()[1]
        
        def _fix_exception_context(new_exc = None, old_exc = None):
            exc_context = new_exc.__context__
            if exc_context is old_exc:
                return None
            if not None is None:
                if exc_context is frame_exc:
                    pass
                else:
                    new_exc = exc_context
                new_exc.__context__ = old_exc
                return None

        suppressed_exc = False
        pending_raise = False
    # WARNING: Decompyle incomplete



class nullcontext(AbstractContextManager):
    '''Context manager that does no additional processing.

    Used as a stand-in for a normal context manager, when a particular
    block of code is only sometimes used with a normal context manager:

    cm = optional_cm if condition else nullcontext()
    with cm:
        # Perform operation, using optional_cm if condition is True
    '''
    
    def __init__(self, enter_result = (None,)):
        self.enter_result = enter_result

    
    def __enter__(self):
        return self.enter_result

    
    def __exit__(self, *excinfo):
        pass


