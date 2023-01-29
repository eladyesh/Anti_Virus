
'''Selectors module.

This module allows high-level and efficient I/O multiplexing, built upon the
`select` module primitives.
'''
from abc import ABCMeta, abstractmethod
from collections import namedtuple
from collections.abc import Mapping
import math
import select
import sys
EVENT_READ = 1
EVENT_WRITE = 2

def _fileobj_to_fd(fileobj):
    '''Return a file descriptor from a file object.

    Parameters:
    fileobj -- file object or file descriptor

    Returns:
    corresponding file descriptor

    Raises:
    ValueError if the object is invalid
    '''
    if isinstance(fileobj, int):
        fd = fileobj
# WARNING: Decompyle incomplete

SelectorKey = namedtuple('SelectorKey', [
    'fileobj',
    'fd',
    'events',
    'data'])
SelectorKey.__doc__ = 'SelectorKey(fileobj, fd, events, data)\n\n    Object used to associate a file object to its backing\n    file descriptor, selected event mask, and attached data.\n'
if sys.version_info >= (3, 5):
    SelectorKey.fileobj.__doc__ = 'File object registered.'
    SelectorKey.fd.__doc__ = 'Underlying file descriptor.'
    SelectorKey.events.__doc__ = 'Events that must be waited for on this file object.'
    SelectorKey.data.__doc__ = 'Optional opaque data associated to this file object.\n    For example, this could be used to store a per-client session ID.'

class _SelectorMapping(Mapping):
    '''Mapping of file objects to selector keys.'''
    
    def __init__(self, selector):
        self._selector = selector

    
    def __len__(self):
        return len(self._selector._fd_to_key)

    
    def __getitem__(self, fileobj):
        pass
    # WARNING: Decompyle incomplete

    
    def __iter__(self):
        return iter(self._selector._fd_to_key)


BaseSelector = <NODE:26>((lambda : __doc__ = 'Selector abstract base class.\n\n    A selector supports registering file objects to be monitored for specific\n    I/O events.\n\n    A file object is a file descriptor or any object with a `fileno()` method.\n    An arbitrary object can be attached to the file object, which can be used\n    for example to store context information, a callback, etc.\n\n    A selector can use various implementations (select(), poll(), epoll()...)\n    depending on the platform. The default `Selector` class uses the most\n    efficient implementation on the current platform.\n    '
def register(self, fileobj, events, data = (None,)):
'''Register a file object.

        Parameters:
        fileobj -- file object or file descriptor
        events  -- events to monitor (bitwise mask of EVENT_READ|EVENT_WRITE)
        data    -- attached data

        Returns:
        SelectorKey instance

        Raises:
        ValueError if events is invalid
        KeyError if fileobj is already registered
        OSError if fileobj is closed or otherwise is unacceptable to
                the underlying system call (if a system call is made)

        Note:
        OSError may or may not be raised
        '''
raise NotImplementedErrorregister = abstractmethod(register)
def unregister(self, fileobj):
'''Unregister a file object.

        Parameters:
        fileobj -- file object or file descriptor

        Returns:
        SelectorKey instance

        Raises:
        KeyError if fileobj is not registered

        Note:
        If fileobj is registered but has since been closed this does
        *not* raise OSError (even if the wrapped syscall does)
        '''
raise NotImplementedErrorunregister = abstractmethod(unregister)
def modify(self, fileobj, events, data = (None,)):
'''Change a registered file object monitored events or attached data.

        Parameters:
        fileobj -- file object or file descriptor
        events  -- events to monitor (bitwise mask of EVENT_READ|EVENT_WRITE)
        data    -- attached data

        Returns:
        SelectorKey instance

        Raises:
        Anything that unregister() or register() raises
        '''
self.unregister(fileobj)self.register(fileobj, events, data)
def select(self, timeout = (None,)):
"""Perform the actual selection, until some monitored file objects are
        ready or a timeout expires.

        Parameters:
        timeout -- if timeout > 0, this specifies the maximum wait time, in
                   seconds
                   if timeout <= 0, the select() call won't block, and will
                   report the currently ready file objects
                   if timeout is None, select() will block until a monitored
                   file object becomes ready

        Returns:
        list of (key, events) for ready file objects
        `events` is a bitwise mask of EVENT_READ|EVENT_WRITE
        """
raise NotImplementedErrorselect = abstractmethod(select)
def close(self):
'''Close the selector.

        This must be called to make sure that any underlying resource is freed.
        '''
pass
def get_key(self, fileobj):
'''Return the key associated to a registered file object.

        Returns:
        SelectorKey for this file object
        '''
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise RuntimeError('Selector is closed'):
mapping = self.get_map()if mapping is None:
raise Ru