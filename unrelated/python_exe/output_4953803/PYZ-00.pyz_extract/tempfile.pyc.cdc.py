
"""Temporary files.

This module provides generic, low- and high-level interfaces for
creating temporary files and directories.  All of the interfaces
provided by this module can be used without fear of race conditions
except for 'mktemp'.  'mktemp' is subject to race conditions and
should not be used; it is provided for backward compatibility only.

The default path names are returned as str.  If you supply bytes as
input, all return values will be in bytes.  Ex:

    >>> tempfile.mkstemp()
    (4, '/tmp/tmptpu9nin8')
    >>> tempfile.mkdtemp(suffix=b'')
    b'/tmp/tmppbi8f0hy'

This module also provides some data items to the user:

  TMP_MAX  - maximum number of names that will be tried before
             giving up.
  tempdir  - If this is set to a string before the first use of
             any routine from this module, it will be considered as
             another candidate location to store temporary files.
"""
__all__ = [
    'NamedTemporaryFile',
    'TemporaryFile',
    'SpooledTemporaryFile',
    'TemporaryDirectory',
    'mkstemp',
    'mkdtemp',
    'mktemp',
    'TMP_MAX',
    'gettempprefix',
    'tempdir',
    'gettempdir',
    'gettempprefixb',
    'gettempdirb']
import functools as _functools
import warnings as _warnings
import io as _io
import os as _os
import shutil as _shutil
import errno as _errno
from random import Random as _Random
import sys as _sys
import types as _types
import weakref as _weakref
import _thread
_allocate_lock = _thread.allocate_lock
_text_openflags = _os.O_RDWR | _os.O_CREAT | _os.O_EXCL
if hasattr(_os, 'O_NOFOLLOW'):
    _text_openflags |= _os.O_NOFOLLOW
_bin_openflags = _text_openflags
if hasattr(_os, 'O_BINARY'):
    _bin_openflags |= _os.O_BINARY
if hasattr(_os, 'TMP_MAX'):
    TMP_MAX = _os.TMP_MAX
else:
    TMP_MAX = 10000
template = 'tmp'
_once_lock = _allocate_lock()

def _exists(fn):
    pass
# WARNING: Decompyle incomplete


def _infer_return_type(*args):
    '''Look at the type of all args and divine their implied return type.'''
    return_type = None
    if isinstance(arg, bytes):
        if return_type is str:
            raise TypeError("Can't mix bytes and non-bytes in path components.")
        return_type = None
        continue
    if return_type is bytes:
        raise TypeError("Can't mix bytes and non-bytes in path components.")
    return_type = None
    continue
    if return_type is None:
        if tempdir is None or isinstance(tempdir, str):
            return str
        return None


def _sanitize_params(prefix, suffix, dir):
    '''Common parameter processing for most APIs in this module.'''
    output_type = _infer_return_type(prefix, suffix, dir)
    if suffix is None:
        suffix = output_type()
    if prefix is None:
        if output_type is str:
            prefix = template
        else:
            prefix = _os.fsencode(template)
    if dir is None:
        if output_type is str:
            dir = gettempdir()
        else:
            dir = gettempdirb()
    return (prefix, suffix, dir, output_type)


class _RandomNameSequence:
    '''An instance of _RandomNameSequence generates an endless
    sequence of unpredictable strings which can safely be incorporated
    into file names.  Each string is eight characters long.  Multiple
    threads can safely use the same instance at the same time.

    _RandomNameSequence is an iterator.'''
    characters = 'abcdefghijklmnopqrstuvwxyz0123456789_'
    
    def rng(self):
        cur_pid = _os.getpid()
        if cur_pid != getattr(self, '_rng_pid', None):
            self._rng = _Random()
            self._rng_pid = cur_pid
        return self._rng

    rng = property(rng)
    
    def __iter__(self):
        return self

    
    def __next__(self):
        return ''.join(self.rng.choices(self.characters, 8, **('k',)))



def _candidate_tempdir_list():
    '''Generate a list of candidate temporary directories which
    _get_default_tempdir will try.'''
    dirlist = []
# WARNING: Decompyle incomplete


def _get_default_tempdir():
    '''Calculate the default directory to use for temporary files.
    This routine should be called exactly once.

    We determine whether or not a candidate temp dir is usable by
    trying to create and write to a file in that directory.  If this
    is successful, the test file is deleted.  To prevent denial of
    service, the name of the test file must be randomized.'''
    namer = _RandomNameSequence()
    dirlist = _candidate_tempdir_list()
# WARNING: Decompyle incomplete

_name_sequence = None

def _get_candidate_names():
    '''Common setup sequence for all user-callable interfaces.'''
    global _name_sequence
    pass
# WARNING: Decompyle incomplete


def _mkstemp_inner(dir, pre, suf, flags, output_type):
    '''Code common to mkstemp, TemporaryFile, and NamedTemporaryFile.'''
    names = _get_candidate_names()
    if output_type is bytes:
        names = map(_os.fsencode, names)
# WARNING: Decompyle incomplete


def gettempprefix():
    '''The default prefix for temporary directories as string.'''
    return _os.fsdecode(template)


def gettempprefixb():
    '''The default prefix for temporary directories as bytes.'''
    return _os.fsencode(template)

tempdir = None

def _gettempdir():
    '''Private accessor for tempfile.tempdir.'''
    global tempdir
    pass
# WARNING: Decompyle incomplete


def gettempdir():
    '''Returns tempfile.tempdir as str.'''
    return _os.fsdecode(_gettempdir())


def gettempdirb():
    '''Returns tempfile.tempdir as bytes.'''
    return _os.fsencode(_gettempdir())


def mkstemp(suffix, prefix, dir, text = (None, None, None, False)):
    """User-callable function to create and return a unique temporary
    file.  The return value is a pair (fd, name) where fd is the
    file descriptor returned by os.open, and name is the filename.

    If 'suffix' is not None, the file name will end with that suffix,
    otherwise there will be no suffix.

    If 'prefix' is not None, the file name will begin with that prefix,
    otherwise a default prefix is used.

    If 'dir' is not None, the file will be created in that directory,
    otherwise a default directory is used.

    If 'text' is specified and true, the file is opened in text
    mode.  Else (the default) the file is opened in binary mode.

    If any of 'suffix', 'prefix' and 'dir' are not None, they must be the
    same type.  If they are bytes, the returned name will be bytes; str
    otherwise.

    The file is readable and writable only by the creating user ID.
    If the operating system uses permission bits to indicate whether a
    file is executable, the file is executable by no one. The file
    descriptor is not inherited by children of this process.

    Caller is responsible for deleting the file when done with it.
    """
    (prefix, suffix, dir, output_type) = _sanitize_params(prefix, suffix, dir)
    if text:
        flags = _text_openflags
    else:
        flags = _bin_openflags
    return _mkstemp_inner(dir, prefix, suffix, flags, output_type)


def mkdtemp(suffix, prefix, dir = (None, None, None)):
    """User-callable function to create and return a unique temporary
    directory.  The return value is the pathname of the directory.

    Arguments are as for mkstemp, except that the 'text' argument is
    not accepted.

    The directory is readable, writable, and searchable only by the
    creating user.

    Caller is responsible for deleting the directory when done with it.
    """
    (prefix, suffix, dir, output_type) = _sanitize_params(prefix, suffix, dir)
    names = _get_candidate_names()
    if output_type is bytes:
        names = map(_os.fsencode, names)
# WARNING: Decompyle incomplete


def mktemp(suffix, prefix, dir = ('', template, None)):
    """User-callable function to return a unique temporary file name.  The
    file is not created.

    Arguments are similar to mkstemp, except that the 'text' argument is
    not accepted, and suffix=None, prefix=None and bytes file names are not
    supported.

    THIS FUNCTION IS UNSAFE AND SHOULD NOT BE USED.  The file name may
 