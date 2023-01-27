
__doc__ = 'create and manipulate C data types in Python'
import os as _os
import sys as _sys
import types as _types
__version__ = '1.1.0'
from _ctypes import Union, Structure, Array
from _ctypes import _Pointer
from _ctypes import CFuncPtr as _CFuncPtr
from _ctypes import __version__ as _ctypes_version
from _ctypes import RTLD_LOCAL, RTLD_GLOBAL
from _ctypes import ArgumentError
from struct import calcsize as _calcsize
if __version__ != _ctypes_version:
    raise Exception('Version number mismatch', __version__, _ctypes_version)
# WARNING: Decompyle incomplete
