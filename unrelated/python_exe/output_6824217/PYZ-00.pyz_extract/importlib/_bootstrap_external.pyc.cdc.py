
__doc__ = 'Core implementation of path-based import.\n\nThis module is NOT meant to be directly imported! It has been designed such\nthat it can be bootstrapped into Python as the implementation of import. As\nsuch it requires the injection of specific modules and attributes in order to\nwork. One should use importlib as the public-facing version of this module.\n\n'
_bootstrap = None
import _imp
import _io
import sys
import _warnings
import marshal
_MS_WINDOWS = sys.platform == 'win32'
if _MS_WINDOWS:
    import nt as _os
    import winreg
else:
    import posix as _os
if _MS_WINDOWS:
    path_separators = [
        '\\',
        '/']
else:
    path_separators = [
        '/']
# WARNING: Decompyle incomplete
