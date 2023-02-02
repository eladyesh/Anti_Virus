
__doc__ = '\nHooks to make ctypes.CDLL, .PyDLL, etc. look in sys._MEIPASS first.\n'
import sys

def install():
    '''
    Install the hooks.

    This must be done from a function as opposed to at module-level, because when the module is imported/executed,
    the import machinery is not completely set up yet.
    '''
    import os
# WARNING: Decompyle incomplete

# WARNING: Decompyle incomplete
