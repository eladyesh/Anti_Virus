
__doc__ = "Utility functions for copying and archiving files and directory trees.\n\nXXX The functions here don't copy the resource fork or other metadata on Mac.\n\n"
import os
import sys
import stat
import fnmatch
import collections
import errno
# WARNING: Decompyle incomplete
