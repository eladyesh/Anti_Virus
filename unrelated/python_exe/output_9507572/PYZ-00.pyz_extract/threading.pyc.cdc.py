
__doc__ = "Thread module emulating a subset of Java's threading model."
import os as _os
import sys as _sys
import _thread
import functools
from time import monotonic as _time
from _weakrefset import WeakSet
from itertools import islice as _islice, count as _count
# WARNING: Decompyle incomplete
