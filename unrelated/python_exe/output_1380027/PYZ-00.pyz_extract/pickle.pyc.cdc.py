
__doc__ = 'Create portable serialized representations of Python objects.\n\nSee module copyreg for a mechanism for registering custom picklers.\nSee module pickletools source for extensive comments.\n\nClasses:\n\n    Pickler\n    Unpickler\n\nFunctions:\n\n    dump(object, file)\n    dumps(object) -> string\n    load(file) -> object\n    loads(bytes) -> object\n\nMisc variables:\n\n    __version__\n    format_version\n    compatible_formats\n\n'
from types import FunctionType
from copyreg import dispatch_table
from copyreg import _extension_registry, _inverted_registry, _extension_cache
from itertools import islice
from functools import partial
import sys
from sys import maxsize
from struct import pack, unpack
import re
import io
import codecs
import _compat_pickle
__all__ = [
    'PickleError',
    'PicklingError',
    'UnpicklingError',
    'Pickler',
    'Unpickler',
    'dump',
    'dumps',
    'load',
    'loads']
# WARNING: Decompyle incomplete
