
__doc__ = '\nRead and write ZIP files.\n\nXXX references to utf-8 need further investigation.\n'
import binascii
import importlib.util as importlib
import io
import itertools
import os
import posixpath
import shutil
import stat
import struct
import sys
import threading
import time
import contextlib
import pathlib
# WARNING: Decompyle incomplete
