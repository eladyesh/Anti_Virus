
__doc__ = 'Read from and write to tar format archives.\n'
version = '0.9.0'
__author__ = 'Lars Gust\xc3\xa4bel (lars@gustaebel.de)'
__credits__ = 'Gustavo Niemeyer, Niels Gust\xc3\xa4bel, Richard Townsend.'
from builtins import open as bltn_open
import sys
import os
import io
import shutil
import stat
import time
import struct
import copy
import re
# WARNING: Decompyle incomplete
