
''' This module tries to retrieve as much platform-identifying data as
    possible. It makes this information available via function APIs.

    If called from the command line, it prints the platform
    information concatenated as single string to stdout. The output
    format is useable as part of a filename.

'''
__copyright__ = '\n    Copyright (c) 1999-2000, Marc-Andre Lemburg; mailto:mal@lemburg.com\n    Copyright (c) 2000-2010, eGenix.com Software GmbH; mailto:info@egenix.com\n\n    Permission to use, copy, modify, and distribute this software and its\n    documentation for any purpose and without fee or royalty is hereby granted,\n    provided that the above copyright notice appear in all copies and that\n    both that copyright notice and this permission notice appear in\n    supporting documentation or portions thereof, including modifications,\n    that you make.\n\n    EGENIX.COM SOFTWARE GMBH DISCLAIMS ALL WARRANTIES WITH REGARD TO\n    THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND\n    FITNESS, IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL,\n    INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING\n    FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,\n    NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION\n    WITH THE USE OR PERFORMANCE OF THIS SOFTWARE !\n\n'
__version__ = '1.0.8'
import collections
import os
import re
import sys
import subprocess
import functools
import itertools
_ver_stages = {
    'dev': 10,
    'alpha': 20,
    'a': 20,
    'beta': 30,
    'b': 30,
    'c': 40,
    'RC': 50,
    'rc': 50,
    'pl': 200,
    'p': 200 }
_component_re = re.compile('([0-9]+|[._+-])')

def _comparable_version(version):
    result = []
# WARNING: Decompyle incomplete

_libc_search = re.compile(b'(__libc_init)|(GLIBC_([0-9.]+))|(libc(_\\w+)?\\.so(?:\\.(\\d[0-9.]*))?)', re.ASCII)

def libc_ver(executable, lib, version, chunksize = (None, '', '', 16384)):
    ''' Tries to determine the libc version that the file executable
        (which defaults to the Python interpreter) is linked against.

        Returns a tuple of strings (lib,version) which default to the
        given parameters in case the lookup fails.

        Note that the function has intimate knowledge of how different
        libc versions add symbols to the executable and thus is probably
        only useable for executables compiled using gcc.

        The file is read and scanned in chunks of chunksize bytes.

    '''
    pass
# WARNING: Decompyle incomplete


def _norm_version(version, build = ('',)):
    ''' Normalize the version and build strings and return a single
        version string using the format major.minor.build (or patchlevel).
    '''
    l = version.split('.')
    if build:
        l.append(build)
# WARNING: Decompyle incomplete

_ver_output = re.compile('(?:([\\w ]+) ([\\w.]+) .*\\[.* ([\\d.]+)\\])')

def _syscmd_ver(system, release, version, supported_platforms = ('', '', '', ('win32', 'win16', 'dos'))):
    ''' Tries to figure out the OS version used and returns
        a tuple (system, release, version).

        It uses the "ver" shell command for this which is known
        to exists on Windows, DOS. XXX Others too ?

        In case this fails, the given parameters are used as
        defaults.

    '''
    if sys.platform not in supported_platforms:
        return (system, release, version)
    import subprocess
# WARNING: Decompyle incomplete

_WIN32_CLIENT_RELEASES = {
    (5, 0): '2000',
    (5, 1): 'XP',
    (5, 2): '2003Server',
    (5, None): 'post2003',
    (6, 0): 'Vista',
    (6, 1): '7',
    (6, 2): '8',
    (6, 3): '8.1',
    (6, None): 'post8.1',
    (10, 0): '10',
    (10, None): 'post10' }
_WIN32_SERVER_RELEASES = {
    (5, 2): '2003Server',
    (6, 0): '2008Server',
    (6, 1): '2008ServerR2',
    (6, 2): '2012Server',
    (6, 3): '2012ServerR2',
    (6, None): 'post2012ServerR2' }

def win32_is_iot():
    return win32_edition() in 