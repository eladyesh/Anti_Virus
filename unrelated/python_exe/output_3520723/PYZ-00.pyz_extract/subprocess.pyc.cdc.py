
__doc__ = 'Subprocesses with accessible I/O streams\n\nThis module allows you to spawn processes, connect to their\ninput/output/error pipes, and obtain their return codes.\n\nFor a complete description of this module see the Python documentation.\n\nMain API\n========\nrun(...): Runs a command, waits for it to complete, then returns a\n          CompletedProcess instance.\nPopen(...): A class for flexibly executing a command in a new process\n\nConstants\n---------\nDEVNULL: Special value that indicates that os.devnull should be used\nPIPE:    Special value that indicates a pipe should be created\nSTDOUT:  Special value that indicates that stderr should go to stdout\n\n\nOlder API\n=========\ncall(...): Runs a command, waits for it to complete, then returns\n    the return code.\ncheck_call(...): Same as call() but raises CalledProcessError()\n    if return code is not 0\ncheck_output(...): Same as check_call() but returns the contents of\n    stdout instead of a return code\ngetoutput(...): Runs a command in the shell, waits for it to complete,\n    then returns the output\ngetstatusoutput(...): Runs a command in the shell, waits for it to complete,\n    then returns a (exitcode, output) tuple\n'
import builtins
import errno
import io
import os
import time
import signal
import sys
import threading
import warnings
import contextlib
from time import monotonic as _time
import types
# WARNING: Decompyle incomplete
