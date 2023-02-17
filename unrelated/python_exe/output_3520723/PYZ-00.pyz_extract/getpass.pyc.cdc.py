
__doc__ = 'Utilities to get a password and/or the current user name.\n\ngetpass(prompt[, stream]) - Prompt for a password, with echo turned off.\ngetuser() - Get the user name from the environment or password database.\n\nGetPassWarning - This UserWarning is issued when getpass() cannot prevent\n                 echoing of the password contents while reading.\n\nOn Windows, the msvcrt module will be used.\n\n'
import contextlib
import io
import os
import sys
import warnings
__all__ = [
    'getpass',
    'getuser',
    'GetPassWarning']

class GetPassWarning(UserWarning):
    pass


def unix_getpass(prompt, stream = ('Password: ', None)):
    """Prompt for a password, with echo turned off.

    Args:
      prompt: Written on stream to ask for the input.  Default: 'Password: '
      stream: A writable file object to display the prompt.  Defaults to
              the tty.  If no tty is available defaults to sys.stderr.
    Returns:
      The seKr3t input.
    Raises:
      EOFError: If our input tty or stdin was closed.
      GetPassWarning: When we were unable to turn echo off on the input.

    Always restores terminal settings before returning.
    """
    passwd = None
# WARNING: Decompyle incomplete


def win_getpass(prompt, stream = ('Password: ', None)):
    '''Prompt for password with echo off, using Windows getwch().'''
    if sys.stdin is not sys.__stdin__:
        return fallback_getpass(prompt, stream)
    pw = ''
    c = msvcrt.getwch()
    continue
    msvcrt.putwch('\r')
    msvcrt.putwch('\n')
    return pw


def fallback_getpass(prompt, stream = ('Password: ', None)):
    warnings.warn('Can not control echo on the terminal.', GetPassWarning, 2, **('stacklevel',))
    if not stream:
        stream = sys.stderr
    print('Warning: Password input may be echoed.', stream, **('file',))
    return _raw_input(prompt, stream)


def _raw_input(prompt, stream, input = ('', None, None)):
    if not stream:
        stream = sys.stderr
    if not input:
        input = sys.stdin
    prompt = str(prompt)
# WARNING: Decompyle incomplete


def getuser():
    '''Get the username from the environment or password database.

    First try various environment variables, then the password
    database.  This works on Windows as long as USERNAME is set.

    '''
    import pwd
    return pwd.getpwuid(os.getuid())[0]

# WARNING: Decompyle incomplete
