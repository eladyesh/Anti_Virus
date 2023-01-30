
"""Command-line parsing library

This module is an optparse-inspired command-line parsing library that:

    - handles both optional and positional arguments
    - produces highly informative usage messages
    - supports parsers that dispatch to sub-parsers

The following is a simple usage example that sums integers from the
command-line and writes the result to a file::

    parser = argparse.ArgumentParser(
        description='sum the integers at the command line')
    parser.add_argument(
        'integers', metavar='int', nargs='+', type=int,
        help='an integer to be summed')
    parser.add_argument(
        '--log', default=sys.stdout, type=argparse.FileType('w'),
        help='the file where the sum should be written')
    args = parser.parse_args()
    args.log.write('%s' % sum(args.integers))
    args.log.close()

The module contains the following public classes:

    - ArgumentParser -- The main entry point for command-line parsing. As the
        example above shows, the add_argument() method is used to populate
        the parser with actions for optional and positional arguments. Then
        the parse_args() method is invoked to convert the args at the
        command-line into an object with attributes.

    - ArgumentError -- The exception raised by ArgumentParser objects when
        there are errors with the parser's actions. Errors raised while
        parsing the command-line are caught by ArgumentParser and emitted
        as command-line messages.

    - FileType -- A factory for defining types of files to be created. As the
        example above shows, instances of FileType are typically passed as
        the type= argument of add_argument() calls.

    - Action -- The base class for parser actions. Typically actions are
        selected by passing strings like 'store_true' or 'append_const' to
        the action= argument of add_argument(). However, for greater
        customization of ArgumentParser actions, subclasses of Action may
        be defined and passed as the action= argument.

    - HelpFormatter, RawDescriptionHelpFormatter, RawTextHelpFormatter,
        ArgumentDefaultsHelpFormatter -- Formatter classes which
        may be passed as the formatter_class= argument to the
        ArgumentParser constructor. HelpFormatter is the default,
        RawDescriptionHelpFormatter and RawTextHelpFormatter tell the parser
        not to change the formatting for help text, and
        ArgumentDefaultsHelpFormatter adds information about argument defaults
        to the help.

All other classes in this module are considered implementation details.
(Also note that HelpFormatter and RawDescriptionHelpFormatter are only
considered public as object names -- the API of the formatter objects is
still considered an implementation detail.)
"""
__version__ = '1.1'
__all__ = [
    'ArgumentParser',
    'ArgumentError',
    'ArgumentTypeError',
    'BooleanOptionalAction',
    'FileType',
    'HelpFormatter',
    'ArgumentDefaultsHelpFormatter',
    'RawDescriptionHelpFormatter',
    'RawTextHelpFormatter',
    'MetavarTypeHelpFormatter',
    'Namespace',
    'Action',
    'ONE_OR_MORE',
    'OPTIONAL',
    'PARSER',
    'REMAINDER',
    'SUPPRESS',
    'ZERO_OR_MORE']
import os as _os
import re as _re
import sys as _sys
from gettext import gettext as _, ngettext
SUPPRESS = '==SUPPRESS=='
OPTIONAL = '?'
ZERO_OR_MORE = '*'
ONE_OR_MORE = '+'
PARSER = 'A...'
REMAINDER = '...'
_UNRECOGNIZED_ARGS_ATTR = '_unrecognized_args'

class _AttributeHolder(object):
    """Abstract base class that provides __repr__.

    The __repr__ method returns a string in the format::
        ClassName(attr=name, attr=name, ...)
    The attributes are determined either by a class-level attribute,
    '_kwarg_names', or by inspecting the instance __dict__.
    """
    
    def __repr__(self):
        type_name = type(self).__name__
        arg_strings = []
        star_args = { }
        star_args[name] = value
        continue
        if star_args:
            arg_strings.append('**%s' % repr(star_args))
        return '%s(%s)' % (type_name, ', '.join(arg_strings))

    
    def _get_kwargs(self):
        return list(self.__dict__.items())

    
    def _get_args(self):
        return []



def _copy_items(items):
    if items is None:
        return []
    if None(items) is list:
        return items[:]
    import copy
    return copy.copy(items)


class HelpFormatter(object):
    '''Formatter for generating usage messages and argument help strings.

    Only the name of this class is considered a public API. All the methods
    provided by the class are considered an implementation detail.
    '''
    
    def __init__(self, prog, indent_increment, max_help_position, width = (2, 24, None)):
        if width is None:
            import shutil
            width = shutil.get_terminal_size().columns
            width -= 2
        self._prog = prog
        self._indent_increment = indent_increment
        self._max_help_position = min(max_help_position, max(width - 20, indent_increment * 2))
        self._width = width
        self._current_indent = 0
        self._level = 0
        self._action_max_length = 0
        self._root_section = self._Section(self, None)
        self._current_section = self._root_section
        self._whitespace_matcher = _re.compile('\\s+', _re.ASCII)
        self._long_break_matcher = _re.compile('\\n\\n\\n+')

    
    def _indent(self):
        self._current_indent += self._indent_increment
        self._level += 1

    
    def _dedent(self):
        self._current_indent -= self._indent_increment
    # WARNING: Decompyle incomplete

    
    class _Section(object):
        __qualname__ = 'HelpFormatter._Section'
        
        def __init__(self, formatter, parent, heading = (None,)):
            self.formatter = formatter
            self.parent = parent
            self.heading = heading
            self.items = []

        
        def format_help(self):
            if self.parent is not None:
                self.formatter._indent()
            join = self.formatter._join_parts
            item_help = join((lambda .0: pass# WARNING: Decompyle incomplete
)(self.items))
            if self.parent is not None:
                self.formatter._dedent()
            if not item_help:
                return ''
            if None.heading is not SUPPRESS and self.heading is not None:
                current_indent = self.formatter._current_indent
                heading = '%*s%s:\n' % (current_indent, '', self.heading)
            else:
                heading = ''
            return join([
                '\n',
                heading,
                item_help,
                '\n'])


    
    def _add_item(self, func, args):
        self._current_section.items.append((func, args))

    
    def start_section(self, heading):
        self._indent()
        section = self._Section(self, self._current_section, heading)
        self._add_item(section.format_help, [])
        self._current_section = section

    
    def end_section(self):
        self._current_section = self._current_section.parent
        self._dedent()

    
    def add_text(self, text):
        if text is not SUPPRESS or text is not None:
            self._add_item(self._format_text, [
                text])
            return None
        return None

    
    def add_usage(self, usage, actions, groups, prefix = (None,)):
        if usage is not SUPPRESS:
            args = (usage, actions, groups, prefix)
            self._add_item(self._format_usage, args)
            return None

    
    def add_argument(self, action):
        if action.help is not SUPPRESS:
            get_invocation = self._format_action_invocation
            invocations = [
                get_invocation(action)]
            invocation_length = max(map(len, invocations))
            action_length = invocation_length + self._current_indent
            self._action_max_length = max(self._action_max_length, action_length)
            self._add_item(self._format_action, [
                action