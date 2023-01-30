
'''Disassembler of Python byte code into mnemonics.'''
import sys
import types
import collections
import io
from opcode import *
from opcode import __all__ as _opcodes_all
__all__ = [
    'code_info',
    'dis',
    'disassemble',
    'distb',
    'disco',
    'findlinestarts',
    'findlabels',
    'show_code',
    'get_instructions',
    'Instruction',
    'Bytecode'] + _opcodes_all
del _opcodes_all
_have_code = (types.MethodType, types.FunctionType, types.CodeType, classmethod, staticmethod, type)
FORMAT_VALUE = opmap['FORMAT_VALUE']
FORMAT_VALUE_CONVERTERS = ((None, ''), (str, 'str'), (repr, 'repr'), (ascii, 'ascii'))
MAKE_FUNCTION = opmap['MAKE_FUNCTION']
MAKE_FUNCTION_FLAGS = ('defaults', 'kwdefaults', 'annotations', 'closure')

def _try_compile(source, name):
    '''Attempts to compile the given source, first as an expression and
       then as a statement if the first approach fails.

       Utility function to accept strings in functions that otherwise
       expect code objects
    '''
    pass
# WARNING: Decompyle incomplete


def dis(x = None, *, file, depth):
    '''Disassemble classes, methods, functions, and other compiled objects.

    With no argument, disassemble the last traceback.

    Compiled objects currently include generator objects, async generator
    objects, and coroutine objects, all of which store their code object
    in a special attribute.
    '''
    if x is None:
        distb(file, **('file',))
        return None
    if None(x, '__func__'):
        x = x.__func__
    if hasattr(x, '__code__'):
        x = x.__code__
    elif hasattr(x, 'gi_code'):
        x = x.gi_code
    elif hasattr(x, 'ag_code'):
        x = x.ag_code
    elif hasattr(x, 'cr_code'):
        x = x.cr_code
# WARNING: Decompyle incomplete


def distb(tb = None, *, file):
    '''Disassemble a traceback (default: last traceback).'''
    pass
# WARNING: Decompyle incomplete

COMPILER_FLAG_NAMES = {
    1: 'OPTIMIZED',
    2: 'NEWLOCALS',
    4: 'VARARGS',
    8: 'VARKEYWORDS',
    16: 'NESTED',
    32: 'GENERATOR',
    64: 'NOFREE',
    128: 'COROUTINE',
    256: 'ITERABLE_COROUTINE',
    512: 'ASYNC_GENERATOR' }

def pretty_flags(flags):
    '''Return pretty representation of code flags.'''
    names = []
    for i in range(32):
        flag = 1 << i
        names.append(COMPILER_FLAG_NAMES.get(flag, hex(flag)))
        flags ^= flag
        [ COMPILER_FLAG_NAMES.get(flag, hex(flag)) ]
        None.append(hex(flags))
        return ', '.join(names)


def _get_code_object(x):
    '''Helper to handle methods, compiled or raw code objects, and strings.'''
    if hasattr(x, '__func__'):
        x = x.__func__
    if hasattr(x, '__code__'):
        x = x.__code__
    elif hasattr(x, 'gi_code'):
        x = x.gi_code
    elif hasattr(x, 'ag_code'):
        x = x.ag_code
    elif hasattr(x, 'cr_code'):
        x = x.cr_code
    if isinstance(x, str):
        x = _try_compile(x, '<disassembly>')
    if hasattr(x, 'co_code'):
        return x
    raise None("don't know how to disassemble %s objects" % type(x).__name__)


def code_info(x):
    '''Formatted details of methods, functions, or code.'''
    return _format_code_info(_get_code_object(x))


def _format_code_info(co):
    lines = []
    lines.append('Name:              %s' % co.co_name)
    lines.append('Filename:          %s' % co.co_filename)
    lines.append('Argument count:    %s' % co.co_argcount)
    lines.append('Positional-only arguments: %s' % co.co_posonlyargcount)
    lines.append('Kw-only arguments: %s' % co.co_kwonlyargcount)
    lines.append('Number of locals:  %s' % co.co_nlocals)
    lines.append('Stack size:        %s' % co.co_stacksize)
    lines.append('Flags:             %s' % pretty_flags(co.co_flags))
    if co.co_cellvars:
        lines.append('Cell variables:')
    return '\n'.join(lines)


def show_code(co = None, *, file):
    '''Print details of methods, functions, or code to *file*.

    If *file* is not provided, the output is printed on stdout.
    '''
    print(code_info(co), file, **('file',))

_Instruction = collections.namedtuple('_Instruction', 'opname opcode arg argval argrepr offset starts_line is_jump_target')
_Instruction.opname.__doc__ = 'Human readable name for operation'
_Instruction.opcode.__doc__ = 'Numeric code for operation'
_Instruction.arg.__doc__ = 'Numeric argument to operation (if any), otherwise None'
_Instruction.argval.__doc__ = 'Resolved arg value (if known), otherwise same as arg'
_Instruction.argrepr.__doc__ = 'Human readable description of operation argument'
_Instruction.offset.__doc__ = 'Start index of operation within bytecode sequence'
_Instruction.starts_line.__doc__ = 'Line started by this opcode (if any), otherwise None'
_Instruction.is_jump_target.__doc__ = 'True if other code jumps to here, otherwise False'
_OPNAME_WIDTH = 20
_OPARG_WIDTH = 5

class Instruction(_Instruction):
    '''Details for a bytecode operation

       Defined fields:
         opname - human readable name for operation
         opcode - numeric code for operation
         arg - numeric argument to operation (if any), otherwise None
         argval - resolved arg value (if known), otherwise same as arg
         argrepr - human readable description of operation argument
         offset - start index of operation within bytecode sequence
         starts_line - line started by this opcode (if any), otherwise None
         is_jump_target - True if other code jumps to here, otherwise False
    '''
    
    def _disassemble(self, lineno_width, mark_as_current, offset_width = (3, False, 4)):
        """Format instruction details for inclusion in disassembly output

        *lineno_width* sets the width of the line number field (0 omits it)
        *mark_as_current* inserts a '-->' marker arrow as part of the line
        *offset_width* sets the width of the instruction offset field
        """
        fields = []
        if lineno_width:
            if self.starts_line is not None:
                lineno_fmt = '%%%dd' % lineno_width
                fields.append(lineno_fmt % self.starts_line)
            else:
                fields.append(' ' * lineno_width)
        if mark_as_current:
            fields.append('-->')
        else:
            fields.append('   ')
        if self.is_jump_target:
            fields.append('>>')
        else:
            fields.append('  ')
        fields.append(repr(self.offset).rjust(offset_width))
        fields.append(self.opname.ljust(_OPNAME_WIDTH))
        if self.arg is not None:
            fields.append(repr(self.arg).rjust(_OPARG_WIDTH))
            if self.argrepr:
                fields.append('(' + self.argrepr + ')')
        return ' '.join(fields).rstrip()



def get_instructions(x = None, *, first_line):
    '''Iterator for the opcodes in methods, functions or code

    Generates a series of Instruction named tuples giving the details of
    each operations in the supplied code.

    If *first_line* is not None, it indicates the line number that should
    be reported for the first source line in the disassembled code.
    Otherwise, the source line information (if any) is taken directly from
    the disassembled code object.
    '''
    co = _get_code_object(x)
    cell_names = co.co_cellvars + co.co_freevars
    linestarts = dict(findlinestarts(co))
    if first_line is not None:
        line_offset = first_line - co.co_firstlineno
    else:
        line_offset = 0
    return _get_instructions_bytes(co.co_code, co.co_varnames, co.co_names, co.co_consts, cell_names, linestarts, line_offset)


def _get_const_info(const_index, const_list):
    '''Helper to get optional details about const references

       Returns the dereferenced constant and its repr if the constant
       list is defined.
       Otherwise returns the constant index and its repr().
    '''
    argval = const_index
    if const_list is not None:
        argval = const_list[const_index]
    return (argval, repr(argval))


def _get_name_info(name_index, name_list):
    '''Helper to get optional details about named references

       Returns the dereferenced name as both value and repr if the name
       list is defined.
       Otherwise returns the name index and its repr().
    '''
    argval = name_index
    if name_list is not None:
        argval = name_list[name_index]
        argrepr = argval
        return (argval, argrepr)
    argrepr = None(argval)
    return (argval, argrepr)


def _get_instructions_bytes(code, varnames, names, constants, cells, linestarts, line_offset = (None, None, None, None, None, 0)):
    """Iterate over the instructions in a bytecode string.

    Generates a sequence of Instruction namedtuples giving the details of each
    opcode.  Additional information about the code's runtime environment
    (e.g. variable names, constants) can be specified using optional
    arguments.

    """
    pass
# WARNING: Decompyle incomplete


def disassemble(co = None, lasti = (-1,), *, file):
    '''Disassemble a code object.'''
    cell_names = co.co_cellvars + co.co_freevars
    linestarts = dict(findlinestarts(co))
    _disassemble_bytes(co.co_code, lasti, co.co_varnames, co.co_names, co.co_consts, cell_names, linestarts, file, **('file',))


def _disassemble_recursive(co = None, *, file, depth):
    disassemble(co, file, **('file',))
    if depth is None or depth > 0:
        if depth is not None:
            depth = depth - 1
    return None


def _disassemble_bytes(code, lasti, varnames, names, constants = None, cells = (-1, None, None, None, None, None), linestarts = {
    'file': None,
    'line_offset': 0 }, *, file, line_offset):
    show_lineno = bool(linestarts)
    if show_lineno:
        maxlineno = max(linestarts.values()) + line_offset
        if maxlineno >= 1000:
            lineno_width = len(str(maxlineno))
        else:
            lineno_width = 3
    else:
        lineno_width = 0
    maxoffset = len(code) - 2
    if maxoffset >= 10000:
        offset_width = len(str(maxoffset))
    else:
        offset_width = 4


def _disassemble_str(source, **kwargs):
    '''Compile the source string, then disassemble the code object.'''
    pass
# WARNING: Decompyle incomplete

disco = disassemble

def _unpack_opargs(code):
    pass
# WARNING: Decompyle incomplete


def findlabels(code):
    '''Detect all offsets in a byte code which are jump targets.

    Return the list of offsets.

    '''
    labels = []
    for offset, op, arg in _unpack_opargs(code):
        label = offset + 2 + arg * 2
    if op in hasjabs:
        label = arg * 2
    
    if label not in labels:
        labels.append(label)
    continue
    return labels


def findlinestarts(code):
    '''Find the offsets in a byte code which are start of lines in the source.

    Generate pairs (offset, lineno)
    '''
    pass
# WARNING: Decompyle incomplete


class Bytecode:
    '''The bytecode operations of a piece of code

    Instantiate this with a function, method, other compiled object, string of
    code, or a code object (as returned by compile()).

    Iterating over this yields the bytecode operations as Instruction instances.
    '''
    
    def __init__(self = None, x = {
        'first_line': None,
        'current_offset': None }, *, first_line, current_offset):
        self.codeobj = co = _get_code_object(x)
        if first_line is None:
            self.first_line = co.co_firstlineno
            self._line_offset = 0
        else:
            self.first_line = first_line
            self._line_offset = first_line - co.co_firstlineno
        self._cell_names = co.co_cellvars + co.co_freevars
        self._linestarts = dict(findlinestarts(co))
        self._original_object = x
        self.current_offset = current_offset

    
    def __iter__(self):
        co = self.codeobj
        return _get_instructions_bytes(co.co_code, co.co_varnames, co.co_names, co.co_consts, self._cell_names, self._linestarts, self._line_offset, **('line_offset',))

    
    def __repr__(self):
        return '{}({!r})'.format(self.__class__.__name__, self._original_object)

    
    def from_traceback(cls, tb):
        ''' Construct a Bytecode from the given traceback '''
        if tb.tb_next:
            tb = tb.tb_next
            if not tb.tb_next:
                return cls(tb.tb_frame.f_code, tb.tb_lasti, **('current_offset',))

    from_traceback = classmethod(from_traceback)
    
    def info(self):
        '''Return formatted information about the code object.'''
        return _format_code_info(self.codeobj)

    
    def dis(self):
        '''Return a formatted view of the bytecode operations.'''
        co = self.codeobj
        if self.current_offset is not None:
            offset = self.current_offset
        else:
            offset = -1
    # WARNING: Decompyle incomplete



def _test():
    '''Simple test program to disassemble a file.'''
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('infile', argparse.FileType('rb'), '?', '-', **('type', 'nargs', 'default'))
    args = parser.parse_args()
    with args.infile as infile:
        source = infile.read()
        None(None, None, None)
# WARNING: Decompyle incomplete

if __name__ == '__main__':
    _test()
    return None
