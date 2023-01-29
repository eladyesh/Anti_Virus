
__doc__ = '\nThis is an implementation of decimal floating point arithmetic based on\nthe General Decimal Arithmetic Specification:\n\n    http://speleotrove.com/decimal/decarith.html\n\nand IEEE standard 854-1987:\n\n    http://en.wikipedia.org/wiki/IEEE_854-1987\n\nDecimal floating point has finite precision with arbitrarily large bounds.\n\nThe purpose of this module is to support arithmetic using familiar\n"schoolhouse" rules and to avoid some of the tricky representation\nissues associated with binary floating point.  The package is especially\nuseful for financial applications or for contexts where users have\nexpectations that are at odds with binary floating point (for instance,\nin binary floating point, 1.00 % 0.1 gives 0.09999999999999995 instead\nof 0.0; Decimal(\'1.00\') % Decimal(\'0.1\') returns the expected\nDecimal(\'0.00\')).\n\nHere are some examples of using the decimal module:\n\n>>> from decimal import *\n>>> setcontext(ExtendedContext)\n>>> Decimal(0)\nDecimal(\'0\')\n>>> Decimal(\'1\')\nDecimal(\'1\')\n>>> Decimal(\'-.0123\')\nDecimal(\'-0.0123\')\n>>> Decimal(123456)\nDecimal(\'123456\')\n>>> Decimal(\'123.45e12345678\')\nDecimal(\'1.2345E+12345680\')\n>>> Decimal(\'1.33\') + Decimal(\'1.27\')\nDecimal(\'2.60\')\n>>> Decimal(\'12.34\') + Decimal(\'3.87\') - Decimal(\'18.41\')\nDecimal(\'-2.20\')\n>>> dig = Decimal(1)\n>>> print(dig / Decimal(3))\n0.333333333\n>>> getcontext().prec = 18\n>>> print(dig / Decimal(3))\n0.333333333333333333\n>>> print(dig.sqrt())\n1\n>>> print(Decimal(3).sqrt())\n1.73205080756887729\n>>> print(Decimal(3) ** 123)\n4.85192780976896427E+58\n>>> inf = Decimal(1) / Decimal(0)\n>>> print(inf)\nInfinity\n>>> neginf = Decimal(-1) / Decimal(0)\n>>> print(neginf)\n-Infinity\n>>> print(neginf + inf)\nNaN\n>>> print(neginf * inf)\n-Infinity\n>>> print(dig / 0)\nInfinity\n>>> getcontext().traps[DivisionByZero] = 1\n>>> print(dig / 0)\nTraceback (most recent call last):\n  ...\n  ...\n  ...\ndecimal.DivisionByZero: x / 0\n>>> c = Context()\n>>> c.traps[InvalidOperation] = 0\n>>> print(c.flags[InvalidOperation])\n0\n>>> c.divide(Decimal(0), Decimal(0))\nDecimal(\'NaN\')\n>>> c.traps[InvalidOperation] = 1\n>>> print(c.flags[InvalidOperation])\n1\n>>> c.flags[InvalidOperation] = 0\n>>> print(c.flags[InvalidOperation])\n0\n>>> print(c.divide(Decimal(0), Decimal(0)))\nTraceback (most recent call last):\n  ...\n  ...\n  ...\ndecimal.InvalidOperation: 0 / 0\n>>> print(c.flags[InvalidOperation])\n1\n>>> c.flags[InvalidOperation] = 0\n>>> c.traps[InvalidOperation] = 0\n>>> print(c.divide(Decimal(0), Decimal(0)))\nNaN\n>>> print(c.flags[InvalidOperation])\n1\n>>>\n'
__all__ = [
    'Decimal',
    'Context',
    'DecimalTuple',
    'DefaultContext',
    'BasicContext',
    'ExtendedContext',
    'DecimalException',
    'Clamped',
    'InvalidOperation',
    'DivisionByZero',
    'Inexact',
    'Rounded',
    'Subnormal',
    'Overflow',
    'Underflow',
    'FloatOperation',
    'DivisionImpossible',
    'InvalidContext',
    'ConversionSyntax',
    'DivisionUndefined',
    'ROUND_DOWN',
    'ROUND_HALF_UP',
    'ROUND_HALF_EVEN',
    'ROUND_CEILING',
    'ROUND_FLOOR',
    'ROUND_UP',
    'ROUND_HALF_DOWN',
    'ROUND_05UP',
    'setcontext',
    'getcontext',
    'localcontext',
    'MAX_PREC',
    'MAX_EMAX',
    'MIN_EMIN',
    'MIN_ETINY',
    'HAVE_THREADS',
    'HAVE_CONTEXTVAR']
__xname__ = __name__
__name__ = 'decimal'
__version__ = '1.70'
__libmpdec_version__ = '2.4.2'
import math as _math
import numbers as _numbers
import sys
# WARNING: Decompyle incomplete
