
'''Fraction, infinite-precision, real numbers.'''
from decimal import Decimal
import math
import numbers
import operator
import re
import sys
__all__ = [
    'Fraction']
_PyHASH_MODULUS = sys.hash_info.modulus
_PyHASH_INF = sys.hash_info.inf
_RATIONAL_FORMAT = re.compile('\n    \\A\\s*                      # optional whitespace at the start, then\n    (?P<sign>[-+]?)            # an optional sign, then\n    (?=\\d|\\.\\d)                # lookahead for digit or .digit\n    (?P<num>\\d*)               # numerator (possibly empty)\n    (?:                        # followed by\n       (?:/(?P<denom>\\d+))?    # an optional denominator\n    |                          # or\n       (?:\\.(?P<decimal>\\d*))? # an optional fractional part\n       (?:E(?P<exp>[-+]?\\d+))? # and optional exponent\n    )\n    \\s*\\Z                      # and optional whitespace to finish\n', re.VERBOSE | re.IGNORECASE)

def Fraction():
    '''Fraction'''
    __doc__ = "This class implements rational numbers.\n\n    In the two-argument form of the constructor, Fraction(8, 6) will\n    produce a rational number equivalent to 4/3. Both arguments must\n    be Rational. The numerator defaults to 0 and the denominator\n    defaults to 1 so that Fraction(3) == 3 and Fraction() == 0.\n\n    Fractions can also be constructed from:\n\n      - numeric strings similar to those accepted by the\n        float constructor (for example, '-2.3' or '1e10')\n\n      - strings of the form '123/456'\n\n      - float and Decimal instances\n\n      - other Rational instances (including integers)\n\n    "
    __slots__ = ('_numerator', '_denominator')
    
    def __new__(cls = None, numerator = None, denominator = None, *, _normalize):
        """Constructs a Rational.

        Takes a string like '3/2' or '1.5', another Rational instance, a
        numerator/denominator pair, or a float.

        Examples
        --------

        >>> Fraction(10, -8)
        Fraction(-5, 4)
        >>> Fraction(Fraction(1, 7), 5)
        Fraction(1, 35)
        >>> Fraction(Fraction(1, 7), Fraction(2, 3))
        Fraction(3, 14)
        >>> Fraction('314')
        Fraction(314, 1)
        >>> Fraction('-35/4')
        Fraction(-35, 4)
        >>> Fraction('3.1415') # conversion from numeric string
        Fraction(6283, 2000)
        >>> Fraction('-47e-2') # string may include a decimal exponent
        Fraction(-47, 100)
        >>> Fraction(1.47)  # direct construction from float (exact conversion)
        Fraction(6620291452234629, 4503599627370496)
        >>> Fraction(2.25)
        Fraction(9, 4)
        >>> Fraction(Decimal('1.47'))
        Fraction(147, 100)

        """
        self = super(Fraction, cls).__new__(cls)
        if denominator is None:
            if type(numerator) is int:
                self._numerator = numerator
                self._denominator = 1
                return self
            if None(numerator, numbers.Rational):
                self._numerator = numerator.numerator
                self._denominator = numerator.denominator
                return self
            if None(numerator, (float, Decimal)):
                (self._numerator, self._denominator) = numerator.as_integer_ratio()
                return self
            if None(numerator, str):
                m = _RATIONAL_FORMAT.match(numerator)
                if m is None:
                    raise ValueError('Invalid literal for Fraction: %r' % numerator)
                if not m.group('num'):
                    numerator = None('0')
                    denom = m.group('denom')
                    if denom:
                        denominator = int(denom)
                    else:
                        denominator = 1
                        decimal = m.group('decimal')
                        if decimal:
                            scale = 10 ** len(decimal)
                            numerator = numerator * scale + int(decimal)
                            denominator *= scale
                            exp = m.group('exp')
                            if exp:
                                exp = int(exp)
                                if exp >= 0:
                                    numerator *= 10 ** exp
                                else:
                                    denominator *= 10 ** (-exp)
                                    if m.group('sign') == '-':
                                        numerator = -numerator
                                    else:
                                        raise TypeError('argument should be a string or a Rational instance')
                                    if int is int or int is type(denominator):
                                        pass
                                    else:
                                        type(numerator)
                            
                        elif isinstance(numerator, numbers.Rational) and isinstance(denominator, numbers.Rational):
                            numerator = numerator.numerator * denominator.denominator
                            denominator = denominator.numerator * numerator.denominator
                        else:
                            raise TypeError('both arguments should be Rational instances')
                        if None == 0:
                            raise ZeroDivisionError('Fraction(%s, 0)' % numerator)
                        if None:
                            g = math.gcd(numerator, denominator)
                            if denominator < 0:
                                g = -g
                                numerator //= g
                                denominator //= g
                                self._numerator = numerator
                                self._denominator = denominator
                                return self

    
    def from_float(cls, f):
        '''Converts a finite float to a rational number, exactly.

        Beware that Fraction.from_float(0.3) != Fraction(3, 10).

        '''
        if isinstance(f, numbers.Integral):
            return cls(f)
        if not None(f, float):
            raise TypeError('%s.from_float() only takes floats, not %r (%s)' % (cls.__name__, f, type(f).__name__))
    # WARNING: Decompyle incomplete

    from_float = classmethod(from_float)
    
    def from_decimal(cls, dec):
        '''Converts a finite Decimal instance to a rational number, exactly.'''
        Decimal = Decimal
        import decimal
        if isinstance(dec, numbers.Integral):
            dec = Decimal(int(dec))
    # WARNING: Decompyle incomplete

    from_decimal = classmethod(from_decimal)
    
    def as_integer_ratio(self):
        '''Return the integer ratio as a tuple.

        Return a tuple of two integers, whose ratio is equal to the
        Fraction and with a positive denominator.
        '''
        return (self._numerator, self._denominator)

    
    def limit_denominator(self, max_denominator = (1000000,)):
        """Closest Fraction to self with denominator at most max_denominator.

        >>> Fraction('3.141592653589793').limit_denominator(10)
        Fraction(22, 7)
        >>> Fraction('3.141592653589793').limit_denominator(100)
        Fraction(311, 99)
        >>> Fraction(4321, 8765).limit_denominator(10000)
        Fraction(4321, 8765)

        """
        if max_denominator < 1:
            raise ValueError('max_denominator should be at least 1')
        if None._denominator <= max_denominator:
            return Fraction(self)
        (p0, q0, p1, q1) = None
        n = self._numerator
        d = self._denominator
        a = n // d
        q2 = q0 + a * q1
        if q2 > max_denominator:
            pass
        else:
            (p0, q0, p1, q1) = (p1, q1, p0 + a * p1, q2)
            n = d
            d = n - a * d
        k = (max_denominator - q0) // q1
        bound1 = Fraction(p0 + k * p1, q0 + k * q1)
        bound2 = Fraction(p1, q1)
        if abs(bound2 - self) <= abs(bound1 - self):
            return bound2
        return None

    
    def numerator(a):
        return a._numerator

    numerator = property(numerator)
    
    def denominator(a):
        return a._denominator

    denominator = property(denominator)
    
    def __repr__(self):
        '''repr(self)'''
        return '%s(%s, %s)' % (self.__class__.__name__, self._numerator, self._denominator)

    
    def __str__(self):
        '''str(self)'''
        if self._denominator == 1:
            return str(self._numerator)
        return None % (self._numerator, self._denominator)

    
    def _operator_fallbacks(monomorphic_operator, fallback_operator):
        '''Generates forward and reverse operators given a purely-rational
        operator and a function from the operator module.

        Use this like:
        __op__, __rop__ = _operator_fallbacks(just_rational_op, operator.op)

        In general, we want to implement the arithmetic operations so
        that mixed-mode operations either call an implementation whose
        author knew about the types of both arguments, or convert both
        to the nearest built in type and do the operation there. In
        Fraction, that means that we define __add__ and __radd__ as:

            def __add__(self, other):
                # Both types have numerators/denominator attributes,
                # so do the operation directly
                if isinstance(other, (int, Fraction)):
                    return Fraction(self.numerator * other.denominator +
                                    other.numerator * self.denominator,
                                    self.denominator * other.denominator)
                # float and complex don\'t have those operations, but we
                # know about those types, so special case them.
                elif isinstance(other, float):
                    return float(self) + other
                elif isinstance(other, complex):
                    return complex(self) + other
                # Let the other type take over.
                return NotImplemented

            def __radd__(self, other):
                # radd handles more types than add because there\'s
                # nothing left to fall back to.
                if isinstance(other, numbers.Rational):
                    return Fraction(self.numerator * other.denominator +
                                    other.numerator * self.denominator,
                                    self.denominator * other.denominator)
                elif isinstance(other, Real):
                    return float(other) + float(self)
                elif isinstance(other, Complex):
                    return complex(other) + complex(self)
                return NotImplemented


        There are 5 different cases for a mixed-type addition on
        Fraction. I\'ll refer to all of the above code that doesn\'t
        refer to Fraction, float, or complex as "boilerplate". \'r\'
        will be an instance of Fraction, which is a subtype of
        Rational (r : Fraction <: Rational), and b : B <:
        Complex. The first three involve \'r + b\':

            1. If B <: Fraction, int, float, or complex, we handle
               that specially, and all is well.
            2. If Fraction falls back to the boilerplate code, and it
               were to return a value from __add__, we\'d miss the
               possibility that B defines a more intelligent __radd__,
               so the boilerplate should return NotImplemented from
               __add__. In particular, we don\'t handle Rational
               here, even though we could get an exact answer, in case
               the other type wants to do something special.
            3. If B <: Fraction, Python tries B.__radd__ before
               Fraction.__add__. This is ok, because it was
               implemented with knowledge of Fraction, so it can
               handle those instances before delegating to Real or
               Complex.

        The next two situations describe \'b + r\'. We assume that b
        didn\'t know about Fraction in its implementation, and that it
        uses similar boilerplate code:

            4. If B <: Rational, then __radd_ converts both to the
               builtin rational type (hey look, that\'s us) and
               proceeds.
            5. Otherwise, __radd__ tries to find the nearest common
               base ABC, and fall back to its builtin type. Since this
               class doesn\'t subclass a concrete type, there\'s no
               implementation to fall back to, so we need to try as
               hard as possible to return an actual value, or the user
               will get a TypeError.

        '''
        
        def forward(a = None, b = None):
            if isinstance(b, (int, Fraction)):
                return monomorphic_operator(a, b)
            if None(b, float):
                return fallback_operator(float(a), b)
            if None(b, complex):
                return fallback_operator(complex(a), b)
            return None

        forward.__name__ = '__' + fallback_operator.__name__ + '__'
        forward.__doc__ = monomorphic_operator.__doc__
        
        def reverse(b = None, a = None):
            if isinstance(a, numbers.Rational):
                return monomorphic_operator(a, b)
            if None(a, numbers.Real):
                return fallback_operator(float(a), float(b))
            if None(a, numbers.Complex):
                return fallback_operator(complex(a), complex(b))
            return None

        reverse.__name__ = '__r' + fallback_operator.__name__ + '__'
        reverse.__doc__ = monomorphic_operator.__doc__
        return (forward, reverse)

    
    def _add(a, b):
        '''a + b'''
        da = a.denominator
        db = b.denominator
        return Fraction(a.numerator * db + b.numerator * da, da * db)

    (__add__, __radd__) = _operator_fallbacks(_add, operator.add)
    
    def _sub(a, b):
        '''a - b'''
        da = a.denominator
        db = b.denominator
        return Fraction(a.numerator * db - b.numerator * da, da * db)

    (__sub__, __rsub__) = _operator_fallbacks(_sub, operator.sub)
    
    def _mul(a, b):
        '''a * b'''
        return Fraction(a.numerator * b.numerator, a.denominator * b.denominator)

    (__mul__, __rmul__) = _operator_fallbacks(_mul, operator.mul)
    
    def _div(a, b):
        '''a / b'''
        return Fraction(a.numerator * b.denominator, a.denominator * b.numerator)

    (__truediv__, __rtruediv__) = _operator_fallbacks(_div, operator.truediv)
    
    def _floordiv(a, b):
        '''a // b'''
        return a.numerator * b.denominator // a.denominator * b.numerator

    (__floordiv__, __rfloordiv__) = _operator_fallbacks(_floordiv, operator.floordiv)
    
    def _divmod(a, b):
        '''(a // b, a % b)'''
        da = a.denominator
        db = b.denominator
        (div, n_mod) = divmod(a.numerator * db, da * b.numerator)
        return (div, Fraction(n_mod, da * db))

    (__divmod__, __rdivmod__) = _operator_fallbacks(_divmod, divmod)
    
    def _mod(a, b):
        '''a % b'''
        da = a.denominator
        db = b.denominator
        return Fraction(a.numerator * db % b.numerator * da, da * db)

    (__mod__, __rmod__) = _operator_fallbacks(_mod, operator.mod)
    
    def __pow__(a, b):
        '''a ** b

        If b is not an integer, the result will be a float or complex
        since roots are generally irrational. If b is an integer, the
        result will be rational.

        '''
        if isinstance(b, numbers.Rational):
            if b.denominator == 1:
                power = b.numerator
                if power >= 0:
                    return Fraction(a._numerator ** power, a._denominator ** power, False, **('_normalize',))
                if None._numerator >= 0:
                    return Fraction(a._denominator ** (-power), a._numerator ** (-power), False, **('_normalize',))
                return None((-(a._denominator)) ** (-power), (-(a._numerator)) ** (-power), False, **('_normalize',))
            return float(a) ** float(b)
        return float(a) ** b

    
    def __rpow__(b, a):
        '''a ** b'''
        if b._denominator == 1 and b._numerator >= 0:
            return a ** b._numerator
        if None(a, numbers.Rational):
            return Fraction(a.numerator, a.denominator) ** b
        if None._denominator == 1:
            return a ** b._numerator
        return None ** float(b)

    
    def __pos__(a):
        '''+a: Coerces a subclass instance to Fraction'''
        return Fraction(a._numerator, a._denominator, False, **('_normalize',))

    
    def __neg__(a):
        '''-a'''
        return Fraction(-(a._numerator), a._denominator, False, **('_normalize',))

    
    def __abs__(a):
        '''abs(a)'''
        return Fraction(abs(a._numerator), a._denominator, False, **('_normalize',))

    
    def __trunc__(a):
        '''trunc(a)'''
        if a._numerator < 0:
            return -(-(a._numerator) // a._denominator)
        return None._numerator // a._denominator

    
    def __floor__(a):
        '''math.floor(a)'''
        return a.numerator // a.denominator

    
    def __ceil__(a):
        '''math.ceil(a)'''
        return -(-(a.numerator) // a.denominator)

    
    def __round__(self, ndigits = (None,)):
        '''round(self, ndigits)

        Rounds half toward even.
        '''
        if ndigits is None:
            (floor, remainder) = divmod(self.numerator, self.denominator)
            if remainder * 2 < self.denominator:
                return floor
            if None * 2 > self.denominator:
                return floor + 1
            if None % 2 == 0:
                return floor
            return None + 1
        shift = None ** abs(ndigits)
        if ndigits > 0:
            return Fraction(round(self * shift), shift)
        return None(round(self / shift) * shift)

    
    def __hash__(self):
        '''hash(self)'''
        pass
    # WARNING: Decompyle incomplete

    
    def __eq__(a, b):
        '''a == b'''
        if type(b) is int:
            if a._numerator == b:
                return a._denominator == 1
            if a._numerator == b(b, numbers.Rational):
                if a._numerator == b.numerator:
                    return a._denominator == b.denominator
                if a._numerator == b.numerator(b, numbers.Complex) and b.imag == 0:
                    b = b.real
                    if isinstance(b, float):
                        if math.isnan(b) or math.isinf(b):
                            return 0 == b
                        return None == a.from_float(b)
                    return NotImplemented
                return None

    
    def _richcmp(self, other, op):
        '''Helper for comparison operators, for internal use only.

        Implement comparison between a Rational instance `self`, and
        either another Rational instance or a float `other`.  If
        `other` is not a Rational instance or a float, return
        NotImplemented. `op` should be one of the six standard
        comparison operators.

        '''
        if isinstance(other, numbers.Rational):
            return op(self._numerator * other.denominator, self._denominator * other.numerator)
        if None(other, float):
            if math.isnan(other) or math.isinf(other):
                return op(0, other)
            return None(self, self.from_float(other))
        return NotImplemented

    
    def __lt__(a, b):
        '''a < b'''
        return a._richcmp(b, operator.lt)

    
    def __gt__(a, b):
        '''a > b'''
        return a._richcmp(b, operator.gt)

    
    def __le__(a, b):
        '''a <= b'''
        return a._richcmp(b, operator.le)

    
    def __ge__(a, b):
        '''a >= b'''
        return a._richcmp(b, operator.ge)

    
    def __bool__(a):
        '''a != 0'''
        return bool(a._numerator)

    
    def __reduce__(self):
        return (self.__class__, (str(self),))

    
    def __copy__(self):
        if type(self) == Fraction:
            return self
        return None.__class__(self._numerator, self._denominator)

    
    def __deepcopy__(self, memo):
        if type(self) == Fraction:
            return self
        return None.__class__(self._numerator, self._denominator)

    __classcell__ = None

Fraction = <NODE:26>(Fraction, 'Fraction', numbers.Rational)
