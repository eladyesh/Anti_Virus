
'''Abstract Base Classes (ABCs) for numbers, according to PEP 3141.

TODO: Fill out more detailed documentation on the operators.'''
from abc import ABCMeta, abstractmethod
__all__ = [
    'Number',
    'Complex',
    'Real',
    'Rational',
    'Integral']
Number = <NODE:26>((lambda : __doc__ = 'All numbers inherit from this class.\n\n    If you just want to check if an argument x is a number, without\n    caring what kind, use isinstance(x, Number).\n    '__slots__ = ()__hash__ = None), 'Number', ABCMeta, **('metaclass',))

class Complex(Number):
    """Complex defines the operations that work on the builtin complex type.

    In short, those are: a conversion to complex, .real, .imag, +, -,
    *, /, **, abs(), .conjugate, ==, and !=.

    If it is given heterogeneous arguments, and doesn't have special
    knowledge about them, it should fall back to the builtin complex
    type as described below.
    """
    __slots__ = ()
    
    def __complex__(self):
        '''Return a builtin complex instance. Called for complex(self).'''
        pass

    __complex__ = abstractmethod(__complex__)
    
    def __bool__(self):
        '''True if self != 0. Called for bool(self).'''
        return self != 0

    
    def real(self):
        '''Retrieve the real component of this number.

        This should subclass Real.
        '''
        raise NotImplementedError

    real = property(abstractmethod(real))
    
    def imag(self):
        '''Retrieve the imaginary component of this number.

        This should subclass Real.
        '''
        raise NotImplementedError

    imag = property(abstractmethod(imag))
    
    def __add__(self, other):
        '''self + other'''
        raise NotImplementedError

    __add__ = abstractmethod(__add__)
    
    def __radd__(self, other):
        '''other + self'''
        raise NotImplementedError

    __radd__ = abstractmethod(__radd__)
    
    def __neg__(self):
        '''-self'''
        raise NotImplementedError

    __neg__ = abstractmethod(__neg__)
    
    def __pos__(self):
        '''+self'''
        raise NotImplementedError

    __pos__ = abstractmethod(__pos__)
    
    def __sub__(self, other):
        '''self - other'''
        return self + -other

    
    def __rsub__(self, other):
        '''other - self'''
        return -self + other

    
    def __mul__(self, other):
        '''self * other'''
        raise NotImplementedError

    __mul__ = abstractmethod(__mul__)
    
    def __rmul__(self, other):
        '''other * self'''
        raise NotImplementedError

    __rmul__ = abstractmethod(__rmul__)
    
    def __truediv__(self, other):
        '''self / other: Should promote to float when necessary.'''
        raise NotImplementedError

    __truediv__ = abstractmethod(__truediv__)
    
    def __rtruediv__(self, other):
        '''other / self'''
        raise NotImplementedError

    __rtruediv__ = abstractmethod(__rtruediv__)
    
    def __pow__(self, exponent):
        '''self**exponent; should promote to float or complex when necessary.'''
        raise NotImplementedError

    __pow__ = abstractmethod(__pow__)
    
    def __rpow__(self, base):
        '''base ** self'''
        raise NotImplementedError

    __rpow__ = abstractmethod(__rpow__)
    
    def __abs__(self):
        '''Returns the Real distance from 0. Called for abs(self).'''
        raise NotImplementedError

    __abs__ = abstractmethod(__abs__)
    
    def conjugate(self):
        '''(x+y*i).conjugate() returns (x-y*i).'''
        raise NotImplementedError

    conjugate = abstractmethod(conjugate)
    
    def __eq__(self, other):
        '''self == other'''
        raise NotImplementedError

    __eq__ = abstractmethod(__eq__)

Complex.register(complex)

class Real(Complex):
    '''To Complex, Real adds the operations that work on real numbers.

    In short, those are: a conversion to float, trunc(), divmod,
    %, <, <=, >, and >=.

    Real also provides defaults for the derived operations.
    '''
    __slots__ = ()
    
    def __float__(self):
        '''Any Real can be converted to a native float object.

        Called for float(self).'''
        raise NotImplementedError

    __float__ = abstractmethod(__float__)
    
    def __trunc__(self):
        '''trunc(self): Truncates self to an Integral.

        Returns an Integral i such that:
          * i>0 iff self>0;
          * abs(i) <= abs(self);
          * for any Integral j satisfying the first two conditions,
            abs(i) >= abs(j) [i.e. i has "maximal" abs among those].
        i.e. "truncate towards 0".
        '''
        raise NotImplementedError

    __trunc__ = abstractmethod(__trunc__)
    
    def __floor__(self):
        '''Finds the greatest Integral <= self.'''
        raise NotImplementedError

    __floor__ = abstractmethod(__floor__)
    
    def __ceil__(self):
        '''Finds the least Integral >= self.'''
        raise NotImplementedError

    __ceil__ = abstractmethod(__ceil__)
    
    def __round__(self, ndigits = (None,)):
        '''Rounds self to ndigits decimal places, defaulting to 0.

        If ndigits is omitted or None, returns an Integral, otherwise
        returns a Real. Rounds half toward even.
        '''
        raise NotImplementedError

    __round__ = abstractmethod(__round__)
    
    def __divmod__(self, other):
        '''divmod(self, other): The pair (self // other, self % other).

        Sometimes this can be computed faster than the pair of
        operations.
        '''
        return (self // other, self % other)

    
    def __rdivmod__(self, other):
        '''divmod(other, self): The pair (self // other, self % other).

        Sometimes this can be computed faster than the pair of
        operations.
        '''
        return (other // self, other % self)

    
    def __floordiv__(self, other):
        '''self // other: The floor() of self/other.'''
        raise NotImplementedError

    __floordiv__ = abstractmethod(__floordiv__)
    
    def __rfloordiv__(self, other):
        '''other // self: The floor() of other/self.'''
        raise NotImplementedError

    __rfloordiv__ = abstractmethod(__rfloordiv__)
    
    def __mod__(self, other):
        '''self % other'''
        raise NotImplementedError

    __mod__ = abstractmethod(__mod__)
    
    def __rmod__(self, other):
        '''other % self'''
        raise NotImplementedError

    __rmod__ = abstractmethod(__rmod__)
    
    def __lt__(self, other):
        '''self < other

        < on Reals defines a total ordering, except perhaps for NaN.'''
        raise NotImplementedError

    __lt__ = abstractmethod(__lt__)
    
    def __le__(self, other):
        '''self <= other'''
        raise NotImplementedError

    __le__ = abstractmethod(__le__)
    
    def __complex__(self):
        '''complex(self) == complex(float(self), 0)'''
        return complex(float(self))

    
    def real(self):
        '''Real numbers are their real component.'''
        return +self

    real = property(real)
    
    def imag(self):
        '''Real numbers have no imaginary component.'''
        return 0

    imag = property(imag)
    
    def conjugate(self):
        '''Conjugate is a no-op for Reals.'''
        return +self


Real.register(float)

class Rational(Real):
    '''.numerator and .denominator should be in lowest terms.'''
    __slots__ = ()
    
    def numerator(self):
        raise NotImplementedError

    numerator = property(abstractmethod(numerator))
    
    def denominator(self):
        raise NotImplementedError

    denominator = property(abstractmethod(denominator))
    
    def __float__(self):
        '''float(self) = self.numerator / self.denominator

        It\'s important that this conversion use the integer\'s "true"
        division rather than casting one side to float before dividing
        so that ratios of huge integers convert without overflowing.

        '''
        return self.numerator / self.denominator



class Integral(Rational):
    '''Integral adds methods that work on integral numbers.

    In short, these are conversion to int, pow with modulus, and the
    bit-string operations.
    '''
    __slots__ = ()
    
    def __int__(self):
        '''int(self)'''
        raise NotImplementedError

    __int__ = abstractmethod(__int__)
    
    def __index__(self):
        '''Called whenever an index is needed, such as in slicing'''
        return int(self)

    
    def __pow__(self, exponent, modulus = (None,)):
        """self ** exponent % modulus, but maybe faster.

        Accept the modulus argument if you want to support the
        3-argument version of pow(). Raise a TypeError if exponent < 0
        or any argument isn't Integral. Otherwise, just implement the
        2-argument version described in Complex.
        """
        raise NotImplementedError

    __pow__ = abstractmethod(__pow__)
    
    def __lshift__(self, other):
        '''self << other'''
        raise NotImplementedError

    __lshift__ = abstractmethod(__lshift__)
    
    def __rlshift__(self, other):
        '''other << self'''
        raise NotImplementedError

    __rlshift__ = abstractmethod(__rlshift__)
    
    def __rshift__(self, other):
        '''self >> other'''
        raise NotImplementedError

    __rshift__ = abstractmethod(__rshift__)
    
    def __rrshift__(self, other):
        '''other >> self'''
        raise NotImplementedError

    __rrshift__ = abstractmethod(__rrshift__)
    
    def __and__(self, other):
        '''self & other'''
        raise NotImplementedError

    __and__ = abstractmethod(__and__)
    
    def __rand__(self, other):
        '''other & self'''
        raise NotImplementedError

    __rand__ = abstractmethod(__rand__)
    
    def __xor__(self, other):
        '''self ^ other'''
        raise NotImplementedError

    __xor__ = abstractmethod(__xor__)
    
    def __rxor__(self, other):
        '''other ^ self'''
        raise NotImplementedError

    __rxor__ = abstractmethod(__rxor__)
    
    def __or__(self, other):
        '''self | other'''
        raise NotImplementedError

    __or__ = abstractmethod(__or__)
    
    def __ror__(self, other):
        '''other | self'''
        raise NotImplementedError

    __ror__ = abstractmethod(__ror__)
    
    def __invert__(self):
        '''~self'''
        raise NotImplementedError

    __invert__ = abstractmethod(__invert__)
    
    def __float__(self):
        '''float(self) == float(int(self))'''
        return float(int(self))

    
    def numerator(self):
        '''Integers are their own numerators.'''
        return +self

    numerator = property(numerator)
    
    def denominator(self):
        '''Integers have a denominator of 1.'''
        return 1

    denominator = property(denominator)

Integral.register(int)
