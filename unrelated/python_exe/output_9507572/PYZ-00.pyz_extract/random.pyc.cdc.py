
__doc__ = 'Random variable generators.\n\n    bytes\n    -----\n           uniform bytes (values between 0 and 255)\n\n    integers\n    --------\n           uniform within range\n\n    sequences\n    ---------\n           pick random element\n           pick random sample\n           pick weighted random sample\n           generate random permutation\n\n    distributions on the real line:\n    ------------------------------\n           uniform\n           triangular\n           normal (Gaussian)\n           lognormal\n           negative exponential\n           gamma\n           beta\n           pareto\n           Weibull\n\n    distributions on the circle (angles 0 to 2pi)\n    ---------------------------------------------\n           circular uniform\n           von Mises\n\nGeneral notes on the underlying Mersenne Twister core generator:\n\n* The period is 2**19937-1.\n* It is one of the most extensively tested generators in existence.\n* The random() method is implemented in C, executes in a single Python step,\n  and is, therefore, threadsafe.\n\n'
from warnings import warn as _warn
from math import log as _log, exp as _exp, pi as _pi, e as _e, ceil as _ceil
from math import sqrt as _sqrt, acos as _acos, cos as _cos, sin as _sin
from math import tau as TWOPI, floor as _floor
from os import urandom as _urandom
from _collections_abc import Set as _Set, Sequence as _Sequence
from itertools import accumulate as _accumulate, repeat as _repeat
from bisect import bisect as _bisect
import os as _os
import _random
# WARNING: Decompyle incomplete
