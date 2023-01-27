
__doc__ = '\nBasic statistics module.\n\nThis module provides functions for calculating statistics of data, including\naverages, variance, and standard deviation.\n\nCalculating averages\n--------------------\n\n==================  ==================================================\nFunction            Description\n==================  ==================================================\nmean                Arithmetic mean (average) of data.\nfmean               Fast, floating point arithmetic mean.\ngeometric_mean      Geometric mean of data.\nharmonic_mean       Harmonic mean of data.\nmedian              Median (middle value) of data.\nmedian_low          Low median of data.\nmedian_high         High median of data.\nmedian_grouped      Median, or 50th percentile, of grouped data.\nmode                Mode (most common value) of data.\nmultimode           List of modes (most common values of data).\nquantiles           Divide data into intervals with equal probability.\n==================  ==================================================\n\nCalculate the arithmetic mean ("the average") of data:\n\n>>> mean([-1.0, 2.5, 3.25, 5.75])\n2.625\n\n\nCalculate the standard median of discrete data:\n\n>>> median([2, 3, 4, 5])\n3.5\n\n\nCalculate the median, or 50th percentile, of data grouped into class intervals\ncentred on the data values provided. E.g. if your data points are rounded to\nthe nearest whole number:\n\n>>> median_grouped([2, 2, 3, 3, 3, 4])  #doctest: +ELLIPSIS\n2.8333333333...\n\nThis should be interpreted in this way: you have two data points in the class\ninterval 1.5-2.5, three data points in the class interval 2.5-3.5, and one in\nthe class interval 3.5-4.5. The median of these data points is 2.8333...\n\n\nCalculating variability or spread\n---------------------------------\n\n==================  =============================================\nFunction            Description\n==================  =============================================\npvariance           Population variance of data.\nvariance            Sample variance of data.\npstdev              Population standard deviation of data.\nstdev               Sample standard deviation of data.\n==================  =============================================\n\nCalculate the standard deviation of sample data:\n\n>>> stdev([2.5, 3.25, 5.5, 11.25, 11.75])  #doctest: +ELLIPSIS\n4.38961843444...\n\nIf you have previously calculated the mean, you can pass it as the optional\nsecond argument to the four "spread" functions to avoid recalculating it:\n\n>>> data = [1, 2, 2, 4, 4, 4, 5, 6]\n>>> mu = mean(data)\n>>> pvariance(data, mu)\n2.5\n\n\nExceptions\n----------\n\nA single exception is defined: StatisticsError is a subclass of ValueError.\n\n'
__all__ = [
    'NormalDist',
    'StatisticsError',
    'fmean',
    'geometric_mean',
    'harmonic_mean',
    'mean',
    'median',
    'median_grouped',
    'median_high',
    'median_low',
    'mode',
    'multimode',
    'pstdev',
    'pvariance',
    'quantiles',
    'stdev',
    'variance']
import math
import numbers
import random
from fractions import Fraction
from decimal import Decimal
from itertools import groupby
from bisect import bisect_left, bisect_right
from math import hypot, sqrt, fabs, exp, erf, tau, log, fsum
from operator import itemgetter
from collections import Counter

class StatisticsError(ValueError):
    pass


def _sum(data, start = (0,)):
    '''_sum(data [, start]) -> (type, sum, count)

    Return a high-precision sum of the given numeric data as a fraction,
    together with the type to be converted to and the count of items.

    If optional argument ``start`` is given, it is added to the total.
    If ``data`` is empty, ``start`` (defaulting to 0) is returned.


    Examples
    --------

    >>> _sum([3, 2.25, 4.5, -0.5, 1.0], 0.75)
    (<class \'float\'>, Fraction(11, 1), 5)

    Some sources of round-off error will be avoided:

    # Built-in sum returns zero.
    >>> _sum([1e50, 1, -1e50] 