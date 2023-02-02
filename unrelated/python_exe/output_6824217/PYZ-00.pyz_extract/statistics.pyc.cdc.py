
__doc__ = '\nBasic statistics module.\n\nThis module provides functions for calculating statistics of data, including\naverages, variance, and standard deviation.\n\nCalculating averages\n--------------------\n\n==================  ==================================================\nFunction            Description\n==================  ==================================================\nmean                Arithmetic mean (average) of data.\nfmean               Fast, floating point arithmetic mean.\ngeometric_mean      Geometric mean of data.\nharmonic_mean       Harmonic mean of data.\nmedian              Median (middle value) of data.\nmedian_low          Low median of data.\nmedian_high         High median of data.\nmedian_grouped      Median, or 50th percentile, of grouped data.\nmode                Mode (most common value) of data.\nmultimode           List of modes (most common values of data).\nquantiles           Divide data into intervals with equal probability.\n==================  ==================================================\n\nCalculate the arithmetic mean ("the average") of data:\n\n>>> mean([-1.0, 2.5, 3.25, 5.75])\n2.625\n\n\nCalculate the standard median of discrete data:\n\n>>> median([2, 3, 4, 5])\n3.5\n\n\nCalculate the median, or 50th percentile, of data grouped into class intervals\ncentred on the data values provided. E.g. if your data points are rounded to\nthe nearest whole number:\n\n>>> median_grouped([2, 2, 3, 3, 3, 4])  #doctest: +ELLIPSIS\n2.8333333333...\n\nThis should be interpreted in this way: you have two data points in the class\ninterval 1.5-2.5, three data points in the class interval 2.5-3.5, and one in\nthe class interval 3.5-4.5. The median of these data points is 2.8333...\n\n\nCalculating variability or spread\n---------------------------------\n\n==================  =============================================\nFunction            Description\n==================  =============================================\npvariance           Population variance of data.\nvariance            Sample variance of data.\npstdev              Population standard deviation of data.\nstdev               Sample standard deviation of data.\n==================  =============================================\n\nCalculate the standard deviation of sample data:\n\n>>> stdev([2.5, 3.25, 5.5, 11.25, 11.75])  #doctest: +ELLIPSIS\n4.38961843444...\n\nIf you have previously calculated the mean, you can pass it as the optional\nsecond argument to the four "spread" functions to avoid recalculating it:\n\n>>> data = [1, 2, 2, 4, 4, 4, 5, 6]\n>>> mu = mean(data)\n>>> pvariance(data, mu)\n2.5\n\n\nStatistics for relations between two inputs\n-------------------------------------------\n\n==================  ====================================================\nFunction            Description\n==================  ====================================================\ncovariance          Sample covariance for two variables.\ncorrelation         Pearson\'s correlation coefficient for two variables.\nlinear_regression   Intercept and slope for simple linear regression.\n==================  ====================================================\n\nCalculate covariance, Pearson\'s correlation, and simple linear regression\nfor two inputs:\n\n>>> x = [1, 2, 3, 4, 5, 6, 7, 8, 9]\n>>> y = [1, 2, 3, 1, 2, 3, 1, 2, 3]\n>>> covariance(x, y)\n0.75\n>>> correlation(x, y)  #doctest: +ELLIPSIS\n0.31622776601...\n>>> linear_regression(x, y)  #doctest:\nLinearRegression(slope=0.1, intercept=1.5)\n\n\nExceptions\n----------\n\nA single exception is defined: StatisticsError is a subclass of ValueError.\n\n'
__all__ = [
    'NormalDist',
    'StatisticsError',
    'correlation',
    'covariance',
    'fmean',
    'geometric_mean',
    'harmonic_mean',
    'linear_regression',
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
from itertools import groupby, repeat
from bisect import bisect_left, bisect_right
from math import hypot, sqrt, fabs, exp, erf, tau, log, fsum
from operator import itemgetter
from collections import Counter, namedtuple

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
    >>> _sum([1e50, 1, -1e50] * 1000)
    (<class \'float\'>, Fraction(1000, 1), 3000)

    Fractions and Decimals are also supported:

    >>> from fractions import Fraction as F
    >>> _sum([F(2, 3), F(7, 5), F(1, 4), F(5, 6)])
    (<class \'fractions.Fraction\'>, Fraction(63, 20), 4)

    >>> from decimal import Decimal as D
    >>> data = [D("0.1375"), D("0.2108"), D("0.3061"), D("0.0419")]
    >>> _sum(data)
    (<class \'decimal.Decimal\'>, Fraction(6963, 10000), 4)

    Mixed types are currently treated as an error, except that int is
    allowed.
    '''
    count = 0
    (n, d) = _exact_ratio(start)
    partials = {
        d: n }
    partials_get = partials.get
    T = _coerce(int, type(start))
# WARNING: Decompyle incomplete


def _isfinite(x):
    pass
# WARNING: Decompyle incomplete


def _coerce(T, S):
    '''Coerce types T and S to a common type, or raise TypeError.

    Coercion rules are currently an implementation detail. See the CoerceTest
    test class in test_statistics for details.
    '''
    pass
# WARNING: Decompyle incomplete


def _exact_ratio(x):
    '''Return Real number x to exact (numerator, denominator) pair.

    >>> _exact_ratio(0.25)
    (1, 4)

    x is expected to be an int, Fraction, Decimal or float.
    '''
    pass
# WARNING: Decompyle incomplete


def _convert(value, T):
    '''Convert value to given numeric type T.'''
    if type(value) is T:
        return value
    if None(T, int) and value.denominator != 1:
        T = float
# WARNING: Decompyle incomplete


def _find_lteq(a, x):
    '''Locate the leftmost value exactly equal to x'''
    i = bisect_left(a, x)
    if i != len(a) and a[i] == x:
        return i
    raise None


def _find_rteq(a, l, x):
    '''Locate the rightmost value exactly equal to x'''
    i = bisect_right(a, x, l, **('lo',))
    if i != len(a) + 1 and a[i - 1] == x:
        return i - 1
    raise None


def _fail_neg(values, errmsg = ('negative value',)):
    '''Iterate over values, failing if any are less than zero.'''
    pass
# WARNING: Decompyle incomplete


def mean(data):
    '''Return the sample arithmetic mean of data.

    >>> mean([1, 2, 3, 4, 4])
    2.8

    >>> from fractions import Fraction as F
    >>> mean([F(3, 7), F(1, 21), F(5, 3), F(1, 3)])
    Fraction(13, 21)

    >>> from decimal import Decimal as D
    >>> mean([D("0.5"), D("0.75"), D("0.625"), D("0.375")])
    Decimal(\'0.5625\')

    If ``data`` is empty, StatisticsError will be raised.
    '''
    if iter(data) is data:
        data = list(data)
    n = len(data)
    if n < 1:
        raise StatisticsError('mean requires at least one data point')
    (T, total, count) = None(data)
# WARNING: Decompyle incomplete


def fmean(data):
    '''Convert data to floats and compute the arithmetic mean.

    This runs faster than the mean() function and it always returns a float.
    If the input dataset is empty, it raises a StatisticsError.

    >>> fmean([3.5, 4.0, 5.25])
    4.25
    '''
    pass
# WARNING: Decompyle incomplete


def geometric_mean(data):
    '''Convert data to floats and compute the geometric mean.

    Raises a StatisticsError if the input dataset is empty,
    if it contains a zero, or if it contains a negative value.

    No special efforts are made to achieve exact results.
    (However, this may change in the future.)

    >>> round(geometric_mean([54, 24, 36]), 9)
    36.0
    '''
    pass
# WARNING: Decompyle incomplete


def harmonic_mean(data, weights = (None,)):
    '''Return the harmonic mean of data.

    The harmonic mean is the reciprocal of the arithmetic mean of the
    reciprocals of the data.  It can be used for averaging ratios or
    rates, for example speeds.

    Suppose a car travels 40 km/hr for 5 km and then speeds-up to
    60 km/hr for another 5 km. What is the average speed?

        >>> harmonic_mean([40, 60])
        48.0

    Suppose a car travels 40 km/hr for 5 km, and when traffic clears,
    speeds-up to 60 km/hr for the remaining 30 km of the journey. What
    is the average speed?

        >>> harmonic_mean([40, 60], weights=[5, 30])
        56.0

    If ``data`` is empty, or any element is less than zero,
    ``harmonic_mean`` will raise ``StatisticsError``.
    '''
    if iter(data) is data:
        data = list(data)
    errmsg = 'harmonic mean does not support negative values'
    n = len(data)
    if n < 1:
        raise StatisticsError('harmonic_mean requires at least one data point')
    if None == 1 and weights is None:
        x = data[0]
        if isinstance(x, (numbers.Real, Decimal)):
            if x < 0:
                raise StatisticsError(errmsg)
            return None
        raise None('unsupported type')
    if None is None:
        weights = repeat(1, n)
        sum_weights = n
    elif iter(weights) is weights:
        weights = list(weights)
    if len(weights) != n:
        raise StatisticsError('Number of weights does not match data size')
    (_, sum_weights, _) = None((lambda .0: pass# WARNING: Decompyle incomplete
)(_fail_neg(weights, errmsg)))
# WARNING: Decompyle incomplete


def median(data):
    '''Return the median (middle value) of numeric data.

    When the number of data points is odd, return the middle data point.
    When the number of data points is even, the median is interpolated by
    taking the average of the two middle values:

    >>> median([1, 3, 5])
    3
    >>> median([1, 3, 5, 7])
    4.0

    '''
    data = sorted(data)
    n = len(data)
    if n == 0:
        raise StatisticsError('no median for empty data')
    if None % 2 == 1:
        return data[n // 2]
    i = None // 2
    return (data[i - 1] + data[i]) / 2


def median_low(data):
    '''Return the low median of numeric data.

    When the number of data points is odd, the middle value is returned.
    When it is even, the smaller of the two middle values is returned.

    >>> median_low([1, 3, 5])
    3
    >>> median_low([1, 3, 5, 7])
    3

    '''
    data = sorted(data)
    n = len(data)
    if n == 0:
        raise StatisticsError('no median for empty data')
    if None % 2 == 1:
        return data[n // 2]
    return None[n // 2 - 1]


def median_high(data):
    '''Return the high median of data.

    When the number of data points is odd, the middle value is returned.
    When it is even, the larger of the two middle values is returned.

    >>> median_high([1, 3, 5])
    3
    >>> median_high([1, 3, 5, 7])
    5

    '''
    data = sorted(data)
    n = len(data)
    if n == 0:
        raise StatisticsError('no median for empty data')
    return None[n // 2]


def median_grouped(data, interval = (1,)):
    '''Return the 50th percentile (median) of grouped continuous data.

    >>> median_grouped([1, 2, 2, 3, 4, 4, 4, 4, 4, 5])
    3.7
    >>> median_grouped([52, 52, 53, 54])
    52.5

    This calculates the median as the 50th percentile, and should be
    used when your data is continuous and grouped. In the above example,
    the values 1, 2, 3, etc. actually represent the midpoint of classes
    0.5-1.5, 1.5-2.5, 2.5-3.5, etc. The middle value falls somewhere in
    class 3.5-4.5, and interpolation is used to estimate it.

    Optional argument ``interval`` represents the class interval, and
    defaults to 1. Changing the class interval naturally will change the
    interpolated 50th percentile value:

    >>> median_grouped([1, 3, 3, 5, 7], interval=1)
    3.25
    >>> median_grouped([1, 3, 3, 5, 7], interval=2)
    3.5

    This function does not check whether the data points are at least
    ``interval`` apart.
    '''
    data = sorted(data)
    n = len(data)
    if n == 0:
        raise StatisticsError('no median for empty data')
    if None == 1:
        return data[0]
    x = None[n // 2]
# WARNING: Decompyle incomplete


def mode(data):
    '''Return the most common data point from discrete or nominal data.

    ``mode`` assumes discrete data, and returns a single value. This is the
    standard treatment of the mode as commonly taught in schools:

        >>> mode([1, 1, 2, 3, 3, 3, 3, 4])
        3

    This also works with nominal (non-numeric) data:

        >>> mode(["red", "blue", "blue", "red", "green", "red", "red"])
        \'red\'

    If there are multiple modes with same frequency, return the first one
    encountered:

        >>> mode([\'red\', \'red\', \'green\', \'blue\', \'blue\'])
        \'red\'

    If *data* is empty, ``mode``, raises StatisticsError.

    '''
    pairs = Counter(iter(data)).most_common(1)
# WARNING: Decompyle incomplete


def multimode(data):
    """Return a list of the most frequently occurring values.

    Will return more than one result if there are multiple modes
    or an empty list if *data* is empty.

    >>> multimode('aabbbbbbbbcc')
    ['b']
    >>> multimode('aabbbbccddddeeffffgg')
    ['b', 'd', 'f']
    >>> multimode('')
    []
    """
    counts = Counter(iter(data)).most_common()
    (maxcount, mode_items) = next(groupby(counts, itemgetter(1), **('key',)), (0, []))
    return list(map(itemgetter(0), mode_items))


def quantiles(data = None, *, n, method):
    '''Divide *data* into *n* continuous intervals with equal probability.

    Returns a list of (n - 1) cut points separating the intervals.

    Set *n* to 4 for quartiles (the default).  Set *n* to 10 for deciles.
    Set *n* to 100 for percentiles which gives the 99 cuts points that
    separate *data* in to 100 equal sized groups.

    The *data* can be any iterable containing sample.
    The cut points are linearly interpolated between data points.

    If *method* is set to *inclusive*, *data* is treated as population
    data.  The minimum value is treated as the 0th percentile and the
    maximum value is treated as the 100th percentile.
    '''
    if n < 1:
        raise StatisticsError('n must be at least 1')
    data = None(data)
    ld = len(data)
    if ld < 2:
        raise StatisticsError('must have at least two data points')
    raise ValueError(f'''Unknown method: {method!r}''')


def _ss(data, c = (None,)):
    '''Return sum of square deviations of sequence data.

    If ``c`` is None, the mean is calculated in one pass, and the deviations
    from the mean are calculated in a second pass. Otherwise, deviations are
    calculated from ``c`` as given. Use the second case with care, as it can
    lead to garbage results.
    '''
    if c is not None:
        (T, total, count) = None((lambda .0 = None: pass# WARNING: Decompyle incomplete
)(data))
        return (T, total)
    c = None(data)
    (T, total, count) = None((lambda .0 = None: pass# WARNING: Decompyle incomplete
)(data))
    (U, total2, count2) = None((lambda .0 = None: pass# WARNING: Decompyle incomplete
)(data))
# WARNING: Decompyle incomplete


def variance(data, xbar = (None,)):
    '''Return the sample variance of data.

    data should be an iterable of Real-valued numbers, with at least two
    values. The optional argument xbar, if given, should be the mean of
    the data. If it is missing or None, the mean is automatically calculated.

    Use this function when your data is a sample from a population. To
    calculate the variance from the entire population, see ``pvariance``.

    Examples:

    >>> data = [2.75, 1.75, 1.25, 0.25, 0.5, 1.25, 3.5]
    >>> variance(data)
    1.3720238095238095

    If you have already calculated the mean of your data, you can pass it as
    the optional second argument ``xbar`` to avoid recalculating it:

    >>> m = mean(data)
    >>> variance(data, m)
    1.3720238095238095

    This function does not check that ``xbar`` is actually the mean of
    ``data``. Giving arbitrary values for ``xbar`` may lead to invalid or
    impossible results.

    Decimals and Fractions are supported:

    >>> from decimal import Decimal as D
    >>> variance([D("27.5"), D("30.25"), D("30.25"), D("34.5"), D("41.75")])
    Decimal(\'31.01875\')

    >>> from fractions import Fraction as F
    >>> variance([F(1, 6), F(1, 2), F(5, 3)])
    Fraction(67, 108)

    '''
    if iter(data) is data:
        data = list(data)
    n = len(data)
    if n < 2:
        raise StatisticsError('variance requires at least two data points')
    (T, ss) = None(data, xbar)
    return _convert(ss / (n - 1), T)


def pvariance(data, mu = (None,)):
    '''Return the population variance of ``data``.

    data should be a sequence or iterable of Real-valued numbers, with at least one
    value. The optional argument mu, if given, should be the mean of
    the data. If it is missing or None, the mean is automatically calculated.

    Use this function to calculate the variance from the entire population.
    To estimate the variance from a sample, the ``variance`` function is
    usually a better choice.

    Examples:

    >>> data = [0.0, 0.25, 0.25, 1.25, 1.5, 1.75, 2.75, 3.25]
    >>> pvariance(data)
    1.25

    If you have already calculated the mean of the data, you can pass it as
    the optional second argument to avoid recalculating it:

    >>> mu = mean(data)
    >>> pvariance(data, mu)
    1.25

    Decimals and Fractions are supported:

    >>> from decimal import Decimal as D
    >>> pvariance([D("27.5"), D("30.25"), D("30.25"), D("34.5"), D("41.75")])
    Decimal(\'24.815\')

    >>> from fractions import Fraction as F
    >>> pvariance([F(1, 4), F(5, 4), F(1, 2)])
    Fraction(13, 72)

    '''
    if iter(data) is data:
        data = list(data)
    n = len(data)
    if n < 1:
        raise StatisticsError('pvariance requires at least one data point')
    (T, ss) = None(data, mu)
    return _convert(ss / n, T)


def stdev(data, xbar = (None,)):
    '''Return the square root of the sample variance.

    See ``variance`` for arguments and other details.

    >>> stdev([1.5, 2.5, 2.5, 2.75, 3.25, 4.75])
    1.0810874155219827

    '''
    var = variance(data, xbar)
# WARNING: Decompyle incomplete


def pstdev(data, mu = (None,)):
    '''Return the square root of the population variance.

    See ``pvariance`` for arguments and other details.

    >>> pstdev([1.5, 2.5, 2.5, 2.75, 3.25, 4.75])
    0.986893273527251

    '''
    var = pvariance(data, mu)
# WARNING: Decompyle incomplete


def covariance(x, y):
    '''Covariance

    Return the sample covariance of two inputs *x* and *y*. Covariance
    is a measure of the joint variability of two inputs.

    >>> x = [1, 2, 3, 4, 5, 6, 7, 8, 9]
    >>> y = [1, 2, 3, 1, 2, 3, 1, 2, 3]
    >>> covariance(x, y)
    0.75
    >>> z = [9, 8, 7, 6, 5, 4, 3, 2, 1]
    >>> covariance(x, z)
    -7.5
    >>> covariance(z, x)
    -7.5

    '''
    n = len(x)
    if len(y) != n:
        raise StatisticsError('covariance requires that both inputs have same number of data points')
    if None < 2:
        raise StatisticsError('covariance requires at least two data points')
    xbar = None(x) / n
    ybar = fsum(y) / n
    sxy = None((lambda .0 = None: pass# WARNING: Decompyle incomplete
)(zip(x, y)))
    return sxy / (n - 1)


def correlation(x, y):
    """Pearson's correlation coefficient

    Return the Pearson's correlation coefficient for two inputs. Pearson's
    correlation coefficient *r* takes values between -1 and +1. It measures the
    strength and direction of the linear relationship, where +1 means very
    strong, positive linear relationship, -1 very strong, negative linear
    relationship, and 0 no linear relationship.

    >>> x = [1, 2, 3, 4, 5, 6, 7, 8, 9]
    >>> y = [9, 8, 7, 6, 5, 4, 3, 2, 1]
    >>> correlation(x, x)
    1.0
    >>> correlation(x, y)
    -1.0

    """
    n = len(x)
    if len(y) != n:
        raise StatisticsError('correlation requires that both inputs have same number of data points')
    if None < 2:
        raise StatisticsError('correlation requires at least two data points')
    xbar = None(x) / n
    ybar = fsum(y) / n
    sxy = None((lambda .0 = None: pass# WARNING: Decompyle incomplete
)(zip(x, y)))
    sxx = None((lambda .0 = None: pass# WARNING: Decompyle incomplete
)(x))
    syy = None((lambda .0 = None: pass# WARNING: Decompyle incomplete
)(y))
# WARNING: Decompyle incomplete

LinearRegression = namedtuple('LinearRegression', ('slope', 'intercept'))

def linear_regression(x, y):
    '''Slope and intercept for simple linear regression.

    Return the slope and intercept of simple linear regression
    parameters estimated using ordinary least squares. Simple linear
    regression describes relationship between an independent variable
    *x* and a dependent variable *y* in terms of linear function:

        y = slope * x + intercept + noise

    where *slope* and *intercept* are the regression parameters that are
    estimated, and noise represents the variability of the data that was
    not explained by the linear regression (it is equal to the
    difference between predicted and actual values of the dependent
    variable).

    The parameters are returned as a named tuple.

    >>> x = [1, 2, 3, 4, 5]
    >>> noise = NormalDist().samples(5, seed=42)
    >>> y = [3 * x[i] + 2 + noise[i] for i in range(5)]
    >>> linear_regression(x, y)  #doctest: +ELLIPSIS
    LinearRegression(slope=3.09078914170..., intercept=1.75684970486...)

    '''
    n = len(x)
    if len(y) != n:
        raise StatisticsError('linear regression requires that both inputs have same number of data points')
    if None < 2:
        raise StatisticsError('linear regression requires at least two data points')
    xbar = None(x) / n
    ybar = fsum(y) / n
    sxy = None((lambda .0 = None: pass# WARNING: Decompyle incomplete
)(zip(x, y)))
    sxx = None((lambda .0 = None: pass# WARNING: Decompyle incomplete
)(x))
# WARNING: Decompyle incomplete


def _normal_dist_inv_cdf(p, mu, sigma):
    q = p - 0.5
    if fabs(q) <= 0.425:
        r = 0.180625 - q * q
        num = (((((((2509.08 * r + 33430.6) * r + 67265.8) * r + 45922) * r + 13731.7) * r + 1971.59) * r + 133.142) * r + 3.38713) * q
        den = ((((((5226.5 * r + 28729.1) * r + 39307.9) * r + 21213.8) * r + 5394.2) * r + 687.187) * r + 42.3133) * r + 1
        x = num / den
        return mu + x * sigma
    r = p if None <= 0 else 1 - p
    r = sqrt(-log(r))
    if r <= 5:
        r = r - 1.6
        num = ((((((0.000774545 * r + 0.0227238) * r + 0.241781) * r + 1.27046) * r + 3.64785) * r + 5.7695) * r + 4.63034) * r + 1.42344
        den = ((((((1.05075e-09 * r + 0.000547594) * r + 0.0151987) * r + 0.148104) * r + 0.689767) * r + 1.67638) * r + 2.05319) * r + 1
    else:
        r = r - 5
        num = ((((((2.01033e-07 * r + 2.71156e-05) * r + 0.00124266) * r + 0.0265322) * r + 0.296561) * r + 1.78483) * r + 5.46378) * r + 6.6579
        den = ((((((2.04426e-15 * r + 1.42151e-07) * r + 1.84632e-05) * r + 0.000786869) * r + 0.0148754) * r + 0.13693) * r + 0.599832) * r + 1
    x = num / den
    if q < 0:
        x = -x
    return mu + x * sigma

# WARNING: Decompyle incomplete
