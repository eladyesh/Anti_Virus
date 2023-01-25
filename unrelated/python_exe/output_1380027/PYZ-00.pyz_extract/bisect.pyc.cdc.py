
__doc__ = 'Bisection algorithms.'

def insort_right(a, x, lo, hi = (0, None)):
    '''Insert item x in list a, and keep it sorted assuming a is sorted.

    If x is already in a, insert it to the right of the rightmost x.

    Optional args lo (default 0) and hi (default len(a)) bound the
    slice of a to be searched.
    '''
    lo = bisect_right(a, x, lo, hi)
    a.insert(lo, x)


def bisect_right(a, x, lo, hi = (0, None)):
    '''Return the index where to insert item x in list a, assuming a is sorted.

    The return value i is such that all e in a[:i] have e <= x, and all e in
    a[i:] have e > x.  So if x already appears in the list, a.insert(x) will
    insert just after the rightmost x already there.

    Optional args lo (default 0) and hi (default len(a)) bound the
    slice of a to be searched.
    '''
    if lo < 0:
        raise ValueError('lo must be non-negative')
    if None is None:
        hi = len(a)
        if lo < hi:
            mid = (lo + hi) // 2
            if x < a[mid]:
                hi = mid
                continue
                lo = mid + 1
                continue
                return lo


def insort_left(a, x, lo, hi = (0, None)):
    '''Insert item x in list a, and keep it sorted assuming a is sorted.

    If x is already in a, insert it to the left of the leftmost x.

    Optional args lo (default 0) and hi (default len(a)) bound the
    slice of a to be searched.
    '''
    lo = bisect_left(a, x, lo, hi)
    a.insert(lo, x)


def bisect_left(a, x, lo, hi = (0, None)):
    '''Return the index where to insert item x in list a, assuming a is sorted.

    The return value i is such that all e in a[:i] have e < x, and all e in
    a[i:] have e >= x.  So if x already appears in the list, a.insert(x) will
    insert just before the leftmost x already there.

    Optional args lo (default 0) and hi (default len(a)) bound the
    slice of a to be searched.
    '''
    if lo < 0:
        raise ValueError('lo must be non-negative')
    if None is None:
        hi = len(a)
        if lo < hi:
            mid = (lo + hi) // 2
            if a[mid] < x:
                lo = mid + 1
                continue
                hi = mid
                continue
                return lo

# WARNING: Decompyle incomplete
