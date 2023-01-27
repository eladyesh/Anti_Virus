
from collections.abc import Sequence, Iterable
from functools import total_ordering
import fnmatch
import linecache
import os.path as os
import pickle
from _tracemalloc import *
from _tracemalloc import _get_object_traceback, _get_traces

def _format_size(size, sign):
    pass


class Statistic:
    '''
    Statistic difference on memory allocations between two Snapshot instance.
    '''
    __slots__ = ('traceback', 'size', 'count')
    
    def __init__(self, traceback, size, count):
        self.traceback = traceback
        self.size = size
        self.count = count

    
    def __hash__(self):
        return hash((self.traceback, self.size, self.count))

    
    def __eq__(self, other):
        if not isinstance(other, Statistic):
            return NotImplemented
        if None.traceback == other.traceback and self.size == other.size:
            return self.count == other.count

    
    def __str__(self):
        text = '%s: size=%s, count=%i' % (self.traceback, _format_size(self.size, False), self.count)
        if self.count:
            average = self.size / self.count
            text += ', average=%s' % _format_size(average, False)
            return text

    
    def __repr__(self):
        return '<Statistic traceback=%r size=%i count=%i>' % (self.traceback, self.size, self.count)

    
    def _sort_key(self):
        return (self.size, self.count, self.traceback)



class StatisticDiff:
    '''
    Statistic difference on memory allocations between an old and a new
    Snapshot instance.
    '''
    __slots__ = ('traceback', 'size', 'size_diff', 'count', 'count_diff')
    
    def __init__(self, traceback, size, size_diff, count, count_diff):
        self.traceback = traceback
        self.size = size
        self.size_diff = size_diff
        self.count = count
        self.count_diff = count_diff

    
    def __hash__(self):
        return hash((self.traceback, self.size, self.size_diff, self.count, self.count_diff))

    
    def __eq__(self, other):
        if not isinstance(other, StatisticDiff):
            return NotImplemented
        if None.traceback == other.traceback and self.size == other.size and self.size_diff == other.size_diff and self.count == other.count:
            return self.count_diff == other.count_diff

    
    def __str__(self):
        text = '%s: size=%s (%s), count=%i (%+i)' % (self.traceback, _format_size(self.size, False), _format_size(self.size_diff, True), self.count, self.count_diff)
        if self.count:
            average = self.size / self.count
            text += ', average=%s' % _format_size(average, False)
            return text

    
    def __repr__(self):
        return '<StatisticDiff traceback=%r size=%i (%+i) count=%i (%+i)>' % (self.traceback, self.size, self.size_diff, self.count, self.count_diff)

    
    def _sort_key(self):
        return (abs(self.size_diff), self.size, abs(self.count_diff), self.count, self.traceback)



def _compare_grouped_stats(old_group, new_group):
    statistics = []
    for traceback, stat in new_group.items():
        previous = old_group.pop(traceback, None)
        stat = StatisticDiff(traceback, stat.size, stat.size - previous.size, stat.count, stat.count - previous.count)
    stat = StatisticDiff(traceback, stat.size, stat.size, stat.count, stat.count)
    statistics.append(stat)
    continue
    for traceback, stat in old_group.items():
        stat = StatisticDiff(traceback, 0, -(stat.size), 0, -(stat.count))
        statistics.append(stat)

Frame = total_ordering(<NODE:12>)
Traceback = total_ordering(<NODE:12>)

def get_object_traceback(obj):
    '''
    Get the traceback where the Python object *obj* was allocated.
    Return a Traceback instance.

    Return None if the tracemalloc module is not tracing memory allocations or
    did not trace the allocation of the object.
    '''
    frames = _get_object_traceback(obj)
    if frames is not None:
        return Traceback(frames)
    return None


class Trace:
    '''
    Trace of a memory block.
    '''
    __slots__ = ('_trace',)
    
    def __init__(self, trace):
        self._trace = trace

    
    def domain(self):
        return self._trace[0]

    domain = property(domain)
    
    def size(self):
        return self._trace[1]

    size = property(size)
    
    def traceback(self):
        pass
    # WARNING: Decompyle incomplete

    traceback = property(traceback)
    
    def __eq__(self, other):
        if not isinstance(other, Trace):
            return NotImplemented
        return None._trace == other._trace

    
    def __hash__(self):
        return hash(self._trace)

    
    def __str__(self):
        return '%s: %s' % (self.traceback, _format_size(self.size, False))

    
    def __repr__(self):
        return '<Trace domain=%s size=%s, traceback=%r>' % (self.domain, _format_size(self.size, False), self.traceback)



class _Traces(Sequence):
    
    def __init__(self, traces):
        Sequence.__init__(self)
        self._traces = traces

    
    def __len__(self):
        return len(self._traces)

    
    def __getitem__(self, index):
        if isinstance(index, slice):
            return tuple((lambda .0: pass)(self._traces[index]))
        return None(self._traces[index])

    
    def __contains__(self, trace):
        return trace._trace in self._traces

    
    def __eq__(self, other):
        if not isinstance(other, _Traces):
            return NotImplemented
        return None._traces == other._traces

    
    def __repr__(self):
        return '<Traces len=%s>' % len(self)



def _normalize_filename(filename):
    filename = os.path.normcase(filename)
    if filename.endswith('.pyc'):
        filename = filename[:-1]
        return filename


class BaseFilter:
    
    def __init__(self, inclusive):
        self.inclusive = inclusive

    
    def _match(self, trace):
        raise NotImplementedError



class Filter(BaseFilter):
    
    def __init__(self = None, inclusive = None, filename_pattern = None, lineno = None, all_frames = None, domain = None):
        super().__init__(inclusive)
        self.inclusive = inclusive
        self._filename_pattern = _normalize_filename(filename_pattern)
        self.lineno = lineno
        self.all_frames = all_frames
        self.domain = domain

    
    def filename_pattern(self):
        return self._filename_pattern

    filename_pattern = property(filename_pattern)
    
    def _match_frame_impl(self, filename, lineno):
        filename = _normalize_filename(filename)
        if not fnmatch.fnmatch(filename, self._filename_pattern):
            return False
        if None.lineno is None:
            return True
        return None == self.lineno

    
    def _match_frame(self, filename, lineno):
        return self._match_frame_impl(filename, lineno) ^ (not (self.inclusive))

    
    def _match_traceback(self, traceback):
        if self.all_frames:
            if None((lambda .0 = None: pass)(traceback)):
                return self.inclusive
            return not (None.inclusive)
        (filename, lineno) = traceback[0]
        return self._match_frame(filename, lineno)

    
    def _match(self, trace):
        (domain, size, traceback, total_nframe) = trace
        res = self._match_traceback(traceback)
        if self.domain is not None:
            if self.inclusive:
                if res:
                    return domain == self.domain
                if not res:
                    return domain != self.domain
                return res

    __classcell__ = None


class DomainFilter(BaseFilter):
    
    def __init__(self = None, inclusive = None, domain = None):
        super().__init__(inclusive)
        self._domain = domain

    
    def domain(self):
        return self._domain

    domain = property(domain)
    
    def _match(self, trace):
        (domain, size, traceback, total_nframe) = trace
        return (domain == self.domain) ^ (not (self.inclusive))

    __classcell__ = None


class Snapshot:
    '''
    Snapshot of traces of memory blocks allocated by Python.
    '''
    
    def __init__(self, traces, traceback_limit):
        self.traces = _Traces(traces)
        self.traceback_limit = traceback_limit

    
    def dump(self, filename):
        '''
        Write the snapshot into a file.
        '''
        with open(filename, 'wb') as fp:
            pickle.dump(self, fp, pickle.HIGHEST_PROTOCOL)
            None(None, None, None)
    # WARNING: Decompyle incomplete

    
    def load(filename):
        '''
        Load a snapshot from a file.
        '''
        pass
    # WARNING: Decompyle incomplete

    load = staticmethod(load)
    
    def _filter_trace(self, include_filters, exclude_filters, trace):
        if not include_filters and None((lambda .0 = None: pass)(include_filters)):
            return False
        if None and None((lambda .0 = None: pass)(exclude_filters)):
            return False

    
    def filter_traces(self, filters):
        '''
        Create a new Snapshot instance with a filtered traces sequence, filters
        is a list of Filter or DomainFilter instances.  If filters is an empty
        list, return a new Snapshot instance with a copy of the traces.
        '''
        if not isinstance(filters, Iterable):
            raise TypeError('filters must be a list of filters, not %s' % type(filters).__name__)
        if None:
            include_filters = []
            exclude_filters = []
            for trace_filter in filters:
                include_filters.append(trace_filter)
            exclude_filters.append(trace_filter)
            new_traces = (lambda .0 = None: [ trace for trace in .0 if self._filter_trace(include_filters, exclude_filters, trace) ])(self.traces._traces)
        else:
            new_traces = self.traces._traces.copy()
            return Snapshot(new_traces, self.traceback_limit)

    
    def _group_by(self, key_type, cumulative):
        if key_type not in ('traceback', 'filename', 'lineno'):
            raise ValueError('unknown key_type: %r' % (key_type,))
        if None and key_type not in ('lineno', 'filename'):
            raise ValueError('cumulative mode cannot by used with key type %r' % key_type)
        stats = None
        tracebacks = { }
    # WARNING: Decompyle incomplete

    
    def statistics(self, key_type, cumulative = (False,)):
        '''
        Group statistics by key_type. Return a sorted list of Statistic
        instances.
        '''
        grouped = self._group_by(key_type, cumulative)
        statistics = list(grouped.values())
        statistics.sort(True, Statistic._sort_key, **('reverse', 'key'))
        return statistics

    
    def compare_to(self, old_snapshot, key_type, cumulative = (False,)):
        '''
        Compute the differences with an old snapshot old_snapshot. Get
        statistics as a sorted list of StatisticDiff instances, grouped by
        group_by.
        '''
        new_group = self._group_by(key_type, cumulative)
        old_group = old_snapshot._group_by(key_type, cumulative)
        statistics = _compare_grouped_stats(old_group, new_group)
        statistics.sort(True, StatisticDiff._sort_key, **('reverse', 'key'))
        return statistics



def take_snapshot():
    '''
    Take a snapshot of traces of memory blocks allocated by Python.
    '''
    if not is_tracing():
        raise RuntimeError('the tracemalloc module must be tracing memory allocations to take a snapshot')
    traces = None()
    traceback_limit = get_traceback_limit()
    return Snapshot(traces, traceback_limit)

