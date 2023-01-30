
"""
Logging package for Python. Based on PEP 282 and comments thereto in
comp.lang.python.

Copyright (C) 2001-2019 Vinay Sajip. All Rights Reserved.

To use, simply 'import logging' and log away!
"""
import sys
import os
import time
import io
import re
import traceback
import warnings
import weakref
import collections.abc as collections
from string import Template
from string import Formatter as StrFormatter
__all__ = [
    'BASIC_FORMAT',
    'BufferingFormatter',
    'CRITICAL',
    'DEBUG',
    'ERROR',
    'FATAL',
    'FileHandler',
    'Filter',
    'Formatter',
    'Handler',
    'INFO',
    'LogRecord',
    'Logger',
    'LoggerAdapter',
    'NOTSET',
    'NullHandler',
    'StreamHandler',
    'WARN',
    'WARNING',
    'addLevelName',
    'basicConfig',
    'captureWarnings',
    'critical',
    'debug',
    'disable',
    'error',
    'exception',
    'fatal',
    'getLevelName',
    'getLogger',
    'getLoggerClass',
    'info',
    'log',
    'makeLogRecord',
    'setLoggerClass',
    'shutdown',
    'warn',
    'warning',
    'getLogRecordFactory',
    'setLogRecordFactory',
    'lastResort',
    'raiseExceptions']
import threading
__author__ = 'Vinay Sajip <vinay_sajip@red-dove.com>'
__status__ = 'production'
__version__ = '0.5.1.2'
__date__ = '07 February 2010'
_startTime = time.time()
raiseExceptions = True
logThreads = True
logMultiprocessing = True
logProcesses = True
CRITICAL = 50
FATAL = CRITICAL
ERROR = 40
WARNING = 30
WARN = WARNING
INFO = 20
DEBUG = 10
NOTSET = 0
_levelToName = {
    NOTSET: 'NOTSET',
    DEBUG: 'DEBUG',
    INFO: 'INFO',
    WARNING: 'WARNING',
    ERROR: 'ERROR',
    CRITICAL: 'CRITICAL' }
_nameToLevel = {
    'CRITICAL': CRITICAL,
    'FATAL': FATAL,
    'ERROR': ERROR,
    'WARN': WARNING,
    'WARNING': WARNING,
    'INFO': INFO,
    'DEBUG': DEBUG,
    'NOTSET': NOTSET }

def getLevelName(level):
    """
    Return the textual or numeric representation of logging level 'level'.

    If the level is one of the predefined levels (CRITICAL, ERROR, WARNING,
    INFO, DEBUG) then you get the corresponding string. If you have
    associated levels with names using addLevelName then the name you have
    associated with 'level' is returned.

    If a numeric value corresponding to one of the defined levels is passed
    in, the corresponding string representation is returned.

    If a string representation of the level is passed in, the corresponding
    numeric value is returned.

    If no matching numeric or string value is passed in, the string
    'Level %s' % level is returned.
    """
    result = _levelToName.get(level)
    if result is not None:
        return result
    result = None.get(level)
    if result is not None:
        return result
    return None % level


def addLevelName(level, levelName):
    """
    Associate 'levelName' with 'level'.

    This is used when converting levels to text during message formatting.
    """
    _acquireLock()
# WARNING: Decompyle incomplete

if hasattr(sys, '_getframe'):
    
    currentframe = lambda : sys._getframe(3)
else:
    
    def currentframe():
        """Return the frame object for the caller's stack frame."""
        pass
    # WARNING: Decompyle incomplete

_srcfile = os.path.normcase(addLevelName.__code__.co_filename)

def _checkLevel(level):
    if isinstance(level, int):
        rv = level
        return rv
    if None(level) == level:
        if level not in _nameToLevel:
            raise ValueError('Unknown level: %r' % level)
        rv = None[level]
        return rv
    raise None('Level not an integer or a valid string: %r' % (level,))

_lock = threading.RLock()

def _acquireLock():
    '''
    Acquire the module-level lock for serializing access to shared data.

    This should be released with _releaseLock().
    '''
    if _lock:
        _lock.acquire()
        return None


def _releaseLock():
    '''
    Release the module-level lock acquired by calling _acquireLock().
    '''
    if _lock:
        _lock.release()
        return None

if not hasattr(os, 'register_at_fork'):
    
    def _register_at_fork_reinit_lock(instance):
        pass

else:
    _at_fork_reinit_lock_weakset = weakref.WeakSet()
    
    def _register_at_fork_reinit_lock(instance):
        _acquireLock()
    # WARNING: Decompyle incomplete

    
    def _after_at_fork_child_reinit_locks():
        _lock._at_fork_reinit()

    os.register_at_fork(_acquireLock, _after_at_fork_child_reinit_locks, _releaseLock, **('before', 'after_in_child', 'after_in_parent'))

class LogRecord(object):
    '''
    A LogRecord instance represents an event being logged.

    LogRecord instances are created every time something is logged. They
    contain all the information pertinent to the event being logged. The
    main information passed in is in msg and args, which are combined
    using str(msg) % args to create the message field of the record. The
    record also includes information such as when the record was created,
    the source line where the logging call was made, and any exception
    information to be logged.
    '''
    
    def __init__(self, name, level, pathname, lineno, msg, args, exc_info, func, sinfo = (None, None), **kwargs):
        '''
        Initialize a logging record with interesting information.
        '''
        ct = time.time()
        self.name = name
        self.msg = msg
        if args and len(args) == 1 and isinstance(args[0], collections.abc.Mapping) and args[0]:
            args = args[0]
        self.args = args
        self.levelname = getLevelName(level)
        self.levelno = level
        self.pathname = pathname
    # WARNING: Decompyle incomplete

    
    def __repr__(self):
        return '<LogRecord: %s, %s, %s, %s, "%s">' % (self.name, self.levelno, self.pathname, self.lineno, self.msg)

    
    def getMessage(self):
        '''
        Return the message for this LogRecord.

        Return the message for this LogRecord after merging any user-supplied
        arguments with the message.
        '''
        msg = str(self.msg)
        if self.args:
            msg = msg % self.args
        return msg


_logRecordFactory = LogRecord

def setLogRecordFactory(factory):
    '''
    Set the factory to be used when instantiating a log record.

    :param factory: A callable which will be called to instantiate
    a log record.
    '''
    global _logRecordFactory
    _logRecordFactory = factory


def getLogRecordFactory():
    '''
    Return the factory to be used when instantiating a log record.
    '''
    return _logRecordFactory


def makeLogRecord(dict):
    '''
    Make a LogRecord whose attributes are defined by the specified dictionary,
    This function is useful for converting a logging event received over
    a socket connection (which is sent as a dictionary) into a LogRecord
    instance.
    '''
    rv = _logRecordFactory(None, None, '', 0, '', (), None, None)
    rv.__dict__.update(dict)
    return rv

_str_formatter = StrFormatter()
del StrFormatter

class PercentStyle(object):
    default_format = '%(message)s'
    asctime_format = '%(asctime)s'
    asctime_search = '%(asctime)'
    validation_pattern = re.compile('%\\(\\w+\\)[#0+ -]*(\\*|\\d+)?(\\.(\\*|\\d+))?[diouxefgcrsa%]', re.I)
    
    def __init__(self = None, fmt = {
        'defaults': None }, *, defaults):
        if not fmt:
            pass
        self._fmt = self.default_format
        self._defaults = defaults

    
    def usesTime(self):
        return self._fmt.find(self.asctime_search) >= 0

    
    def validate(self):
        '''Validate the input format, ensure it matches the correct style'''
        if not self.validation_pattern.search(self._fmt):
            raise ValueError("Invalid format '%s' for '%s' style" % (self._fmt, self.default_format[0]))

    
    def _format(self, record):
        return self._fmt % values

    
    def format(self, record):
        pass
    # WARNING: Decompyle incomplete



class StrFormatStyle(PercentStyle):
    default_format = '{message}'
    asctime_format = '{asctime}'
    asctime_search = '{asctime'
    fmt_spec = re.compile('^(.?[<>=^])?[+ -]?#?0?(\\d+|{\\w+})?[,_]?(\\.(\\d+|{\\w+}))?[bcdefgnosx%]?$', re.I)
    field_spec = re.compile('^(\\d+|\\w+)(\\.\\w+|\\[[^]]+\\])*$')
    
    def _format(self, record):
        pass
    # WARNING: Decompyle incomplete

    
    def validate(self):
        '''Validate the input format, ensure it is the correct string formatting style'''
        fields = set()
    # WARNING: Decompyle incomplete



class StringTemplateStyle(PercentStyle):
    default_format = '${message}'
    asctime_format = '${asctime}'
    asctime_search = '${asctime}'
    
    def __init__(self = None, *args, **kwargs):
        pass
    # WARNING: Decompyle incomplete

    
    def usesTime(self):
        fmt = self._fmt
        if not fmt.find('$asctime') >= 0:
            pass
        return fmt.find(self.asctime_format) >= 0

    
    def validate(self):
        pattern = Template.pattern
        fields = set()
        if d['braced']:
            fields.add(d['braced'])
            continue
        if m.group(0) == '$':
            raise ValueError("invalid format: bare '$' not allowed")
        if not fields:
            raise ValueError('invalid format: no fields')
        return [ d['named'] for m in pattern.finditer(self._fmt) if d['named'] ]

    
    def _format(self, record):
        pass
    # WARNING: Decompyle incomplete

    __classcell__ = None

BASIC_FORMAT = '%(levelname)s:%(name)s:%(message)s'
_STYLES = {
    '%': (PercentStyle, BASIC_FORMAT),
    '{': (StrFormatStyle, '{levelname}:{name}:{message}'),
    '$': (StringTemplateStyle, '${levelname}:${name}:${message}') }

class Formatter(object):
    '''
    Formatter instances are used to convert a LogRecord to text.

    Formatters need to know how a LogRecord is constructed. They are
    responsible for converting a LogRecord to (usually) a string which can
    be interpreted by either a human or an external system. The base Formatter
    allows a formatting string to be specified. If none is supplied, the
    style-dependent default value, "%(message)s", "{message}", or
    "${message}", is used.

    The Formatter can be initialized with a format string which makes use of
    knowledge of the LogRecord attributes - e.g. the default value mentioned
    above makes use of the fact that the user\'s message and arguments are pre-
    formatted into a LogRecord\'s message attribute. Currently, the useful
    attributes in a LogRecord are described by:

    %(name)s            Name of the logger (logging channel)
    %(levelno)s         Numeric logging level for the message (DEBUG, INFO,
                        WARNING, ERROR, CRITICAL)
    %(levelname)s       Text logging level for the message ("DEBUG", "INFO",
                        "WARNING", "ERROR", "CRITICAL")
    %(pathname)s        Full pathname of the source file where the logging
                        call was issued (if available)
    %(filename)s        Filename portion of pathname
    %(module)s          Module (name portion of filename)
    %(lineno)d          Source line number where the logging call was issued
                        (if available)
    %(funcName)s        Function name
    %(created)f         Time when the LogRecord was created (time.time()
                        return value)
    %(asctime)s         Textual time when the LogRecord was created
    %(msecs)d           Millisecond portion of the creation time
    %(relativeCreated)d Time in milliseconds when the LogRecord was created,
                        relative to the time the logging module was loaded
                        (typically at application startup time)
    %(thread)d          Thread ID (if available)
    %(threadName)s      Thread name (if available)
    %(process)d         Process ID (if available)
    %(message)s         The result of record.getMessage(), computed just as
                        the record is emitted
    '''
    converter = time.localtime
    
    def __init__(self, fmt, datefmt = None, style = (None, None, '%', True), validate = {
        'defaults': None }, *, defaults):
        """
        Initialize the formatter with specified format strings.

        Initialize the formatter either with the specified format string, or a
        default as described above. Allow for specialized date formatting with
        the optional datefmt argument. If datefmt is omitted, you get an
        ISO8601-like (or RFC 3339-like) format.

        Use a style parameter of '%', '{' or '$' to specify that you want to
        use one of %-formatting, :meth:`str.format` (``{}``) formatting or
        :class:`string.Template` formatting in your format string.

        .. versionchanged:: 3.2
           Added the ``style`` parameter.
        """
        if style not in _STYLES:
            raise ValueError('Style must be one of: %s' % ','.join(_STYLES.keys()))
        self._style = None[style][0](fmt, defaults, **('defaults',))
        if validate:
            self._style.validate()
        self._fmt = self._style._fmt
        self.datefmt = datefmt

    default_time_format = '%Y-%m-%d %H:%M:%S'
    default_msec_format = '%s,%03d'
    
    def formatTime(self, record, datefmt = (None,)):
        """
        Return the creation time of the specified LogRecord as formatted text.

        This method should be called from format() by a formatter which
        wants to make use of a formatted time. This method can be overridden
        in formatters to provide for any specific requirement, but the
        basic behaviour is as follows: if datefmt (a string) is specified,
        it is used with time.strftime() to format the creation time of the
        record. Otherwise, an ISO8601-like (or RFC 3339-like) format is used.
        The resulting string is returned. This function uses a user-configurable
        function to convert the creation time to a tuple. By default,
        time.localtime() is used; to change this for a particular formatter
        instance, set the 'converter' attribute to a function with the same
        signature as time.localtime() or time.gmtime(). To change it for all
        formatters, for example if you want all logging times to be shown in GMT,
        set the 'converter' attribute in the Formatter class.
        """
        ct = self.converter(record.created)
        if datefmt:
            s = time.strftime(datefmt, ct)
            return s
        s = None.strftime(self.default_time_format, ct)
        if self.default_msec_format:
            s = self.default_msec_format % (s, record.msecs)
        return s

    
    def formatException(self, ei):
        '''
        Format and return the specified exception information as a string.

        This default implementation just uses
        traceback.print_exception()
        '''
        sio = io.StringIO()
        tb = ei[2]
        traceback.print_exception(ei[0], ei[1], tb, None, sio)
        s = sio.getvalue()
        sio.close()
        if s[-1:] == '\n':
            s = s[:-1]
        return s

    
    def usesTime(self):
        '''
        Check if the format uses the creation time of the record.
        '''
        return self._style.usesTime()

    
    def formatMessage(self, record):
        return self._style.format(record)

    
    def formatStack(self, stack_info):
        '''
        This method is provided as an extension point for specialized
        formatting of stack information.

        The input data is a string as returned from a call to
        :func:`traceback.print_stack`, but with the last trailing newline
        removed.

        The base implementation just returns the value passed in.
        '''
        return stack_info

    
    def format(self, record):
        """
        Format the specified record as text.

        The record's attribute dictionary is used as the operand to a
        string formatting operation which yields the returned string.
        Before formatting the dictionary, a couple of preparatory steps
        are carried out. The message attribute of the record is computed
        using LogRecord.getMessage(). If the formatting string uses the
        time (as determined by a call to usesTime(), formatTime() is
        called to format the event time. If there is exception information,
        it is formatted using formatException() and appended to the message.
        """
        record.message = record.getMessage()
        if self.usesTime():
            record.asctime = self.formatTime(record, self.datefmt)
        s = self.formatMessage(record)
        if not record.exc_info and record.exc_text:
            record.exc_text = self.formatException(record.exc_info)
        if record.exc_text:
            if s[-1:] != '\n':
                s = s + '\n'
            s = s + record.exc_text
        if record.stack_info:
            if s[-1:] != '\n':
                s = s + '\n'
            s = s + self.formatStack(record.stack_info)
        return s


_defaultFormatter = Formatter()

class BufferingFormatter(object):
    '''
    A formatter suitable for formatting a number of records.
    '''
    
    def __init__(self, linefmt = (None,)):
        '''
        Optionally specify a formatter which will be used to format each
        individual record.
        '''
        if linefmt:
            self.linefmt = linefmt
            return None
        self.linefmt = None

    
    def formatHeader(self, records):
        '''
        Return the header string for the specified records.
        '''
        return ''

    
    def formatFooter(self, records):
        '''
        Return the footer string for the specified records.
        '''
        return ''

    
    def format(self, records):
        '''
        Format the specified records and return the result as a string.
        '''
        rv = ''
        if len(records) > 0:
            rv = rv + self.formatHeader(records)
            rv = rv + self.formatFooter(records)
        return rv



class Filter(object):
    '''
    Filter instances are used to perform arbitrary filtering of LogRecords.

    Loggers and Handlers can optionally use Filter instances to filter
    records as desired. The base filter class only allows events which are
    below a certain point in the logger hierarchy. For example, a filter
    initialized with "A.B" will allow events logged by loggers "A.B",
    "A.B.C", "A.B.C.D", "A.B.D" etc. but not "A.BB", "B.A.B" etc. If
    initialized with the empty string, all events are passed.
    '''
    
    def __init__(self, name = ('',)):
        '''
        Initialize a filter.

        Initialize with the name of the logger which, together with its
        children, will have its events allowed through the filter. If no
        name is specified, allow every event.
        '''
        self.name = name
        self.nlen = len(name)

    
    def filter(self, record):
        '''
        Determine if the specified record is to be logged.

        Returns True if the record should be logged, or False otherwise.
        If deemed appropriate, the record may be modified in-place.
        '''
        if self.nlen == 0:
            return True
        if None.name == record.name:
            return True
        if None.name.find(self.name, 0, self.nlen) != 0:
            return False
        return None.name[self.nlen] == '.'



class Filterer(object):
    '''
    A base class for loggers and handlers which allows them to share
    common code.
    '''
    
    def __init__(self):
        '''
        Initialize the list of filters to be an empty list.
        '''
        self.filters = []

    
    def addFilter(self, filter):
        '''
        Add the specified filter to this handler.
        '''
        if filter not in self.filters:
            self.filters.append(filter)
            return None

    
    def removeFilter(self, filter):
        '''
        Remove the specified filter from this handler.
        '''
        if filter in self.filters:
            self.filters.remove(filter)
            return None

    
    def filter(self, record):
        '''
        Determine if a record is loggable by consulting all the filters.

        The default is to allow the record to be logged; any filter can veto
        this and the record is then dropped. Returns a zero value if a record
        is to be dropped, else non-zero.

        .. versionchanged:: 3.2

           Allow filters to be just callables.
        '''
        rv = True
        for f in self.filters:
            result = f.filter(record)
        result = f(record)
        if not result:
            rv = False
            return rv
        return rv


_handlers = weakref.WeakValueDictionary()
_handlerList = []

def _removeHandlerRef(wr):
    '''
    Remove a handler reference from the internal cleanup list.
    '''
    acquire = _acquireLock
    release = _releaseLock
    handlers = _handlerList
# WARNING: Decompyle incomplete


def _addHandlerRef(handler):
    '''
    Add a handler to the internal cleanup list using a weak reference.
    '''
    _acquireLock()
# WARNING: Decompyle incomplete


class Handler(Filterer):
    """
    Handler instances dispatch logging events to specific destinations.

    The base handler class. Acts as a placeholder which defines the Handler
    interface. Handlers can optionally use Formatter instances to format
    records as desired. By default, no formatter is specified; in this case,
    the 'raw' message as determined by record.message is logged.
    """
    
    def __init__(self, level = (NOTSET,)):
        '''
        Initializes the instance - basically setting the formatter to None
        and the filter list to empty.
        '''
        Filterer.__init__(self)
        self._name = None
        self.level = _checkLevel(level)
        self.formatter = None
        _addHandlerRef(self)
        self.createLock()

    
    def get_name(self):
        return self._name

    
    def set_name(self, name):
        _acquireLock()
    # WARNING: Decompyle incomplete

    name = property(get_name, set_name)
    
    def createLock(self):
        '''
        Acquire a thread lock for serializing access to the underlying I/O.
        '''
        self.lock = threading.RLock()
        _register_at_fork_reinit_lock(self)

    
    def _at_fork_reinit(self):
        self.lock._at_fork_reinit()

    
    def acquire(self):
        '''
        Acquire the I/O thread lock.
        '''
        if self.lock:
            self.lock.acquire()
            return None

    
    def release(self):
        '''
        Release the I/O thread lock.
        '''
        if self.lock:
            self.lock.release()
            return None

    
    def setLevel(self, level):
        '''
        Set the logging level of this handler.  level must be an int or a str.
        '''
        self.level = _checkLevel(level)

    
    def format(self, record):
        '''
        Format the specified record.

        If a formatter is set, use it. Otherwise, use the default formatter
        for the module.
        '''
        if self.formatter:
            fmt = self.formatter
        else:
            fmt = _defaultFormatter
        return fmt.format(record)

    
    def emit(self, record):
        '''
        Do whatever it takes to actually log the specified logging record.

        This version is intended to be implemented by subclasses and so
        raises a NotImplementedError.
        '''
        raise NotImplementedError('emit must be implemented by Handler subclasses')

    
    def handle(self, record):
        '''
        Conditionally emit the specified logging record.

        Emission depends on filters which may have been added to the handler.
        Wrap the actual emission of the record with acquisition/release of
        the I/O thread lock. Returns whether the filter passed the record for
        emission.
        '''
        rv = self.filter(record)
    # WARNING: Decompyle incomplete

    
    def setFormatter(self, fmt):
        '''
        Set the formatter for this handler.
        '''
        self.formatter = fmt

    
    def flush(self):
        '''
        Ensure all logging output has been flushed.

        This version does nothing and is intended to be implemented by
        subclasses.
        '''
        pass

    
    def close(self):
        '''
        Tidy up any resources used by the handler.

        This version removes the handler from an internal map of handlers,
        _handlers, which is used for handler lookup by name. Subclasses
        should ensure that this gets called from overridden close()
        methods.
        '''
        _acquireLock()
    # WARNING: Decompyle incomplete

    
    def handleError(self, record):
        '''
        Handle errors which occur during an emit() call.

        This method should be called from handlers when an exception is
        encountered during an emit() call. If raiseExceptions is false,
        exceptions get silently ignored. This is what is mostly wanted
        for a logging system - most users will not care about errors in
        the logging system, they are more interested in application errors.
        You could, however, replace this with a custom handler if you wish.
        The record which was being processed is passed in to this method.
        '''
        pass
    # WARNING: Decompyle incomplete

    
    def __repr__(self):
        level = getLevelName(self.level)
        return '<%s (%s)>' % (self.__class__.__name__, level)



class StreamHandler(Handler):
    '''
    A handler class which writes logging records, appropriately formatted,
    to a stream. Note that this class does not close the stream, as
    sys.stdout or sys.stderr may be used.
    '''
    terminator = '\n'
    
    def __init__(self, stream = (None,)):
        '''
        Initialize the handler.

        If stream is not specified, sys.stderr is used.
        '''
        Handler.__init__(self)
        if stream is None:
            stream = sys.stderr
        self.stream = stream

    
    def flush(self):
        '''
        Flushes the stream.
        '''
        self.acquire()
    # WARNING: Decompyle incomplete

    
    def emit(self, record):
        """
        Emit a record.

        If a formatter is specified, it is used to format the record.
        The record is then written to the stream with a trailing newline.  If
        exception information is present, it is formatted using
        traceback.print_exception and appended to the stream.  If the stream
        has an 'encoding' attribute, it is used to determine how to do the
        output to the stream.
        """
        pass
    # WARNING: Decompyle incomplete

    
    def setStream(self, stream):
        """
        Sets the StreamHandler's stream to the specified value,
        if it is different.

        Returns the old stream, if the stream was changed, or None
        if it wasn't.
        """
        if stream is self.stream:
            result = None
            return result
        result = None.stream
        self.acquire()
    # WARNING: Decompyle incomplete

    
    def __repr__(self):
        level = getLevelName(self.level)
        name = getattr(self.stream, 'name', '')
        name = str(name)
        if name:
            name += ' '
        return '<%s %s(%s)>' % (self.__class__.__name__, name, level)



class FileHandler(StreamHandler):
    '''
    A handler class which writes formatted logging records to disk files.
    '''
    
    def __init__(self, filename, mode, encoding, delay, errors = ('a', None, False, None)):
        '''
        Open the specified file and use it as the stream for logging.
        '''
        filename = os.fspath(filename)
        self.baseFilename = os.path.abspath(filename)
        self.mode = mode
        self.encoding = encoding
        if 'b' not in mode:
            self.encoding = io.text_encoding(encoding)
        self.errors = errors
        self.delay = delay
        self._builtin_open = open
        if delay:
            Handler.__init__(self)
            self.stream = None
            return None
        None.__init__(self, self._open())

    
    def close(self):
        '''
        Closes the stream.
        '''
        self.acquire()
    # WARNING: Decompyle incomplete

    
    def _open(self):
        '''
        Open the current base file with the (original) mode and encoding.
        Return the resulting stream.
        '''
        open_func = self._builtin_open
        return open_func(self.baseFilename, self.mode, self.encoding, self.errors, **('encoding', 'errors'))

    
    def emit(self, record):
        """
        Emit a record.

        If the stream was not opened because 'delay' was specified in the
        constructor, open it before calling the superclass's emit.
        """
        if self.stream is None:
            self.stream = self._open()
        StreamHandler.emit(self, record)

    
    def __repr__(self):
        level = getLevelName(self.level)
        return '<%s %s (%s)>' % (self.__class__.__name__, self.baseFilename, level)



class _StderrHandler(StreamHandler):
    '''
    This class is like a StreamHandler using sys.stderr, but always uses
    whatever sys.stderr is currently set to rather than the value of
    sys.stderr at handler construction time.
    '''
    
    def __init__(self, level = (NOTSET,)):
        '''
        Initialize the handler.
        '''
        Handler.__init__(self, level)

    
    def stream(self):
        return sys.stderr

    stream = property(stream)

_defaultLastResort = _StderrHandler(WARNING)
lastResort = _defaultLastResort

class PlaceHolder(object):
    '''
    PlaceHolder instances are used in the Manager logger hierarchy to take
    the place of nodes for which no loggers have been defined. This class is
    intended for internal use only and not as part of the public API.
    '''
    
    def __init__(self, alogger):
        '''
        Initialize with the specified logger being a child of this placeholder.
        '''
        self.loggerMap = {
            alogger: None }

    
    def append(self, alogger):
        '''
        Add the specified logger as a child of this placeholder.
        '''
        if alogger not in self.loggerMap:
            self.loggerMap[alogger] = None
            return None



def setLoggerClass(klass):
    '''
    Set the class to be used when instantiating a logger. The class should
    define __init__() such that only a name argument is required, and the
    __init__() should call Logger.__init__()
    '''
    global _loggerClass
    if not klass != Logger and issubclass(klass, Logger):
        raise TypeError('logger not derived from logging.Logger: ' + klass.__name__)
    _loggerClass = None


def getLoggerClass():
    '''
    Return the class to be used when instantiating a logger.
    '''
    return _loggerClass


class Manager(object):
    '''
    There is [under normal circumstances] just one Manager instance, which
    holds the hierarchy of loggers.
    '''
    
    def __init__(self, rootnode):
        '''
        Initialize the manager with the root node of the logger hierarchy.
        '''
        self.root = rootnode
        self.disable = 0
        self.emittedNoHandlerWarning = False
        self.loggerDict = { }
        self.loggerClass = None
        self.logRecordFactory = None

    
    def disable(self):
        return self._disable

    disable = property(disable)
    
    def disable(self, value):
        self._disable = _checkLevel(value)

    disable = disable.setter(disable)
    
    def getLogger(self, name):
        '''
        Get a logger with the specified name (channel name), creating it
        if it doesn\'t yet exist. This name is a dot-separated hierarchical
        name, such as "a", "a.b", "a.b.c" or similar.

        If a PlaceHolder existed for the specified name [i.e. the logger
        didn\'t exist but a child of it did], replace it with the created
        logger and fix up the parent/child references which pointed to the
        placeholder to now point to the logger.
        '''
        rv = None
        if not isinstance(name, str):
            raise TypeError('A logger name must be a string')
        None()
    # WARNING: Decompyle incomplete

    
    def setLoggerClass(self, klass):
        '''
        Set the class to be used when instantiating a logger with this Manager.
        '''
        if not klass != Logger and issubclass(klass, Logger):
           