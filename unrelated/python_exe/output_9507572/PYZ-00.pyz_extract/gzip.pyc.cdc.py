
"""Functions that read and write gzipped files.

The user of the file doesn't have to worry about the compression,
but random access is not allowed."""
import struct
import sys
import time
import os
import zlib
import builtins
import io
import _compression
__all__ = [
    'BadGzipFile',
    'GzipFile',
    'open',
    'compress',
    'decompress']
(FTEXT, FHCRC, FEXTRA, FNAME, FCOMMENT) = (1, 2, 4, 8, 16)
(READ, WRITE) = (1, 2)
_COMPRESS_LEVEL_FAST = 1
_COMPRESS_LEVEL_TRADEOFF = 6
_COMPRESS_LEVEL_BEST = 9

def open(filename, mode, compresslevel, encoding, errors, newline = ('rb', _COMPRESS_LEVEL_BEST, None, None, None)):
    '''Open a gzip-compressed file in binary or text mode.

    The filename argument can be an actual filename (a str or bytes object), or
    an existing file object to read from or write to.

    The mode argument can be "r", "rb", "w", "wb", "x", "xb", "a" or "ab" for
    binary mode, or "rt", "wt", "xt" or "at" for text mode. The default mode is
    "rb", and the default compresslevel is 9.

    For binary mode, this function is equivalent to the GzipFile constructor:
    GzipFile(filename, mode, compresslevel). In this case, the encoding, errors
    and newline arguments must not be provided.

    For text mode, a GzipFile object is created, and wrapped in an
    io.TextIOWrapper instance with the specified encoding, error handling
    behavior, and line ending(s).

    '''
    if 't' in mode or 'b' in mode:
        raise ValueError('Invalid mode: %r' % (mode,))
    if encoding is not None:
        raise ValueError("Argument 'encoding' not supported in binary mode")
    if None is not None:
        raise ValueError("Argument 'errors' not supported in binary mode")
    if None is not None:
        raise ValueError("Argument 'newline' not supported in binary mode")
    gz_mode = None.replace('t', '')
    if isinstance(filename, (str, bytes, os.PathLike)):
        binary_file = GzipFile(filename, gz_mode, compresslevel)
    elif hasattr(filename, 'read') or hasattr(filename, 'write'):
        binary_file = GzipFile(None, gz_mode, compresslevel, filename)
    else:
        raise TypeError('filename must be a str or bytes object, or a file')
    if None in mode:
        return io.TextIOWrapper(binary_file, encoding, errors, newline)
    return None


def write32u(output, value):
    output.write(struct.pack('<L', value))


class _PaddedFile:
    """Minimal read-only file object that prepends a string to the contents
    of an actual file. Shouldn't be used outside of gzip.py, as it lacks
    essential functionality."""
    
    def __init__(self, f, prepend = (b'',)):
        self._buffer = prepend
        self._length = len(prepend)
        self.file = f
        self._read = 0

    
    def read(self, size):
        if self._read is None:
            return self.file.read(size)
        if None._read + size <= self._length:
            read = self._read
            self._read += size
            return self._buffer[read:self._read]
        read = None._read
        self._read = None
        return self._buffer[read:] + self.file.read((size - self._length) + read)

    
    def prepend(self, prepend = (b'',)):
        if self._read is None:
            self._buffer = prepend
        else:
            self._read -= len(prepend)
            return None
        self._length = None(self._buffer)
        self._read = 0

    
    def seek(self, off):
        self._read = None
        self._buffer = None
        return self.file.seek(off)

    
    def seekable(self):
        return True



class BadGzipFile(OSError):
    '''Exception raised in some cases for invalid gzip files.'''
    pass


def GzipFile():
    '''GzipFile'''
    __doc__ = 'The GzipFile class simulates most of the methods of a file object with\n    the exception of the truncate() method.\n\n    This class only supports opening files in binary mode. If you need to open a\n    compressed file in text mode, use the gzip.open() function.\n\n    '
    myfileobj = None
    
    def __init__(self, filename, mode, compresslevel, fileobj, mtime = (None, None, _COMPRESS_LEVEL_BEST, None, None)):
        """Constructor for the GzipFile class.

        At least one of fileobj and filename must be given a
        non-trivial value.

        The new class instance is based on fileobj, which can be a regular
        file, an io.BytesIO object, or any other object which simulates a file.
        It defaults to None, in which case filename is opened to provide
        a file object.

        When fileobj is not None, the filename argument is only used to be
        included in the gzip file header, which may include the original
        filename of the uncompressed file.  It defaults to the filename of
        fileobj, if discernible; otherwise, it defaults to the empty string,
        and in this case the original filename is not included in the header.

        The mode argument can be any of 'r', 'rb', 'a', 'ab', 'w', 'wb', 'x', or
        'xb' depending on whether the file will be read or written.  The default
        is the mode of fileobj if discernible; otherwise, the default is 'rb'.
        A mode of 'r' is equivalent to one of 'rb', and similarly for 'w' and
        'wb', 'a' and 'ab', and 'x' and 'xb'.

        The compresslevel argument is an integer from 0 to 9 controlling the
        level of compression; 1 is fastest and produces the least compression,
        and 9 is slowest and produces the most compression. 0 is no compression
        at all. The default is 9.

        The mtime argument is an optional numeric timestamp to be written
        to the last modification time field in the stream when compressing.
        If omitted or None, the current time is used.

        """
        if mode:
            if 't' in mode or 'U' in mode:
                raise ValueError('Invalid mode: {!r}'.format(mode))
            if None and 'b' not in mode:
                mode += 'b'
                if fileobj is None:
                    if not mode:
                        fileobj = self.myfileobj = builtins.open(filename, 'rb')
                        if filename is None:
                            filename = getattr(fileobj, 'name', '')
                            if not isinstance(filename, (str, bytes)):
                                filename = ''
                            else:
                                filename = os.fspath(filename)
                                origmode = mode
                                if mode is None:
                                    mode = getattr(fileobj, 'mode', 'rb')
                                    if mode.startswith('r'):
                                        self.mode = READ
                                        raw = _GzipReader(fileobj)
                                        self._buffer = io.BufferedReader(raw)
                                        self.name = filename
                                    elif mode.startswith(('w', 'a', 'x')):
                                        if origmode is None:
                                            import warnings
                                            warnings.warn('GzipFile was opened for writing, but this will change in future Python releases.  Specify the mode argument for opening it for writing.', FutureWarning, 2)
                                            self.mode = WRITE
                                            self._init_write(filename)
                                            self.compress = zlib.compressobj(compresslevel, zlib.DEFLATED, -(zlib.MAX_WBITS), zlib.DEF_MEM_LEVEL, 0)
                                            self._write_mtime = mtime
                                        else:
                                            raise ValueError('Invalid mode: {!r}'.format(mode))
                                        self.fileobj = None
                                        if self.mode == WRITE:
                                            self._write_gzip_header(compresslevel)
                                            return None

    
    def filename(self):
        import warnings
        warnings.warn('use the name attribute', DeprecationWarning, 2)
        if self.mode == WRITE and self.name[-3:] != '.gz':
            return self.name + '.gz'
        return None.name

    filename = property(filename)
    
    def mtime(self):
        '''Last modification time read from stream, or None'''
        return self._buffer.raw._last_mtime

    mtime = property(mtime)
    
    def __repr__(self):
        s = repr(self.fileobj)
        return '<gzip ' + s[1:-1] + ' ' + hex(id(self)) + '>'

    
    def _init_write(self, filename):
        self.name = filename
        self.crc = zlib.crc32(b'')
        self.size = 0
        self.writebuf = []
        self.bufsize = 0
        self.offset = 0

    
    def _write_gzip_header(self, compresslevel):
        self.fileobj.write(b'\x1f\x8b')
        self.fileobj.write(b'\x08')
    # WARNING: Decompyle incomplete

    
    def write(self, data):
        self._check_not_closed()
        if self.mode != WRITE:
            import errno
            raise OSError(errno.EBADF, 'write() on read-only GzipFile object')
        if None.fileobj is None:
            raise ValueError('write() on closed GzipFile object')
        if None(data, bytes):
            length = len(data)
        else:
            data = memoryview(data)
            length = data.nbytes
            if length > 0:
                self.fileobj.write(self.compress.compress(data))
                self.size += length
                self.crc = zlib.crc32(data, self.crc)
                self.offset += length
                return length

    
    def read(self, size = (-1,)):
        self._check_not_closed()
        if self.mode != READ:
            import errno
            raise OSError(errno.EBADF, 'read() on write-only GzipFile object')
        return None._buffer.read(size)

    
    def read1(self, size = (-1,)):
        """Implements BufferedIOBase.read1()

        Reads up to a buffer's worth of data if size is negative."""
        self._check_not_closed()
        if self.mode != READ:
            import errno
            raise OSError(errno.EBADF, 'read1() on write-only GzipFile object')
        if None < 0:
            size = io.DEFAULT_BUFFER_SIZE
            return self._buffer.read1(size)

    
    def peek(self, n):
        self._check_not_closed()
        if self.mode != READ:
            import errno
            raise OSError(errno.EBADF, 'peek() on write-only GzipFile object')
        return None._buffer.peek(n)

    
    def closed(self):
        return self.fileobj is None

    closed = property(closed)
    
    def close(self):
        fileobj = self.fileobj
        if fileobj is None:
            return None
        self.fileobj = None
    # WARNING: Decompyle incomplete

    
    def flush(self, zlib_mode = (zlib.Z_SYNC_FLUSH,)):
        self._check_not_closed()
        if self.mode == WRITE:
            self.fileobj.write(self.compress.flush(zlib_mode))
            self.fileobj.flush()
            return None

    
    def fileno(self):
        """Invoke the underlying file object's fileno() method.

        This will raise AttributeError if the underlying file object
        doesn't support fileno().
        """
        return self.fileobj.fileno()

    
    def rewind(self):
        '''Return the uncompressed stream file position indicator to the
        beginning of the file'''
        if self.mode != READ:
            raise OSError("Can't rewind in write mode")
        None._buffer.seek(0)

    
    def readable(self):
        return self.mode == READ

    
    def writable(self):
        return self.mode == WRITE

    
    def seekable(self):
        return True

    
    def seek(self, offset, whence = (io.SEEK_SET,)):
        if self.mode == WRITE:
            if whence != io.SEEK_SET:
                if whence == io.SEEK_CUR:
                    offset = self.offset + offset
                else:
                    raise ValueError('Seek from end not supported')
                if None < self.offset:
                    raise OSError('Negative seek in write mode')
                count = None - self.offset
                chunk = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                for i in range(count // 1024):
                    self.write(chunk)
                self.write(b'\x00' * (count % 1024))
            elif self.mode == READ:
                self._check_not_closed()
                return self._buffer.seek(offset, whence)
                return self.offset

    
    def readline(self, size = (-1,)):
        self._check_not_closed()
        return self._buffer.readline(size)


GzipFile = <NODE:26>(GzipFile, 'GzipFile', _compression.BaseStream)

def _GzipReader():
    '''_GzipReader'''
    
    def __init__(self = None, fp = None):
        super().__init__(_PaddedFile(fp), zlib.decompressobj, -(zlib.MAX_WBITS), **('wbits',))
        self._new_member = True
        self._last_mtime = None

    
    def _init_read(self):
        self._crc = zlib.crc32(b'')
        self._stream_size = 0

    
    def _read_exact(self, n):
        '''Read exactly *n* bytes from `self._fp`

        This method is required because self._fp may be unbuffered,
        i.e. return short reads.
        '''
        data = self._fp.read(n)
        if len(data) < n:
            b = self._fp.read(n - len(data))
            if not b:
                raise EOFError('Compressed file ended before the end-of-stream marker was reached')
            None += b
            continue
            return data

    
    def _read_gzip_header(self):
        magic = self._fp.read(2)
        if magic == b'':
            return False
        if None != b'\x1f\x8b':
            raise BadGzipFile('Not a gzipped file (%r)' % magic)
        (method, flag, self._last_mtime) = None.unpack('<BBIxx', self._read_exact(8))
        if method != 8:
            raise BadGzipFile('Unknown compression method')
        if None & FEXTRA:
            (extra_len,) = struct.unpack('<H', self._read_exact(2))
            self._read_exact(extra_len)
            if flag & FNAME:
                s = self._fp.read(1)
                if s:
                    if s == b'\x00':
                        pass
                    
                elif flag & FCOMMENT:
                    s = self._fp.read(1)
                    if s:
                        if s == b'\x00':
                            pass
                        
                    elif flag & FHCRC:
                        self._read_exact(2)
                        return True

    
    def read(self, size = (-1,)):
        if size < 0:
            return self.readall()
        if not None:
            return b''
    # WARNING: Decompyle incomplete

    
    def _add_read_data(self, data):
        self._crc = zlib.crc32(data, self._crc)
        self._stream_size = self._stream_size + len(data)

    
    def _read_eof(self):
        (crc32, isize) = struct.unpack('<II', self._read_exact(8))
        if crc32 != self._crc:
            raise BadGzipFile('CRC check failed %s != %s' % (hex(crc32), hex(self._crc)))
        if isize != self._stream_size & 0xFFFFFFFFL:
            raise BadGzipFile('Incorrect length of data produced')
        c = None
        if c == b'\x00':
            c = self._fp.read(1)
        elif c:
            self._fp.prepend(c)
            return None

    
    def _rewind(self = None):
        super()._rewind()
        self._new_member = True

    __classcell__ = None

_GzipReader = <NODE:26>(_GzipReader, '_GzipReader', _compression.DecompressReader)

def compress(data = None, compresslevel = (_COMPRESS_LEVEL_BEST,), *, mtime):
    '''Compress data in one shot and return the compressed string.
    Optional argument is the compression level, in range of 0-9.
    '''
    buf = io.BytesIO()
    with GzipFile(buf, 'wb', compresslevel, mtime, **('fileobj', 'mode', 'compresslevel', 'mtime')) as f:
        f.write(data)
        None(None, None, None)
# WARNING: Decompyle incomplete


def decompress(data):
    '''Decompress a gzip compressed string in one shot.
    Return the decompressed string.
    '''
    pass
# WARNING: Decompyle incomplete


def main():
    ArgumentParser = ArgumentParser
    import argparse
    parser = ArgumentParser('A simple command line interface for the gzip module: act like gzip, but do not delete the input file.', **('description',))
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--fast', 'store_true', 'compress faster', **('action', 'help'))
    group.add_argument('--best', 'store_true', 'compress better', **('action', 'help'))
    group.add_argument('-d', '--decompress', 'store_true', 'act like gunzip instead of gzip', **('action', 'help'))
    parser.add_argument('args', '*', [
        '-'], 'file', **('nargs', 'default', 'metavar'))
    args = parser.parse_args()
    compresslevel = _COMPRESS_LEVEL_TRADEOFF
    None(None if args.fast else g.write if not chunk else chunk)
    if None is not None.stdout.buffer:
        g.close()
        if f is not sys.stdin.buffer:
            f.close()
            continue
            return None

if __name__ == '__main__':
    main()
    return None
