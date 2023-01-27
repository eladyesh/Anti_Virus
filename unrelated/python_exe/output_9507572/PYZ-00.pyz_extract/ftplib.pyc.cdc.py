
__doc__ = "An FTP client class and some helper functions.\n\nBased on RFC 959: File Transfer Protocol (FTP), by J. Postel and J. Reynolds\n\nExample:\n\n>>> from ftplib import FTP\n>>> ftp = FTP('ftp.python.org') # connect to host, default port\n>>> ftp.login() # default, i.e.: user anonymous, passwd anonymous@\n'230 Guest login ok, access restrictions apply.'\n>>> ftp.retrlines('LIST') # list directory contents\ntotal 9\ndrwxr-xr-x   8 root     wheel        1024 Jan  3  1994 .\ndrwxr-xr-x   8 root     wheel        1024 Jan  3  1994 ..\ndrwxr-xr-x   2 root     wheel        1024 Jan  3  1994 bin\ndrwxr-xr-x   2 root     wheel        1024 Jan  3  1994 etc\nd-wxrwxr-x   2 ftp      wheel        1024 Sep  5 13:43 incoming\ndrwxr-xr-x   2 root     wheel        1024 Nov 17  1993 lib\ndrwxr-xr-x   6 1094     wheel        1024 Sep 13 19:07 pub\ndrwxr-xr-x   3 root     wheel        1024 Jan  3  1994 usr\n-rw-r--r--   1 root     root          312 Aug  1  1994 welcome.msg\n'226 Transfer complete.'\n>>> ftp.quit()\n'221 Goodbye.'\n>>>\n\nA nice test that reveals some of the network dialogue would be:\npython ftplib.py -d localhost -l -p -l\n"
import sys
import socket
from socket import _GLOBAL_DEFAULT_TIMEOUT
__all__ = [
    'FTP',
    'error_reply',
    'error_temp',
    'error_perm',
    'error_proto',
    'all_errors']
MSG_OOB = 1
FTP_PORT = 21
MAXLINE = 8192

class Error(Exception):
    pass


class error_reply(Error):
    pass


class error_temp(Error):
    pass


class error_perm(Error):
    pass


class error_proto(Error):
    pass

all_errors = (Error, OSError, EOFError)
CRLF = '\r\n'
B_CRLF = b'\r\n'

class FTP:
    """An FTP client class.

    To create a connection, call the class using these arguments:
            host, user, passwd, acct, timeout, source_address, encoding

    The first four arguments are all strings, and have default value ''.
    The parameter \xc2\xb4timeout\xc2\xb4 must be numeric and defaults to None if not
    passed, meaning that no timeout will be set on any ftp socket(s).
    If a timeout is passed, then this is now the default timeout for all ftp
    socket operations for this instance.
    The last parameter is the encoding of filenames, which defaults to utf-8.

    Then use self.connect() with optional host and port argument.

    To download a file, use ftp.retrlines('RETR ' + filename),
    or ftp.retrbinary() with slightly different arguments.
    To upload a file, use ftp.storlines() or ftp.storbinary(),
    which have an open file as argument (see their definitions
    below for details).
    The download/upload functions first issue appropriate TYPE
    and PORT or PASV commands.
    """
    debugging = 0
    host = ''
    port = FTP_PORT
    maxline = MAXLINE
    sock = None
    file = None
    welcome = None
    passiveserver = True
    trust_server_pasv_ipv4_address = False
    
    def __init__(self, host, user, passwd, acct = None, timeout = ('', '', '', '', _GLOBAL_DEFAULT_TIMEOUT, None), source_address = {
        'encoding': 'utf-8' }, *, encoding):
        '''Initialization method (called by class instantiation).
        Initialize host to localhost, port to standard ftp port.
        Optional arguments are host (for connect()),
        and user, passwd, acct (for login()).
        '''
        self.encoding = encoding
        self.source_address = source_address
        self.timeout = timeout
        if host:
            self.connect(host)
            if user:
                self.login(user, passwd, acct)
                return None

    
    def __enter__(self):
        return self

    
    def __exit__(self, *args):
        pass
    # WARNING: Decompyle incomplete

    
    def connect(self, host, port, timeout, source_address = ('', 0, -999, None)):
        '''Connect to host.  Arguments are:
         - host: hostname to connect to (string, default previous host)
         - port: port to connect to (integer, default previous port)
         - timeout: the timeout to set against the ftp socket(s)
         - source_address: a 2-tuple (host, port) for the socket to bind
           to as its source address before connecting.
        '''
        if host != '':
            self.host = host
            if port > 0:
                self.port = port
                if timeout != -999:
                    self.timeout = timeout
                    if not self.timeout is not None and self.timeout:
                        raise ValueError('Non-blocking socket (timeout=0) is not supported')
                    if None is not None:
                        self.source_address = source_address
                        sys.audit('ftplib.connect', self, self.host, self.port)
                        self.sock = socket.create_connection((self.host, self.port), self.timeout, self.source_address, **('source_address',))
                        self.af = self.sock.family
                        self.file = self.sock.makefile('r', self.encoding, **('encoding',))
        self.welcome = self.getresp()
        return self.welcome

    
    def getwelcome(self):
        '''Get the welcome message from the server.
        (this is read and squirreled away by connect())'''
        if self.debugging:
            print('*welcome*', self.sanitize(self.welcome))
            return self.welcome

    
    def set_debuglevel(self, level):
        '''Set the debugging level.
        The required argument level means:
        0: no debugging output (default)
        1: print commands and responses but not body text etc.
        2: also print raw lines read and sent before stripping CR/LF'''
        self.debugging = level

    debug = set_debuglevel
    
    def set_pasv(self, val):
        '''Use passive or active mode for data transfers.
        With a false argument, use the normal PORT mode,
        With a true argument, use the PASV command.'''
        self.passiveserver = val

    
    def sanitize(self, s):
        if s[:5] in :
            i = len(s.rstrip('\r\n'))
            s = s[:5] + '*' * (i - 5) + s[i:]
            return repr(s)

    
    def putline(self, line):
        if '\r' in line or '\n' in line:
            raise ValueError('an illegal newline character should not be contained')
        None.audit('ftplib.sendcmd', self, line)
        line = line + CRLF
        if self.debugging > 1:
            print('*put*', self.sanitize(line))
            self.sock.sendall(line.encode(self.encoding))
            return None

    
    def putcmd(self, line):
        if self.debugging:
            print('*cmd*', self.sanitize(line))
            self.putline(line)
            return None

    
    def getline(self):
        line = self.file.readline(self.maxline + 1)
        if len(line) > self.maxline:
            raise Error('got more than %d bytes' % self.maxline)
        if None.debugging > 1:
            print('*get*', self.sanitize(line))
            if not line:
                raise EOFError
            if None[-2:] == CRLF:
                line = line[:-2]
            elif line[-1:] in CRLF:
                line = line[:-1]
                return line

    
    def getmultiline(self):
        line = self.getline()
        if line[3:4] == '-':
            code = line[:3]
            nextline = self.getline()
            line = line + '\n' + nextline
            if nextline[:3] == code:
                pass
            if nextline[3:4] != '-':
                pass
            
            return line

    
    def getresp(self):
        resp = self.getmultiline()
        if self.debugging:
            print('*resp*', self.sanitize(resp))
            self.lastresp = resp[:3]
            c = resp[:1]
        if c in :
            return resp
        if None == '4':
            raise error_temp(resp)
        if None == '5':
            raise error_perm(resp)
        raise None(resp)

    
    def voidresp(self):
        """Expect a response beginning with '2'."""
        resp = self.getresp()
        if resp[:1] != '2':
            raise error_reply(resp)

    
    def abort(self):
        """Abort a file transfer.  Uses out-of-band data.
        This does not follow the procedure from the RFC to send Telnet
        IP and Synch; that doesn't seem to work with the servers I've
        tried.  Instead, just send the ABOR command as OOB data."""
        line = b'ABOR' + B_CRLF
        if self.debugging > 1:
            print('*put urgent*', self.sanitize(line))
            self.sock.sendall(line, MSG_OOB)
            resp = self.getmultiline()
        if resp[:3] not in :
            raise error_proto(resp)

    
    def sendcmd(self, cmd):
        '''Send a command and return the response.'''
        self.putcmd(cmd)
        return self.getresp()

    
    def voidcmd(self, cmd):
        """Send a command and expect a response beginning with '2'."""
        self.putcmd(cmd)
        return self.voidresp()

    
    def sendport(self, host, port):
        '''Send a PORT command with the current host and the given
        port number.
        '''
        hbytes = host.split('.')
        pbytes = [
            repr(port // 256),
            repr(port % 256)]
        bytes = hbytes + pbytes
        cmd = 'PORT ' + ','.join(bytes)
        return self.voidcmd(cmd)

    
    def sendeprt(self, host, port):
        '''Send an EPRT command with the current host and the given port number.'''
        af = 0
        if self.af == socket.AF_INET:
            af = 1
            if self.af == socket.AF_INET6:
                af = 2
                if af == 0:
                    raise error_proto('unsupported address family')
        fields = [
            None,
            repr(af),
            host,
            repr(port),
            '']
        cmd = 'EPRT ' + '|'.join(fields)
        return self.voidcmd(cmd)

    
    def makeport(self):
        '''Create a new socket and send a PORT command for it.'''
        sock = socket.create_server(('', 0), self.af, 1, **('family', 'backlog'))
        port = sock.getsockname()[1]
        host = self.sock.getsockname()[0]
        if self.af == socket.AF_INET:
            resp = self.sendport(host, port)
        else:
            resp = self.sendeprt(host, port)
            if self.timeout is not _GLOBAL_DEFAULT_TIMEOUT:
                sock.settimeout(self.timeout)
                return sock

    
    def makepasv(self):
        '''Internal: Does the PASV or EPSV handshake -> (address, port)'''
        if self.af == socket.AF_INET:
            (untrusted_host, port) = parse227(self.sendcmd('PASV'))
            if self.trust_server_pasv_ipv4_address:
                host = untrusted_host
            else:
                host = self.sock.getpeername()[0]
        else:
            (host, port) = parse229(self.sendcmd('EPSV'), self.sock.getpeername())
            return (host, port)

    
    def ntransfercmd(self, cmd, rest = (None,)):
        """Initiate a transfer over the data connection.

        If the transfer is active, send a port command and the
        transfer command, and accept the connection.  If the server is
        passive, send a pasv command, connect to it, and start the
        transfer command.  Either way, return the socket for the
        connection and the expected size of the transfer.  The
        expected size may be None if it could not be determined.

        Optional `rest' argument can be a string that is sent as the
        argument to a REST command.  This is essentially a server
        marker used to tell the server to skip over any data up to the
        given marker.
        """
        size = None
    # WARNING: Decompyle incomplete

    
    def transfercmd(self, cmd, rest = (None,)):
        '''Like ntransfercmd() but returns only the socket.'''
        return self.ntransfercmd(cmd, rest)[0]

    
    def login(self, user, passwd, acct = ('', '', '')):
        '''Login, default anonymous.'''
        if not user:
            user = 'anonymous'
            if not passwd:
                passwd = ''
                if not acct:
                    acct = ''
                    if user == 'anonymous' and passwd in :
                        passwd = passwd + 'anonymous@'
                        resp = self.sendcmd('USER ' + user)
                        if resp[0] == '3':
                            resp = self.sendcmd('PASS ' + passwd)
                            if resp[0] == '3':
                                resp = self.sendcmd('ACCT ' + acct)
                                if resp[0] != '2':
                                    raise error_reply(resp)
                                return None

    
    def retrbinary(self, cmd, callback, blocksize, rest = (8192, None)):
        '''Retrieve data in binary mode.  A new port is created for you.

        Args:
          cmd: A RETR command.
          callback: A single parameter callable to be called on each
                    block of data read.
          blocksize: The maximum number of bytes to read from the
                     socket at one time.  [default: 8192]
          rest: Passed to transfercmd().  [default: None]

        Returns:
          The response code.
        '''
        self.voidcmd('TYPE I')
        with self.transfercmd(cmd, rest) as conn:
            data = conn.recv(blocksize)
            if not data:
                pass
            else:
                callback(data)
            if _SSLSocket is not None and isinstance(conn, _SSLSocket):
                conn.unwrap()
            None(None, None, None)
    # WARNING: Decompyle incomplete

    
    def retrlines(self, cmd, callback = (None,)):
        '''Retrieve data in line mode.  A new port is created for you.

        Args:
          cmd: A RETR, LIST, or NLST command.
          callback: An optional single parameter callable that is called
                    for each line with the trailing CRLF stripped.
                    [default: print_line()]

        Returns:
          The response code.
        '''
        if callback is None:
            callback = print_line
            resp = self.sendcmd('TYPE A')
    # WARNING: Decompyle incomplete

    
    def storbinary(self, cmd, fp, blocksize, callback, rest = (8192, None, None)):
        '''Store a file in binary mode.  A new port is created for you.

        Args:
          cmd: A STOR command.
          fp: A file-like object with a read(num_bytes) method.
          blocksize: The maximum data size to read from fp and send over
                     the connection at once.  [default: 8192]
          callback: An optional single parameter callable that is called on
                    each block of data after it is sent.  [default: None]
          rest: Passed to transfercmd().  [default: None]

        Returns:
          The response code.
        '''
        self.voidcmd('TYPE I')
    # WARNING: Decompyle incomplete

    
    def storlines(self, cmd, fp, callback = (None,)):
        '''Store a file in line mode.  A new port is created for you.

        Args:
          cmd: A STOR command.
          fp: A file-like object with a readline() method.
          callback: An optional single parameter callable that is called on
                    each line after it is sent.  [default: None]

        Returns:
          The response code.
        '''
        self.voidcmd('TYPE A')
    # WARNING: Decompyle incomplete

    
    def acct(self, password):
        '''Send new account name.'''
        cmd = 'ACCT ' + password
        return self.voidcmd(cmd)

    
    def nlst(self, *args):
        '''Return a list of files in a given directory (default the current).'''
        cmd = 'NLST'
        files = []
        self.retrlines(cmd, files.append)
        return files

    
    def dir(self, *args):
        '''List a directory in long form.
        By default list current directory to stdout.
        Optional last argument is callback function; all
        non-empty arguments before it are concatenated to the
        LIST command.  (This *should* only be used for a pathname.)'''
        cmd = 'LIST'
        func = None
        if args[-1:] and type(args[-1]) != type(''):
            args = args[:-1]
            func = args[-1]
            for arg in args:
                cmd = cmd + ' ' + arg
            self.retrlines(cmd, func)
            return None

    
    def mlsd(self, path, facts = ('', [])):
        '''List a directory in a standardized format by using MLSD
        command (RFC-3659). If path is omitted the current directory
        is assumed. "facts" is a list of strings representing the type
        of information desired (e.g. ["type", "size", "perm"]).

        Return a generator object yielding a tuple of two elements
        for every file found in path.
        First element is the file name, the second one is a dictionary
        including a variable number of "facts" depending on the server
        and whether "facts" argument has been provided.
        '''
        if facts:
            self.sendcmd('OPTS MLST ' + ';'.join(facts) + ';')
            if path:
                cmd = 'MLSD %s' % path
            else:
                cmd = 'MLSD'
                lines = []
        self.retrlines(cmd, lines.append)
        for line in lines:
            (facts_found, _, name) = line.rstrip(CRLF).partition(' ')
            entry = { }
            return None

    
    def rename(self, fromname, toname):
        '''Rename a file.'''
        resp = self.sendcmd('RNFR ' + fromname)
        if resp[0] != '3':
            raise error_reply(resp)
        return None.voidcmd('RNTO ' + toname)

    
    def delete(self, filename):
        '''Delete a file.'''
        resp = self.sendcmd('DELE ' + filename)
        if resp[:3] in :
            return resp
        raise None(resp)

    
    def cwd(self, dirname):
        '''Change to a directory.'''
        pass
    # WARNING: Decompyle incomplete

    
    def size(self, filename):
        '''Retrieve the size of a file.'''
        resp = self.sendcmd('SIZE ' + filename)
        if resp[:3] == '213':
            s = resp[3:].strip()
            return int(s)

    
    def mkd(self, dirname):
        '''Make a directory, return its full pathname.'''
        resp = self.voidcmd('MKD ' + dirname)
        if not resp.startswith('257'):
            return ''
        return None(resp)

    
    def rmd(self, dirname):
        '''Remove a directory.'''
        return self.voidcmd('RMD ' + dirname)

    
    def pwd(self):
        '''Return current working directory.'''
        resp = self.voidcmd('PWD')
        if not resp.startswith('257'):
            return ''
        return None(resp)

    
    def quit(self):
        '''Quit, and close the connection.'''
        resp = self.voidcmd('QUIT')
        self.close()
        return resp

    
    def close(self):
        '''Close the connection without assuming anything about it.'''
        pass
    # WARNING: Decompyle incomplete


# WARNING: Decompyle incomplete
