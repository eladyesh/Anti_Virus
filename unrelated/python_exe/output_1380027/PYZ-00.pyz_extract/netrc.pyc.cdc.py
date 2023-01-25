
'''An object-oriented interface to .netrc files.'''
import os
import shlex
import stat
__all__ = [
    'netrc',
    'NetrcParseError']

class NetrcParseError(Exception):
    '''Exception raised on syntax errors in the .netrc file.'''
    
    def __init__(self, msg, filename, lineno = (None, None)):
        self.filename = filename
        self.lineno = lineno
        self.msg = msg
        Exception.__init__(self, msg)

    
    def __str__(self):
        return '%s (%s, line %s)' % (self.msg, self.filename, self.lineno)



class netrc:
    
    def __init__(self, file = (None,)):
        default_netrc = file is None
    # WARNING: Decompyle incomplete

    
    def _parse(self, file, fp, default_netrc):
        lexer = shlex.shlex(fp)
        lexer.wordchars += '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
        lexer.commenters = lexer.commenters.replace('#', '')
        saved_lineno = lexer.lineno
        if not tt:
            pass
        
    # WARNING: Decompyle incomplete

    
    def authenticators(self, host):
        '''Return a (user, account, password) tuple for given host.'''
        if host in self.hosts:
            return self.hosts[host]
        if None in self.hosts:
            return self.hosts['default']
        return None

    
    def __repr__(self):
        '''Dump the class data in the format of a .netrc file.'''
        rep = ''
        for macro in self.macros.keys():
            rep += f'''macdef {macro}\n'''
            for line in self.macros[macro]:
                rep += line
                None += None


if __name__ == '__main__':
    print(netrc())
    return None
