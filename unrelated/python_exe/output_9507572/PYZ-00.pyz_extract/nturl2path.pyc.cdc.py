
'''Convert a NT pathname to a file URL and vice versa.

This module only exists to provide OS-specific code
for urllib.requests, thus do not use directly.
'''

def url2pathname(url):
    """OS-specific conversion from a relative URL of the 'file' scheme
    to a file system path; not recommended for general use."""
    import string
    import urllib.parse as urllib
    url = url.replace(':', '|')
    if '|' not in url:
        if url[:4] == '////':
            url = url[2:]
            components = url.split('/')
            return urllib.parse.unquote('\\'.join(components))
        comp = None.split('|')
        if len(comp) != 2 or comp[0][-1] not in string.ascii_letters:
            error = 'Bad URL: ' + url
            raise OSError(error)
        drive = None[0][-1].upper()
        components = comp[1].split('/')
    path = drive + ':'
    for comp in components:
        path = path + '\\' + urllib.parse.unquote(comp)
        path += '\\'
        return path


def pathname2url(p):
    """OS-specific conversion from a file system path to a relative URL
    of the 'file' scheme; not recommended for general use."""
    import urllib.parse as urllib
    if p[:4] == '\\\\?\\':
        p = p[4:]
        if p[:4].upper() == 'UNC\\':
            p = '\\' + p[4:]
        elif p[1:2] != ':':
            raise OSError('Bad path: ' + p)
            if ':' not in p:
                if p[:2] == '\\\\':
                    p = '\\\\' + p
                    components = p.split('\\')
                    return urllib.parse.quote('/'.join(components))
                comp = None.split(':', 2, **('maxsplit',))
                if len(comp) != 2 or len(comp[0]) > 1:
                    error = 'Bad path: ' + p
                    raise OSError(error)
                drive = None.parse.quote(comp[0].upper())
                components = comp[1].split('\\')
                path = '///' + drive + ':'
                for comp in components:
                    path = path + '/' + urllib.parse.quote(comp)
                return path

