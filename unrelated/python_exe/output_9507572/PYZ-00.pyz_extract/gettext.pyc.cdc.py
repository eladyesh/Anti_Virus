
'''Internationalization and localization support.

This module provides internationalization (I18N) and localization (L10N)
support for your Python programs by providing an interface to the GNU gettext
message catalog library.

I18N refers to the operation by which a program is made aware of multiple
languages.  L10N refers to the adaptation of your program, once
internationalized, to the local language and cultural habits.

'''
import os
import re
import sys
__all__ = [
    'NullTranslations',
    'GNUTranslations',
    'Catalog',
    'find',
    'translation',
    'install',
    'textdomain',
    'bindtextdomain',
    'bind_textdomain_codeset',
    'dgettext',
    'dngettext',
    'gettext',
    'lgettext',
    'ldgettext',
    'ldngettext',
    'lngettext',
    'ngettext',
    'pgettext',
    'dpgettext',
    'npgettext',
    'dnpgettext']
_default_localedir = os.path.join(sys.base_prefix, 'share', 'locale')
_token_pattern = re.compile('\n        (?P<WHITESPACES>[ \\t]+)                    | # spaces and horizontal tabs\n        (?P<NUMBER>[0-9]+\\b)                       | # decimal integer\n        (?P<NAME>n\\b)                              | # only n is allowed\n        (?P<PARENTHESIS>[()])                      |\n        (?P<OPERATOR>[-*/%+?:]|[><!]=?|==|&&|\\|\\|) | # !, *, /, %, +, -, <, >,\n                                                     # <=, >=, ==, !=, &&, ||,\n                                                     # ? :\n                                                     # unary and bitwise ops\n                                                     # not allowed\n        (?P<INVALID>\\w+|.)                           # invalid token\n    ', re.VERBOSE | re.DOTALL)

def _tokenize(plural):
    value = mo.group(kind)
    if kind == 'INVALID':
        raise ValueError('invalid token in plural form: %s' % value)
    yield None
    continue
    yield ''


def _error(value):
    if value:
        return ValueError('unexpected token in plural form: %s' % value)
    return None('unexpected end of plural form')

_binary_ops = (('||',), ('&&',), ('==', '!='), ('<', '>', '<=', '>='), ('+', '-'), ('*', '/', '%'))
_binary_ops = (lambda .0: pass# WARNING: Decompyle incomplete
)(enumerate(_binary_ops, 1))
_c2py_ops = {
    '||': 'or',
    '&&': 'and',
    '/': '//' }

def _parse(tokens, priority = (-1,)):
    result = ''
    nexttok = next(tokens)
# WARNING: Decompyle incomplete


def _as_int(n):
    pass
# WARNING: Decompyle incomplete


def c2py(plural):
    '''Gets a C expression as used in PO files for plural forms and returns a
    Python function that implements an equivalent expression.
    '''
    if len(plural) > 1000:
        raise ValueError('plural form expression is too long')
    (result, nexttok) = _parse(_tokenize(plural))
    if nexttok:
        raise _error(nexttok)
    depth = None
    for c in result:
        depth += 1
        raise ValueError('plural form expression is too complex')
        depth -= 1
        ns = {
            None: None }
        exec('if True:\n            def func(n):\n                if not isinstance(n, int):\n                    n = _as_int(n)\n                return int(%s)\n            ' % result, ns)
    return ns['func']
# WARNING: Decompyle incomplete


def _expand_lang(loc):
    import locale
    loc = locale.normalize(loc)
    COMPONENT_CODESET = 1
    COMPONENT_TERRITORY = 2
    COMPONENT_MODIFIER = 4
    mask = 0
    pos = loc.find('@')
    pos = None if pos >= 0 else loc.find('.')
    pos = None if pos >= 0 else loc.find('_')
    if pos >= 0:
        territory = loc[pos:]
        loc = loc[:pos]
        mask |= COMPONENT_TERRITORY
    else:
        territory = ''
        language = loc
    ret = []
    for i in range(mask + 1):
        val = language
        val += territory
        val += codeset
        val += modifier
        ret.append(val)
        [ val ]()
        return ret


class NullTranslations:
    
    def __init__(self, fp = (None,)):
        self._info = { }
        self._charset = None
        self._output_charset = None
        self._fallback = None
        if fp is not None:
            self._parse(fp)
            return None

    
    def _parse(self, fp):
        pass

    
    def add_fallback(self, fallback):
        if self._fallback:
            self._fallback.add_fallback(fallback)
        else:
            self._fallback = fallback
            return None

    
    def gettext(self, message):
        if self._fallback:
            return self._fallback.gettext(message)

    
    def lgettext(self, message):
        import warnings
        warnings.warn('lgettext() is deprecated, use gettext() instead', DeprecationWarning, 2)
        import locale
    # WARNING: Decompyle incomplete

    
    def ngettext(self, msgid1, msgid2, n):
        if self._fallback:
            return self._fallback.ngettext(msgid1, msgid2, n)
        if None == 1:
            return msgid1
        return None

    
    def lngettext(self, msgid1, msgid2, n):
        import warnings
        warnings.warn('lngettext() is deprecated, use ngettext() instead', DeprecationWarning, 2)
        import locale
    # WARNING: Decompyle incomplete

    
    def pgettext(self, context, message):
        if self._fallback:
            return self._fallback.pgettext(context, message)

    
    def npgettext(self, context, msgid1, msgid2, n):
        if self._fallback:
            return self._fallback.npgettext(context, msgid1, msgid2, n)
        if None == 1:
            return msgid1
        return None

    
    def info(self):
        return self._info

    
    def charset(self):
        return self._charset

    
    def output_charset(self):
        import warnings
        warnings.warn('output_charset() is deprecated', DeprecationWarning, 2)
        return self._output_charset

    
    def set_output_charset(self, charset):
        import warnings
        warnings.warn('set_output_charset() is deprecated', DeprecationWarning, 2)
        self._output_charset = charset

    
    def install(self, names = (None,)):
        import builtins
        builtins.__dict__['_'] = self.gettext
    # WARNING: Decompyle incomplete



class GNUTranslations(NullTranslations):
    LE_MAGIC = 0x950412DEL
    BE_MAGIC = 0xDE120495L
    CONTEXT = '%s\x04%s'
    VERSIONS = (0, 1)
    
    def _get_versions(self, version):
        '''Returns a tuple of major version, minor version'''
        return (version >> 16, version & 65535)

    
    def _parse(self, fp):
        '''Override this method to support alternative .mo formats.'''
        unpack = unpack
        import struct
        filename = getattr(fp, 'name', '')
        self._catalog = catalog = { }
        
        self.plural = lambda n: int(n != 1)
        buf = fp.read()
        buflen = len(buf)
        magic = unpack('<I', buf[:4])[0]
        if magic == self.LE_MAGIC:
            (version, msgcount, masteridx, transidx) = unpack('<4I', buf[4:20])
            ii = '<II'
        elif magic == self.BE_MAGIC:
            (version, msgcount, masteridx, transidx) = unpack('>4I', buf[4:20])
            ii = '>II'
        else:
            raise OSError(0, 'Bad magic number', filename)
        (major_version, minor_version) = None._get_versions(version)
        if major_version not in self.VERSIONS:
            raise OSError(0, 'Bad version number ' + str(major_version), filename)
        for i in None(0, msgcount):
            (mlen, moff) = unpack(ii, buf[masteridx:masteridx + 8])
            mend = moff + mlen
            (tlen, toff) = unpack(ii, buf[transidx:transidx + 8])
            tend = toff + tlen
            msg = buf[moff:mend]
            tmsg = buf[toff:tend]
        raise OSError(0, 'File is corrupt', filename)
        if mlen == 0:
            lastk = None
            for b_item in tmsg.split(b'\n'):
                item = b_item.decode().strip()
            if item.startswith('#-#-#-#-#') and item.endswith('#-#-#-#-#'):
                pass
            else:
                k = None
                v = None
                if ':' in item:
                    (k, v) = item.split(':', 1)
                    k = k.strip().lower()
                    v = v.strip()
                    self._info[k] = v
                    lastk = k
                elif lastk:
                    self._info[lastk] += '\n' + item
                    if k == 'content-type':
                        self._charset = v.split('charset=')[1]
                    elif k == 'plural-forms':
                        v = v.split(';')
                        plural = v[1].split('plural=')[1]
                        self.plural = c2py(plural)
                    elif not self._charset:
                        charset = 'ascii'
                        if b'\x00' in msg:
                            (msgid1, msgid2) = msg.split(b'\x00')
                            tmsg = tmsg.split(b'\x00')
                            msgid1 = str(msgid1, charset)
                            for i, x in enumerate(tmsg):
                                catalog[(msgid1, i)] = str(x, charset)
                        else:
                            catalog[str(msg, charset)] = str(tmsg, charset)
                            masteridx += 8
                            transidx += 8
                        return None

    
    def lgettext(self, message):
        import warnings
        warnings.warn('lgettext() is deprecated, use gettext() instead', DeprecationWarning, 2)
        import locale
        missing = object()
        tmsg = self._catalog.get(message, missing)
        if tmsg is missing:
            if self._fallback:
                return self._fallback.lgettext(message)
            tmsg = None
            if self._output_charset:
                return tmsg.encode(self._output_charset)
            return None.encode(locale.getpreferredencoding())

    
    def lngettext(self, msgid1, msgid2, n):
        import warnings
        warnings.warn('lngettext() is deprecated, use ngettext() instead', DeprecationWarning, 2)
        import locale
    # WARNING: Decompyle incomplete

    
    def gettext(self, message):
        missing = object()
        tmsg = self._catalog.get(message, missing)
        if tmsg is missing:
            if self._fallback:
                return self._fallback.gettext(message)
            return None

    
    def ngettext(self, msgid1, msgid2, n):
        pass
    # WARNING: Decompyle incomplete

    
    def pgettext(self, context, message):
        ctxt_msg_id = self.CONTEXT % (context, message)
        missing = object()
        tmsg = self._catalog.get(ctxt_msg_id, missing)
        if tmsg is missing:
            if self._fallback:
                return self._fallback.pgettext(context, message)
            return None

    
    def npgettext(self, context, msgid1, msgid2, n):
        ctxt_msg_id = self.CONTEXT % (context, msgid1)
    # WARNING: Decompyle incomplete



def find(domain, localedir, languages, all = (None, None, False)):
    if localedir is None:
        localedir = _default_localedir
        if languages is None:
            languages = []
            for envar in ('LANGUAGE', 'LC_ALL', 'LC_MESSAGES', 'LANG'):
                val = os.environ.get(envar)
                languages = val.split(':')
            continue
            if 'C' not in languages:
                languages.append('C')
                nelangs = []
                for lang in languages:
                    for nelang in _expand_lang(lang):
                        nelangs.append(nelang)
                for lang in None if all else nelangs:
                    mofile = None.join(localedir, lang, 'LC_MESSAGES', '%s.mo' % domain)
                    result.append(mofile)
                    [ mofile ]
                    return None

_translations = { }
_unspecified = [
    'unspecified']

def translation(domain, localedir, languages, class_, fallback, codeset = (None, None, None, False, _unspecified)):
    if class_ is None:
        class_ = GNUTranslations
    mofiles = find(domain, localedir, languages, True, **('all',))
    if not mofiles:
        if fallback:
            return NullTranslations()
        ENOENT = ENOENT
        import errno
        raise FileNotFoundError(ENOENT, 'No translation file found for domain', domain)
    result = None
# WARNING: Decompyle incomplete


def install(domain, localedir, codeset, names = (None, _unspecified, None)):
    t = translation(domain, localedir, True, codeset, **('fallback', 'codeset'))
    t.install(names)

_localedirs = { }
_localecodesets = { }
_current_domain = 'messages'

def textdomain(domain = (None,)):
    global _current_domain
    if domain is not None:
        _current_domain = domain
        return _current_domain


def bindtextdomain(domain, localedir = (None,)):
    if localedir is not None:
        _localedirs[domain] = localedir
        return _localedirs.get(domain, _default_localedir)


def bind_textdomain_codeset(domain, codeset = (None,)):
    import warnings
    warnings.warn('bind_textdomain_codeset() is deprecated', DeprecationWarning, 2)
    if codeset is not None:
        _localecodesets[domain] = codeset
        return _localecodesets.get(domain)


def dgettext(domain, message):
    pass
# WARNING: Decompyle incomplete


def ldgettext(domain, message):
    import warnings
    warnings.warn('ldgettext() is deprecated, use dgettext() instead', DeprecationWarning, 2)
    import locale
    codeset = _localecodesets.get(domain)
# WARNING: Decompyle incomplete


def dngettext(domain, msgid1, msgid2, n):
    pass
# WARNING: Decompyle incomplete


def ldngettext(domain, msgid1, msgid2, n):
    import warnings
    warnings.warn('ldngettext() is deprecated, use dngettext() instead', DeprecationWarning, 2)
    import locale
    codeset = _localecodesets.get(domain)
# WARNING: Decompyle incomplete


def dpgettext(domain, context, message):
    pass
# WARNING: Decompyle incomplete


def dnpgettext(domain, context, msgid1, msgid2, n):
    pass
# WARNING: Decompyle incomplete


def gettext(message):
    return dgettext(_current_domain, message)


def lgettext(message):
    import warnings
    warnings.warn('lgettext() is deprecated, use gettext() instead', DeprecationWarning, 2)
# WARNING: Decompyle incomplete


def ngettext(msgid1, msgid2, n):
    return dngettext(_current_domain, msgid1, msgid2, n)


def lngettext(msgid1, msgid2, n):
    import warnings
    warnings.warn('lngettext() is deprecated, use ngettext() instead', DeprecationWarning, 2)
# WARNING: Decompyle incomplete


def pgettext(context, message):
    return dpgettext(_current_domain, context, message)


def npgettext(context, msgid1, msgid2, n):
    return dnpgettext(_current_domain, context, msgid1, msgid2, n)

Catalog = translation
