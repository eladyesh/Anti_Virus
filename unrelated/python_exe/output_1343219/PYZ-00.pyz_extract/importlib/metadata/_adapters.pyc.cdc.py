
import re
import textwrap
import email.message as email
from _text import FoldedCase

def Message():
    '''Message'''
    multiple_use_keys = set(map(FoldedCase, [
        'Classifier',
        'Obsoletes-Dist',
        'Platform',
        'Project-URL',
        'Provides-Dist',
        'Provides-Extra',
        'Requires-Dist',
        'Requires-External',
        'Supported-Platform',
        'Dynamic']))
    
    def __new__(cls = None, orig = None):
        res = super().__new__(cls)
        vars(res).update(vars(orig))
        return res

    
    def __init__(self, *args, **kwargs):
        self._headers = self._repair_headers()

    
    def __iter__(self = None):
        return super().__iter__()

    
    def _repair_headers(self):
        
        def redent(value):
            '''Correct for RFC822 indentation'''
            if value or '\n' not in value:
                return value
            return None.dedent('        ' + value)

        headers = (lambda .0 = None: [ (key, redent(value)) for key, value in .0 ])(vars(self)['_headers'])
        if self._payload:
            headers.append(('Description', self.get_payload()))
        return headers

    
    def json(self):
        '''
        Convert PackageMetadata to a JSON-compatible format
        per PEP 0566.
        '''
        
        def transform(key = None):
            value = self.get_all(key) if key in self.multiple_use_keys else self[key]
            if key == 'Keywords':
                value = re.split('\\s+', value)
            tk = key.lower().replace('-', '_')
            return (tk, value)

        return dict(map(transform, map(FoldedCase, self)))

    json = property(json)
    __classcell__ = None

Message = <NODE:26>(Message, 'Message', email.message.Message)
