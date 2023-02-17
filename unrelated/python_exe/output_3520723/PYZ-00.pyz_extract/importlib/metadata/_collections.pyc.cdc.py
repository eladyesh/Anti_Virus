
import collections

def FreezableDefaultDict():
    '''FreezableDefaultDict'''
    __doc__ = "\n    Often it is desirable to prevent the mutation of\n    a default dict after its initial construction, such\n    as to prevent mutation during iteration.\n\n    >>> dd = FreezableDefaultDict(list)\n    >>> dd[0].append('1')\n    >>> dd.freeze()\n    >>> dd[1]\n    []\n    >>> len(dd)\n    1\n    "
    
    def __missing__(self = None, key = None):
        return getattr(self, '_frozen', super().__missing__)(key)

    
    def freeze(self):
        
        self._frozen = lambda key = None: self.default_factory()

    __classcell__ = None

FreezableDefaultDict = <NODE:26>(FreezableDefaultDict, 'FreezableDefaultDict', collections.defaultdict)

def Pair():
    '''Pair'''
    
    def parse(cls, text):
        pass
    # WARNING: Decompyle incomplete

    parse = classmethod(parse)

Pair = <NODE:26>(Pair, 'Pair', collections.namedtuple('Pair', 'name value'))
