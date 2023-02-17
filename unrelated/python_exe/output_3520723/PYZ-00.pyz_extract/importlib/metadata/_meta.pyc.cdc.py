
from typing import Any, Dict, Iterator, List, Protocol, TypeVar, Union
_T = TypeVar('_T')

class PackageMetadata(Protocol):
    
    def __len__(self = None):
        pass

    
    def __contains__(self = None, item = None):
        pass

    
    def __getitem__(self = None, key = None):
        pass

    
    def __iter__(self = None):
        pass

    
    def get_all(self = None, name = None, failobj = None):
        '''
        Return all values associated with a possibly multi-valued key.
        '''
        pass

    
    def json(self = None):
        '''
        A JSON-compatible form of the metadata.
        '''
        pass

    json = None(json)


class SimplePath(Protocol):
    '''
    A minimal subset of pathlib.Path required by PathDistribution.
    '''
    
    def joinpath(self = None):
        pass

    
    def __div__(self = None):
        pass

    
    def parent(self = None):
        pass

    
    def read_text(self = None):
        pass


