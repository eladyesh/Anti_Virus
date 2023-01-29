
import collections
import zipfile
import pathlib
from  import abc

def remove_duplicates(items):
    return iter(collections.OrderedDict.fromkeys(items))


def FileReader():
    '''FileReader'''
    
    def __init__(self, loader):
        self.path = pathlib.Path(loader.path).parent

    
    def resource_path(self, resource):
        '''
        Return the file system path to prevent
        `resources.path()` from creating a temporary
        copy.
        '''
        return str(self.path.joinpath(resource))

    
    def files(self):
        return self.path


FileReader = <NODE:26>(FileReader, 'FileReader', abc.TraversableResources)

def ZipReader():
    '''ZipReader'''
    
    def __init__(self, loader, module):
        (_, _, name) = module.rpartition('.')
        self.prefix = loader.prefix.replace('\\', '/') + name + '/'
        self.archive = loader.archive

    
    def open_resource(self = None, resource = None):
        pass
    # WARNING: Decompyle incomplete

    
    def is_resource(self, path):
        target = self.files().joinpath(path)
        if target.is_file():
            pass
        return target.exists()

    
    def files(self):
        return zipfile.Path(self.archive, self.prefix)

    __classcell__ = None

ZipReader = <NODE:26>(ZipReader, 'ZipReader', abc.TraversableResources)

def MultiplexedPath():
    '''MultiplexedPath'''
    __doc__ = '\n    Given a series of Traversable objects, implement a merged\n    version of the interface across all objects. Useful for\n    namespace packages which may be multihomed at a single\n    name.\n    '
    
    def __init__(self, *paths):
        self._paths = list(map(pathlib.Path, remove_duplicates(paths)))
        if not self._paths:
            message = 'MultiplexedPath must contain at least one path'
            raise FileNotFoundError(message)
        if not None((lambda .0: pass# WARNING: Decompyle incomplete
)(self._paths)):
            raise NotADirectoryError('MultiplexedPath only supports directories')

    
    def iterdir(self):
        pass
    # WARNING: Decompyle incomplete

    
    def read_bytes(self):
        raise FileNotFoundError(f'''{self} is not a file''')

    
    def read_text(self, *args, **kwargs):
        raise FileNotFoundError(f'''{self} is not a file''')

    
    def is_dir(self):
        return True

    
    def is_file(self):
        return False

    
    def joinpath(self, child):
        return self._paths[0] / child

    __truediv__ = joinpath
    
    def open(self, *args, **kwargs):
        raise FileNotFoundError(f'''{self} is not a file''')

    
    def name(self):
        return self._paths[0].name

    name = property(name)
    
    def __repr__(self):
        paths = ', '.join((lambda .0: pass# WARNING: Decompyle incomplete
)(self._paths))
        return f'''MultiplexedPath({paths})'''


MultiplexedPath = <NODE:26>(MultiplexedPath, 'MultiplexedPath', abc.Traversable)

def NamespaceReader():
    '''NamespaceReader'''
    
    def __init__(self, namespace_path):
        if 'NamespacePath' not in str(namespace_path):
            raise ValueError('Invalid path')
    # WARNING: Decompyle incomplete

    
    def resource_path(self, resource):
        '''
        Return the file system path to prevent
        `resources.path()` from creating a temporary
        copy.
        '''
        return str(self.path.joinpath(resource))

    
    def files(self):
        return self.path


NamespaceReader = <NODE:26>(NamespaceReader, 'NamespaceReader', abc.TraversableResources)
