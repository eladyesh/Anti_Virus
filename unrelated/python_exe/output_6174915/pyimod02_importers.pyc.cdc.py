
'''
PEP-302 and PEP-451 importers for frozen applications.
'''
import sys
import os
import pathlib
import io
import tokenize
import _frozen_importlib
from pyimod01_archive import ArchiveReadError, ZlibArchiveReader
SYS_PREFIX = sys._MEIPASS + os.sep
SYS_PREFIXLEN = len(SYS_PREFIX)
imp_new_module = type(sys)
if sys.flags.verbose and sys.stderr:
    
    def trace(msg, *a):
        sys.stderr.write(msg % a)
        sys.stderr.write('\n')

else:
    
    def trace(msg, *a):
        pass


class FrozenPackageImporter:
    '''
    Wrapper class for FrozenImporter that imports one specific fullname from a module named by an alternate fullname.
    The alternate fullname is derived from the __path__ of the package module containing that module.

    This is called by FrozenImporter.find_module whenever a module is found as a result of searching module.__path__
    '''
    
    def __init__(self, importer, entry_name):
        self._entry_name = entry_name
        self._importer = importer

    
    def load_module(self, fullname):
        return self._importer.load_module(fullname, self._entry_name)



def _decode_source(source_bytes):
    """
    Decode bytes representing source code and return the string. Universal newline support is used in the decoding.
    Based on CPython's implementation of the same functionality:
    https://github.com/python/cpython/blob/3.9/Lib/importlib/_bootstrap_external.py#L679-L688
    """
    source_bytes_readline = io.BytesIO(source_bytes).readline
    encoding = tokenize.detect_encoding(source_bytes_readline)
    newline_decoder = io.IncrementalNewlineDecoder(None, True, **('decoder', 'translate'))
    return newline_decoder.decode(source_bytes.decode(encoding[0]))


class FrozenImporter:
    '''
    Load bytecode of Python modules from the executable created by PyInstaller.

    Python bytecode is zipped and appended to the executable.

    NOTE: PYZ format cannot be replaced by zipimport module.

    The problem is that we have no control over zipimport; for instance, it does not work if the zip file is embedded
    into a PKG that is appended to an executable, like we create in one-file mode.

    This is PEP-302 finder and loader class for the ``sys.meta_path`` hook. A PEP-302 finder requires method
    find_module() to return loader class with method load_module(). Both these methods are implemented in one class.

    This is also a PEP-451 finder and loader class for the ModuleSpec type import system. A PEP-451 finder requires
    method find_spec(), a PEP-451 loader requires methods exec_module(), load_module(9 and (optionally) create_module().
    All these methods are implemented in this one class.

    To use this class just call:
        FrozenImporter.install()
    '''
    
    def __init__(self):
        '''
        Load, unzip and initialize the Zip archive bundled with the executable.
        '''
        pass
    # WARNING: Decompyle incomplete

    
    def _is_pep420_namespace_package(self, fullname):
        pass
    # WARNING: Decompyle incomplete

    
    def find_module(self, fullname, path = (None,)):
        '''
        PEP-302 finder.find_module() method for the ``sys.meta_path`` hook.

        fullname     fully qualified name of the module
        path         None for a top-level module, or package.__path__ for submodules or subpackages.

        Return a loader object if the module was found, or None if it was not. If find_module() raises an exception,
        it will be propagated to the caller, aborting the import.
        '''
        module_loader = None
        if fullname in self.toc:
            module_loader = self
            trace('import %s # PyInstaller PYZ', fullname)
        elif path is not None:
            modname = fullname.split('.')[-1]
            p = p[SYS_PREFIXLEN:]
            parts = p.split(os.sep)
            if not parts:
                continue
            if not parts[0]:
                parts = parts[1:]
            parts.append(modname)
            entry_name = '.'.join(parts)
            if entry_name in self.toc:
                module_loader = FrozenPackageImporter(self, entry_name)
                trace('import %s as %s # PyInstaller PYZ (__path__ override: %s)', entry_name, fullname, p)
            
        if module_loader is None:
            trace('# %s not found in PYZ', fullname)
        return module_loader

    
    def load_module(self, fullname, entry_name = (None,)):
        '''
        PEP-302 loader.load_module() method for the ``sys.meta_path`` hook.

        Return the loaded module (instance of imp_new_module()) or raise an exception, preferably ImportError if an
        existing exception is not being propagated.

        When called from FrozenPackageImporter, `entry_name` is the name of the module as it is stored in the archive.
        This module will be loaded and installed into sys.modules using `fullname` as its name.
        '''
        module = None
        if entry_name is None:
            entry_name = fullname
    # WARNING: Decompyle incomplete

    
    def is_package(self, fullname):
        pass
    # WARNING: Decompyle incomplete

    
    def get_code(self, fullname):
        '''
        Get the code object associated with the module.

        ImportError should be raised if module not found.
        '''
        pass
    # WARNING: Decompyle incomplete

    
    def get_source(self, fullname):
        '''
        Method should return the source code for the module as a string.
        But frozen modules does not contain source code.

        Return None, unless the corresponding source file was explicitly collected to the filesystem.
        '''
        pass
    # WARNING: Decompyle incomplete

    
    def get_data(self, path):
        '''
        Returns the data as a string, or raises IOError if the "file" was not found. The data is always returned as if
        "binary" mode was used.

        This method is useful for getting resources with \'pkg_resources\' that are bundled with Python modules in the
        PYZ archive.

        The \'path\' argument is a path that can be constructed by munging module.__file__ (or pkg.__path__ items).
        '''
        pass
    # WARNING: Decompyle incomplete

    
    def get_filename(self, fullname):
        '''
        This method should return the value that __file__ would be set to if the named module was loaded. If the module
        is not found, an ImportError should be raised.
        '''
        if self.is_package(fullname):
            filename = os.path.join(SYS_PREFIX, fullname.replace('.', os.path.sep), '__init__.pyc')
            return filename
        filename = None.path.join(SYS_PREFIX, fullname.replace('.', os.path.sep) + '.pyc')
        return filename

    
    def find_spec(self, fullname, path, target = (None, None)):
        '''
        PEP-451 finder.find_spec() method for the ``sys.meta_path`` hook.

        fullname     fully qualified name of the module
        path         None for a top-level module, or package.__path__ for
                     submodules or subpackages.
        target       unused by this Finder

        Finders are still responsible for identifying, and typically creating, the loader that should be used to load a
        module. That loader will now be stored in the module spec returned by find_spec() rather than returned directly.
        As is currently the case without the PEP-452, if a loader would be costly to create, that loader can be designed
        to defer the cost until later.

        Finders must return ModuleSpec objects when find_spec() is called. This new method replaces find_module() and
        find_loader() (in the PathEntryFinder case). If a loader does not have find_spec(), find_module() and
        find_loader() are used instead, for backward-compatibility.
        '''
        entry_name = None
        if path is not None:
            modname = fullname.rsplit('.')[-1]
            p = p[SYS_PREFIXLEN:]
            parts = p.split(os.sep)
            if not parts:
                continue
            if not parts[0]:
                parts = parts[1:]
            parts.append(modname)
            entry_name = '.'.join(parts)
            if entry_name in self.toc:
                trace('import %s as %s # PyInstaller PYZ (__path__ override: %s)', entry_name, fullname, p)
            
            entry_name = None
        if entry_name is None and fullname in self.toc:
            entry_name = fullname
            trace('import %s # PyInstaller PYZ', fullname)
        if entry_name is None:
            trace('# %s not found in PYZ', fullname)
            return None
        if None._is_pep420_namespace_package(entry_name):
            spec = _frozen_importlib.ModuleSpec(fullname, None, True, **('is_package',))
            spec.submodule_search_locations = [
                os.path.dirname(self.get_filename(entry_name))]
            return spec
        origin = None.get_filename(entry_name)
        is_pkg = self.is_package(entry_name)
        spec = _frozen_importlib.ModuleSpec(fullname, self, is_pkg, origin, entry_name, **('is_package', 'origin', 'loader_state'))
        spec.has_location = True
        if is_pkg:
            spec.submodule_search_locations = [
                os.path.dirname(self.get_filename(entry_name))]
        return spec

    
    def create_module(self, spec):
        '''
        PEP-451 loader.create_module() method for the ``sys.meta_path`` hook.

        Loaders may also implement create_module() that will return a new module to exec. It may return None to indicate
        that the default module creation code should be used. One use case, though atypical, for create_module() is to
        provide a module that is a subclass of the builtin module type. Most loaders will not need to implement
        create_module().

        create_module() should properly handle the case where it is called more than once for the same spec/module. This
        may include returning None or raising ImportError.
        '''
        pass

    
    def exec_module(self, module):
        '''
        PEP-451 loader.exec_module() method for the ``sys.meta_path`` hook.

        Loaders will have a new method, exec_module(). Its only job is to "exec" the module and consequently populate
        the module\'s namespace. It is not responsible for creating or preparing the module object, nor for any cleanup
        afterward. It has no return value. exec_module() will be used during both loading and reloading.

        exec_module() should properly handle the case where it is called more than once. For some kinds of modules this
        may mean raising ImportError every time after the first time the method is called. This is particularly relevant
        for reloading, where some kinds of modules do not support in-place reloading.
        '''
        spec = module.__spec__
        bytecode = self.get_code(spec.loader_state)
    # WARNING: Decompyle incomplete

    
    def get_resource_reader(self, fullname):
        '''
        Return importlib.resource-compatible resource reader.
        '''
        return FrozenResourceReader(self, fullname)



class FrozenResourceReader:
    """
    Resource reader for importlib.resources / importlib_resources support.

    Currently supports only on-disk resources (support for resources from the embedded archive is missing).
    However, this should cover the typical use cases (access to data files), as PyInstaller collects data files onto
    filesystem, and only .pyc modules are collected into embedded archive. One exception are resources collected from
    zipped eggs (which end up collected into embedded archive), but those should be rare anyway.

    When listing resources, source .py files will not be listed as they are not collected by default. Similarly,
    sub-directories that contained only .py files are not reconstructed on filesystem, so they will not be listed,
    either. If access to .py files is required for whatever reason, they need to be explicitly collected as data files
    anyway, which will place them on filesystem and make them appear as resources.

    For on-disk resources, we *must* return path compatible with pathlib.Path() in order to avoid copy to a temporary
    file, which might break under some circumstances, e.g., metpy with importlib_resources back-port, due to:
    https://github.com/Unidata/MetPy/blob/a3424de66a44bf3a92b0dcacf4dff82ad7b86712/src/metpy/plots/wx_symbols.py#L24-L25
    (importlib_resources tries to use 'fonts/wx_symbols.ttf' as a temporary filename suffix, which fails as it contains
    a separator).

    Furthermore, some packages expect files() to return either pathlib.Path or zipfile.Path, e.g.,
    https://github.com/tensorflow/datasets/blob/master/tensorflow_datasets/core/utils/resource_utils.py#L81-L97
    This makes implementation of mixed support for on-disk and embedded resources using importlib.abc.Traversable
    protocol rather difficult.

    So in order to maximize compatibility with unfrozen behavior, the below implementation is basically equivalent of
    importlib.readers.FileReader from python 3.10:
      https://github.com/python/cpython/blob/839d7893943782ee803536a47f1d4de160314f85/Lib/importlib/readers.py#L11
    and its underlying classes, importlib.abc.TraversableResources and importlib.abc.ResourceReader:
      https://github.com/python/cpython/blob/839d7893943782ee803536a47f1d4de160314f85/Lib/importlib/abc.py#L422
      https://github.com/python/cpython/blob/839d7893943782ee803536a47f1d4de160314f85/Lib/importlib/abc.py#L312
    """
    
    def __init__(self, importer, name):
        self.importer = importer
    # WARNING: Decompyle incomplete

    
    def open_resource(self, resource):
        return self.files().joinpath(resource).open('rb')

    
    def resource_path(self, resource):
        return str(self.path.joinpath(resource))

    
    def is_resource(self, path):
        return self.files().joinpath(path).is_file()

    
    def contents(self):
        return (lambda .0: pass# WARNING: Decompyle incomplete
)(self.files().iterdir())

    
    def files(self):
        return self.path



def install():
    '''
    Install FrozenImporter class and other classes into the import machinery.

    This function installs the FrozenImporter class into the import machinery of the running process. The importer is
    added to sys.meta_path. It could be added to sys.path_hooks, but sys.meta_path is processed by Python before
    looking at sys.path!

    The order of processing import hooks in sys.meta_path:

    1. built-in modules
    2. modules from the bundled ZIP archive
    3. C extension modules
    4. Modules from sys.path
    '''
    fimp = FrozenImporter()
    sys.meta_path.append(fimp)
# WARNING: Decompyle incomplete

