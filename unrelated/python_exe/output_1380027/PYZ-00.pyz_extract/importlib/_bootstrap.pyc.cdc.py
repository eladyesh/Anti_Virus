
'''Core implementation of import.

This module is NOT meant to be directly imported! It has been designed such
that it can be bootstrapped into Python as the implementation of import. As
such it requires the injection of specific modules and attributes in order to
work. One should use importlib as the public-facing version of this module.

'''
_bootstrap_external = None

def _wrap(new, old):
    '''Simple substitute for functools.update_wrapper.'''
    new.__dict__.update(old.__dict__)


def _new_module(name):
    return type(sys)(name)

_module_locks = { }
_blocking_on = { }

class _DeadlockError(RuntimeError):
    pass


class _ModuleLock:
    '''A recursive lock implementation which is able to detect deadlocks
    (e.g. thread 1 trying to take locks A then B, and thread 2 trying to
    take locks B then A).
    '''
    
    def __init__(self, name):
        self.lock = _thread.allocate_lock()
        self.wakeup = _thread.allocate_lock()
        self.name = name
        self.owner = None
        self.count = 0
        self.waiters = 0

    
    def has_deadlock(self):
        me = _thread.get_ident()
        tid = self.owner
        seen = set()
        lock = _blocking_on.get(tid)
        if lock is None:
            return False
        tid = None.owner
        if tid == me:
            return True
        if None in seen:
            return False
        None.add(tid)
        continue

    
    def acquire(self):
        '''
        Acquire the module lock.  If a potential deadlock is detected,
        a _DeadlockError is raised.
        Otherwise, the lock is always acquired and True is returned.
        '''
        tid = _thread.get_ident()
        _blocking_on[tid] = self
    # WARNING: Decompyle incomplete

    
    def release(self):
        tid = _thread.get_ident()
    # WARNING: Decompyle incomplete

    
    def __repr__(self):
        return '_ModuleLock({!r}) at {}'.format(self.name, id(self))



class _DummyModuleLock:
    '''A simple _ModuleLock equivalent for Python builds without
    multi-threading support.'''
    
    def __init__(self, name):
        self.name = name
        self.count = 0

    
    def acquire(self):
        self.count += 1
        return True

    
    def release(self):
        if self.count == 0:
            raise RuntimeError('cannot release un-acquired lock')
        None.count -= 1

    
    def __repr__(self):
        return '_DummyModuleLock({!r}) at {}'.format(self.name, id(self))



class _ModuleLockManager:
    
    def __init__(self, name):
        self._name = name
        self._lock = None

    
    def __enter__(self):
        self._lock = _get_module_lock(self._name)
        self._lock.acquire()

    
    def __exit__(self, *args, **kwargs):
        self._lock.release()



def _get_module_lock(name):
    '''Get or create the module lock for a given module name.

    Acquire/release internally the global import lock to protect
    _module_locks.'''
    _imp.acquire_lock()
# WARNING: Decompyle incomplete


def _lock_unlock_module(name):
    '''Acquires then releases the module lock for a given module name.

    This is used to ensure a module is completely initialized, in the
    event it is being imported by another thread.
    '''
    lock = _get_module_lock(name)
# WARNING: Decompyle incomplete


def _call_with_frames_removed(f, *args, **kwds):
    '''remove_importlib_frames in import.c will always remove sequences
    of importlib frames that end with a call to this function

    Use it instead of a normal call in places where including the importlib
    frames introduces unwanted noise into the traceback (e.g. when executing
    module code)
    '''
    pass
# WARNING: Decompyle incomplete


def _verbose_message(message = None, *, verbosity, *args):
    '''Print the message to stderr if -v/PYTHONVERBOSE is turned on.'''
    pass
# WARNING: Decompyle incomplete


def _requires_builtin(fxn):
    '''Decorator to verify the named module is built-in.'''
    
    def _requires_builtin_wrapper(self = None, fullname = None):
        if fullname not in sys.builtin_module_names:
            raise ImportError('{!r} is not a built-in module'.format(fullname), fullname, **('name',))
        return None(self, fullname)

    _wrap(_requires_builtin_wrapper, fxn)
    return _requires_builtin_wrapper


def _requires_frozen(fxn):
    '''Decorator to verify the named module is frozen.'''
    
    def _requires_frozen_wrapper(self = None, fullname = None):
        if not _imp.is_frozen(fullname):
            raise ImportError('{!r} is not a frozen module'.format(fullname), fullname, **('name',))
        return None(self, fullname)

    _wrap(_requires_frozen_wrapper, fxn)
    return _requires_frozen_wrapper


def _load_module_shim(self, fullname):
    '''Load the specified module into sys.modules and return it.

    This method is deprecated.  Use loader.exec_module instead.

    '''
    spec = spec_from_loader(fullname, self)
    if fullname in sys.modules:
        module = sys.modules[fullname]
        _exec(spec, module)
        return sys.modules[fullname]
    return None(spec)


def _module_repr(module):
    loader = getattr(module, '__loader__', None)
# WARNING: Decompyle incomplete


class ModuleSpec:
    '''The specification for a module, used for loading.

    A module\'s spec is the source for information about the module.  For
    data associated with the module, including source, use the spec\'s
    loader.

    `name` is the absolute name of the module.  `loader` is the loader
    to use when loading the module.  `parent` is the name of the
    package the module is in.  The parent is derived from the name.

    `is_package` determines if the module is considered a package or
    not.  On modules this is reflected by the `__path__` attribute.

    `origin` is the specific location used by the loader from which to
    load the module, if that information is available.  When filename is
    set, origin will match.

    `has_location` indicates that a spec\'s "origin" reflects a location.
    When this is True, `__file__` attribute of the module is set.

    `cached` is the location of the cached bytecode file, if any.  It
    corresponds to the `__cached__` attribute.

    `submodule_search_locations` is the sequence of path entries to
    search when importing submodules.  If set, is_package should be
    True--and False otherwise.

    Packages are simply modules that (may) have submodules.  If a spec
    has a non-None value in `submodule_search_locations`, the import
    system will consider modules loaded from the spec as packages.

    Only finders (see importlib.abc.MetaPathFinder and
    importlib.abc.PathEntryFinder) should modify ModuleSpec instances.

    '''
    
    def __init__(self, name = None, loader = {
        'origin': None,
        'loader_state': None,
        'is_package': None }, *, origin, loader_state, is_package):
        self.name = name
        self.loader = loader
        self.origin = origin
        self.loader_state = loader_state
        None if is_package else self.submodule_search_locations = []
        self._set_fileattr = False
        self._cached = None

    
    def __repr__(self):
        args = [
            'name={!r}'.format(self.name),
            'loader={!r}'.format(self.loader)]
        if self.origin is not None:
            args.append('origin={!r}'.format(self.origin))
            if self.submodule_search_locations is not None:
                args.append('submodule_search_locations={}'.format(self.submodule_search_locations))
                return '{}({})'.format(self.__class__.__name__, ', '.join(args))

    
    def __eq__(self, other):
        smsl = self.submodule_search_locations
    # WARNING: Decompyle incomplete

    
    def cached(self):
        if self._cached is None and self.origin is not None and self._set_fileattr:
            if _bootstrap_external is None:
                raise NotImplementedError
            self._cached = None._get_cached(self.origin)
            return self._cached

    cached = property(cached)
    
    def cached(self, cached):
        self._cached = cached

    cached = cached.setter(cached)
    
    def parent(self):
        """The name of the module's parent."""
        if self.submodule_search_locations is None:
            return self.name.rpartition('.')[0]
        return None.name

    parent = property(parent)
    
    def has_location(self):
        return self._set_fileattr

    has_location = property(has_location)
    
    def has_location(self, value):
        self._set_fileattr = bool(value)

    has_location = has_location.setter(has_location)


def spec_from_loader(name = None, loader = {
    'origin': None,
    'is_package': None }, *, origin, is_package):
    '''Return a module spec based on various loader methods.'''
    if hasattr(loader, 'get_filename'):
        if _bootstrap_external is None:
            raise NotImplementedError
        spec_from_file_location = None.spec_from_file_location
        if is_package is None:
            return spec_from_file_location(name, loader, **('loader',))
        return spec_from_file_location(name, loader, search, **('loader', 'submodule_search_locations'))
# WARNING: Decompyle incomplete


def _spec_from_module(module, loader, origin = (None, None)):
    pass
# WARNING: Decompyle incomplete


def _init_module_attrs(spec = None, module = {
    'override': False }, *, override):
    pass
# WARNING: Decompyle incomplete


def module_from_spec(spec):
    '''Create a module based on the provided spec.'''
    module = None
    if hasattr(spec.loader, 'create_module'):
        module = spec.loader.create_module(spec)
    elif hasattr(spec.loader, 'exec_module'):
        raise ImportError('loaders that define exec_module() must also define create_module()')
        if module is None:
            module = _new_module(spec.name)
            _init_module_attrs(spec, module)
            return module


def _module_repr_from_spec(spec):
    '''Return the repr to use for the module.'''
    if '?' if spec.name is None else spec.origin is None:
        if spec.loader is None:
            return '<module {!r}>'.format(name)
        return None.format(name, spec.loader)
    if spec.has_location:
        return '<module {!r} from {!r}>'.format(name, spec.origin)
    return None.format(spec.name, spec.origin)


def _exec(spec, module):
    """Execute the spec's specified module in an existing module's namespace."""
    name = spec.name
    with _ModuleLockManager(name):
        if sys.modules.get(name) is not module:
            msg = 'module {!r} not in sys.modules'.format(name)
            raise ImportError(msg, name, **('name',))
        if spec.loader is None:
            if spec.submodule_search_locations is None:
                raise ImportError('missing loader', spec.name, **('name',))
            None(spec, module, True, **('override',))
        else:
            _init_module_attrs(spec, module, True, **('override',))
            if not hasattr(spec.loader, 'exec_module'):
                spec.loader.load_module(name)
            else:
                spec.loader.exec_module(module)
            module = sys.modules.pop(spec.name)
            sys.modules[spec.name] = module
    module = sys.modules.pop(spec.name)
    sys.modules[spec.name] = module
# WARNING: Decompyle incomplete


def _load_backward_compatible(spec):
    pass
# WARNING: Decompyle incomplete


def _load_unlocked(spec):
    if not spec.loader is not None and hasattr(spec.loader, 'exec_module'):
        return _load_backward_compatible(spec)
    module = None(spec)
    spec._initializing = True
# WARNING: Decompyle incomplete


def _load(spec):
    """Return a new module object, loaded by the spec's loader.

    The module is not added to its parent.

    If a module is already in sys.modules, that existing module gets
    clobbered.

    """
    pass
# WARNING: Decompyle incomplete


class BuiltinImporter:
    '''Meta path import for built-in modules.

    All methods are either class or static methods to avoid the need to
    instantiate the class.

    '''
    _ORIGIN = 'built-in'
    
    def module_repr(module):
        '''Return repr for the module.

        The method is deprecated.  The import machinery does the job itself.

        '''
        return f'''<module {module.__name__!r} ({BuiltinImporter._ORIGIN})>'''

    module_repr = staticmethod(module_repr)
    
    def find_spec(cls, fullname, path, target = (None, None)):
        if path is not None:
            return None
        if None.is_builtin(fullname):
            return spec_from_loader(fullname, cls, cls._ORIGIN, **('origin',))
        return None

    find_spec = classmethod(find_spec)
    
    def find_module(cls, fullname, path = (None,)):
        """Find the built-in module.

        If 'path' is ever specified then the search is considered a failure.

        This method is deprecated.  Use find_spec() instead.

        """
        spec = cls.find_spec(fullname, path)
        if spec is not None:
            return spec.loader

    find_module = classmethod(find_module)
    
    def create_module(self, spec):
        '''Create a built-in module'''
        if spec.name not in sys.builtin_module_names:
            raise ImportError('{!r} is not a built-in module'.format(spec.name), spec.name, **('name',))
        return None(_imp.create_builtin, spec)

    create_module = classmethod(create_module)
    
    def exec_module(self, module):
        '''Exec a built-in module'''
        _call_with_frames_removed(_imp.exec_builtin, module)

    exec_module = classmethod(exec_module)
    
    def get_code(cls, fullname):
        '''Return None as built-in modules do not have code objects.'''
        pass

    get_code = classmethod(_requires_builtin(get_code))
    
    def get_source(cls, fullname):
        '''Return None as built-in modules do not have source code.'''
        pass

    get_source = classmethod(_requires_builtin(get_source))
    
    def is_package(cls, fullname):
        '''Return False as built-in modules are never packages.'''
        return False

    is_package = classmethod(_requires_builtin(is_package))
    load_module = classmethod(_load_module_shim)


class FrozenImporter:
    '''Meta path import for frozen modules.

    All methods are either class or static methods to avoid the need to
    instantiate the class.

    '''
    _ORIGIN = 'frozen'
    
    def module_repr(m):
        '''Return repr for the module.

        The method is deprecated.  The import machinery does the job itself.

        '''
        return '<module {!r} ({})>'.format(m.__name__, FrozenImporter._ORIGIN)

    module_repr = staticmethod(module_repr)
    
    def find_spec(cls, fullname, path, target = (None, None)):
        if _imp.is_frozen(fullname):
            return spec_from_loader(fullname, cls, cls._ORIGIN, **('origin',))
        return None

    find_spec = classmethod(find_spec)
    
    def find_module(cls, fullname, path = (None,)):
        '''Find a frozen module.

        This method is deprecated.  Use find_spec() instead.

        '''
        if _imp.is_frozen(fullname):
            return cls

    find_module = classmethod(find_module)
    
    def create_module(cls, spec):
        '''Use default semantics for module creation.'''
        pass

    create_module = classmethod(create_module)
    
    def exec_module(module):
        name = module.__spec__.name
        if not _imp.is_frozen(name):
            raise ImportError('{!r} is not a frozen module'.format(name), name, **('name',))
        code = None(_imp.get_frozen_object, name)
        exec(code, module.__dict__)

    exec_module = staticmethod(exec_module)
    
    def load_module(cls, fullname):
        '''Load a frozen module.

        This method is deprecated.  Use exec_module() instead.

        '''
        return _load_module_shim(cls, fullname)

    load_module = classmethod(load_module)
    
    def get_code(cls, fullname):
        '''Return the code object for the frozen module.'''
        return _imp.get_frozen_object(fullname)

    get_code = classmethod(_requires_frozen(get_code))
    
    def get_source(cls, fullname):
        '''Return None as frozen modules do not have source code.'''
        pass

    get_source = classmethod(_requires_frozen(get_source))
    
    def is_package(cls, fullname):
        '''Return True if the frozen module is a package.'''
        return _imp.is_frozen_package(fullname)

    is_package = classmethod(_requires_frozen(is_package))


class _ImportLockContext:
    '''Context manager for the import lock.'''
    
    def __enter__(self):
        '''Acquire the import lock.'''
        _imp.acquire_lock()

    
    def __exit__(self, exc_type, exc_value, exc_traceback):
        '''Release the import lock regardless of any raised exceptions.'''
        _imp.release_lock()



def _resolve_name(name, package, level):
    '''Resolve a relative module name to an absolute one.'''
    bits = package.rsplit('.', level - 1)
    if len(bits) < level:
        raise ImportError('attempted relative import beyond top-level package')
    base = None[0]
    if name:
        return '{}.{}'.format(base, name)


def _find_spec_legacy(finder, name, path):
    loader = finder.find_module(name, path)
    if loader is None:
        return None
    return None(name, loader)


def _find_spec(name, path, target = (None,)):
    """Find a module's spec."""
    meta_path = sys.meta_path
    if meta_path is None:
        raise ImportError('sys.meta_path is None, Python is likely shutting down')
# WARNING: Decompyle incomplete


def _sanity_check(name, package, level):
    '''Verify arguments are "sane".'''
    if not isinstance(name, str):
        raise TypeError('module name must be str, not {}'.format(type(name)))
    if None < 0:
        raise ValueError('level must be >= 0')
    if None > 0:
        if not isinstance(package, str):
            raise TypeError('__package__ not set to a string')
        if not package:
            raise ImportError('attempted relative import with no known parent package')
        if None and level == 0:
            raise ValueError('Empty module name')
        return None

_ERR_MSG_PREFIX = 'No module named '
_ERR_MSG = _ERR_MSG_PREFIX + '{!r}'

def _find_and_load_unlocked(name, import_):
    path = None
    parent = name.rpartition('.')[0]
# WARNING: Decompyle incomplete

_NEEDS_LOADING = object()

def _find_and_load(name, import_):
    '''Find and load the module.'''
    with _ModuleLockManager(name):
        module = sys.modules.get(name, _NEEDS_LOADING)
        if module is _NEEDS_LOADING:
            pass
        None(None, None, None)
        return None
        None(None, None, None)
# WARNING: Decompyle incomplete


def _gcd_import(name, package, level = (None, 0)):
    '''Import and return the module based on its name, the package the call is
    being made from, and the level adjustment.

    This function represents the greatest common denominator of functionality
    between import_module and __import__. This includes setting __package__ if
    the loader did not.

    '''
    _sanity_check(name, package, level)
    if level > 0:
        name = _resolve_name(name, package, level)
        return _find_and_load(name, _gcd_import)


def _handle_fromlist(module, fromlist = None, import_ = {
    'recursive': False }, *, recursive):
    """Figure out what __import__ should return.

    The import_ parameter is a callable which takes the name of module to
    import. It is required to decouple the function from assuming importlib's
    import implementation is desired.

    """
    for x in fromlist:
        where = module.__name__ + '.__all__'
    where = "``from list''"
    raise TypeError(f'''Item in {where} must be str, not {type(x).__name__}''')
    continue
# WARNING: Decompyle incomplete


def _calc___package__(globals):
    '''Calculate what __package__ should be.

    __package__ is not guaranteed to be defined or could be set to None
    to represent that its proper value is unknown.

    '''
    package = globals.get('__package__')
    spec = globals.get('__spec__')
    if package is not None:
        if spec is not None and package != spec.parent:
            _warnings.warn(f'''__package__ != __spec__.parent ({package!r} != {spec.parent!r})''', ImportWarning, 3, **('stacklevel',))
            return package
        if None is not None:
            return spec.parent
        None.warn("can't resolve package from __spec__ or __package__, falling back on __name__ and __path__", ImportWarning, 3, **('stacklevel',))
        package = globals['__name__']
        if '__path__' not in globals:
            package = package.rpartition('.')[0]
            return package


def __import__(name, globals, locals, fromlist, level = (None, None, (), 0)):
    """Import a module.

    The 'globals' argument is used to infer where the import is occurring from
    to handle relative imports. The 'locals' argument is ignored. The
    'fromlist' argument specifies what should exist as attributes on the module
    being imported (e.g. ``from module import <fromlist>``).  The 'level'
    argument represents the package location to import from in a relative
    import (e.g. ``from ..pkg import mod`` would have a 'level' of 2).

    """
    if level == 0:
        module = _gcd_import(name)
    elif globals is not None:
        pass
    else:
        globals_ = { }
    package = _calc___package__(globals_)
    module = _gcd_import(name, package, level)
    if not fromlist:
        if level == 0:
            return _gcd_import(name.partition('.')[0])
        if not globals:
            return module
        cut_off = None(name) - len(name.partition('.')[0])
        return sys.modules[module.__name__[:len(module.__name__) - cut_off]]
    if hasattr(module, '__path__'):
        return _handle_fromlist(module, fromlist, _gcd_import)
    return globals


def _builtin_from_name(name):
    spec = BuiltinImporter.find_spec(name)
    if spec is None:
        raise ImportError('no built-in module named ' + name)
    return None(spec)


def _setup(sys_module, _imp_module):
    '''Setup importlib by importing needed built-in modules and injecting them
    into the global namespace.

    As sys is needed for sys.modules access and _imp is needed to load built-in
    modules, those two modules must be explicitly passed in.

    '''
    global _imp, sys
    _imp = _imp_module
    sys = sys_module
    module_type = type(sys)
    for name, module in sys.modules.items():
        loader = BuiltinImporter
    if _imp.is_frozen(name):
        loader = FrozenImporter
    
    spec = _spec_from_module(module, loader)
    _init_module_attrs(spec, module)
    continue
    self_module = sys.modules[__name__]
    for builtin_name in ('_thread', '_warnings', '_weakref'):
        builtin_module = _builtin_from_name(builtin_name)
    builtin_module = sys.modules[builtin_name]
    setattr(self_module, builtin_name, builtin_module)


def _install(sys_module, _imp_module):
    '''Install importers for builtin and frozen modules'''
    _setup(sys_module, _imp_module)
    sys.meta_path.append(BuiltinImporter)
    sys.meta_path.append(FrozenImporter)


def _install_external_importers():
    '''Install importers that require external filesystem access'''
    global _bootstrap_external
    import _frozen_importlib_external
    _bootstrap_external = _frozen_importlib_external
    _frozen_importlib_external._install(sys.modules[__name__])

