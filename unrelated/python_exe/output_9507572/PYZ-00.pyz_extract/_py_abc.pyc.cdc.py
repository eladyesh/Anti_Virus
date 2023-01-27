
from _weakrefset import WeakSet

def get_cache_token():
    '''Returns the current ABC cache token.

    The token is an opaque object (supporting equality testing) identifying the
    current version of the ABC cache for virtual subclasses. The token changes
    with every call to ``register()`` on any ABC.
    '''
    return ABCMeta._abc_invalidation_counter


class ABCMeta(type):
    """Metaclass for defining Abstract Base Classes (ABCs).

    Use this metaclass to create an ABC.  An ABC can be subclassed
    directly, and then acts as a mix-in class.  You can also register
    unrelated concrete classes (even built-in classes) and unrelated
    ABCs as 'virtual subclasses' -- these and their descendants will
    be considered subclasses of the registering ABC by the built-in
    issubclass() function, but the registering ABC won't show up in
    their MRO (Method Resolution Order) nor will method
    implementations defined by the registering ABC be callable (not
    even via super()).
    """
    _abc_invalidation_counter = 0
    
    def __new__(mcls = None, name = None, bases = None, namespace = None, **kwargs):
        pass
    # WARNING: Decompyle incomplete

    
    def register(cls, subclass):
        '''Register a virtual subclass of an ABC.

        Returns the subclass, to allow usage as a class decorator.
        '''
        if not isinstance(subclass, type):
            raise TypeError('Can only register classes')
        if None(subclass, cls):
            return subclass
        if None(cls, subclass):
            raise RuntimeError('Refusing to create an inheritance cycle')
        None._abc_registry.add(subclass)
        ABCMeta._abc_invalidation_counter += 1
        return subclass

    
    def _dump_registry(cls, file = (None,)):
        '''Debug helper to print the ABC registry.'''
        print(f'''Class: {cls.__module__}.{cls.__qualname__}''', file, **('file',))
        print(f'''Inv. counter: {get_cache_token()}''', file, **('file',))

    
    def _abc_registry_clear(cls):
        '''Clear the registry (for debugging or testing).'''
        cls._abc_registry.clear()

    
    def _abc_caches_clear(cls):
        '''Clear the caches (for debugging or testing).'''
        cls._abc_cache.clear()
        cls._abc_negative_cache.clear()

    
    def __instancecheck__(cls, instance):
        '''Override for isinstance(instance, cls).'''
        subclass = instance.__class__
        if subclass in cls._abc_cache:
            return True
        subtype = None(instance)
        if subtype is subclass:
            if cls._abc_negative_cache_version == ABCMeta._abc_invalidation_counter and subclass in cls._abc_negative_cache:
                return False
            return None.__subclasscheck__(subclass)
        return None((lambda .0 = None: pass)((subclass, subtype)))

    
    def __subclasscheck__(cls, subclass):
        '''Override for issubclass(subclass, cls).'''
        if not isinstance(subclass, type):
            raise TypeError('issubclass() arg 1 must be a class')
        if None in cls._abc_cache:
            return True
        if None._abc_negative_cache_version < ABCMeta._abc_invalidation_counter:
            cls._abc_negative_cache = WeakSet()
            cls._abc_negative_cache_version = ABCMeta._abc_invalidation_counter
    # WARNING: Decompyle incomplete

    __classcell__ = None

