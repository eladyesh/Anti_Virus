
import sys
from ctypes import *
_array_type = type(Array)

def _other_endian(typ):
    """Return the type with the 'other' byte order.  Simple types like
    c_int and so on already have __ctype_be__ and __ctype_le__
    attributes which contain the types, for more complicated types
    arrays and structures are supported.
    """
    if hasattr(typ, _OTHER_ENDIAN):
        return getattr(typ, _OTHER_ENDIAN)
    if None(typ, _array_type):
        return _other_endian(typ._type_) * typ._length_
    if None(typ, Structure):
        return typ
    raise None('This type does not support other endian: %s' % typ)

_swapped_meta = None(None, None, <NODE:12>)
if sys.byteorder == 'little':
    _OTHER_ENDIAN = '__ctype_be__'
    LittleEndianStructure = Structure
    BigEndianStructure = <NODE:26>((lambda : __doc__ = 'Structure with big endian byte order'__slots__ = ()_swappedbytes_ = None), 'BigEndianStructure', Structure, _swapped_meta, **('metaclass',))
elif sys.byteorder == 'big':
    _OTHER_ENDIAN = '__ctype_le__'
    BigEndianStructure = Structure
    LittleEndianStructure = <NODE:26>((lambda : __doc__ = 'Structure with little endian byte order'__slots__ = ()_swappedbytes_ = None), 'LittleEndianStructure', Structure, _swapped_meta, **('metaclass',))
else:
    raise RuntimeError('Invalid byteorder')
