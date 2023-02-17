
__doc__ = 'Generic (shallow and deep) copying operations.\n\nInterface summary:\n\n        import copy\n\n        x = copy.copy(y)        # make a shallow copy of y\n        x = copy.deepcopy(y)    # make a deep copy of y\n\nFor module specific errors, copy.Error is raised.\n\nThe difference between shallow and deep copying is only relevant for\ncompound objects (objects that contain other objects, like lists or\nclass instances).\n\n- A shallow copy constructs a new compound object and then (to the\n  extent possible) inserts *the same objects* into it that the\n  original contains.\n\n- A deep copy constructs a new compound object and then, recursively,\n  inserts *copies* into it of the objects found in the original.\n\nTwo problems often exist with deep copy operations that don\'t exist\nwith shallow copy operations:\n\n a) recursive objects (compound objects that, directly or indirectly,\n    contain a reference to themselves) may cause a recursive loop\n\n b) because deep copy copies *everything* it may copy too much, e.g.\n    administrative data structures that should be shared even between\n    copies\n\nPython\'s deep copy operation avoids these problems by:\n\n a) keeping a table of objects already copied during the current\n    copying pass\n\n b) letting user-defined classes override the copying operation or the\n    set of components copied\n\nThis version does not copy types like module, class, function, method,\nnor stack trace, stack frame, nor file, socket, window, nor array, nor\nany similar types.\n\nClasses can use the same interfaces to control copying that they use\nto control pickling: they can define methods called __getinitargs__(),\n__getstate__() and __setstate__().  See the documentation for module\n"pickle" for information on these methods.\n'
import types
import weakref
from copyreg import dispatch_table

class Error(Exception):
    pass

error = Error
# WARNING: Decompyle incomplete
