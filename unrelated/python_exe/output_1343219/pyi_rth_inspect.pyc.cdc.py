
import inspect
import os
import sys
_orig_inspect_getsourcefile = inspect.getsourcefile

def _pyi_getsourcefile(object):
    filename = inspect.getfile(object)
    if not os.path.isabs(filename):
        main_file = sys.modules['__main__'].__file__
        if filename == os.path.basename(main_file):
            return main_file
        if None.endswith('.py'):
            filename = os.path.normpath(os.path.join(sys._MEIPASS, filename + 'c'))
            if filename.startswith(sys._MEIPASS):
                return filename
            return None(object)
        if None.startswith(sys._MEIPASS) and filename.endswith('.pyc'):
            return filename
        return None(object)

inspect.getsourcefile = _pyi_getsourcefile
