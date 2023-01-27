
'''
Set search path for pywin32 DLLs. Due to the large number of pywin32 modules, we use a single loader-level script
instead of per-module runtime hook scripts.
'''
import os
import sys

def install():
    pywin32_system32_path = os.path.join(sys._MEIPASS, 'pywin32_system32')
    if not os.path.isdir(pywin32_system32_path):
        return None
    None.path.append(pywin32_system32_path)
    if hasattr(os, 'add_dll_directory'):
        os.add_dll_directory(pywin32_system32_path)
        path = os.environ.get('PATH', None)
        if not path:
            path = pywin32_system32_path
        else:
            path = pywin32_system32_path + os.pathsep + path
            os.environ['PATH'] = path
            return None

