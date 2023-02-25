import os
import ctypes

FILE_ATTRIBUTE_HIDDEN = 0x02


class Quarantine:

    @staticmethod
    def hide(path):
        if not os.path.exists(path):
            os.makedirs(path)
        ret = ctypes.windll.kernel32.SetFileAttributesW(path, FILE_ATTRIBUTE_HIDDEN)


if __name__ == "__main__":
    pass