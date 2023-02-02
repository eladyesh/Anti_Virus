
__doc__ = 'Guess the MIME type of a file.\n\nThis module defines two useful functions:\n\nguess_type(url, strict=True) -- guess the MIME type and encoding of a URL.\n\nguess_extension(type, strict=True) -- guess the extension for a given MIME type.\n\nIt also contains the following, for tuning the behavior:\n\nData:\n\nknownfiles -- list of files to parse\ninited -- flag set when init() has been called\nsuffix_map -- dictionary mapping suffixes to suffixes\nencodings_map -- dictionary mapping suffixes to encodings\ntypes_map -- dictionary mapping suffixes to types\n\nFunctions:\n\ninit([files]) -- parse a list of files, default knownfiles (on Windows, the\n  default values are taken from the registry)\nread_mime_types(file) -- parse one file, return a dictionary or None\n'
import os
import sys
import posixpath
import urllib.parse as urllib
# WARNING: Decompyle incomplete
