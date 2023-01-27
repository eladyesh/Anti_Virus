
__doc__ = "Parser for command line options.\n\nThis module helps scripts to parse the command line arguments in\nsys.argv.  It supports the same conventions as the Unix getopt()\nfunction (including the special meanings of arguments of the form `-'\nand `--').  Long options similar to those supported by GNU software\nmay be used as well via an optional third argument.  This module\nprovides two functions and an exception:\n\ngetopt() -- Parse command line options\ngnu_getopt() -- Like getopt(), but allow option and non-option arguments\nto be intermixed.\nGetoptError -- exception (class) raised with 'opt' attribute, which is the\noption involved with the exception.\n"
__all__ = [
    'GetoptError',
    'error',
    'getopt',
    'gnu_getopt']
import os
# WARNING: Decompyle incomplete
