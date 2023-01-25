
__doc__ = 'A powerful, extensible, and easy-to-use option parser.\n\nBy Greg Ward <gward@python.net>\n\nOriginally distributed as Optik.\n\nFor support, use the optik-users@lists.sourceforge.net mailing list\n(http://lists.sourceforge.net/lists/listinfo/optik-users).\n\nSimple usage example:\n\n   from optparse import OptionParser\n\n   parser = OptionParser()\n   parser.add_option("-f", "--file", dest="filename",\n                     help="write report to FILE", metavar="FILE")\n   parser.add_option("-q", "--quiet",\n                     action="store_false", dest="verbose", default=True,\n                     help="don\'t print status messages to stdout")\n\n   (options, args) = parser.parse_args()\n'
__version__ = '1.5.3'
__all__ = [
    'Option',
    'make_option',
    'SUPPRESS_HELP',
    'SUPPRESS_USAGE',
    'Values',
    'OptionContainer',
    'OptionGroup',
    'OptionParser',
    'HelpFormatter',
    'IndentedHelpFormatter',
    'TitledHelpFormatter',
    'OptParseError',
    'OptionError',
    'OptionConflictError',
    'OptionValueError',
    'BadOptionError',
    'check_choice']
__copyright__ = '\nCopyright (c) 2001-2006 Gregory P. Ward.  All rights reserved.\nCopyright (c) 2002-2006 Python Software Foundation.  All rights reserved.\n\nRedistribution and use in source and binary forms, with or without\nmodification, are permitted provided that the following conditions are\nmet:\n\n  * Redistributions of source code must retain the above copyright\n    notice, this list of conditions and the following disclaimer.\n\n  * Redistributions in binary form must reproduce the above copyright\n    notice, this list of conditions and the following disclaimer in the\n    documentation and/or other materials provided with the distribution.\n\n  * Neither the name of the author nor the names of its\n    contributors may be used to endorse or promote products derived from\n    this software without specific prior written permission.\n\nTHIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS\nIS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED\nTO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A\nPARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR\nCONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,\nEXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,\nPROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR\nPROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF\nLIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING\nNEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS\nSOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n'
import sys
import os
import textwrap

def _repr(self):
    return '<%s at 0x%x: %s>' % (self.__class__.__name__, id(self), self)

# WARNING: Decompyle incomplete
