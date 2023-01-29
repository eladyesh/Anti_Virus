
'''Various types of useful iterators and generators.'''
__all__ = [
    'body_line_iterator',
    'typed_subpart_iterator',
    'walk']
import sys
from io import StringIO

def walk(self):
    '''Walk over the message tree, yielding each subpart.

    The walk is performed in depth-first order.  This method is a
    generator.
    '''
    pass
# WARNING: Decompyle incomplete


def body_line_iterator(msg, decode = (False,)):
    '''Iterate over the parts, returning string payloads line-by-line.

    Optional decode (default False) is passed through to .get_payload().
    '''
    pass
# WARNING: Decompyle incomplete


def typed_subpart_iterator(msg, maintype, subtype = ('text', None)):
    '''Iterate over the subparts with a given MIME type.

    Use `maintype\' as the main MIME type to match against; this defaults to
    "text".  Optional `subtype\' is the MIME subtype to match against; if
    omitted, only the main type is matched.
    '''
    pass
# WARNING: Decompyle incomplete


def _structure(msg, fp, level, include_default = (None, 0, False)):
    '''A handy debugging aid'''
    if fp is None:
        fp = sys.stdout
    tab = ' ' * level * 4
    print(tab + msg.get_content_type(), '', fp, **('end', 'file'))
    if include_default:
        print(' [%s]' % msg.get_default_type(), fp, **('file',))
    else:
        print(fp, **('file',))
    if msg.is_multipart():
        pass
    return None

