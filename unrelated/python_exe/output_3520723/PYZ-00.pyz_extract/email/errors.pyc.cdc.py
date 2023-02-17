
'''email package exception classes.'''

class MessageError(Exception):
    '''Base class for errors in the email package.'''
    pass


class MessageParseError(MessageError):
    '''Base class for message parsing errors.'''
    pass


class HeaderParseError(MessageParseError):
    '''Error while parsing headers.'''
    pass


class BoundaryError(MessageParseError):
    """Couldn't find terminating boundary."""
    pass


class MultipartConversionError(TypeError, MessageError):
    '''Conversion to a multipart is prohibited.'''
    pass


class CharsetError(MessageError):
    '''An illegal charset was given.'''
    pass


class MessageDefect(ValueError):
    '''Base class for a message defect.'''
    
    def __init__(self = None, line = None):
        if line is not None:
            super().__init__(line)
        self.line = line

    __classcell__ = None


class NoBoundaryInMultipartDefect(MessageDefect):
    '''A message claimed to be a multipart but had no boundary parameter.'''
    pass


class StartBoundaryNotFoundDefect(MessageDefect):
    '''The claimed start boundary was never found.'''
    pass


class CloseBoundaryNotFoundDefect(MessageDefect):
    '''A start boundary was found, but not the corresponding close boundary.'''
    pass


class FirstHeaderLineIsContinuationDefect(MessageDefect):
    '''A message had a continuation line as its first header line.'''
    pass


class MisplacedEnvelopeHeaderDefect(MessageDefect):
    """A 'Unix-from' header was found in the middle of a header block."""
    pass


class MissingHeaderBodySeparatorDefect(MessageDefect):
    '''Found line with no leading whitespace and no colon before blank line.'''
    pass

MalformedHeaderDefect = MissingHeaderBodySeparatorDefect

class MultipartInvariantViolationDefect(MessageDefect):
    '''A message claimed to be a multipart but no subparts were found.'''
    pass


class InvalidMultipartContentTransferEncodingDefect(MessageDefect):
    '''An invalid content transfer encoding was set on the multipart itself.'''
    pass


class UndecodableBytesDefect(MessageDefect):
    '''Header contained bytes that could not be decoded'''
    pass


class InvalidBase64PaddingDefect(MessageDefect):
    '''base64 encoded sequence had an incorrect length'''
    pass


class InvalidBase64CharactersDefect(MessageDefect):
    '''base64 encoded sequence had characters not in base64 alphabet'''
    pass


class InvalidBase64LengthDefect(MessageDefect):
    '''base64 encoded sequence had invalid length (1 mod 4)'''
    pass


class HeaderDefect(MessageDefect):
    '''Base class for a header defect.'''
    
    def __init__(self = None, *args, **kw):
        pass
    # WARNING: Decompyle incomplete

    __classcell__ = None


class InvalidHeaderDefect(HeaderDefect):
    '''Header is not valid, message gives details.'''
    pass


class HeaderMissingRequiredValue(HeaderDefect):
    '''A header that must have a value had none'''
    pass


class NonPrintableDefect(HeaderDefect):
    '''ASCII characters outside the ascii-printable range found'''
    
    def __init__(self = None, non_printables = None):
        super().__init__(non_printables)
        self.non_printables = non_printables

    
    def __str__(self):
        return 'the following ASCII non-printables found in header: {}'.format(self.non_printables)

    __classcell__ = None


class ObsoleteHeaderDefect(HeaderDefect):
    '''Header uses syntax declared obsolete by RFC 5322'''
    pass


class NonASCIILocalPartDefect(HeaderDefect):
    '''local_part contains non-ASCII characters'''
    pass


class InvalidDateDefect(HeaderDefect):
    '''Header has unparseable or invalid date'''
    pass

