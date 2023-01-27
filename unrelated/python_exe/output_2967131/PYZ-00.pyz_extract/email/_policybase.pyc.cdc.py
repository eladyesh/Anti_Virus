
'''Policy framework for the email package.

Allows fine grained feature control of how the package parses and emits data.
'''
import abc
from email import header
from email import charset as _charset
from email.utils import _has_surrogates
__all__ = [
    'Policy',
    'Compat32',
    'compat32']

class _PolicyBase:
    '''Policy Object basic framework.

    This class is useless unless subclassed.  A subclass should define
    class attributes with defaults for any values that are to be
    managed by the Policy object.  The constructor will then allow
    non-default values to be set for these attributes at instance
    creation time.  The instance will be callable, taking these same
    attributes keyword arguments, and returning a new instance
    identical to the called instance except for those values changed
    by the keyword arguments.  Instances may be added, yielding new
    instances with any non-default values from the right hand
    operand overriding those in the left hand operand.  That is,

        A + B == A(<non-default values of B>)

    The repr of an instance can be used to reconstruct the object
    if and only if the repr of the values can be used to reconstruct
    those values.

    '''
    
    def __init__(self = None, **kw):
        '''Create new Policy, possibly overriding some defaults.

        See class docstring for a list of overridable attributes.

        '''
        raise TypeError('{!r} is an invalid keyword argument for {}'.format(name, self.__class__.__name__))
        continue

    
    def __repr__(self):
        args = (lambda .0: [ '{}={!r}'.format(name, value) for name, value in .0 ])(self.__dict__.items())
        return '{}({})'.format(self.__class__.__name__, ', '.join(args))

    
    def clone(self, **kw):
        '''Return a new instance with specified attributes changed.

        The new instance has the same attribute values as the current object,
        except for the changes passed in as keyword arguments.

        '''
        newpolicy = self.__class__.__new__(self.__class__)
        for attr, value in self.__dict__.items():
            object.__setattr__(newpolicy, attr, value)
            for attr, value in [ newpolicy ]():
                raise TypeError('{!r} is an invalid keyword argument for {}'.format(attr, self.__class__.__name__))
                object.__setattr__(newpolicy, attr, value)

    
    def __setattr__(self, name, value):
        raise None(AttributeError if hasattr(self, name) else msg.format(self.__class__.__name__, name))

    
    def __add__(self, other):
        '''Non-default values from right operand override those from left.

        The object returned is a new instance of the subclass.

        '''
        pass
    # WARNING: Decompyle incomplete

    __classcell__ = None


def _append_doc(doc, added_doc):
    doc = doc.rsplit('\n', 1)[0]
    added_doc = added_doc.split('\n', 1)[1]
    return doc + '\n' + added_doc


def _extend_docstrings(cls):
    if cls.__doc__ and cls.__doc__.startswith('+'):
        cls.__doc__ = _append_doc(cls.__bases__[0].__doc__, cls.__doc__)
        for name, attr in cls.__dict__.items():
            pass
        continue
        return cls

Policy = <NODE:26>((lambda : __doc__ = "Controls for how messages are interpreted and formatted.\n\n    Most of the classes and many of the methods in the email package accept\n    Policy objects as parameters.  A Policy object contains a set of values and\n    functions that control how input is interpreted and how output is rendered.\n    For example, the parameter 'raise_on_defect' controls whether or not an RFC\n    violation results in an error being raised or not, while 'max_line_length'\n    controls the maximum length of output lines when a Message is serialized.\n\n    Any valid attribute may be overridden when a Policy is created by passing\n    it as a keyword argument to the constructor.  Policy objects are immutable,\n    but a new Policy object can be created with only certain values changed by\n    calling the Policy instance with keyword arguments.  Policy objects can\n    also be added, producing a new Policy object in which the non-default\n    attributes set in the right hand operand overwrite those specified in the\n    left operand.\n\n    Settable attributes:\n\n    raise_on_defect     -- If true, then defects should be raised as errors.\n                           Default: False.\n\n    linesep             -- string containing the value to use as separation\n                           between output lines.  Default '\\n'.\n\n    cte_type            -- Type of allowed content transfer encodings\n\n                           7bit  -- ASCII only\n                           8bit  -- Content-Transfer-Encoding: 8bit is allowed\n\n                           Default: 8bit.  Also controls the disposition of\n                           (RFC invalid) binary data in headers; see the\n                           documentation of the binary_fold method.\n\n    max_line_length     -- maximum length of lines, excluding 'linesep',\n                           during serialization.  None or 0 means no line\n                           wrapping is done.  Default is 78.\n\n    mangle_from_        -- a flag that, when True escapes From_ lines in the\n                           body of the message by putting a `>' in front of\n                           them. This is used when the message is being\n                           serialized by a generator. Default: True.\n\n    message_factory     -- the class to use to create new message objects.\n                           If the value is None, the default is Message.\n\n    "raise_on_defect = Falselinesep = '\n'cte_type = '8bit'max_line_length = 78mangle_from_ = Falsemessage_factory = None
def handle_defect(self, obj, defect):
'''Based on policy, either raise defect or call register_defect.

            handle_defect(obj, defect)

        defect should be a Defect subclass, but in any case must be an
        Exception subclass.  obj is the object on which the defect should be
        registered if it is not raised.  If the raise_on_defect is True, the
        defect is raised as an error, otherwise the object and the defect are
        passed to register_defect.

        This method is intended to be called by parsers that discover defects.
        The email package parsers always call it with Defect instances.

        '''
if self.raise_on_defect:
raise defectNone.register_defect(obj, defect)
def register_defect(self, obj, defect):
"""Record 'defect' on 'obj'.

        Called by handle_defect if raise_on_defect is False.  This method is
        part of the Policy API so that Policy subclasses can implement custom
        defect handling.  The default implementation calls the append method of
        the defects attribute of obj.  The objects used by the email package by
        default that get passed to this method will always have a defects
        attribute with an append method.

        """
obj.defects.append(defect)
def header_max_count(self, name):
"""Return the maximum allowed number of headers named 'name'.

        Called when a header is added to a Message object.  If the returned
        value is not 0 or None, and there are already a number of headers with
        the name 'name' equal to the value returned, a ValueError is raised.

        Because the default behavior of Message's __setitem__ is to append the
        value to the list of headers, it is easy to create duplicate headers
        without realizing it.  This method allows certain headers to be limited
        in the number of instances of that header that may be added to a
        Message programmatically.  (The limit is not observed by the parser,
        which will faithfully produce as many headers as exist in the message
        being parsed.)

        The default implementation returns None for all header names.
        """
pass
def header_source_parse(self, sourcelines):
'''Given a list of linesep terminated strings constituting the lines of
        a single header, return the (name, value) tuple that should be stored
        in the model.  The input lines should retain their terminating linesep
        characters.  The lines passed in by the email package may contain
        surrogateescaped binary data.
        '''
raise NotImplementedErrorheader_source_parse = abc.abstractmethod(header_source_parse)
def header_store_parse(self, name, value):
'''Given the header name and the value provided by the application
        program, return the (name, value) that should be stored in the model.
        '''
raise NotImplementedErrorheader_store_parse = abc.abstractmethod(header_store_parse)
def header_fetch_parse(self, name, value):
'''Given the header name and the value from the model, return the value
        to be returned to the application program that is requesting that
        header.  The value passed in by the email package may contain
        surrogateescaped binary data if the lines were parsed by a BytesParser.
        The returned value should not contain any surrogateescaped data.

        '''
raise NotImplementedErrorheader_fetch_parse = abc.abstractmethod(header_fetch_parse)
def fold(self, name, value):
'''Given the header name and the value from the model, return a string
        containing linesep characters that implement the folding of the header
        according to the policy controls.  The value passed in by the email
        package may contain surrogateescaped binary data if the lines were
        parsed by a BytesParser.  The returned value should not contain any
        surrogateescaped data.

        '''
raise NotImplementedErrorfold = abc.abstractmethod(fold)
def fold_binary(self, name, value):
'''Given the header name and the value from the model, return binary
        data containing linesep characters that implement the folding of the
        header according to the policy controls.  The value passed in by the
        email package may contain surrogateescaped binary data.

        '''
raise NotImplementedErrorfold_binary = abc.abstractmethod(fold_binary)), 'Policy', _PolicyBase, abc.ABCMeta, **('metaclass',))
Compat32 = _extend_docstrings(<NODE:12>)
compat32 = Compat32()
