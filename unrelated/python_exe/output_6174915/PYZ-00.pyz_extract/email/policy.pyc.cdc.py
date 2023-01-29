
'''This will be the home for the policy that hooks in the new
code that adds all the email6 features.
'''
import re
import sys
from email._policybase import Policy, Compat32, compat32, _extend_docstrings
from email.utils import _has_surrogates
from email.headerregistry import HeaderRegistry
from email.contentmanager import raw_data_manager
from email.message import EmailMessage
__all__ = [
    'Compat32',
    'compat32',
    'Policy',
    'EmailPolicy',
    'default',
    'strict',
    'SMTP',
    'HTTP']
linesep_splitter = re.compile('\\n|\\r')
EmailPolicy = _extend_docstrings(<NODE:12>)
default = EmailPolicy()
del default.header_factory
strict = default.clone(True, **('raise_on_defect',))
SMTP = default.clone('\r\n', **('linesep',))
HTTP = default.clone('\r\n', None, **('linesep', 'max_line_length'))
SMTPUTF8 = SMTP.clone(True, **('utf8',))
