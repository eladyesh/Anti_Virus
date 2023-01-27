
__doc__ = 'HTTP/1.1 client library\n\n<intro stuff goes here>\n<other stuff, too>\n\nHTTPConnection goes through a number of "states", which define when a client\nmay legally make another request or fetch the response for a particular\nrequest. This diagram details these state transitions:\n\n    (null)\n      |\n      | HTTPConnection()\n      v\n    Idle\n      |\n      | putrequest()\n      v\n    Request-started\n      |\n      | ( putheader() )*  endheaders()\n      v\n    Request-sent\n      |\\_____________________________\n      |                              | getresponse() raises\n      | response = getresponse()     | ConnectionError\n      v                              v\n    Unread-response                Idle\n    [Response-headers-read]\n      |\\____________________\n      |                     |\n      | response.read()     | putrequest()\n      v                     v\n    Idle                  Req-started-unread-response\n                     ______/|\n                   /        |\n   response.read() |        | ( putheader() )*  endheaders()\n                   v        v\n       Request-started    Req-sent-unread-response\n                            |\n                            | response.read()\n                            v\n                          Request-sent\n\nThis diagram presents the following rules:\n  -- a second request may not be started until {response-headers-read}\n  -- a response [object] cannot be retrieved until {request-sent}\n  -- there is no differentiation between an unread response body and a\n     partially read response body\n\nNote: this enforcement is applied by the HTTPConnection class. The\n      HTTPResponse class does not enforce this state machine, which\n      implies sophisticated clients may accelerate the request/response\n      pipeline. Caution should be taken, though: accelerating the states\n      beyond the above pattern may imply knowledge of the server\'s\n      connection-close behavior for certain requests. For example, it\n      is impossible to tell whether the server will close the connection\n      UNTIL the response headers have been read; this means that further\n      requests cannot be placed into the pipeline until it is known that\n      the server will NOT be closing the connection.\n\nLogical State                  __state            __response\n-------------                  -------            ----------\nIdle                           _CS_IDLE           None\nRequest-started                _CS_REQ_STARTED    None\nRequest-sent                   _CS_REQ_SENT       None\nUnread-response                _CS_IDLE           <response_class>\nReq-started-unread-response    _CS_REQ_STARTED    <response_class>\nReq-sent-unread-response       _CS_REQ_SENT       <response_class>\n'
import email.parser as email
import email.message as email
import http
import io
import re
import socket
import collections.abc as collections
from urllib.parse import urlsplit
__all__ = [
    'HTTPResponse',
    'HTTPConnection',
    'HTTPException',
    'NotConnected',
    'UnknownProtocol',
    'UnknownTransferEncoding',
    'UnimplementedFileMode',
    'IncompleteRead',
    'InvalidURL',
    'ImproperConnectionState',
    'CannotSendRequest',
    'CannotSendHeader',
    'ResponseNotReady',
    'BadStatusLine',
    'LineTooLong',
    'RemoteDisconnected',
    'error',
    'responses']
HTTP_PORT = 80
HTTPS_PORT = 443
_UNKNOWN = 'UNKNOWN'
_CS_IDLE = 'Idle'
_CS_REQ_STARTED = 'Request-started'
_CS_REQ_SENT = 'Request-sent'
globals().update(http.HTTPStatus.__members__)
responses = (lambda .0: pass# WARNING: Decompyle incomplete
)(http.HTTPStatus.__members__.values())
_MAXLINE = 65536
_MAXHEADERS = 100
_is_legal_header_name = re.compile(b'[^:\\s][^:\\r\\n]*').fullmatch
_is_illegal_header_value = re.compile(b'\\n(?![ \\t])|\\r(?![ \\t\\n])').search
_contains_disallowed_url_pchar_re = re.compile('[\x00- \x7f]')
_contains_disallowed_method_pchar_re = re.compile('[\x00-\x1f]')
# WARNING: Decompyle incomplete
