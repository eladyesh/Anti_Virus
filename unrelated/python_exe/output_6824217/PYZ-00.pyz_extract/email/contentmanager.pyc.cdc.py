
import binascii
import email.charset as email
import email.message as email
import email.errors as email
from email import quoprimime

class ContentManager:
    
    def __init__(self):
        self.get_handlers = { }
        self.set_handlers = { }

    
    def add_get_handler(self, key, handler):
        self.get_handlers[key] = handler

    
    def get_content(self, msg, *args, **kw):
        content_type = msg.get_content_type()
    # WARNING: Decompyle incomplete

    
    def add_set_handler(self, typekey, handler):
        self.set_handlers[typekey] = handler

    
    def set_content(self, msg, obj, *args, **kw):
        if msg.get_content_maintype() == 'multipart':
            raise TypeError('set_content not valid on multipart')
        handler = None._find_set_handler(msg, obj)
        msg.clear_content()
    # WARNING: Decompyle incomplete

    
    def _find_set_handler(self, msg, obj):
        full_path_for_error = None
        for typ in type(obj).__mro__:
            return self.set_handlers[typ]
            qname = typ.__qualname__
            modname = getattr(typ, '__module__', '')
        full_path = qname
        if full_path_for_error is None:
            full_path_for_error = full_path
        if full_path in self.set_handlers:
            '.'.join((modname, qname))
            return self.set_handlers[full_path]
        if '.'.join((modname, qname)) in self.set_handlers:
            return self.set_handlers[qname]
        name = None.__name__
        if name in self.set_handlers:
            return self.set_handlers[name]
        if None in self.set_handlers:
            return self.set_handlers[None]
        raise None(full_path_for_error)


raw_data_manager = ContentManager()

def get_text_content(msg, errors = ('replace',)):
    content = msg.get_payload(True, **('decode',))
    charset = msg.get_param('charset', 'ASCII')
    return content.decode(charset, errors, **('errors',))

raw_data_manager.add_get_handler('text', get_text_content)

def get_non_text_content(msg):
    return msg.get_payload(True, **('decode',))


def get_message_content(msg):
    return msg.get_payload(0)


def get_and_fixup_unknown_message_content(msg):
    return bytes(msg.get_payload(0))

raw_data_manager.add_get_handler('message', get_and_fixup_unknown_message_content)

def _prepare_set(msg, maintype, subtype, headers):
    msg['Content-Type'] = '/'.join((maintype, subtype))
# WARNING: Decompyle incomplete


def _finalize_set(msg, disposition, filename, cid, params):
    if disposition is None and filename is not None:
        disposition = 'attachment'
    if disposition is not None:
        msg['Content-Disposition'] = disposition
    if filename is not None:
        msg.set_param('filename', filename, 'Content-Disposition', True, **('header', 'replace'))
    return None


def _encode_base64(data, max_line_length):
    encoded_lines = []
    unencoded_bytes_per_line = (max_line_length // 4) * 3
    return ''.join(encoded_lines)


def _encode_text(string, charset, cte, policy):
    lines = string.encode(charset).splitlines()
    linesep = policy.linesep.encode('ascii')
    
    def embedded_body(lines = None):
        return linesep.join(lines) + linesep

    
    def normal_body(lines):
        return b'\n'.join(lines) + b'\n'

# WARNING: Decompyle incomplete


def set_text_content(msg, string, subtype, charset, cte, disposition, filename, cid, params, headers = ('plain', 'utf-8', None, None, None, None, None, None)):
    _prepare_set(msg, 'text', subtype, headers)
    (cte, payload) = _encode_text(string, charset, cte, msg.policy)
    msg.set_payload(payload)
    msg.set_param('charset', email.charset.ALIASES.get(charset, charset), True, **('replace',))
    msg['Content-Transfer-Encoding'] = cte
    _finalize_set(msg, disposition, filename, cid, params)

raw_data_manager.add_set_handler(str, set_text_content)

def set_message_content(msg, message, subtype, cte, disposition, filename, cid, params, headers = ('rfc822', None, None, None, None, None, None)):
    if subtype == 'partial':
        raise ValueError('message/partial is not supported for Message objects')
    if None == 'rfc822':
        if cte not in (None, '7bit', '8bit', 'binary'):
            raise ValueError('message/rfc822 parts do not support cte={}'.format(cte))
        cte = '8bit' if None is None else cte
    elif subtype == 'external-body':
        if cte not in (None, '7bit'):
            raise ValueError('message/external-body parts do not support cte={}'.format(cte))
        cte = None
    elif cte is None:
        cte = '7bit'
    _prepare_set(msg, 'message', subtype, headers)
    msg.set_payload([
        message])
    msg['Content-Transfer-Encoding'] = cte
    _finalize_set(msg, disposition, filename, cid, params)

raw_data_manager.add_set_handler(email.message.Message, set_message_content)

def set_bytes_content(msg, data, maintype, subtype, cte, disposition, filename, cid, params, headers = ('base64', None, None, None, None, None)):
    _prepare_set(msg, maintype, subtype, headers)
    if cte == 'base64':
        data = _encode_base64(data, msg.policy.max_line_length, **('max_line_length',))
    elif cte == 'quoted-printable':
        data = binascii.b2a_qp(data, False, False, True, **('istext', 'header', 'quotetabs'))
        data = data.decode('ascii')
    elif cte == '7bit':
        data = data.decode('ascii')
    elif cte in ('8bit', 'binary'):
        data = data.decode('ascii', 'surrogateescape')
    msg.set_payload(data)
    msg['Content-Transfer-Encoding'] = cte
    _finalize_set(msg, disposition, filename, cid, params)

