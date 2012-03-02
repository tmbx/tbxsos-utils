import socket, struct, inspect, select
from gnutls.connection import *
from gnutls.constants import *
from gnutls.errors import *
from Constants import *

class KNPException(Exception):
    """
    """
    pass

class KNPFatalError(Exception):
    """
    """
    pass

class KNPClientFatalError(KNPFatalError):
    """
    """
    pass

class _KNPStructure:
    """
    """

    def _knp_to_element(self, typ, key, el, args):
        """
        """
        is_struct = inspect.isclass(typ) and issubclass(typ, _KNPStructure)
        is_native = type(typ) is str
        nb = 1

        if is_struct:
            obj = typ(args)
            return (obj, obj.nelements)

        elif is_native:
            if typ == 'S':
                if el.__class__ != KNPString:
                    s = "Incorrect type received for structure %s element %s"
                    s += " Expected String, got %s"
                    raise KNPClientFatalError(s % (self.__class__, key, el.name()))
                else:
                    return (el.val, nb)
            elif typ == 'I':
                if el.__class__ != KNPInteger:
                    s = "Incorrect type received for structure %s element %s."
                    s += " Expected type Integer, got %s"
                    raise KNPClientFatalError(s % (self.__class__, key, el.name()))
                else:
                    return (el.val, nb)
            elif typ == 'L':
                if el.__class__ != KNPLongInteger:
                    s = "Incorrect type received for structure %s element %s"
                    s += " Expected type LongInteger, got %s"
                    raise KNPClientFatalError(s % (self.__class__, key, el.name()))
                else:
                    return (el.val, nb)

    def __init__(self, *args):
        self.nelements = 0

        for v in self.__class__._attrs:
            (key, typ, ver) = v
            if inspect.isclass(typ) and issubclass(typ, _KNPStructure):
                self.__dict__[key] = typ()
            elif type(typ) is tuple:
                self.__dict__[key] = []
            elif type(typ) is str:
                self.__dict__[key] = None
            else:
                raise KNPClientFatalError("Incorrect structure definition")

        if args:
            args = list(*args)

            for v in self.__class__._attrs:
                (key, typ, ver) = v
                el = args[0]

                is_array = type(typ) is tuple
                is_struct = inspect.isclass(typ) and issubclass(typ, _KNPStructure)
                is_native = type(typ) is str
                nb = 0

                # Check for arrays.
                if is_array:
                    (nb_attr, typ) = typ

                    # Handle arrays.
                    if nb_attr in self.__dict__ and self.__dict__[nb_attr]:
                        self.__dict__[key] = []
                        for i in range(0, self.__dict__[nb_attr]):
                            (el, n) = self._knp_to_element(typ, key, el, args)
                            self.__dict__[key].append(el)
                            nb += n

                # Check for structure or ordinary types.
                elif is_struct or is_native:
                    (el, n) = self._knp_to_element(typ, key, el, args)
                    self.__dict__[key] = el
                    nb += n

                self.nelements += nb
                for i in range(0, nb): del args[0]

    def __str__(self):
        sl = []
        for v in self.__class__._attrs:
            (key, typ, ver) = v
            if key in self.__dict__:
                sl.append("%s: %s" % (key, str(self.__dict__[key])))
            else:
                if typ == "S":
                    sl.append("%s: %s" % (key, "\"\""))
                elif typ == "I":
                    sl.append("%s: %s" % (key, "0"))
        return " ".join(sl)

    def _elements_to_knp(self, typ, el):
        s = ""
        # Substructure types.
        if inspect.isclass(typ) and issubclass(typ, _KNPStructure):
            struct_typ = typ._attrs
            s += el.to_knp()

        # Simple types.
        elif type(typ) is str:
            if typ == 'S':
                if el:
                    s += KNPString(el).to_knp()
                else:
                    s += KNPString("").to_knp()
            elif typ == 'I':
                if el:
                    s += KNPInteger(int(el)).to_knp()
                else:
                    s += KNPInteger(0).to_knp()
            elif typ == 'L':
                if el:
                    s += KNPLongInteger(int(el)).to_knp()
                else:
                    s += KNPLongInteger(0).to_knp()
        return s

    def to_knp(self):
        """
        Convert the KNP structure into a KNP request suitable to be
        sent over the wire.
        """
        s = ""
        for v in self.__class__._attrs:
            (key, typ, ver) = v

            is_array = type(typ) is tuple
            is_struct = inspect.isclass(typ) and issubclass(typ, _KNPStructure)
            is_native = type(typ) is str

            # Check for arrays.
            if is_array:
                (nb_attr, typ) = typ

                # Handle arrays as a set of native type.
                if nb_attr in self.__dict__ and self.__dict__[nb_attr]:
                    self.__dict__[nb_attr] = len(self.__dict__[key])
                    for i in range(0, self.__dict__[nb_attr]):
                        s += self._elements_to_knp(typ, self.__dict__[key][i])

            # Handle structures and simple types
            elif is_struct or is_native:
                s += self._elements_to_knp(typ, self.__dict__[key])
            else:
                raise KNPClientFatalError("Incorrect structure definition.")
        return s

    def __len__(self):
        # FIXME: Not sure this is efficient.
        return len(self.to_knp())

class KNPPkgRecipient(_KNPStructure):
    _attrs = [('addr', 'S', '2.1'),
              ('enc_type', 'I', '2.1'),
              ('enc_key_data', 'S', '2.1')]
    _num = 0 # Substructure.  Not to be sent on the wire.

class KNPPkgPwd(_KNPStructure):
    _attrs = [('pwd', 'S', '2.1'),
              ('otut', 'S', '2.1')]
    _num = 0 # Substructure.  Not to be sent on the wire.

class KNPPkgAttach(_KNPStructure):
    _attrs = [('type', 'I', '2.1'),
              ('encoding', 'S', '2.1'),
              ('mime_type', 'S', '2.1'),
              ('name', 'S', '2.1'),
              ('payload', 'S', '2.1')]
    _num = 0 # Substructure.  Not to be sent on the wire.

class KNPLoginUserRequest(_KNPStructure):
    _attrs = [('user_name', 'S', '2.1'),
              ('user_secret', 'S', '2.1'),
              ('secret_is_pwd', 'I', '3.1')]
    _num = KNP_CMD_LOGIN_USER

class KNPLoginOkResponse(_KNPStructure):
    _attrs = [('encrypted_pwd', 'S', '3.1')]
    _num = 0 # Response.  Not to be sent on the wire.

class KNPLoginOTUTRequest(_KNPStructure):
    _attrs = [('otut', 'S', '2.1')]
    _num = KNP_CMD_LOGIN_OTUT

class KNPGetUserInfoResponse(_KNPStructure):
    _attrs = [('mid', 'S', '2.1'),
              ('nb_domain', 'S', '2.1'),
              ('domain_array', ('nb_domain', 'S'), '2.1')]
    _num = KNP_CMD_GET_USER_INFO

class KNPPackageMailRequest(_KNPStructure):
    _attrs = [('pkg_type', 'I', '2.1'),
              ('lang', 'I', '2.1'),
              ('to_field', 'S', '2.1'),
              ('cc_field', 'S', '2.1'),
              ('nb_recipient', 'I', '2.1'),
              ('recipient_array', ('nb_recipient', KNPPkgRecipient), '2.1'),
              ('nb_pwd', 'I', '2.1'),
              ('pwd_array', ('nb_pwd', KNPPkgPwd), '2.1'),
              ('from_name', 'S', '2.1'),
              ('from_addr', 'S', '2.1'),
              ('subject', 'S', '2.1'),
              ('body_type', 'I', '2.1'),
              ('body_text', 'S', '2.1'),
              ('body_html', 'S', '2.1'),
              ('nb_attach', 'I', '2.1'),
              ('attach_array', ('nb_attach', KNPPkgAttach), '2.1'),
              ('pod_addr', 'S', '2.1')]
    _num = KNP_CMD_PACKAGE_MAIL

class KNPPackageMailResponse(_KNPStructure):
    _attrs = [('pkg_output', 'S', '2.1'),
              ('ksn', 'S', '2.1'),
              ('sym_key', 'S', '2.1')]
    _num = 0 # Response.  Not to be sent on the wire.

class KNPGetSignKeyRequest(_KNPStructure):
    _attrs = [('key_id', 'L', '2.1')]
    _num = KNP_CMD_GET_SIGN_KEY

class KNPGetSignKeyResponse(_KNPStructure):
    _attrs = [('tm_key_data', 'S', '2.1'),
              ('key_data', 'S', '2.1'),
              ('owner_name', 'S', '2.1')]
    _num = 0 # Response.  Not to be sent on the wire.

class KNPGetOTUTTicketRequest(_KNPStructure):
    _attrs = [('reply_count', 'I', '2.1'),
              ('reply_addr', ('reply_count', 'S'), '2.1')]
    _num = KNP_CMD_GET_OTUT_TICKET

class KNPGetOTUTTicketResponse(_KNPStructure):
    _attrs = [('ticket', 'S', '2.1')]
    _num = 0 # Response.  Not to be sent on the wire.

class KNPGetOTUTStringRequest(_KNPStructure):
    _attrs = [('ticket', 'S', '2.1'),
              ('in_otut_count', 'I', '2.1'),
              ('reply_count_array', ('in_otut_count', 'S'), '2.1')]
    _num = KNP_CMD_GET_OTUT_STRING

class KNPGetOTUTStringResponse(_KNPStructure):
    _attrs = [('out_otut_count', 'I', '2.1'),
              ('otut_array', ('out_otut_count', 'S'), '2.1')]
    _num = 0 # Response.  Not to be sent on the wire.

class KNPValidateOTUTRequest(_KNPStructure):
    _attrs = [('otut_string', 'S', '2.1')]
    _num = KNP_CMD_VALIDATE_OTUT

class KNPValidateOTUTResponse(_KNPStructure):
    _attrs = [('remaining_use_count', 'I', '2.1')]
    _num = 0 # Response.  Not to be sent on the wire.

class KNPDecSymKeyRequest(_KNPStructure):
    _attrs = [('sig_text', 'S', '2.1'),
              ('pub_key_data', 'S', '2.1'),
              ('pub_tm_key_data', 'S', '2.1'),
              ('inter_symkey_data', 'S', '2.1'),
              ('pwd', 'S', '2.1'),
              ('pod_from', 'S', '2.1'),
              ('subject', 'S', '2.1'),
              ('want_dec_email', 'I', '2.1')]
    _num = KNP_CMD_DEC_SYM_KEY

class KNPDecSymKeyResponse(_KNPStructure):
    _attrs = [('sym_key_data', 'S', '2.1'),
              ('otut', 'S', '2.1'),
              ('pod_date', 'I', '2.1'),
              ('dec_email', 'S', '2.1')]
    _num = 0 # Response.  Not to be sent on the wire.

class KNPGetEncKeyRequest(_KNPStructure):
    _attrs = [('nb_address', 'I', '2.1'),
              ('address_array', ('nb_address', 'S'), '2.1')]
    _num = KNP_CMD_GET_ENC_KEY

class KNPGetEncKeyResponse(_KNPStructure):
    _attrs = [('nb_key', 'I', '2.1'),
              ('key_array', ('nb_key', 'S'), '2.1'),
              ('nb_subs', 'I', '2.1'),
              ('subscriber_array', ('nb_subs', 'S'), '2.1')]
    _num = KNP_RES_GET_ENC_KEY

class KNPGetEncKeyByIdRequest(_KNPStructure):
    _attrs = [('key_id', 'L', '4.1')]
    _num = KNP_CMD_GET_ENC_KEY_BY_ID

class KNPGetEncKeyByIdResponse(_KNPStructure):
    _attrs = [('tm_key_data', 'S', '4.1'),
              ('key_data', 'S', '4.1'),
              ('owner_name', 'S', '4.1')]
    _num = 0 # Response. Not to be sent on the wire.

class _KNPElement:
    def to_knp(self): pass
    def __len__(self): pass

class KNPString(_KNPElement):
    format = "!II"

    def __init__(self, s):
        self.val = s

    def to_knp(self):
        buf = ""
        buf += struct.pack("!BI", KNP_STR, len(self.val))
        buf += self.val
        return buf

    def __len__(self):
        return struct.calcsize(KNPString.format) + len(self.val)

    def name(self): return "String"

class KNPInteger(_KNPElement):
    format = "!BL"

    def __init__(self, n):
        self.val = n

    def to_knp(self):
        return struct.pack(KNPInteger.format, KNP_UINT32, self.val)

    def __len__(self):
        return struct.calcsize(KNPInteger.format)

    def name(self): return "Integer"

class KNPLongInteger(_KNPElement):
    format = "!BQ"

    def __init__(self, n):
        self.val = n

    def to_knp(self):
        return struct.pack(KNPLongInteger.format, KNP_UINT64, self.val)

    def __len__(self):
        return struct.calcsize(KNPLongInteger.format)

    def name(self): return "Long Integer"

class KNPHeader:
    format = "!IIII"

    def __init__(self, major = None, minor = None, typ = None, size = None):
        self.major = major
        self.minor = minor
        self.typ = typ
        self.size = size

    def to_knp(self):
        return struct.pack(KNPHeader.format, self.major, self.minor, self.typ, self.size)

class KNPConnection:
    def __read_string(self, buf):
        """
        """
        # Skip the string type.
        buf = buf[1:]
        # Read the string size.
        str_sz_fmt = "!I"
        str_sz_sz = struct.calcsize(str_sz_fmt)
        if len(buf) < str_sz_sz:
            raise KNPFatalError("Malformed KNP packet")
        str_sz_buf = buf[:str_sz_sz]
        (str_sz,) = struct.unpack(str_sz_fmt, str_sz_buf)
        buf = buf[str_sz_sz:]

        # Read the string itself.
        if len(buf) < str_sz:
            raise KNPFatalError("Malformed KNP packet")
        _str = buf[:str_sz]
        buf = buf[str_sz:]

        if not _str: _str = ""

        return (buf, KNPString(_str))

    def __read_uint(self, buf, uint_class):
        """
        """
        uint_fmt = uint_class.format
        uint_sz = struct.calcsize(uint_fmt)
        if len(buf) < uint_sz:
            raise KNPFatalError("Malformed KNP packet")
        uint_buf = buf[:uint_sz]
        buf = buf[uint_sz:]
        return (buf, uint_class(int(struct.unpack(uint_fmt, uint_buf)[1])))

    # NOTE: Unlike write_structure, read_header and read_structure are
    # separated because we can't decide before time what structure we
    # need to read from the wire, if any, before receiving the header.
    # We could be more clever about it, like we are in tbxsosd, but
    # I wanted this module to stick to a low-level, syntaxic, role.

    def read_header(self):
        """
        Return a KNPHeader structure.
        """
        header_fmt = "!IIII"
        header_sz = struct.calcsize(header_fmt)
        buf = self.__read(header_sz)
        (major, minor, typ, sz) = struct.unpack(header_fmt, buf)
        return KNPHeader(major, minor, typ, sz)

    def __read_elements(self, buf):
        els = []
        while len(buf) > 0:
            # Read the element type.
            typ_fmt = "!B"
            typ_sz = struct.calcsize(typ_fmt)
            if len(buf) < typ_sz:
                raise KNPFatalError("Malformed KNP packet")
            typ_buf = buf[:typ_sz]
            (typ,) = struct.unpack(typ_fmt, typ_buf)

            el = None

            # Read the element itself.
            if typ == KNP_STR:
                (buf, el) = self.__read_string(buf)
            elif typ == KNP_UINT32:
                (buf, el) = self.__read_uint(buf, KNPInteger)
            elif typ == KNP_UINT64:
                (buf, el) = self.__read_uint(buf, KNPLongInteger)

            els.append(el)
        return els

    def read_structure(self, sz, st_class):
        """
        Read a structure from the wire.
        """
        buf = self.__read(sz)
        els = self.__read_elements(buf)
        return st_class(els)

    def write_structure(self, el_obj):
        """
        Write a structure _and_ it's accompanying header on the wire,
        the header before the wire.
        """
        if el_obj._num == 0:
            s = "Structure %s cannot be sent on the wire" % str(el_obj.__class__)
            raise KNPClientFatalError(s)

        (major, minor) = self.version.split(".")
        hdr_buf = KNPHeader(int(major), int(minor), el_obj._num, len(el_obj)).to_knp()
        el_buf = el_obj.to_knp()
        self.__write(hdr_buf + el_buf)

    def __read(self, sz):
        """
        Low level read with timeout.
        """
        buf = ""
        n = sz
        while n > 0:
            (rd, _, er) = select.select([self.__knp_sock.fileno()],
                                        [],
                                        [self.__knp_sock.fileno()],
                                        self.timeout / 1000)
            try:
                if len(rd) > 0:
                    b = self.__ssl_session.recv(n)
                    if len(b) > 0:
                        buf += b
                        n -= len(b)
                    else:
                        raise KNPException("Read error from server")
                elif len(er) > 0:
                    raise KNPException("Read error from server")
                else:
                    raise KNPException("Timeout")
            except OperationWouldBlock, ex: pass
        return buf

    def __write(self, buf):
        """
        Low level write with timeout.  Returns nothing if the whole
        buffer was written successfully.
        """
        n = len(buf)
        s = 0
        while n > 0:
            (_, wr, er) = select.select([],
                                        [self.__knp_sock.fileno()],
                                        [self.__knp_sock.fileno()],
                                        self.timeout / 1000)
            try:
                if len(wr) > 0:
                    s = self.__ssl_session.send(buf[-n])
                    n -= s
                elif len(er) > 0:
                    raise KNPException("Write error to server.")
                else:
                    raise KNPException("Timeout")
            except OperationWouldBlock, ex: pass

    def close(self):
        try:
            self.sock.setblocking(True)
            self.ssl_session.bye()
            self.ssl_session.shutdown()
            self.ssl_session.close()
        except: pass

    def connect(self):
        """
        Connect to the target server through SSL.
        """
        self.__knp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__ssl_creds = X509Credentials()
        # GNUTLS obviously defaults to TLS.  We use SSLv3.
        self.__ssl_creds.session_params.protocols = (PROTO_SSL3,)

        # Proper connection.
        self.__knp_sock.connect((self.knp_host, self.knp_port))

        # FIXME: Announce the certificate we will use.
        self.__ssl_session = ClientSession(self.__knp_sock, self.__ssl_creds)
        self.__ssl_session.handshake()

        # Set the socket non-blocking.
        self.__knp_sock.setblocking(False)

    def __init__(self, version, knp_host, knp_port):
        self.version = version
        self.knp_host = knp_host
        self.knp_port = knp_port
        self.timeout = 2000

        self.__knp_sock = None
        self.__ssl_creds = None
        self.__ssl_session = None

if __name__ == "__main__":
    knp = KNPConnection("4.1", "kps.teambox.co", 443)

    knp.connect()

    req = KNPLoginUserRequest()
    req.user_name = "source"
    req.user_secret = "source"
    req.secret_is_pwd = True

    knp.write_structure(req)

    hdr = knp.read_header()

    if hdr.typ == KNP_RES_LOGIN_OK:
        s = knp.read_structure(hdr.size, KNPLoginOkResponse)
        print s.encrypted_pwd

    recip = KNPPkgRecipient()
    recip.addr = ""
    recip.enc_type = KNP_PKG_ENC_PWD
    recip.enc_key_data = None

    pkg = KNPPackageMailRequest()
    pkg.pkg_type = 1
    pkg.lang = 0
    pkg.to_field = ""
    pkg.cc_field = None
    pkg.recipient_array = [recip]
    pkg.pwd_array = []
    pkg.from_name = "Mister Source"
    pkg.from_addr = "source@source.com"
    pkg.subject = "BLARG!"
    pkg.body_type = KNP_PKG_BODY_TEXT
    pkg.body_text = "BLORG!"
    pkg.attach_array = []
    pkg.pod_addr = "source@source.com"

    knp.write_structure(pkg)

    knp.close()
