# Low level protocol implementation for the K3P.
#
# This provides everything a plugin need to talk to KMOD in a
# convenient way.  By itself, this class does not talk to KMOD in any
# way.
#
# Author: Francois-Denis Gonthier

import os, sys, socket, tempfile, time, inspect, shutil, signal, select
from Constants import *

class K3PException(Exception):
    """
    Thrown when an error is thrown that is not fatal to the running
    KMOD instance.
    """
    pass

class K3PFatalError(Exception):
    """
    Thrown in case an error means that the communication with KMOD
    needs to be closed because it is in an incorrect state.
    """
    pass

class K3PClientFatalError(K3PFatalError):
    """
    Thrown when the KMOD client, the plugin, causes a fatal error
    while communicating with KMOD.

    Protocol syntax and protocol structure definition errors are
    included.
    """
    pass

class _K3PStructure:
    """
    A structure is a set of many K3P elements.
    """

    def _k3p_to_element(self, typ, key, el, args):
        """
        Convert a raw K3P element to a Python native value
        """
        is_struct = inspect.isclass(typ) and issubclass(typ, _K3PStructure)
        is_native = type(typ) is str
        nb = 1

        if is_struct:
            obj = typ(args)
            self.__dict__[key] = obj
            nb = obj.nelements

        elif is_native:
            if typ == 'S':
                if el.__class__ != K3PString:
                    s = "Incorrect type received for structure %s element %s"
                    s += " Expected String, got %s"
                    raise K3PClientFatalError(s % (self.__class__, key, el.name()))
                else:
                    #print key + " = " + el.val
                    self.__dict__[key] = el.val
            elif typ == 'I':
                if el.__class__ != K3PInteger:
                    s = "Incorrect type received for structure %s element %s."
                    s += " Expected type Integer, got %s"
                    raise K3PClientFatalError(s % (self.__class__, key, el.name()))
                else:
                    #print key + " = " + str(el.val)
                    self.__dict__[key] = el.val
        return nb

    def __init__(self, *args):
        """
        If args is None, this creates an empty structure with
        integers, string, substructure and arrays initialized to 0,"", None and [] respectively.

        If args is not None, this interprets a set of K3P elements as
        a given structure.
        """
        self.nelements = 0

        for v in self.__class__._attrs:
            (key, typ) = v
            if inspect.isclass(typ) and issubclass(typ, _K3PStructure):
                self.__dict__[key] = typ()
            elif type(typ) is tuple:
                self.__dict__[key] = []
            elif type(typ) is str:
                self.__dict__[key] = None
            else:
                raise K3PClientFatalError("Incorrect structure definition")

        if args:
            args = list(*args)

            for v in self.__class__._attrs:
                (key, typ) = v
                el = args[0]

                is_array = type(typ) is tuple
                is_struct = inspect.isclass(typ) and issubclass(typ, _K3PStructure)
                is_native = type(typ) is str
                nb = 0

                # Check for arrays.
                if is_array:
                    (nb_attr, typ) = typ

                    # Handle arrays.
                    if nb_attr in self.__dict__ and self.__dict__[nb_attr]:
                        for i in range(0, self.__dict__[nb_attr]):
                            nb += self._k3p_to_element(typ, key, el, args)

                # Check for structure or ordinary types.
                elif is_struct or is_native:
                    nb = self._k3p_to_element(typ, key, el, args)

                self.nelements += nb
                for i in range(0, nb): del args[0]

    def __str__(self):
        sl = []
        for v in self.__class__._attrs:
            (key, typ) = v
            if key in self.__dict__:
                sl.append("%s: %s" % (key, str(self.__dict__[key])))
            else:
                if typ == "S":
                    sl.append("%s: %s" % (key, "\"\""))
                elif typ == "I":
                    sl.append("%s: %s" % (key, "0"))
        return " ".join(sl)

    def _elements_to_k3p(self, typ, key):
        s = ""
        # Substructure types.
        if inspect.isclass(typ) and issubclass(typ, _K3PStructure):
            if key in self.__dict__:
                s += self.__dict__[key].to_k3p()
            else:
                raise K3PClientFatalError("Don't know what to do with null structures.")

        # Simple types.
        elif type(typ) is str:
            if typ == 'S':
                if key in self.__dict__:
                    s += K3PString(self.__dict__[key]).to_k3p()
                else:
                    s += K3PString("").to_k3p()
            elif typ == 'I':
                if key in self.__dict__:
                    s += K3PInteger(self.__dict__[key]).to_k3p()
                else:
                    s += K3PInteger(0).to_k3p()
        return s

    def to_k3p(self):
        s = ""
        for v in self.__class__._attrs:
            (key, typ) = v

            is_array = type(typ) is tuple
            is_struct = inspect.isclass(typ) and issubclass(typ, _K3PStructure)
            is_native = type(typ) is str

            # Check for arrays.
            if is_array:
                (nb_attr, typ) = typ

                # Handle arrays as a set of native type.
                if nb_attr in self.__dict__ and self.__dict__[nb_attr]:
                    for i in range(0, self.__dict__[nb_attr]):
                        s += self._elements_to_k3p(typ, key)

            # Handle structures and simple types
            elif is_struct or is_native:
                s += self._elements_to_k3p(typ, key)
            else:
                raise K3PClientFatalError("Incorrect structure definition.")

        return s

class K3pMailBody(_K3PStructure):
    _attrs = [('type', 'I'),
              ('text', 'S'),
              ('html', 'S')]

class K3pOtut(_K3PStructure):
    _attrs = [('status', 'I'),
              ('entry_id', 'S'),
              ('reply_addr', 'S'),
              ('msg', 'S')]

class K3pMailAttachment(_K3PStructure):
    _attrs = [('tie', 'I'),
              ('data_is_file_path', 'I'),
              ('data', 'S'),
              ('name', 'S'),
              ('encoding', 'S'),
              ('mime_type', 'S')]

class KmoEvalResAttachment(_K3PStructure):
    _attrs = [('name', 'S'),
              ('status', 'I')]

class KmoEvalRes(_K3PStructure):
    _attrs = [('display_pref', 'I'),
              ('string_status', 'I'),
              ('sig_valid', 'I'),
              ('sig_msg', 'S'),
              ('original_packaging', 'I'),
              ('subscriber_name', 'S'),
              ('from_name_status', 'I'),
              ('from_addr_status', 'I'),
              ('to_status', 'I'),
              ('cc_status', 'I'),
              ('subject_status', 'I'),
              ('body_text_status', 'I'),
              ('body_html_status', 'I'),
              ('attachment_nbr', 'I'),
              ('attachments', ('attachment_nbr', KmoEvalResAttachment)),
              ('encryption_status', 'I'),
              ('decryption_error_msg', 'S'),
              ('default_pwd', 'S'),
              ('pod_status', 'I'),
              ('pod_msg', 'S'),
              ('otut', K3pOtut)]

class K3pMail(_K3PStructure):
    _attrs = [('msg_id', 'S'),
              ('recipient_list', 'S'),
              ('from_name', 'S'),
              ('from_addr', 'S'),
              ('to', 'S'),
              ('cc', 'S'),
              ('subject', 'S'),
              ('body', K3pMailBody),
              ('attachment_nbr', 'I'),
              ('attachments', ('attachment_nbr', K3pMailAttachment)),
              ('otut', K3pOtut)]

class KmoToolInfo(_K3PStructure):
    _attrs = [('sig_marker', 'S'),
              ('kmo_version', 'S'),
              ('k3p_version', 'S')]

class KmoServerError(_K3PStructure):
    _attrs = [('sid', 'I'),
              ('error', 'I'),
              ('message', 'S')]

class KmoPackExplain(_K3PStructure):
    _attrs = [('type', 'I'),
              ('text', 'S'),
              ('captcha', 'S')]

class KppMua(_K3PStructure):
    _attrs = [('product', 'I'),
              ('version', 'I'),
              ('release', 'S'),
              ('kpp_major', 'I'),
              ('kpp_minor', 'I'),
              ('incoming_attachment_is_file_path', 'I'),
              ('lang', 'I')]

class KppServerInfo(_K3PStructure):
    _attrs = [('kps_login', 'S'),
              ('kps_secret', 'S'),
              ('secret_is_pwd', 'I'),
              ('pod_addr', 'S'),
              ('kps_net_addr', 'S'),
              ('kps_port_num', 'I'),
              ('kps_ssl_key', 'S'),
              ('kps_use_proxy', 'I'),
              ('kps_proxy_net_addr', 'S'),
              ('kps_proxy_port_num', 'I'),
              ('kps_proxy_login', 'S'),
              ('kps_proxy_pwd', 'S'),
              ('kos_use_proxy', 'I'),
              ('kos_proxy_net_addr', 'S'),
              ('kos_proxy_port_num', 'I'),
              ('kos_proxy_login', 'S'),
              ('kos_proxy_pwd', 'S')]

class KppMailProcessReq(_K3PStructure):
    _attrs = [('mail', K3pMail),
              ('decrypt', 'I'),
              ('decryption_pwd', 'S'),
              ('save_pwd', 'I'),
              ('ack_pod', 'I'),
              ('recipient_mail_address', 'S')]

class KppRecipientPwd(_K3PStructure):
    _attrs = [('recipient', 'S'),
              ('password', 'S'),
              ('give_otut', 'I'),
              ('save_pwd', 'I')]

class KmoProcessNack(_K3PStructure):
    _attrs = [('error', 'I'),
              ('error_msg', 'S')]

class _K3PElement:
    def parse(str):
        pass
    parse = staticmethod(parse)

    def is_instruction(self):
        return self.__class__ == K3PInstruction

    def is_integer(self):
        return self.__class__ == K3PInteger

    def is_string(self):
        return self.__class__ == K3PString

    def to_k3p(self): pass
    def name(self): pass

class K3PInstruction(_K3PElement):
    def __init__(self, inst):
        self.inst = int(inst)

    def name(self): return "Instruction"

    def to_k3p(self):
        return "INS%08x" % self.inst

    def __str__(self):
        return "INSTR 0x%08x" % self.inst

class K3PInteger(_K3PElement):
    def __init__(self, val):
        if val:
            self.val = int(val)
        else:
            self.val = 0

    def name(self): return "Integer"

    def to_k3p(self):
        return "INT" + str(self.val) + ">"

    def __int__(self):
        return self.val

    def __str__(self):
        return str(self.val)

class K3PString(_K3PElement):
    def __init__(self, val):
        if val:
            self.val = val
        else:
            self.val = ""

    def name(self): return "String"

    def to_k3p(self):
        return "STR%u>%s" % (len(self.val), self.val)

    def __str__(self):
        return self.val

class K3PConnection:
    def read_instruction(self):
        """
        Read one element from KMOD, asserting that it is of instruction type.
        """
        els = self.read(1)
        if not els[0].is_instruction():
            raise K3PClientFatalError("Expected Instruction, got %s" % els[0])
        else:
            return els[0]

    def read_integer(self):
        """
        Read one element from KMOD, asserting that it is of integer type.
        """
        els = self.read(1)
        if not els[0].is_integer():
            raise K3PClientFatalError("Expected Integer, got %s" % els[0])
        else:
            return int(els[0])

    def read_string(self):
        """
        Read one element from KMOD, asserting that is is of string type.
        """
        els = self.read(1)
        if not els[0].is_string():
            raise K3PClientFatalError("Expected String, got %s" % els[0])
        else:
            return str(els[0])

    def _read_structure_elements(self, struct_class):
        els = []
        crap = {} # Gotta save integer attributes to handle arrays.

        for i in range(0, len(struct_class._attrs)):
            (key, typ) = struct_class._attrs[i]

            # Read arrays.
            if type(typ) is tuple:
                (nb_els, typ) = typ

                for i in range(0, crap[nb_els]):
                    els.extend(self._read_structure_elements(typ))

            # Read structure.
            elif inspect.isclass(typ) and issubclass(typ, _K3PStructure):
                els.extend(self._read_structure_elements(typ))

            # Read ordinary types.
            elif type(typ) is str:
                if typ == 'S':
                    el = self.read(1)
                    if not el[0].is_string():
                        raise K3PClientFatalError("Expected String, got %s" % el[0].name())
                    els.extend(el)
                elif typ == 'I':
                    el = self.read(1)
                    if not el[0].is_integer():
                        raise K3PClientFatalError("Expected Integer, got %s" % el[0].name())
                    els.extend(el)
                    crap[key] = int(el[0])
                else:
                    raise K3PClientFatalError("Invalid structure definition: %s" % typ)
            else:
                raise K3PClientFatalError("Invalid structure definition")
        return els

    def read_structure(self, struct_class):
        """
        Read a K3P structure from KMOD.  'struct_class' is the class
        of the structure you want to read from KMOD.
        """
        return struct_class(self._read_structure_elements(struct_class))

    def read(self, nb_el):
        """
        Read a certain number of K3P elements on the wire.  Return a
        list of native elements.
        """
        if not self.kmod: raise K3PClientFatalError("Not started")
        # NOTE: This function is knowingly low-tech, I don't believe
        # it's necessary to do any clever buffering in test scripts.
        els = []
        for i in range(0, nb_el):
            # Read 3 bytes, check what to expect next.
            typ = self.kmod.read(3)

            if typ == 'INT':
                # Read 1 char until the next >
                s = ""
                while True:
                    c = self.kmod.read(1)
                    if c != ">": s += c
                    else: break
                els += [K3PInteger(int(s))]
            elif typ == 'STR':
                # Read the lenght of the string we can expect.
                s = ""
                while True:
                    c = self.kmod.read(1)
                    if c != ">": s += c
                    else: break
                sz = int(s)
                s = ""
                for i in range(0, sz): s += self.kmod.read(1)
                els += [K3PString(s)]
            elif typ == 'INS':
                # Read 8 bytes.
                inst = self.kmod.read(8)
                els += [K3PInstruction(int(inst, 16))]
            else:
                raise K3PFatalError("Weird stuff received: %s" % typ)
        return els

    def write_integer(self, i):
        """
        Wrap the integer into a K3PInteger object then call write.
        """
        self.write(K3PInteger(i))

    def write_string(self, s):
        """
        Wrap the string into a K3PString object then call write.
        """
        self.write(K3PString(s))

    def write_instruction(self, i):
        """
        Wrap the instruction into a K3PInstruction object then call write.
        """
        self.write(K3PInstruction(i))

    def write_structure(self, s):
        """
        Simply calls write.
        """
        self.write(s)

    def write(self, obj):
        """
        Write an Element subclass instance to kmod.  This will flush
        the socket file if self.hold_flush isn't False.
        """
        if not self.kmod: raise K3PClientFatalError("Not started")
        try:
            self.kmod.write(obj.to_k3p())
            self.kmod.flush()
        except socket.error, ex:
            raise K3PFatalError("Write error")

    def close(self):
        """
        Close the socket connected to KMOD.
        """
        try:
            if self.kmod_sock:
                self.kmod_sock.shutdown(socket.SHUT_RDWR)
                self.kmod_sock.close()
        except socket.error, ex: pass
        finally:
            self.kmod_sock = None
            self.kmod = None

        if self.kmod_pid:
            # Makes sure KMOD is down.
            if self.kmod_pid:
                os.kill(self.kmod_pid, signal.SIGTERM)

            # Wait for kmod to die.
            os.waitpid(self.kmod_pid, 0)
            self.kmod_pid = None

    def running(self):
        """
        Return true of the KMOD socket is still alive.
        """
        return (self.kmod_sock != None)

    def clean(self):
        """
        Remove the temporary directory.  This will disconnect the kmod
        socket if not done already.
        """
        if self.running(): self.close()
        
        # Integrally remove the temporary directory.
        if self.kmod_dir:
            shutil.rmtree(self.kmod_dir)
            self.kmod_dir = None

    def __del__(self):
        """
        Hopefully cleans the temporary directory.
        """
        self.clean()

    def _connect_kmod_connect(self):
        """
        This method handles the automatic connection of KMOD to the
        plugin.
        """
        srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv_sock.bind((self.kmod_host, self.kmod_port))
        srv_sock.listen(1)

        # Fork for kmod.
        self.kmod_pid = os.fork()

        if self.kmod_pid == 0:
            # Client side.  Execute KMOD.
            srv_sock.close()

            args = [self.kmod_path,
                    "-C", self.__connect_mode,
                    "-l", "3",
                    "-p", str(self.kmod_port),
                    "-k", self.kmod_dir]
            os.execve(self.kmod_path, args, {})
            
        elif self.kmod_pid > 0:           
            # Parent side.  Wait for KMOD to connect.
            (rd, _, er) = select.select([srv_sock.fileno()],
                                       [],
                                       [srv_sock.fileno()],
                                       float(self.timeout) / 1000)
            if len(er) > 0:
                raise K3PException("Failed to connect to KMOD.")
            elif len(rd) > 0:
                (self.kmod_sock, _) = srv_sock.accept()
            else:
                raise K3PException("Timeout connecting to KMOD (timeout is %d ms)." % self.timeout)

            self.kmod = self.kmod_sock.makefile()
            srv_sock.close()

            secret_file = os.path.join(self.kmod_dir, "connect_secret")
            secret_stuff = None

            if os.path.exists(secret_file):
                secret_file = open(secret_file, "r")
                secret_stuff = secret_file.read()
                secret_file.close()

                kmod_secret_stuff = self.kmod.read(len(secret_stuff))
                if secret_stuff != kmod_secret_stuff:
                    raise K3PException("Secret handshake with KMOD failed.")
            else:
                raise K3PException("Failed to complete the connexion with KMOD.")
        else:
            raise K3PException("Failed to fork to start kmod.")

    def _connect_kpp_connect(self):
        """
        This handles connection of the plugin to KMOD.
        """
        # FIXME: Better exception handling.
        self.kmod_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.kmod_sock.settimeout(float(self.timeout) / 1000)
        self.kmod_sock.connect((self.kmod_host, self.kmod_port))
        self.kmod = self.kmod_sock.makefile()

    def connect(self):
        """
        Start kmod and return a socket connected to it.
        """
        if self.kmod_sock: raise K3PException("Cannot connect twice.")

        if not self.kmod_dir:
            self.kmod_dir = tempfile.mkdtemp()

        if self.__connect_mode == "kmod_connect":
            self._connect_kmod_connect()
        elif self.__connect_mode == "kpp_connect":
            self._connect_kpp_connect()

    def __init__(self, kmod_path = None, kmod_host = None, kmod_port = None, kmod_timeout = 1000):
        """
        Initialize basic stuff.  kmod_path is the path to the kmod
        executable.

        kmod_host is the hostname of the computer running kmod and
        kmod_port is the port to connect to.  If kmod_host and
        kmod_port are both defined, this plugin will attempt to
        connect to KMOD.  If both are None, then we have n
        """       
        # Check the connection mode.
        if kmod_host and kmod_port:
            self.__connect_mode = "kpp_connect"
        else:
            self.__connect_mode = "kmod_connect"

        # Check for the KMOD port.
        if not kmod_port:
            self.kmod_port = 29999
        else:
            self.kmod_port = int(kmod_port)

        # Check for the KMOD host.
        if not kmod_host:
            self.kmod_host = "localhost"
        else:
            self.kmod_host = kmod_host

        self.timeout = kmod_timeout
        self.kmod_path = kmod_path
        self.kmod_dir = None
        self.kmod_sock = None
        self.kmod_pid = None
