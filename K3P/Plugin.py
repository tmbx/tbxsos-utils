# High-level object to manipulate KMO.  Keep in mind that this was
# designed for quick and dirty testing of Teambox online services.
# It could conceivable be used to make some sort of GUI in the future
# but it's currently not its main goal.
#
# The following is currently implemented:
# - Signature and encryption of mail.
# - Decryption of mails and evaluation of signature.
#
# What is missing and that I don't immediately plan to implement:
# - Storing passwords and mail evaluation permanently through KMO.
#   Actually, KMO does that by himself but it is not exposed through
#   this API.  That's one of the killer for using this class for GUI.
#

import os, shutil, uuid, copy
from Protocol import *
from Constants import *

class PluginException(Exception):
    """
    Protocol errors.
    """
    def __init__(self, msg = None, cause = None):
        Exception.__init__(self, msg)
        self.cause = cause

class FatalPluginError(Exception):
    """
    Invalid requests, and other things that means we should make KMO bail out.
    """
    def __init__(self, msg = None, cause = None):
        Exception.__init__(self, msg)
        self.cause = cause

class OTUT:
    """
    """
    def __init__(self, o):
        is_valid = o.status == KMO_OTUT_STATUS_USABLE or o.status == KMO_OTUT_STATUS_USED        
        self.valid = is_valid
        self.entry_id = o.entry_id
        self.reply_addr = o.reply_addr
        self.date = o.msg
        self.o = o

    def to_k3p(self):
        return self.o

class EncryptionPasswordQuery:
    """
    Class that provides an encryption password to the mail encryption
    process if needed.

    Subclass this class if you want more complex processing to ask for
    a password.
    """
    def getotut(self, addr):
        if not addr in self.pwds: return None
        (_, has_otut) = self.pwds[addr]
        return has_otut

    def getpass(self, addr):
        if addr in self.pwds:
            (pwd, _) = self.pwds[addr]
            return pwd
        else:
            return None

    def __init__(self, pwds):
        self.pwds = pwds

class MessageEvaluation:
    """
    High-level class for KmoEvalRes.

    This is meant to contain the same information as in the K3pEvalRes
    structure except done in a Python friendly way.

    Individual field evaluation (from_name, to, etc) is to be
    interpreted that way:

    if the attribute == None, then the field was absent.  If the
    attribute != None but the attribute == False, then the field was
    modified.  If the attribute == True, then the field was not
    modified.

    NOTE: You really have to check for None if you want to know if a
    field was absent since None is evaluated to False in a if.

    NOTE: Please note that body_text and body_html are changed to
    text_body and html_body in that object, to keep the naming
    standard for text and HTML bodies.
    """

    def _eval_field(self, res, struct_field, obj_field):
        if struct_field in res.__dict__:
            self.__dict__[obj_field] = (res.__dict__[struct_field] == KMO_FIELD_STATUS_INTACT)
        else:
            self.__dict__[obj_field] = None

    def __init__(self, res):
        self.is_valid = res.sig_valid
        self.signature_msg = res.sig_msg
        self.subscriber = res.subscriber_name

        # Interpret the structure in a Python-friendly way.  The
        # left-hand member of the tuple list is the name of the
        # corresponding element in the K3pEvalRes structure.  The
        # right-hand member is the name of the attribute to which the
        # value will be mapped in the current object instance.
        for i in [('from_name_status', 'from_name'),
                  ('from_addr_status', 'from_addr'),
                  ('to_status', 'to'),
                  ('cc_status', 'cc'),
                  ('subject_status', 'subject'),
                  ('body_text_status', 'text_body'),
                  ('body_html_status', 'html_body')]:
            (struct_field, obj_field) = i
            self._eval_field(res, struct_field, obj_field)

        self.encryption_status = res.encryption_status
        self.decryption_err_msg = res.decryption_error_msg
        self.default_pwd = res.default_pwd
        self.pod_status = res.pod_status
        self.pod_msg = res.pod_msg

        # The state of the OTUT is very weird.  Let's try to force
        # some sense into it.  Let's say that an OTUT is exists if
        # it's, really, usable, or if it has been used in the past.
        # If KMOD tells the OTUT is unusable because of an error, then
        # we shall consider the message has no OTUT.  If the OTUT
        # exists, usable or not, an OTUT object is set which as a
        # 'valid' attribute set to True or False depending whether the
        # OTUT is valid or not.  If there is no OTUT, or we have an
        # error from KMOD about the OTUT, then the otut attribute is
        # not set and otut_msg is set to the message returned by KMOD
        # if available.
        if res.otut.status == KMO_OTUT_STATUS_USABLE:
            self.otut = OTUT(True, res.entry_id, res.reply_addr, res.msg)
            self.otut_msg = None
        elif res.otut.status == KMO_OTUT_STATUS_USED:
            self.otut = OTUT(False, res.entry_id, res.reply_addr, res.msg)
            self.otut.msg = None
        elif res.otut.status == KMO_OTUT_STATUS_ERROR:
            self.otut = None
            self.otut.msg = res.otut.msg
        else: # KMO_OTUT_STATUS_NONE
            self.otut = None
            self.otut_msg = None

class Message:
    def __init__(self, k3p_msg = None):
        if not k3p_msg:
            # Set this, most of the time.
            self.from_name = None
            self.from_addr = None
            self.to = None
            self.cc = None
            self.subject = None
            self.text_body = None
            self.html_body = None
            self.id = str(uuid.uuid4())
            self.otut = None
            self.passwords = None
        else:
            self.from_name = k3p_msg.from_name
            self.from_addr = k3p_msg.from_addr
            self.to = k3p_msg.to
            self.cc = k3p_msg.cc
            self.subject = k3p_msg.subject
            self.text_body = k3p_msg.body.text
            self.html_body = k3p_msg.body.text
            self.id = k3p_msg.msg_id
            self.otut = OTUT(k3p_msg.otut)
            self.passwords = None

    def to_k3p(self):
        """
        Convert this class into a structure that can be sent on the
        KMOD wire.
        """
        m = K3pMail()

        # Fill in things that go directly on the wire.
        recips = []
        if self.to:
            recips.extend(self.to)
        if self.cc and recips:
            recips.extend(self.cc)
        m.recipient_list = ";".join(recips)
        m.from_name = self.from_name
        m.from_addr = self.from_addr
        if self.to:
            m.to = ";".join(self.to)
        else:
            m.to = ""
        if self.cc:
            m.cc = ";".join(self.cc)
        else:
            m.cc = ""
        m.subject = self.subject

        # Things we need to "invent"
        m.msg_id = self.id
        if self.text_body and self.html_body:
            m.body.type = K3P_MAIL_BODY_TYPE_TEXT_N_HTML
            m.body.text = self.text_body
            m.body.html = self.html_body
        elif self.text_body and not self.html_body:
            m.body.type = K3P_MAIL_BODY_TYPE_TEXT
            m.body.text = self.text_body
        elif not self.text_body and self.html_body:
            m.body.type = K3P_MAIL_BODY_TYPE_HTML
            m.body.html = self.html_body
        else:
            m.body.type = K3P_MAIL_BODY_TYPE_TEXT
            m.body.text = ""

        if self.otut:
            m.otut = self.otut.to_k3p()

        return m

class Plugin:
    def __init__(self, kmod_path = None, kmod_host = None, kmod_port = None, kmod_timeout = 1000):
        self.full_name = None
        self.pod_addr = None
        self.username = None
        self.password = None
        self.kps_host = None
        self.kps_port = None

        self.ticket = None
        self.toolinfo = None

        self.conn = None

        # Prepare a KppMua structure.
        self.mua = KppMua()
        self.mua.product = 0
        self.mua.version = 11
        self.mua.release = "K3P.py"
        self.mua.kpp_major = 1
        self.mua.kpp_minor = 0
        self.incoming_attachment_is_file_path = 0
        self.lang = 0

        # Check what connection mode we support.
        if not os.path.exists(kmod_path):
            raise PluginException("%s does not exists." % kmod_path)
        else:
            self.kmod_path = kmod_path
        
        if kmod_host and kmod_port:
            # The scripts will connect to KMOD.
            self.conn = K3PConnection(kmod_host = kmod_host,
                                      kmod_port = kmod_port,
                                      kmod_timeout = kmod_timeout)
        else:
            # KMOD will connect to the scripts.
            self.conn = K3PConnection(kmod_path = kmod_path,
                                      kmod_timeout = kmod_timeout)

    def start(self):
        """
        Start KMOD and establish a communication link with it.
        """
        self.conn.connect()

        # Write the hello and the KppMua structure.
        self.conn.write_instruction(KPP_CONNECT_KMO)
        self.conn.write(self.mua)

        # Expect KMO_COGITO_ERGO_SUM
        i = self.conn.read_instruction()

        if i.inst == KMO_COGITO_ERGO_SUM:
            # Read the KmoToolInfo structure.
            self.toolInfo = self.conn.read_structure(KmoToolInfo)
        else:
            raise PluginException("Failed to establish link to KMOD.")

    def stop(self):
        """
        Wave KMOD goodbye.  No-op if KMOD is already stopped.
        """
        # Avoids write error if connection is closed.
        if self.conn.running():
            self.conn.write_instruction(KPP_DISCONNECT_KMO)

        # Closing an already closed KMOD is harmless.
        self.conn.close()

    def reset(self):
        """
        Destroy the KMOD temporary directory.  Stopping KMOD if
        necessary.

        Resetting the object will required recalling start() to
        restart KMOD.
        """
        self.stop()
        self.conn.clean()

    def _server_info(self):
        si = KppServerInfo()
        si.kps_login = self.username
        si.kps_secret = self.password
        si.secret_is_pwd = True
        si.kps_net_addr = self.kps_host
        si.kps_port_num = self.kps_port
        return si

    def login_test(self):
        """
        Do a login test with the server info provided.

        Won't return anything if successful but will throw an
        exception if not.
        """
        si = self._server_info()

        # Start communication.
        self.conn.write_instruction(KPP_BEG_SESSION)
        self.conn.write_instruction(KPP_IS_KSERVER_INFO_VALID)
        self.conn.write_structure(si)

        i = self.conn.read_instruction()

        if i.inst == KMO_SERVER_INFO_ACK:
            self.token = self.conn.read_string()

        elif i.inst == KMO_SERVER_INFO_NACK:
            msg = self.conn.read_string()
            raise PluginException(msg)
        else:
            raise PluginException("Incorrect reply to IS_KSERVER_INFO_VALID")

        self.conn.write_instruction(KPP_END_SESSION)

    def set_server_info(self):
        """
        Set the server info structure to be used by KMOD for the
        actual commands he needs to send.  If you configure a KPS
        address, this will make KMOD think that the user is a
        subscribed member and will make it behave so.

        Won't return or throw anything willingly.
        """
        si = self._server_info()

        # Send the server info to KMOD.
        self.conn.write_instruction(KPP_BEG_SESSION)
        self.conn.write_instruction(KPP_SET_KSERVER_INFO)
        self.conn.write_structure(si)
        self.conn.write_instruction(KPP_END_SESSION)

    def __check_errors(self, i):
        """
        Check for common K3P error codes.
        """
        if i.inst == KMO_INVALID_REQ:
            raise FatalPluginError("Invalid request")
        elif i.inst == KMO_INVALID_CONFIG:
            raise FatalPluginError("Invalid configuration")
        elif i.inst == KMO_SERVER_ERROR:
            # Read the error structure.
            s = self.conn.read_structure(KmoServerError)
            m = ""
            ms = ""
            me = ""

            if s.error == KMO_SERROR_MISC:
                me = "miscellaneous error"
            elif s.error == KMO_SERROR_TIMEOUT:
                me = "timeout"
            elif s.error == KMO_SERROR_UNREACHABLE:
                me = "unreachable"
            elif s.error == KMO_SERROR_CRIT_MSG:
                me = "critical error"

            if s.sid == KMO_SID_KPS:
                ms = "KPS error"
            elif s.sid == KMO_SID_OPS:
                ms = "Online packaging server error"
            elif s.sid == KMO_SID_OUS:
                ms = "Online unpackaging server error"
            elif s.sid == KMO_SID_OTS:
                ms = "OTUT ticket server error"
            elif s.sid == KMO_SID_IKS:
                ms = "Identity key server error"
            elif s.sid == KMO_SID_EKS:
                ms = "Encryption key server error"

            if s.message and len(s.message) > 0:
                m = "%s [%s: %s]" % (s.message, ms, me)
            else:
                m = "%s: %s" % (ms, me)
            raise FatalPluginError(m)

    def __package_mail_password(self, msg):
        """
        Handle queries for missing passwords.
        """
        nb = self.conn.read_integer()
        missing_pwds = []
        for i in range(0, nb):
            missing_pwds.append(self.conn.read_structure(KppRecipientPwd))

        # See if the caller has provided us with passwords.
        if msg.passwords:
            for i in range(0, nb):
                addr = missing_pwds[i].recipient
                pwd = msg.passwords.getpass(addr)
                if pwd != None:
                    missing_pwds[i].password = pwd
                    missing_pwds[i].save_pwd = False # FIXME: Password not saved.
                    missing_pwds[i].give_otut = int(msg.passwords.getotut(addr))
                else:
                    raise PluginException("No password for %s" % addr)
        else:
            raise PluginException("Can't continue without any passwords")

        # Got all the passwords we need.
        self.conn.write_instruction(KPP_USE_PWDS)
        self.conn.write_integer(nb)

        for i in range(0, nb):
            self.conn.write_structure(missing_pwds[i])

# This method was implemented to test a KMO bug.  I can't support it yet.
#     def lookup_address(self, addr):
#         # Start the session and send the command with parameters.
#         self.conn.write_instruction(KPP_BEG_SESSION)
#         self.conn.write_instruction(K3P_LOOKUP_REC_ADDR)
#         self.conn.write_integer(1)
#         self.conn.write_string(addr)

#         i = self.conn.read_instruction()

#         self.conn.write_instruction(KPP_END_SESSION)
        
    def __package_mail(self, pkg_inst, msg):
        """
        If this is successful, return a tuple containing the signature
        code for the text body and the signature code for the HTML
        body.

        Return a copy of the message passed as argument with text and
        HTML bodies changed to their encrypted content.
        """
        ret = None
        m = msg.to_k3p()

        # Start the session and send the command with parameters.
        self.conn.write_instruction(KPP_BEG_SESSION)
        self.conn.write_instruction(pkg_inst)

        # Write the message to package.
        self.conn.write_structure(m)

        try:
            ret = None
            while ret == None:
                # Check for the return value.
                i = self.conn.read_instruction()

                self.__check_errors(i)

                if i.inst == KMO_NO_RECIPIENT_PUB_KEY:
                    self.__package_mail_password(msg)

                if i.inst == KMO_PACK_ACK:
                    # Read the returned message.
                    mb = self.conn.read_structure(K3pMailBody)

                    # Replace the body in the passed message.
                    msg_ret = copy.copy(msg)                    
                    msg_ret.text_body = mb.text
                    msg_ret.html_body = mb.html
                    return msg_ret

                elif i.inst == KMO_PACK_NACK:
                    # Read the error message.
                    s = self.conn.read_structure(KmoPackExplain)
                    if s.text:
                        raise PluginException(s.text)
                    else:
                        raise PluginException("Signature failed, explanation code: %08x" % s.type)
        except (K3PException, K3PFatalError), ex:
            raise FatalPluginError("Protocol error", ex)
        finally:
            self.conn.write_instruction(KPP_END_SESSION)

        return ret

    def sign_mail(self, msg):
        return self.__package_mail(KPP_SIGN_MAIL, msg)

    def encrypt_mail(self, msg):
        return self.__package_mail(KPP_SIGN_N_ENCRYPT_MAIL, msg)

    def pod_mail(self, msg):
        return self.__package_mail(KPP_SIGN_N_POD_MAIL, msg)

    def encrypt_and_pod_mail(self, msg):
        return self.__package_mail(KPP_SIGN_N_ENCRYPT_N_POD_MAIL, msg)

    def process_mail(self, msg, pwd = None):
        """
        Returns a ProcessedMessage object.  This will use the
        'pod_addr' attribute as the recipient mail address.

        Throws a a PluginException in case of a processing error.
        """
        req = KppMailProcessReq()
        req.mail = msg.to_k3p()
        req.decrypt = int(True) # FIXME: Could it be necessary to expose this?
        if pwd:
            req.decryption_pwd = pwd
        else:
            req.decryption_pwd = ""
        self.ack_pod = int(True) # FIXME: Could it be necessary to expose this?
        self.recipient_mail_address = self.pod_addr

        # Commands
        self.conn.write_instruction(KPP_BEG_SESSION)
        self.conn.write_instruction(KPP_PROCESS_INCOMING)

        # Write the message.
        self.conn.write_structure(req)

        # Read the result.
        i = self.conn.read_instruction()

        try:
            # Check for generic errors.
            self.__check_errors(i)

            if i.inst == KMO_PROCESS_ACK:
                # Correct processing result.  Get the decrypted content.
                n = self.conn.read_structure(K3pMail)
                return Message(n)
            else:
                if i.inst == KMO_PROCESS_NACK:
                    n = self.conn.read_structure(KmoProcessNack)
                    if n.error == KMO_PROCESS_NACK_POD_ERROR:
                        raise PluginException("PoD delivery error")
                    elif n.error == KMO_PROCESS_NACK_PWD_ERROR:
                        raise PluginException("Incorrect password")
                    elif n.error == KMO_PROCESS_NACK_DECRYPT_PERM_FAIL:
                        raise PluginException("Not authorized to decrypt the message")
                    else:
                        if len(n.error_msg) > 0:
                            raise PluginException(n.error_msg)
                        else:
                            raise PluginException("Unknown processing error")                
                else:
                    raise PluginException("Processing request returned unknown instruction %s" % i)
        except (K3PException, K3PFatalError), ex:
            raise FatalPluginException("Protocol error", ex)
        finally:
            self.conn.write_instruction(KPP_END_SESSION)

    def eval_mail(self, msg):
        """
        Returns a MessageEvaluation object.
        """
        m = msg.to_k3p()

        # Commands
        self.conn.write_instruction(KPP_BEG_SESSION)
        self.conn.write_instruction(KPP_EVAL_INCOMING)

        # Write the message.
        self.conn.write_structure(m)

        # Read the result.  Expects KMO_EVAL_STATUS.
        i = self.conn.read_instruction()

        try:
            # Check for generic errors.
            self.__check_errors(i)

            if i.inst == KMO_EVAL_STATUS:
                # Correct request.  Get evaluation status.
                n = self.conn.read_integer()

                # FIXME: 2???
                if n == 2:
                    return None
                else:
                    mb = self.conn.read_structure(KmoEvalRes)
                    return MessageEvaluation(mb)
            else:
                raise PluginException("Don't know what to do.")
        except (K3PException, K3PFatalError), ex:
            raise FatalPluginException(ex)
        finally:
            self.conn.write_instruction(KPP_END_SESSION)

    def save_logs(self, destdir):
        """
        Copy all the content in the KMOD log directory to destdir.
        Won't work if KMOD is running.
        """
        if not self.conn.kmod_dir: return # No op.  There will be no logs in this case.        
        if self.conn.running():
            raise PluginException("Can't save logs while kmod is running")
        if not os.path.exists(destdir):
            os.mkdir(destdir)
        logs_path = os.path.join(self.conn.kmod_dir, "kmod_logs")
        for logfile in os.listdir(logs_path):
            logfile_path = os.path.join(logs_path, logfile)
            shutil.copyfile(logfile_path, os.path.join(destdir, logfile))
