K3P_VER_MAJOR = 1
K3P_VER_MINOR = 8

K3P_CHECK_OTUT = 33
K3P_OPEN_KAPPSD_SESSION = 34
K3P_CLOSE_KAPPSD_SESSION = 35
K3P_EXCHANGE_KAAPSD_MESSAGE = 36

K3P_COMMAND_OK = 0

K3P_GET_KWS_TICKET = 40
K3P_CONVERT_EXCHANGE_ADDRESS = 41
K3P_LOOKUP_REC_ADDR = 42
K3P_PROCESS_INCOMING_EX = 43
K3P_VALIDATE_TICKET = 44

K3P_MAIL_BODY_TYPE = 0x4783AF39
K3P_MAIL_BODY_TYPE_TEXT = K3P_MAIL_BODY_TYPE + 1
K3P_MAIL_BODY_TYPE_HTML = K3P_MAIL_BODY_TYPE + 2
K3P_MAIL_BODY_TYPE_TEXT_N_HTML = K3P_MAIL_BODY_TYPE + 3

K3P_MAIL_ATTACHMENT_TIE = 0x57252924
K3P_MAIL_ATTACHMENT_EXPLICIT = K3P_MAIL_ATTACHMENT_TIE + 1
K3P_MAIL_ATTACHMENT_IMPLICIT = K3P_MAIL_ATTACHMENT_TIE + 2
K3P_MAIL_ATTACHMENT_UNKNOWN = K3P_MAIL_ATTACHMENT_TIE + 3

KMO_OTUT_STATUS_MAGIC_NUMBER = 0xFAEB9091
KMO_OTUT_STATUS_NONE = KMO_OTUT_STATUS_MAGIC_NUMBER + 1
KMO_OTUT_STATUS_USABLE = KMO_OTUT_STATUS_MAGIC_NUMBER + 2
KMO_OTUT_STATUS_USED = KMO_OTUT_STATUS_MAGIC_NUMBER + 3
KMO_OTUT_STATUS_ERROR = KMO_OTUT_STATUS_MAGIC_NUMBER + 4

KPP_MAGIC_NUMBER = 0x43218765

KPP_CONNECT_KMO = KPP_MAGIC_NUMBER +  1  
KPP_DISCONNECT_KMO = KPP_MAGIC_NUMBER +  2
KPP_BEG_SESSION = KPP_MAGIC_NUMBER +  3
KPP_END_SESSION = KPP_MAGIC_NUMBER +  4

KPP_IS_KSERVER_INFO_VALID = KPP_MAGIC_NUMBER + 10  
KPP_SET_KSERVER_INFO = KPP_MAGIC_NUMBER + 11  

KPP_SIGN_MAIL = KPP_MAGIC_NUMBER + 20  
KPP_SIGN_N_POD_MAIL = KPP_MAGIC_NUMBER + 21
KPP_SIGN_N_ENCRYPT_MAIL = KPP_MAGIC_NUMBER + 22
KPP_SIGN_N_ENCRYPT_N_POD_MAIL = KPP_MAGIC_NUMBER + 23
KPP_CONFIRM_REQUEST = KPP_MAGIC_NUMBER + 24
KPP_USE_PWDS = KPP_MAGIC_NUMBER + 25  

KPP_EVAL_INCOMING = KPP_MAGIC_NUMBER + 30  
KPP_PROCESS_INCOMING = KPP_MAGIC_NUMBER + 31  
KPP_MARK_UNSIGNED_MAIL = KPP_MAGIC_NUMBER + 32
KPP_SET_DISPLAY_PREF = KPP_MAGIC_NUMBER + 33

KPP_GET_EVAL_STATUS = KPP_MAGIC_NUMBER + 40  
KPP_GET_STRING_STATUS = KPP_MAGIC_NUMBER + 41

KPP_GET_EMAIL_PWD = KPP_MAGIC_NUMBER + 50
KPP_GET_ALL_EMAIL_PWD = KPP_MAGIC_NUMBER + 51
KPP_SET_EMAIL_PWD = KPP_MAGIC_NUMBER + 52
KPP_REMOVE_EMAIL_PWD = KPP_MAGIC_NUMBER + 53

KPP_MUA_OUTLOOK = 1
KPP_MUA_THUNDERBIRD = 2
KPP_MUA_LOTUS_NOTES = 3

KMO_MAGIC_NUMBER = 0x12349876

KMO_COGITO_ERGO_SUM = KMO_MAGIC_NUMBER +  1  
KMO_INVALID_REQ = KMO_MAGIC_NUMBER +  2  
KMO_INVALID_CONFIG = KMO_MAGIC_NUMBER +  3  
KMO_SERVER_ERROR = KMO_MAGIC_NUMBER +  4  

KMO_SERVER_INFO_ACK = KMO_MAGIC_NUMBER + 10  
KMO_SERVER_INFO_NACK = KMO_MAGIC_NUMBER + 11  

KMO_PACK_ACK = KMO_MAGIC_NUMBER + 20
KMO_PACK_NACK = KMO_MAGIC_NUMBER + 21  

KMO_PACK_CONFIRM = KMO_MAGIC_NUMBER + 22  
KMO_PACK_ERROR = KMO_MAGIC_NUMBER + 23  
KMO_NO_RECIPIENT_PUB_KEY = KMO_MAGIC_NUMBER + 24  
KMO_INVALID_OTUT = KMO_MAGIC_NUMBER + 25  

KMO_EVAL_STATUS = KMO_MAGIC_NUMBER + 30  
KMO_STRING_STATUS = KMO_MAGIC_NUMBER + 31
KMO_PROCESS_ACK = KMO_MAGIC_NUMBER + 32  
KMO_PROCESS_NACK = KMO_MAGIC_NUMBER + 33  
KMO_MARK_UNSIGNED_MAIL = KMO_MAGIC_NUMBER + 34  
KMO_SET_DISPLAY_PREF_ACK = KMO_MAGIC_NUMBER + 35
KMO_SET_DISPLAY_PREF_NACK = KMO_MAGIC_NUMBER + 36

KMO_PWD_ACK = KMO_MAGIC_NUMBER + 50

KMO_MUST_UPGRADE = KMO_MAGIC_NUMBER + 60  

KMO_UPGRADE_SIG = 1 
KMO_UPGRADE_KOS = 2 
KMO_UPGRADE_KPS = 3 

KMO_PROCESS_NACK_MAGIC_NUMBER = 0x531AB246
KMO_PROCESS_NACK_POD_ERROR = KMO_PROCESS_NACK_MAGIC_NUMBER + 1  
KMO_PROCESS_NACK_PWD_ERROR = KMO_PROCESS_NACK_MAGIC_NUMBER + 2  
KMO_PROCESS_NACK_DECRYPT_PERM_FAIL = KMO_PROCESS_NACK_MAGIC_NUMBER + 3  
KMO_PROCESS_NACK_MISC_ERROR = KMO_PROCESS_NACK_MAGIC_NUMBER + 4  

KMO_SID_MAGIC_NUMBER = (0x8724 << 16) + (1 << 8)
KMO_SID_KPS = KMO_SID_MAGIC_NUMBER + 1
KMO_SID_OPS = KMO_SID_MAGIC_NUMBER + 2
KMO_SID_OUS = KMO_SID_MAGIC_NUMBER + 3
KMO_SID_OTS = KMO_SID_MAGIC_NUMBER + 4
KMO_SID_IKS = KMO_SID_MAGIC_NUMBER + 5
KMO_SID_EKS = KMO_SID_MAGIC_NUMBER + 6

KMO_SERROR_MAGIC_NUMBER = 0X8FBA3CDE
KMO_SERROR_MISC = KMO_SERROR_MAGIC_NUMBER + 1
KMO_SERROR_TIMEOUT = KMO_SERROR_MAGIC_NUMBER + 2
KMO_SERROR_UNREACHABLE = KMO_SERROR_MAGIC_NUMBER + 3
KMO_SERROR_CRIT_MSG = KMO_SERROR_MAGIC_NUMBER + 4

KMO_EVAL_ATTACHMENT_MAGIC_NUMBER = 0X65920424
KMO_EVAL_ATTACHMENT_DROPPED = KMO_EVAL_ATTACHMENT_MAGIC_NUMBER + 1
KMO_EVAL_ATTACHMENT_INTACT = KMO_EVAL_ATTACHMENT_MAGIC_NUMBER + 2
KMO_EVAL_ATTACHMENT_MODIFIED = KMO_EVAL_ATTACHMENT_MAGIC_NUMBER + 3
KMO_EVAL_ATTACHMENT_INJECTED = KMO_EVAL_ATTACHMENT_MAGIC_NUMBER + 4
KMO_EVAL_ATTACHMENT_ERROR = KMO_EVAL_ATTACHMENT_MAGIC_NUMBER + 5

KMO_SIGNED_MASK = (1 << 0)  
KMO_ENCRYPTED_MASK = (1 << 1)  
KMO_ENCRYPTED_WITH_PWD_MASK = (1 << 2)  
KMO_REQUIRED_POD_MASK = (1 << 3)  
KMO_CONTAINED_OTUT_MASK = (1 << 4)  

KMO_FIELD_STATUS_MAGIC_NUMBER = 0xFD4812ED
KMO_FIELD_STATUS_ABSENT = KMO_FIELD_STATUS_MAGIC_NUMBER + 1
KMO_FIELD_STATUS_INTACT = KMO_FIELD_STATUS_MAGIC_NUMBER + 2
KMO_FIELD_STATUS_CHANGED = KMO_FIELD_STATUS_MAGIC_NUMBER + 3

KMO_DECRYPTION_STATUS_MAGIC_NUMBER = 0xFED123AB
KMO_DECRYPTION_STATUS_NONE = KMO_DECRYPTION_STATUS_MAGIC_NUMBER + 1
KMO_DECRYPTION_STATUS_ENCRYPTED = KMO_DECRYPTION_STATUS_MAGIC_NUMBER + 2
KMO_DECRYPTION_STATUS_ENCRYPTED_WITH_PWD = KMO_DECRYPTION_STATUS_MAGIC_NUMBER + 3
KMO_DECRYPTION_STATUS_DECRYPTED = KMO_DECRYPTION_STATUS_MAGIC_NUMBER + 4
KMO_DECRYPTION_STATUS_ERROR = KMO_DECRYPTION_STATUS_MAGIC_NUMBER + 5

KMO_POD_STATUS_MAGIC_NUMBER = 0xCBA987EF
KMO_POD_STATUS_NONE = KMO_POD_STATUS_MAGIC_NUMBER + 1
KMO_POD_STATUS_UNDELIVERED = KMO_POD_STATUS_MAGIC_NUMBER + 2
KMO_POD_STATUS_DELIVERED = KMO_POD_STATUS_MAGIC_NUMBER + 3
KMO_POD_STATUS_ERROR = KMO_POD_STATUS_MAGIC_NUMBER + 4
 
KMO_PACK_EXPL_MAGIC_NUMBER = 0x820994AF
KMO_PACK_EXPL_UNSPECIFIED = KMO_PACK_EXPL_MAGIC_NUMBER + 1
KMO_PACK_EXPL_SUSPECT_SPAM = KMO_PACK_EXPL_MAGIC_NUMBER + 2
KMO_PACK_EXPL_SUSPECT_VIRUS = KMO_PACK_EXPL_MAGIC_NUMBER + 3
KMO_PACK_EXPL_SHOULD_ENCRYPT = KMO_PACK_EXPL_MAGIC_NUMBER + 4
KMO_PACK_EXPL_SHOULD_POD = KMO_PACK_EXPL_MAGIC_NUMBER + 5
KMO_PACK_EXPL_SHOULD_ENCRYPT_N_POD = KMO_PACK_EXPL_MAGIC_NUMBER + 6
KMO_PACK_EXPL_CUSTOM = KMO_PACK_EXPL_MAGIC_NUMBER + 7
