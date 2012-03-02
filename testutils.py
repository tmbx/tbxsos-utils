# -*- coding: utf-8 -*-

import K3P, random
from unittest import TestCase
from ConfigParser import *

class KMODTestCase(TestCase):
    def fail(self, msg = None):
        try:
            TestCase.fail(self, msg)
        except:
            self.kmod.stop()
            self.kmod.save_logs(self.destdir)
            raise

    def failIf(self, expr, msg = None):
        try:
            TestCase.failIf(self, expr, msg)
        except:
            self.kmod.stop()
            self.kmod.save_logs(self.destdir)
            raise

    def failUnless(self, expr, msg = None):
        try:
            TestCase.failUnless(self, expr, msg)
        except:
            self.kmod.stop()
            self.kmod.save_logs(self.destdir)
            raise

    def failUnlessRaises(self, excClass, callableObj, *args, **kwargs):
        try:
            TestCase.failUnlessRaises(self, excClass, callableObj, *args, **kwargs)
        except:
            self.kmod.stop()
            self.kmod.save_logs(self.destdir)
            raise

    def failUnlessEqual(self, first, second, msg = None):
        try:
            TestCase.failUnlessEqual(self, first, second, msg)
        except:
            self.kmod.stop()
            self.kmod.save_logs(self.destdir)
            raise

    def failIfEqual(self, first, second, msg = None):
        try:
            TestCase.failIfEqual(self, first, second, msg)
        except:
            self.kmod.stop()
            self.kmod.save_logs(self.destdir)
            raise

    def failUnlessAlmostEqual(self, first, second, places = 7, msg = None):
        try:
            TestCase.failUnlessAlmostEqual(self, first, second, places, msg)
        except:
            self.kmod.stop()
            self.kmod.save_logs(self.destdir)
            raise

    def failIfAlmostEqual(self, first, second, places = 7, msg = None):
        try:
            TestCase.failIfAlmostEqual(self, first, second, places, msg)
        except:
            self.kmod.stop()
            self.kmod.save_logs(self.destdir)
            raise

    assertEqual = assertEquals = failUnlessEqual
    assertNotEqual = assertNotEquals = failIfEqual
    assertAlmostEqual = assertAlmostEquals = failUnlessAlmostEqual
    assertNotAlmostEqual = assertNotAlmostEquals = failIfAlmostEqual
    assertRaises = failUnlessRaises
    assert_ = assertTrue = failUnless
    assertFalse = failIf

    def __init__(self, methodName, kmod, destdir):
        TestCase.__init__(self, methodName)
        self.kmod = kmod
        self.destdir = destdir

def kmod_from_cfg(cfg_parser, cfg_section):
    kmod = K3P.Plugin(cfg_parser.get("kmod", "kmod"), kmod_timeout = cfg_parser.getint("kmod", "timeout"))

    kmod.full_name = cfg_parser.get("member", "full_name")
    kmod.pod_addr = cfg_parser.get("member", "pod_addr")
    kmod.username = cfg_parser.get("member", "username")
    kmod.password = cfg_parser.get("member", "password")
    kmod.kps_host = cfg_parser.get("member", "host")
    kmod.kps_port = int(cfg_parser.get("member", "port"))

    return kmod

def msg_from_cfg(cfg_parser, cfg_section):
    msg = K3P.Message()

    # Check we have all the elements we need in the ini section.
    for k in ["from_name", "from_addr", "to", "cc", "subject", "nonmember-passwords"]:
        if not cfg_parser.has_option(cfg_section, k):
            raise Exception("Missing element %s in section %s" % (k, cfg_section))

    msg.from_name = cfg_parser.get(cfg_section, "from_name")
    msg.from_addr = cfg_parser.get(cfg_section, "from_addr")

    msg.to = []
    for addr in cfg_parser.get(cfg_section, "to").split(";"):
        addr = addr.strip()
        if len(addr) > 0:
            msg.to.append(addr)

    msg.cc = []
    for addr in cfg_parser.get(cfg_section, "cc").split(";"):
        addr = addr.strip()
        if len(addr) > 0:
            msg.cc.append(addr)

    pwds_text = cfg_parser.get(cfg_section, "nonmember-passwords")
    if len(pwds_text) > 0:
        pwd_hash = {}
        pwds = pwds_text.split(";")
        for p in pwds:
            try:
                (pwd_email, pwd, pwd_otut) = p.split(":")
                pwd_hash[pwd_email] = (pwd, bool(int(pwd_otut)))
            except:
                raise Exception("Incorrect format for non-member encryption password")
        msg.passwords = K3P.EncryptionPasswordQuery(pwd_hash)
        
    msg.subject = cfg_parser.get(cfg_section, "subject")

    # Add weird data as bodies.
    # The text body will be a random mix of that.
    text_body_chars = ['à']
    text_body_max_size = 1024
    text_body = ""

    for i in range(0, 1024):
        idx = random.randrange(len(text_body_chars))
        text_body += text_body_chars[idx]

    msg.text_body = text_body + "\n"
    # FIXME: This could be quite a bit better but will give just
    # enough work for KMOD.
    msg.html_body = "<html><body><pre>%s</pre></body></html>\n" % text_body

    return msg
