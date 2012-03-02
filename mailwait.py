#!/usr/bin/python
#
# To be called by postfix upon reception of a message.  It will try to
# write the full received mail to the /tmp/mailwait-sock UNIX socket.
# If a client wants to actively wait for a mail to be received, it
# should open the /tmp/mailwait-sock socket and make sure it is
# writable by the postfix process.
#
# This script will not throw errors out.  It will happily ignore write
# errors.  It won't do anything if the socket doesn't exists.

import sys, os, os.path, stat, socket, select, syslog
from datetime import datetime, timedelta
from pyinotify import *

mailwait_dir = "/tmp/mailwait/"

__all__ = ['mailwait', 'mailwait_receive']

class MailWaitProcessor(ProcessEvent):
    def process_IN_CREATE(self, event):
        self.new_files.append(os.path.join(event.path, event.name))

    def __init__(self):
        self.new_files = []

def mailwait():
    """
    This uses pyinotify to wait for new mail arriving.  This return
    the list of files in that directory.  Files that are consumed by
    the user of this function needs to be unlinked by the caller.

    """
    global mailwait_dir

    # Check for files that are already there.  Return the list of
    # files if there are some files already.
    files = os.listdir(mailwait_dir)
    if len(files) > 0: return files

    # Otherwise, we have to wait for a new file.
    wm = WatchManager()
    wm_proc = MailWaitProcessor()
    wm.add_watch(mailwait_dir, EventsCodes.IN_CREATE, rec = True)
    n = Notifier(wm, wm_proc)

    # Wait for the event.
    if n.check_events(timeout = None):
        n.read_events()
        n.process_events()

    n.stop()

    return wm_proc.new_files

def mailwait_receive():
    """
    This is to be called by postfix on reception of a new mail.  This
    create a new file in /tmp/mailwait/ if a 'RUN' file exist in that
    directory.
    """
    try:
        mailwait_index = 0
        syslog.openlog("mailwait")

        syslog.syslog(syslog.LOG_DEBUG, "mailwait received a mail")

        # Read the message.  Presume we will not block reading, which
        # I think is reasonable.
        msg = sys.stdin.read()

        # Add the received file in the directory.
        while os.path.exists(os.path.join(mailwait_dir, "%04d" % mailwait_index)) and mailwait_index < 10000:
            mailwait_index += 1

        if mailwait_index > 9999:
            raise Exception("/tmp/mailwait is full")
            
        file_name = os.path.join(mailwait_dir, "%04d" % mailwait_index)

        fobj = open(file_name, "w")
        fobj.write(msg)
        fobj.close()

        # Postfix runs this program as an unpriviledged user.
        os.chmod(file_name, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

        # Scan the directory for old files.  Delete file older
        # than 5 minutes.
        for fs in os.listdir(mailwait_dir):
            fn = os.path.join(mailwait_dir, fs)
            st = os.stat(fn)
            now = datetime.now()
            ftime = datetime.fromtimestamp(st[stat.ST_CTIME])
            if (now - ftime) > timedelta(minutes = 5):
                os.unlink(fn)

        syslog.syslog(syslog.LOG_DEBUG, "mailwait has delivered its package to %s" % file_name)

    except BaseException, ex:
        syslog.syslog("mailwait interrupted by exception %s: %s" % (ex.__class__, ex))
    finally:
        syslog.syslog(syslog.LOG_DEBUG, "mailwait is exiting shamelessly")
        syslog.closelog()
