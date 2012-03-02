#!/bin/bash

MAIL_MSG=""
MAIL_FILE=$(mktemp)
BIN_KPS=/home/fdgonthier/repos/ktests/kpstests
BIN_OTUT=/home/fdgonthier/repos/ktests/otutcycle

$BIN_KPS /home/fdgonthier/repos/ktests/ini/internal_kps.ini 2>&1 >> $MAIL_FILE
$BIN_OTUT /home/fdgonthier/repos/ktests/ini/otutcycle.ini 2>&1 >> $MAIL_FILE

DATE=$(date)
mail -e -s "Teambox service health report $DATE" kos@teambox.co < $MAIL_FILE

[ -e $MAIL_FILE ] && rm $MAIL_FILE

exit 0
