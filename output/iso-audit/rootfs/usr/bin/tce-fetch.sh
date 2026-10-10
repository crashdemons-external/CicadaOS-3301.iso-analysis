#!/bin/sh
#(c) Robert Shingledecker 2004-2012
#
. /etc/init.d/tc-functions
getMirror
if [ "$1" == "-O" ]; then
	shift
	busybox wget -cq -O- "$MIRROR"/"$1"
else
	[ -f "$1" ] && rm -f "$1"
	busybox wget -cq "$MIRROR"/"$1"
fi
