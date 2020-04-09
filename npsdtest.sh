#!/bin/sh
#
#	npsdtest.sh - nbphpsessd test
#
prg=`basename $0 .sh`
dir=`dirname $0`
cfg="${NBPHPSESS_CONF:-/etc/epiconcept/$prg.conf}"
echo "cfg=$cfg"

conf()
{
    #global cfg

    sed -nr -e 's/\s*#.*$//' -e "s/^\\s*$1\\s*=\\s*(\\S+)/\\1/p" $cfg
}

#
#   Init
#
test -s "$cfg" || { echo "$0: cannot find $cfg" >&2; exit 1; }
url=`conf 'report_url'`
#echo "url=[$url]"; exit 0

#
#   Main loop
#
while read nb
do
    test "$nb" || continue
    la=`uptime | sed -e 's/^.* load average: //' -e 's/, /;/g'`
    echo "nbsess=$nb loadavg=$la"
done
