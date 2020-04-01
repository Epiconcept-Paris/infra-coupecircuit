#!/bin/sh
#
#	nbphpsess.sh - Store NB_SESSIONS_PHP and LOAD_AVG in APC cache
#
prg=`basename $0 .sh`
dir=`dirname $0`
cfg="${NBPHPSESS_CONF:-$dir/$prg.conf}"
#echo "cfg=$cfg"; exit 0

nbv='NB_SESSIONS_PHP'
lav='LOAD_AVG'

conf()
{
    #global cfg

    sed -nr -e 's/[ 	]*#.*$//' -e "s/^ *$1 *= *([^ ]+)/\\1/p" $cfg
}

#
#   Init
#
test -s "$cfg" || { echo "$0: cannot find $cfg" >&2; exit 1; }
url=`conf 'report_url'`
#echo "url=[$url]"; exit 0

if tty >/dev/null; then		# Interactive test mode
    schr='?'
    eof=`stty -a | sed -nr 's/^.* eof = ([^;]+);.*\$/\1/p'`
    echo "Enter (int)nb-sessions-php (or type $eof for end, $schr<cr> for status)"
fi
#
#   Main loop
#
while read nb
do
    test "$nb" || continue
    if [ "$schr" -a "$nb" = "$schr" ]; then
	echo "curl -s \"$url?$nbv&$lav\" =>"
	curl -s "$url?$nbv&$lav" | sed 's/^/  > /'
    else
	la=`uptime | sed -e 's/^.* load average: //' -e 's/, /;/g'`
	#echo "URL=[$url?$nbv=$nb&$lav=$la]"
	curl "$url?$nbv=$nb&$lav=$la"
    fi
done
