#!/bin/sh
#
#	nbphpsess.sh - Store NB_SESSIONS_PHP and LOAD_AVG in APC cache
#
Def='/etc/epiconcept'
NSV='NB_SESSIONS_PHP'
LAV='LOAD_AVG'

cfgfile()
{
    #global Pkg Prg Dir Def
    local f

    if [ "$NBPHPSESS_CONF" ]; then
	f="$NBPHPSESS_CONF"
	test -s "$f" && expr "$f" : / >/dev/null && echo "$f" && return
	test -s "$Dir/$f" && echo "$Dir/$f" && return
	test -s "$Def/$f" && echo "$Def/$f" && return
    fi
    f="$Pkg.conf"
	test -s "$Dir/$f" && echo "$Dir/$f" && return
	test -s "$Def/$f" && echo "$Def/$f" && return
    echo "$Prg: cannot find configuration file" >&2
    exit 1
}

cfgvar()
{
    #global Cfg
    local val

    val=`sed -nr -e 's/\s*#.*$//' -e "s/^\\s*$1\\s*=\\s*(\\S+)/$2=\"\\1\"/p" $Cfg`
    test "$val" && echo "$val" || echo "$2=\"$3\""
}

getcfg()
{
    local Cfg

    Cfg=`cfgfile`
    test "$1" && echo "Reloading $Cfg" >&2
    cfgvar report_url Url 'https://`hostname`.voozanoo.net/localapc'
    cfgvar curl_timeout Cto '10'
    cfgvar conf_reload_sig Rld USR1
}

gotsig()
{
    # global Sig
    echo "Received SIG$1" >&2
    Sig=$1
}

sigterm()
{
    gotsig TERM
}

sigrld()
{
    #global Rld
    gotsig $Rld
}

#
#   Init
#
Pkg=`basename $0 .sh`
Prg=`basename $0`
Dir=`dirname $0`
eval `getcfg`
#echo "Cfg=$Cfg Url=[$Url] Cto=$Cto Rld=$Rld"; exit 0

trap sigterm TERM
trap sigrld $Rld
if tty >/dev/null; then		# Interactive test mode
    schr='?'
    eof=`stty -a | sed -nr 's/^.* eof = ([^;]+);.*\$/\1/p'`
    echo "Enter (int)nb-sessions-php (or type $eof for end, $schr<cr> for status)"
fi
#
#   Main loop
#
test "$schr" || echo "Starting $Prg" >&2
sleep 1
while :
do
    if [ "$Sig" = "$Rld" ]; then
	oRld="$Rld"
	eval `getcfg y`
	test "$Rld" = "$oRld" || echo "ignoring conf_reload_sig=$Rld until next restart" >&2
	Rld="$oRld"
	Sig=
    fi
    while read nb
    do
	test "$Sig" && break
	test "$nb" || continue
	if [ "$schr" -a "$nb" = "$schr" ]; then
	    echo "curl -s \"$Url?$NSV&$LAV\" =>"
	    curl -m $Cto -s "$Url?$NSV&$LAV" | sed 's/^/  > /'
	else
	    la=`uptime | sed -e 's/^.* load average: //' -e 's/, /;/g'`
	    #echo "URL=[$Url?$NSV=$nb&$LAV=$la]"
	    curl -m $Cto "$Url?$NSV=$nb&$LAV=$la"
	fi
    done
    test "$Sig" = 'TERM' && break
done
