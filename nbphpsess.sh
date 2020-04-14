#!/bin/sh
#
#	nbphpsess.sh - Store NB_SESSIONS_PHP and LOAD_AVG in APC cache
#
Def='/etc/epiconcept'
NSV='NB_SESSIONS_PHP'
LAV='LOAD_AVG'

CfgFile()
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

CfgVar()
{
    #global Cfg
    local val

    val=`sed -nr -e 's/\s*#.*$//' -e "s/^\\s*$1\\s*=\\s*(\\S+)/$2=\"\\1\"/p" $Cfg`
    test "$val" && echo "$val" || echo "$2=\"$3\""
}

GetCfg()
{
    local Cfg

    Cfg=`CfgFile`
    test "$1" && echo "Reloading $Cfg" >&2 || echo "Config from $Cfg" >&2
    CfgVar conf_reload_sig Rld USR1
    CfgVar report_url Url 'https://`hostname`.voozanoo.net/localapc'
    CfgVar curl_timeout Cto 20
    CfgVar report_freq Frq 5
}

GotSig()
{
    # global Sig
    echo "Received SIG$1" >&2
    Sig=$1
}

SigTerm()
{
    GotSig TERM
}

SigRld()
{
    #global Rld
    GotSig $Rld
}

#
#   Init
#
Pkg=`basename $0 .sh`
Prg=`basename $0`
Dir=`dirname $0`
expr "$Pkg" : '.*test$' >/dev/null && Dry=y	# Dry run mode (do not call curl)

if tty >/dev/null; then		# Interactive test mode
    schr='?'
    eof=`stty -a | sed -nr 's/^.* eof = ([^;]+);.*\$/\1/p'`
    echo "Enter (int)nb-sessions-php (or type $eof for end, $schr<cr> for status)"
fi
test "$schr" || echo "Starting $Prg" >&2

eval `GetCfg`
#echo "Cfg=$Cfg Rld=$Rld Url=[$Url] Cto=$Cto Frq=$Frq"; exit 0
test "$Dry" && echo "Dry-run mode (curl not called)" >&2

trap SigTerm TERM
trap SigRld $Rld
#
#   Main loop
#
sleep 1
while :
do
    if [ "$Sig" = "$Rld" ]; then
	oRld="$Rld"
	eval `GetCfg y`
	if [ "$Rld" != "$oRld" ]; then
	    trap $oRld
	    trap SigRld $Rld
	    echo "Config-reload signal changed from $oRld to $Rld" >&2
	fi
	Sig=
    fi
    Nxt=$(expr $(date '+%s') + 1)
    while read nb
    do
	test "$Sig" && break
	test "$nb" || continue
	if [ "$schr" -a "$nb" = "$schr" ]; then
	    echo "curl -m $Cto -s \"$Url?$NSV&$LAV\" =>"
	    curl -m $Cto -s "$Url?$NSV&$LAV" | sed 's/^/  > /'
	else
	    Now=`date '+%s'`
	    if [ "$Now" -le "$Nxt" ]; then
		la=`uptime | sed -e 's/^.* load average: //' -e 's/, /;/g'`
		echo "NbSess=$nb LdAvg=\"$la\""
		test "$Dry" || curl -m $Cto -s "$Url?$NSV=$nb&$LAV=$la"
	    elif [ -z "$schr" ]; then
		echo "Skipped curl as we are `expr $Now - $Nxt` second(s) late" >&2
	    fi
	    Nxt=`expr $Now + $Frq`
	fi
    done
    test "$Sig" = 'TERM' && break
done
