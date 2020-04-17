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
    CfgVar report_freq Frq 5
    CfgVar report_curl Rpc y
    CfgVar report_url Url 'https://`hostname`.voozanoo.net/localapc'
    CfgVar ldavg_method Lar php
    CfgVar curl_timeout Cto 20
    CfgVar report_file Rpf ''
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

if tty >/dev/null; then		# Interactive test mode
    # Sch (status character) is only set in interactive mode
    Sch='?'
    eof=`stty -a | sed -nr 's/^.* eof = ([^;]+);.*\$/\1/p'`
    echo "Enter (int)nb-sessions-php (or type $eof for end, $Sch<cr> for status)"
fi
test "$Sch" || echo "Starting $Prg" >&2

eval `GetCfg`
#echo "Cfg=$Cfg Rld=$Rld Frq=$Frq Rpc=$Rpc Url=[$Url] Lar=$Lar Cto=$Cto Rpf=$Rpf"; exit 0
test "$Rpc" && echo "Report with curl (to PHP APC-set page)" >&2
test "$Rpf" && echo "Report to file $Rpf" >&2
test "$Rpc" -o "$Rpf" || { echo "Reporting to curl by default (legacy)" >&2; Rpc=y; }

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

	if [ "$Sch" -a "$nb" = "$Sch" ]; then
	    # interactive get
	    echo "curl -m $Cto -s \"$Url?$NSV&$LAV\" =>"
	    curl -m $Cto -s "$Url?$NSV&$LAV" | sed 's/^/  > /'
	    continue
	fi
	Now=`date '+%s'`
	if [ "$Now" -le "$Nxt" ]; then
	    if [ "$Rpc" ]; then
		if [ "$Lra" = 'sh' ]; then
		    la=`uptime | sed -e 's/^.* load average: //' -e 's/, /;/g'`
		    echo "NbSess=$nb LdAvg=\"$la\""
		else
		    la='php'
		    echo "NbSess=$nb"
		fi
		curl -m $Cto -s "$Url?$NSV=$nb&$LAV=$la"
	    fi
	elif [ "$Rpc" ]; then
	    test "$Sch" || echo "Skipped curl as we are `expr $Now - $Nxt` second(s) late" >&2
	fi
	test "$Rpf" && echo "$nb" >$Rpf
	Nxt=`expr $Now + $Frq`
    done
    test "$Sig" = 'TERM' && break
done
