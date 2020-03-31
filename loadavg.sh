#!/bin/sh

exec uptime|sed -e 's/^.* load average: //' -e 's/ //g'
