/*
 *  nbphpsess.c
 *
 *  Count PHP 'active' sessions in given directory
 *
 *  Synopsis:
 *
 *	- Scan directory for active sessions and report initial count
 *	- setup directory watch
 *	- directory watch loop (with 1s timeout)
 *	    if new file:
 *		add file to watcch
 *	    if file modified:
 *		check if active (contains "s:15:\"iConnectionType\";")
 * TBC...
 *
 */
#include <stdio.h>

int main(int ac, char *av[])
{
     return 0;
}
