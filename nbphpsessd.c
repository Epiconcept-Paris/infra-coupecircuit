/*
 *	phpnbsessd.c
 *
 *	- become daemon
 *	- Setup av[1] and av[2] connected by pipes
 *	- if av[3] passed, it is log file
 *	- optional log connected to fd=2 (av[1]) and fd=1,2 (av[2])
 *	- watch and restart both av[1] and av[2] if any dies
 *	- kill them both if SIGTERM
 *	- pass on SIGUSR1
 */
#include <stdio.h>

int main(int ac, char *av[])
{
     return 0;
}
