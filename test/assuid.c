/*
 *      root - Run a command with this tool's EUID/EGID (normally root)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ATTR(a) __attribute__((__##a##__))
#define IGNORE(e)       do{if(e){}}while(0)

int main(int ac ATTR(unused), char *av[])
{
    char    *p, *q;

    if ((p = getenv("SHELL")) == NULL)
    {
        p = "/bin/sh";
        av[0] = "sh";
    }
    else
        av[0] = (q = strrchr(p, '/')) != NULL ? q + 1 : p;

    IGNORE(setuid(geteuid()));
    IGNORE(setgid(getegid()));
    execv(p, av);
    perror(av[0]);
    return 0;
}
