/*
 *	real.c - Test behaviour of stdlib's realpath()
 */
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int ac, char *av[])
{
    if (ac > 1)
    {
	char	real[PATH_MAX];

	if (realpath(av[1], real) == NULL)
	{
	    fprintf(stderr, "cannot get realpath of \"%s\": %s (errno=%d)\n", av[1], strerror(errno), errno);
	    exit(1);
	}
	puts(real);
    }
    else
    {
	fprintf(stderr, "missing file-name\n");
	exit(1);
    }
}
