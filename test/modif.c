#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

int main(int ac, char **av)
{
    char    buf[8];
    int	    fd, len, ret;

    if (ac < 2)
    {
	fprintf(stderr, "Usage: %s file-to-rewrite\n", av[0]);
	exit(1);
    }
    if ((fd = open(av[1], O_RDWR)) >= 0)
    {
	if ((len = read(fd, buf, sizeof buf)) > 0)
	{
	    lseek(fd, 0, SEEK_SET);
	    if ((ret = write(fd, buf, len)) != len)
	    {
		if (len >= 0)
		    fprintf(stderr, "%s: read %d from %s, could write only %d ?\n", av[0], len, av[1], ret);
		else
		    fprintf(stderr, "%s: could not write %d bytes to %s (errno=%d): %s\n", av[0], len, av[1], errno, strerror(errno));
	    }
	}
	else if (len == 0)
	    fprintf(stderr, "%s: file %s is empty\n", av[0], av[1]);
	else
	    fprintf(stderr, "%s: could not read %zd bytes from %s (errno=%d): %s\n", av[0], sizeof buf, av[1], errno, strerror(errno));
	close(fd);
    }
    else
	fprintf(stderr, "%s: could not open %s for read/write (errno=%d): %s\n", av[0], av[1], errno, strerror(errno));

    return errno > 0 ? 2 : 0;
}
