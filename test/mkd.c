/*
 *	mkd.c - Make directory, with parents if needed
 *
 *	This is just a test of mkdir_p(). Remove debug() calls for production.
 */
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define LOG_BUF_SIZE	(4 * 1024)
#define EX_PATH	2

#define debug(f,a...)		errmsg(-1,0,__FUNCTION__,__LINE__,f,##a)
#define errexit(x,e,f,a...)	errmsg(x,e,__FUNCTION__,__LINE__,f,##a)

char	*prg;

void errmsg(int xc, int er, const char *fn, int ln, char *fmt, ...)
{
    va_list	ap;
    char	buf[LOG_BUF_SIZE];

    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (er > 0)
	fprintf(stderr, "In %s:%s() line %d, %s: %s (%d)\n", prg, fn, ln, buf, strerror(er), er);
    else
	fprintf(stderr, "%s:%s() line %d, %s\n", prg, fn, ln, buf);

    if (xc >= 0)
	exit(xc);
}

void		mkdir_p(char *dir)
{
    char	*p, c;
    int		len, ret;
    struct stat	sb;

    len = strlen(dir);
    while (dir[len - 1] == '/')
	dir[--len] = '\0';

    debug("dir=\"%s\"", dir);
    p = dir + 1;
    for (;;)
    {
	c = *p;
	if (c == '/' || c == '\0')	// Check at dir-sep or end
	{
	    *p = '\0';
	    debug("sub=\"%s\"", dir);
	    ret = (stat(dir, &sb) == 0 && S_ISDIR(sb.st_mode)) ? 0 : mkdir(dir, 0777);
	    if (ret < 0)
		break;
	    if (c == '\0')
		return;
	    *p = c;
	}
	p++;
    }
    errexit(EX_PATH, errno, "cannot create directory %s", dir);
}

int main(int ac, char *av[])
{
    if ((prg = strrchr(av[0], '/')) != NULL)
	prg++;
    else
	prg = av[0];

    if (ac < 2)
    {
	fprintf(stderr, "%s: missing file-name\n", prg);
	return 1;
    }
    mkdir_p(av[1]);
    return 0;
}
