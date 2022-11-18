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
    char	*last = dir + strlen(dir),
		*prev, *ptr;
    struct stat	sb;

    debug("dir=\"%s\"", dir);
    for (ptr = prev = dir; ptr <= last; prev = ptr++)
    {
	if (*ptr == '/' || *ptr == '\0')	/* At subdir or end */
	{
	    debug("*ptr='%c'", *ptr);
	    if (*prev == '/')			/* Skip multiple '/' */
		continue;
	    if (*ptr == '/')			/* We have a subdir */
		*ptr = '\0';
	    debug("sub=\"%s\"", dir);
	    if (((stat(dir, &sb) == 0 && S_ISDIR(sb.st_mode)) ? 0 : mkdir(dir, 0777)) < 0)
		errexit(EX_PATH, errno, "cannot create directory '%s'", dir);
	    if (ptr < last)			/* Put back the '/' for subdirs */
		*ptr = '/';
	}
    }
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
