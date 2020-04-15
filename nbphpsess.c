/*
 *  nbphpsess.c
 *
 *  Count PHP 'active' sessions in given directory
 *
 *  Synopsis:
 *
 *	- Scan directory for active sessions and report initial count
 *	- setup directory watch
 *	- directory watch loop (in select with report_freq timeout)
 *	    if new file:
 *		add file to watcch
 *	    if file modified:
 *		check if active (contains "s:15:\"iConnectionType\";")
 *	- max user watch in /proc/sys/fs/inotify/max_user_watches
 *		but we need only ONE !
 *
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <regex.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/inotify.h>

/* Exit codes */
#define EX_OK		0
#define EX_USAGE	1
#define EX_CONF		2
#define EX_PATH		3

#define EX_INOT		4
#define EX_PIPE		5

#define EX_NOMEM	8
#define EX_LOGIC	9

/* global errors */
#define ERR_CFG_NUM	1
#define ERR_CFG_SIG	2
#define ERR_CFG_FAC	3
#define ERR_CFG_LVL	4

/* trace levels */
#define TL_CONF		16
#define TL_INOT		32
#define TL_EVNT		64

#define LOG_BUF_SIZE	4096

#define CFG_DEFDIR	"/etc/epiconcept"
#define CFGPATH_ENVFMT	"%s_CONF"

/* Parse regexp format (28 chr) for config (%s) values */
#define CFGVAR_REFMT	"^\\s*%s\\s*=\\s*(\\S*)\\s*(#.*)?$"
#define NB_CFGV_RESUBS	3

typedef struct dirent      dent_t;
typedef struct inotify_event ivent_t;

typedef struct timeval timeval_t;

typedef struct	sconvi_s	/* str conversion to int table entries */
{
    char	*str;
    int		val;
}		sconvi_t;

typedef union	cfgval_u	/* configuration values (current or default) */
{
#   define	STRIVAL	NULL
#   define	NUMIVAL	-1
    char	*s;
    int		i;
}		cfgval_t;

struct	glob_s;			/* Needed for forward ref in cfgvar_t below */

typedef struct	cfgvar_s	/* configuration variables */
{
    char	*name;
    short	isupd;		/* 1 if var updatable on reloads */
    short	isint;		/* 1 if var is int (vs str) */
    int		(*icv)(struct glob_s *, const char *, int);	/* function to convert to int */
    cfgval_t	val;		/* value */
    cfgval_t	def;		/* default */
    int		line;		/* line in file where defined, 0 if default */
    regex_t	regexp;		/* compiled regexp for config parsing */
    char	*help;
}		cfgvar_t;

typedef struct	sess_s
{
    char	name[40];
    time_t	mtime;
}		sess_t;

typedef	struct	glob_s
{
#define NB_CFGVARS	9
    cfgvar_t	config[NB_CFGVARS];	/* Must be 1st member for init */

    char	*prg;		/* basename from av[0] */
    char	*prg_dir;

    char	*cfg_path;
    int		cfgerr;

    int		ifd;
    int		iwd;

    sess_t	*sessions;
    int		pfx_len;

    int		loop;
    int		sig;
}		glob_t;

/*
 *  Initialize 'globals'
 *	used as 'globals' only in main(), signal handlers and log functions
 *	used as 'glob_t *g' everywhere else
*/
int	intv(glob_t *, const char *, int);
int	sigv(glob_t *, const char *, int);

glob_t		globals = {

	/*	When adding to the config variables belon, don't forget to:
	 *	  - update the NB_CFGVARS macro in glob_t definition above
	 *	  - add default values to the CFG_IVALS macro below
	 */
#	define TlvConv		config[0].icv

#	define TraceLevel	config[0].val.i
#	define SessDir		config[1].val.s
#	define MaxActive	config[2].val.i
#	define SessPrefix	config[3].val.s
#	define SessMinSize	config[4].val.i
#	define SessMaxAge	config[5].val.i
#	define ActiveStr	config[6].val.s
#	define ReportFreq	config[7].val.i
#	define SigReload	config[8].val.i

#	define VarSessDir	config[1].name
#	define VarReload	config[8].name

#	define DefSessDir	config[1].def.s
#	define DefReload	config[8].def.i

#	define RefSessDir	config[1].line
#	define RefReload	config[8].line

#	define ValSessDir(v)	v[1].s
#	define ValReload(v)	v[8].i

#	define CFG_IVALS	{ \
	{.i=NUMIVAL}, {.s=STRIVAL},\
	{.i=NUMIVAL}, {.s=STRIVAL},\
	{.i=NUMIVAL}, {.i=NUMIVAL}, {.s=STRIVAL},\
	{.i=NUMIVAL}, {.i=NUMIVAL}\
    }
    {
	{ "dtrace_level",	1, 1, intv, { .i = NUMIVAL },	{ .i = 0 },		0, {},
				"trace level for deamon and counter" },
	{ "sess_dir",		1, 0, NULL, { .s = STRIVAL },	{ .s = "/var/lib/php/sessions" }, 0, {},
				"main directory to watch" },
	{ "max_sess_size",	1, 1, intv, { .i = NUMIVAL },	{ .i = 16384 },		0, {},
				"maximum sessions size examined" },
	{ "sess_prefix",	1, 0, NULL, { .s = STRIVAL },	{ .s = "sess_" },	0, {},
				"ignore filenames not starting like this" },
	{ "sess_minsize",	1, 1, intv, { .i = NUMIVAL },	{ .i = 64 },		0, {},
				"ignore sessions files smaller than this bytes" },
	{ "sess_maxage",	1, 1, intv, { .i = NUMIVAL },	{ .i = 1800 },		0, {},
				"ignore sessions files older than this seconds" },
	{ "active_string",	1, 0, NULL, { .s = STRIVAL },	{ .s = "s:15:\"iConnectionType\";" }, 0, {},
				"ignore sessions files not containing this" },
	{ "report_freq",	1, 1, intv, { .i = NUMIVAL },	{ .i = 5 },		0, {},
				"report to our report-script every this seconds" },
	{ "conf_reload_sig",	1, 1, sigv, { .i = NUMIVAL },	{ .i = SIGUSR1 },	0, {},
				"conf-reload signal (SIGxxx also accepted)" }
    },
    NULL, NULL, NULL, 0, -1, -1
};

/*
 *  Log and trace macros
 *
 *	info("pid=%d sd=%d net write=0", s->pid, s->netsd);
 *	trace(TL_T1, "output_fd=%d", e->output_fd);
 *	error(errno, "pid=%d sd=%d net write", s->pid, s->netsd);
 *	error(0, "discarding invalid IAC 0x%X", p[1]);
 */
#define trace(l,f,a...)		logmsg(l,__FUNCTION__,__LINE__,NULL,f,##a)

#define info(f,a...)		logmsg(0,__FUNCTION__,__LINE__,"",f,##a)
#define notice(f,a...)		logmsg(0,__FUNCTION__,__LINE__,"NOTICE: ",f,##a)
#define warn(f,a...)		logmsg(0,__FUNCTION__,__LINE__,"WARNING: ",f,##a)
#define report(f,a...)		logmsg(0,__FUNCTION__,__LINE__,"REPORT: ",f,##a)
#define error(e,f,a...)		logmsg(e,__FUNCTION__,__LINE__,"ERROR: ",f,##a)

#define errexit(x,e,f,a...)	xitmsg(x,e,__FUNCTION__,__LINE__,f,##a)
/*
 * ====	Logging and tracing functions ==================================
 */
#define	hstamp(t)		(tstamp(t," ")+11)
char		*tstamp(time_t t, char *sep)	/* Only for loglines() just below */
{
    static char	buf[32];
    struct tm	*tp;

    if (t == 0)
	t = time(NULL);
    tp = localtime(&t);
    snprintf(buf, sizeof buf, "%04d-%02d-%02d%s%02d:%02d:%02d",
	 tp->tm_year + 1900, tp->tm_mon + 1, tp->tm_mday, sep, tp->tm_hour, tp->tm_min, tp->tm_sec);

    return buf;
}

/*  Log line (called by logmsg(), trcmsg() and xitmsg()) */
void		loglines(int syserr, const char *fn, int ln, char *tag, char *msg)
{
    FILE	*fp = stderr;
    char	*line, *p;
    int		nl = 0;

    if (*msg == '\0')
	return;

    p = msg;
    while ((line = strsep(&p, "\r\n")) != NULL)
    {
	if (*line == '\0')
	    continue;

	if (nl == 0)
	{
	    if (isatty(fileno(stdin)))
		fprintf(fp, "%s ", tstamp(0, " "));

	    if (tag == NULL)		/* trace */
		fprintf(fp, "%s:%d ", fn, ln);
	    else if (*tag != '\0')	/* all others but info */
		fputs(tag, fp);

	    fputs(line, fp);

	    if (syserr > 0)
		fprintf(fp, ": %s (errno=%d)\n", strerror(syserr), syserr);
	    else
		fputc('\n', fp);
	}
	else
	    fprintf(fp, "    %s\n", line);

	fflush(fp);
	nl++;
    }
}

void		logmsg(int x, const char *fn, int ln, char *tag, char *fmt, ...)
{
    va_list	ap;
    char	buf[LOG_BUF_SIZE];

    if (tag == NULL)	/* x is level and not errno */
    {
	if (globals.TraceLevel < 0 || (x & globals.TraceLevel) == 0)
	    return;
    }
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    loglines(tag != NULL ? x : 0, fn, ln, tag, buf);
}

void		xitmsg(int xcode, int syserr, const char *fn, int ln, char *fmt, ...)
{
    va_list	ap;
    char	buf[LOG_BUF_SIZE];

    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    /* force trace if EX_LOGIC */
    loglines(syserr, fn, ln, xcode == EX_LOGIC ? NULL : "", buf);
    info("exiting with code=%d", xcode);
    usleep(500 * 1000);
    exit(xcode);
}

/*
 * ====	Memory allocation functions ====================================
 */
void		*xmalloc(size_t u)
{
    void	*ret;

    if ((ret = malloc(u)) == NULL)
	errexit(EX_NOMEM, 0, "unable to alloc %u bytes", u);
    return ret;
}

void		*xfree(void *ptr)
{
    if (ptr != NULL)
	free(ptr);

    return NULL;
}

void		*xstrdup(const char *str)
{
    void	*ret;

    if (str == NULL)
	errexit(EX_NOMEM, 0, "called with NULL argument");
    if ((ret = strdup(str)) == NULL)
	errexit(EX_NOMEM, 0, "unable to alloc %u bytes", strlen(str));

    return ret;
}

int		xasprintf(char **buf, const char *fmt, ...)
{
    int		nb;
    va_list	ap;

    va_start(ap, fmt);
    if ((nb = vasprintf(buf, fmt, ap)) < 0)
	errexit(EX_NOMEM, 0, "unable to allocate memory");
    va_end(ap);

    return nb;
}

/*
 * ====	File utilities =================================================
 *
 *  Return a pointer to 'path' file's text content
 *	and file length if *plen is not NULL
 *  If error or file empty, return NULL
 */
char		*getfile(char *path, int *plen)
{
    struct stat	st;
    char	buf[LOG_BUF_SIZE], *big = NULL;
    int		fd, len, sz = sizeof buf;

    /* local buffer is used to read /proc file that have size=0 */
    if ((fd = open(path, O_RDONLY)) >= 0)
    {
	if (fstat(fd, &st) == 0)
	{
	    if ((sz = st.st_size) > sizeof buf)
		big = xmalloc(sz + 1);
	}
	len = read(fd, big != NULL ? big : buf, sz);
	close(fd);
    }
    if (len > 0)
    {
	if (big == NULL)
	{
	    big = xmalloc(len + 1);
	    memcpy(big, buf, len);
	}
	if (plen != NULL && memchr(big, '\0', len) != NULL)
	    warn("file \"%s\" contains NUL(s)", path);
	big[len] = '\0';
	if (plen != NULL)
	    *plen = len;
	return big;
    }
    if (big != NULL)
	xfree(big);

    return NULL;
}

/*
 *  Return basename of a path, or path itself if no '/' in it
 */
char		*base_name(char *path)
{
    char	*p = strrchr(path, '/');

    return p == NULL ? path : p + 1;
}

/*
 * ====	Parse config file ==============================================
 *
 *  Return regcomp / regex error string
 */
char		*re_err(regex_t *rep, int errcode)
{
    static char	msg[1024];

    regerror(errcode, rep, msg, sizeof msg);

    return msg;
}

/*
 *  Compile regexps in 'globals.config'
 */
void		conf_init(glob_t *g)
{
    cfgvar_t	*vp;
    char	*refmt = CFGVAR_REFMT;
    char	re[64], def[PATH_MAX];
    int		iv, err;

    /*
     *	Initialize config-file parser: compile rexexp for each config variable
     */
    for (iv = 0; iv < NB_CFGVARS; iv++)
    {
	vp = &g->config[iv];
	snprintf(re, sizeof re, refmt, vp->name);
	if ((err = regcomp(&vp->regexp, re, REG_EXTENDED)) != 0)
	    errexit(EX_LOGIC, 0, "regcomp error for %s: %s", vp->name, re_err(&vp->regexp, err));
	if (vp->regexp.re_nsub != (NB_CFGV_RESUBS - 1))
	    errexit(EX_LOGIC, 0, "regcomp requires %d matches for %s", vp->regexp.re_nsub + 1, vp->name);
	if (vp->isint == 0 && strchr(vp->def.s, '%') != NULL)
	{
	    snprintf(def, sizeof def, vp->def.s, g->prg);
	    vp->def.s = xstrdup(def);	/* free: never (init) */
	}
    }
}

/*
 *  Determine config path
 */
void		get_cfgpath(glob_t *g)
{
    char	path[PATH_MAX];
    char	env_var[32];
    char	*p;
    int		i;

    /* Make variable name */
    if (snprintf(env_var, sizeof env_var, CFGPATH_ENVFMT, g->prg) >= sizeof env_var)
	errexit(EX_CONF, 0, "env variable name for config-file is too long");
    for (i = 0; i < strlen(g->prg); i++)
	env_var[i] = toupper(env_var[i]);
    trace(TL_CONF, "env_var = %s", env_var);

    /* Try from getenv */
    if ((p = getenv(env_var)) != NULL)
    {
	trace(TL_CONF, "trying cfg_path = %s", p);
	if (access(p, R_OK) == 0)
	{
	    g->cfg_path = xstrdup(p);	/* free: never (init 1) */
	    return;
	}
    }

    /* Try from prg_dir */
    snprintf(path, sizeof path, "%s/%s.conf", g->prg_dir, g->prg);
    trace(TL_CONF, "trying cfg_path = %s", path);
    if (access(path, R_OK) == 0)
    {
	g->cfg_path = xstrdup(path);	/* free: never (init 2) */
	return;
    }

    /* Try from default config dir */
    snprintf(path, sizeof path, CFG_DEFDIR "/%s.conf", g->prg);
    trace(TL_CONF, "trying cfg_path = %s", path);
    if (access(path, R_OK) == 0)
    {
	g->cfg_path = xstrdup(path);	/* free: never (init 3) */
	return;
    }
    errexit(EX_CONF, 0, "cannot find config-file %s.conf in env, %s or in " CFG_DEFDIR,
	g->prg, g->prg_dir);
}

/*
 *  String to integer conversion functions
 *
 *	Check integer value
 */
int		intv(glob_t *g, const char *s, int ln)
{
    const char	*p = s;

    while (*p != '\0')
    {
	if (*p != '-' && (*p < '0' || *p > '9'))
	{
	    if (ln > 0)
		warn("non-numeric character '%c' in value \"%s\" at line %d of %s", *p, s, ln, g->cfg_path);
	    else
		warn("non-numeric character '%c' in value \"%s\"", *p, s);

	    g->cfgerr = ERR_CFG_NUM;
	    return NUMIVAL;
	}
	p++;
    }
    return atoi(s);
}

/*	Generic string to int conversion. Also returns list of valid strings. */
int		stoi(sconvi_t *tbl, int sz, const char *s, char **help, char *sep)
{
    int		i, nb;

    for (i = 0; i < sz; i++)
    {
	if (strcmp(tbl[i].str, s) == 0)
	    return tbl[i].val;
    }

    /* Not found: build help text for values */
    *help = xmalloc(LOG_BUF_SIZE);	/* free: never (init) */
    nb = 0;
    for (i = 0; i < sz; i++)
    {
	nb += snprintf(*help + nb, LOG_BUF_SIZE - nb, "%s%s", i > 0 ? sep : "", tbl[i].str);
    }
    return NUMIVAL;
}

/*	Convert signal name to signal number */
int		sigv(glob_t *g, const char *s, int ln)
{
    /* If you change this table, also update apply_conf()'s array */
    static sconvi_t	tbl[] = {
	{ "USR1",	SIGUSR1	},
	{ "USR2",	SIGUSR2	},
	{ "HUP",	SIGHUP	},
	{ "SIGUSR1",	SIGUSR1	},
	{ "SIGUSR2",	SIGUSR2	},
	{ "SIGHUP",	SIGHUP	}
    };
    char	*help = NULL;
    int		val, i;

    /*
     *	Ugly hack (with sigstr()) to reverse convert number to name
     */
    if (*s == '\0')
    {
	for (i = 0; i < sizeof tbl / sizeof tbl[0]; i++)
	{
	    if (ln == tbl[i].val)
	    {
		/* ln is sig */
		strcpy((char *)s, tbl[i].str);
		return ln;	/* found */
	    }
	}
	return NUMIVAL;
    }

    /*	Standard use */
    if ((val = stoi(tbl, sizeof tbl / sizeof tbl[0], s, &help, ", ")) != NUMIVAL)
	return val;

    g->cfgerr = ERR_CFG_SIG;
    warn("unknown signal name \"%s\" at line %d of %s\nKnown signal values: %s",
	s, ln, g->cfg_path, help);

    return NUMIVAL;
}

/*	Ugly hack to convert signal number to signal name */
char		*sigstr(glob_t *g, int sig)
{
    static char	def[16];

    def[0] = '\0';
    /* The uglyness of the hack appears in the mandatory cast below */
    if (sigv(g, (const char *)&def, sig) != sig)
	snprintf(def, sizeof def, "sig%d", sig);

    return def;
}

/*
 *  Parse config file (called at init and config reloads)
 */
bool		parse_conf(glob_t *g, int(*apply)(glob_t *, cfgval_t *), bool(*end)(glob_t *))
{
    regmatch_t	match[NB_CFGV_RESUBS], *mp = &match[1];
#ifdef CFG_IVALS
    cfgval_t	nv[NB_CFGVARS] = CFG_IVALS;
#else
    cfgval_t	nv[NB_CFGVARS];
#endif
    cfgvar_t	*vp;
    char	cfgfile[NAME_MAX];
    char	**lines;
    char	*buf, *p;
    int		nl, ln, iv, err, n;

    trace(TL_CONF, "reading config from %s", g->cfg_path);
    if ((buf = getfile(g->cfg_path, NULL)) == NULL)	/* free: before parse_conf() return */
    {
	error(errno, "cannot read %s", g->cfg_path);
	return false;
    }
    strcpy(cfgfile, base_name(g->cfg_path));

    /* count lines */
    nl = 0;
    for (p = buf; *p != '\0'; p++)
    {
	if (*p == '\n')
	    nl++;
    }
    if (nl == 0)
    {
	error(0, "config file %s has no newline characters ??", g->cfg_path);
	xfree(buf);
	return false;
    }

    /*
     *	Split file into a lines array
     *
     *	Note that we NEED nl + 2 elements in this array:
     *  1st extra for the '\0' terminating buf and
     *	2nd extra for the final NULL returned by strsep
     */
    lines = xmalloc((nl + 2) * sizeof *lines);	/* free: before parse_conf() return */
    ln = 0;
    p = buf;
    while ((lines[ln] = strsep(&p, "\n")) != NULL)
    {
	if (ln <= nl)
	    ln++;
	else
	    warn("more lines than %d counted in file %s ? Ignoring...", nl, g->cfg_path);
    }

    /*
     *	Parse file into new values array 'nv'
     */
#ifndef CFG_IVALS
    /*
     *  If CFG_IVALS (ConFiG Initial VALueS) is undefined,
     *  initialize our nv array with these default values
     */
    for (iv = 0; iv < NB_CFGVARS; iv++)
    {
	if (g->config[iv].isint)
	    nv[iv].i = NUMIVAL;
	else
	    nv[iv].s = STRIVAL;
    }
#endif
    /*
     *  For every line in config-file
     */
    for (ln = 0; ln < nl; ln++)
    {
	/* Ignore empty or comment-only lines */
	if (lines[ln][0] == '\0' || lines[ln][0] == '#')
	    continue;

	/*
	 *  Look for all known cfgvar names
	 *  If var already defined earlier in file, tell it
	 */
	for (iv = 0; iv < NB_CFGVARS; iv++)
	{
	    vp = &g->config[iv];
	    if ((err = regexec(&vp->regexp, lines[ln], NB_CFGV_RESUBS, match, 0)) == 0)	/* Match ! */
	    {
		xasprintf(&p, "%.*s", mp->rm_eo - mp->rm_so, lines[ln] + mp->rm_so);	/* free: just below */
		if (vp->isint)	/* Integer value */
		{
		    n = *p != '\0' ? vp->icv(g, p, ln) : NUMIVAL;	/* Call integer conversion */
		    if (g->cfgerr  > 0)
		    {
			g->cfgerr = 0;
			break;		/* match ok, but bad value: move to next line  */
		    }
		    xfree(p);	/* not needed for integer */

		    if (nv[iv].i != NUMIVAL)
			notice("in %s line %d, %s redefined: %d -> %d",
			    cfgfile, 1 + ln, vp->name, nv[iv].i, n);
		    else
			trace(TL_CONF, "in %s line %d: %s = %d", cfgfile, 1 + ln, vp->name, n);

		    vp->line = ln;
		    nv[iv].i = n;
		}
		else		/* String value */
		{
		    if (nv[iv].s != STRIVAL)
		    {
			notice("in %s line %d, %s redefined: \"%s\" -> \"%s\"",
			    cfgfile, 1 + ln, vp->name, nv[iv].s, p);
			xfree(nv[iv].s);	/* free: defined again */
		    }
		    else
			trace(TL_CONF, "in %s line %d: %s = \"%s\"", cfgfile, 1 + ln, vp->name, p);

		    vp->line = ln;
		    nv[iv].s = p;
		}
		break;	/* Found */
	    }
	    else if (err != REG_NOMATCH)
		warn("parse error in %s line %d for %s: %s",
		    cfgfile, 1 + ln, vp->name, re_err(&vp->regexp, err));
	}
	if (iv >= NB_CFGVARS)
	    trace(TL_CONF, "no match in %s line %d \"%s\"", cfgfile, 1 + ln, lines[ln]);
    }
    xfree(lines);
    xfree(buf);		/* from getfile() */

    /*
     *	Call our apply function, which can access
     *	both the old and the new config values
     */
    if (apply != NULL && apply(g, nv) < 0)
	return false;

    /*
     *	Last, loop on cfgvars for updatable / defaults
     */
    for (iv = 0; iv < NB_CFGVARS; iv++)
    {
	vp = &g->config[iv];
	if (vp->isint)
	{
	    bool	upd = false;

	    n = nv[iv].i != NUMIVAL ? nv[iv].i : vp->def.i;
	    if (vp->val.i == NUMIVAL || vp->isupd)
	    {
#if 0
		if (vp->val.i != NUMIVAL)	/* it's an update */
		{
		    if (n != vp->val.i)		/* value changed */
		    {
			;	/* do what would be needed */
		    }
		}
#endif
		vp->val.i = n;
		upd = true;
	    }
	    else if (n != vp->val.i)
		notice("config %s will only be updated from %d to %d at %s restart",
		    vp->name, vp->val.i, n, g->prg);

	    /* will show old (and kept) value if not set */
	    trace(TL_CONF, "config['%s'] %s= %d", vp->name, upd ? "" : "!", vp->val.i);
	}
	else
	{
	    bool	upd = false;

	    p = nv[iv].s != STRIVAL ? nv[iv].s : vp->def.s;
	    if (vp->val.s == STRIVAL || vp->isupd)
	    {
		if (vp->val.s != STRIVAL)	/* it's an update */
		{
#if 0
		    if (strcmp(vp->val.s, p) != 0)	/* value changed */
		    {
			;	/* do what would be needed */
		    }
#endif
		    xfree(vp->val.s);		/* free the old value */
		}
		vp->val.s = xstrdup(p);
		upd = true;
	    }
	    else if (strcmp(vp->val.s, p) != 0)
		notice("config %s will only be updated from \"%s\" to \"%s\" at %s restart",
		    vp->name, vp->val.s, p, g->prg);

	    /* will show old (and kept) value if not set */
	    trace(TL_CONF, "config['%s'] %s= \"%s\"", vp->name, upd ? "" : "!", vp->val.s);
	}
    }
    return end(g);
}

/*
 *=====	Parse command line and check paths =============================
 */
void		parse_args(glob_t *g, int ac, char **av)
{
    char	real[PATH_MAX];
    char	*path, *exe, *p;

    exe = NULL;
    if (av[0][0] != '/')
    {
	char	*name = "/proc/self/exe";

	if (realpath(av[0], real) == NULL)
	{
	    if ((exe = getfile(name, NULL)) == NULL)	/* free: just below */
		errexit(EX_PATH, errno, "cannot read file %s ?", name);
	    path = exe;
	}
	else
	    path = real;
    }
    else
	path = av[0];

    if ((p = strrchr(path, '/')) == NULL)
	errexit(EX_LOGIC, 0, "no '/' in program path %s ??", path);
    xasprintf(&g->prg_dir, "%.*s", p - path, path);	/* free: never (init) */
    g->prg = xstrdup(++p);
    if (exe != NULL)
	xfree(exe);				/* free from getfile() */

    trace(TL_CONF, "prg=% prg_dir=%s", g->prg, g->prg_dir);
}

/*
 *=====	Main scan ======================================================
 */
time_t		invalid_sess(glob_t *g, char *file, struct stat *stp)
{
    struct stat	st;
    time_t	now;

    if (stp == NULL)
    {
	if (stat(file, &st) < 0)
	{
	    error(errno, "cannot stat %s", file);
	    return 0;
	}
	stp = &st;
    }

    /* file size must be at least SessMinSize */
    if (stp->st_size < g->SessMinSize)
	return 0;

    /* file mtime must be less than SessMaxAge old */
    now = time(NULL);
    if ((now - stp->st_mtime) > g->SessMaxAge)
	return 0;

    return stp->st_mtime;
}

int		find_session(glob_t *g, char *name)
{
    sess_t	*sp;
    int		i;

    for (i = 0; i < g->MaxActive; i++)
    {
	sp = &g->sessions[i];

	if (sp->name[0] == '\0')
	{
	    if (name == NULL)
		return i;
	    continue;
	}
	if (name != NULL && strcmp(sp->name, name) == 0)
	    return i;
    }
    return -1;
}

bool		active_session(glob_t *g, char *file)
{
    char	*sess, *ptr, *p;
    int		len, nn;

    if ((sess = getfile(file, &len)) == NULL)
    {
	error(errno, "cannot read %s", file);
	return false;
    }
    nn = 0;
    ptr = sess;
    while ((p = memchr(ptr, '\0', len)) != NULL)
    {
	len -= p + 1 - ptr;
	if (len > 0)
	{
	    *p = ' ';
	    ptr = p + 1;
	    nn++;
	}
	else
	    break;
    }
    if (nn > 0)
	trace(TL_EVNT, "replaced %d NULs from %s with spaces", nn, file);
    p = strstr(sess, g->ActiveStr);
    xfree(sess);

    return p != NULL;
}

void		add_session(glob_t *g, char *name, time_t mtime)
{
    sess_t	*sp;
    int		i;

    if ((i = find_session(g, NULL)) < 0)
    {
	warn("no more sessions (max=%d)", g->MaxActive);
    }
    sp = &g->sessions[i];
    snprintf(sp->name, sizeof sp->name, name);
    sp->mtime = mtime;
}

int		delete_session(glob_t *g, char *name)
{
    int		i;

    if ((i = find_session(g, name)) >= 0)
	g->sessions[i].name[0] = '\0';

    return i;
}

void		scan_dir(glob_t *g)
{
    DIR		*dp;
    dent_t	*ep;
    time_t	mtime;
    int		nbf = 0, nbs = 0, nbr = 0, nba = 0;

    if ((dp = opendir(".")) != NULL)
    {
	while ((ep = readdir(dp)) != NULL)
	{
	    if (ep->d_type != DT_REG)
		continue;
	    nbf++;
	    /* 'name' must start with "sess_" */
	    if (strlen(ep->d_name) <= g->pfx_len || strncmp(ep->d_name, g->SessPrefix, g->pfx_len) != 0)
		continue;
	    nbs++;
	    if ((mtime = invalid_sess(g, ep->d_name, NULL)) == 0)
		continue;
	    nbr++;
	    if (active_session(g, ep->d_name))
	    {
		add_session(g, ep->d_name + g->pfx_len, mtime);
		nba++;
	    }
	}
	closedir(dp);
    }
    trace(TL_INOT, "%d files, %d session, %d recent/big enough, %d active", nbf, nbs, nbr, nba);
}

bool		setup_loop(glob_t *g)
{
    if (chdir(g->SessDir) < 0)
    {
	error(errno, "chdir %s", g->SessDir);
	return false;
    }
    info("Watching directory \"%s\"", g->SessDir);

    if ((g->ifd = inotify_init()) < 0)
    {
	error(errno, "inotify_init");
	return false;
    }
    if ((g->iwd = inotify_add_watch(g->ifd, ".", IN_MODIFY|IN_DELETE)) < 0)
    {
	error(errno, "inotify_add_watch \".\"");
	return false;
    }
    if (g->sessions == NULL)
	g->sessions = xmalloc(g->MaxActive * sizeof(sess_t));

    scan_dir(g);
    g->loop = 1;

    return true;
}

void		handle_events(glob_t *g, timeval_t *timeout)
{
    fd_set	readfd;
    ivent_t	 *evp;
    struct stat	st;
    time_t	mtime;
    char	evbuf[512], *file;
    int		ret, evn;

    trace(TL_EVNT, "left=%d.%03d", timeout->tv_sec, timeout->tv_usec / 1000);
    FD_ZERO(&readfd);
    FD_SET(g->ifd, &readfd);
    if ((ret = select(g->ifd + 1, &readfd, NULL, NULL, timeout)) < 0)
    {
	trace(TL_INOT, "select errno=%d", errno);
	if (errno == EINTR)
	{
	    if (g->sig == 0)
		error(0, "select interrupted with no signal ?");
	}
	else
	    error(errno, "select");
    }
    else if (ret > 0)
    {
	evp = (ivent_t *)evbuf;
	if ((evn = read(g->ifd, evbuf, sizeof evbuf)) >= (int)(sizeof *evp))
	{
	    file = evp->len > 0 ? evp->name : "";
	    trace(TL_EVNT, "wd=%d mask=0x%x len=%d file=\"%s\"", evp->wd, evp->mask, evp->len, file);
	    if ((evp->mask & IN_MODIFY))
	    {
		if (evp->len <= 0)
		    error(0, "mask=0x%08X MODIFY no file ?", evp->mask);
		else if (stat(file, &st) < 0)
		    error(errno, "mask=0x%08X MODIFY cannot stat \"%s\"", evp->mask, file);
		else if ((mtime = invalid_sess(g, file, &st)) > 0)
		{
		    trace(TL_EVNT, "checking if MODIFY file %s size=%d mtime=%s is active", file, st.st_size, tstamp(mtime, " "));
		    if (active_session(g, file))
		    {
			add_session(g, file + g->pfx_len, mtime);
			return;
		    }
		}
		trace(TL_EVNT, "ignoring MODIFY file %s size=%d mtime=%s", file, st.st_size, hstamp(mtime));
	    }
	    if ((evp->mask & IN_DELETE))
	    {
		if (evp->len <= 0)
		    error(0, "mask=0x%08X DELETE no file ?", evp->mask);
		else if (strlen(file) > g->pfx_len && strncmp(file, g->SessPrefix, g->pfx_len) == 0)
		{
		    int i = delete_session(g, file + g->pfx_len);
		    trace(TL_EVNT, "deleting %s file (%sin active list)", file, i < 0 ? "NOT " : "");
		}
		else
		    trace(TL_EVNT, "ignoring DELETE file %s", file);
	    }
	}
	else if (evn < 0)
	    error(errno, "read ifd=%d", g->ifd);
    }
}

void		watch_sessions(glob_t *g)
{
    timeval_t	now, freq, next, left;

    trace(TL_EVNT, "freq=%d", g->ReportFreq);
    if (gettimeofday(&now, NULL) < 0)
    {
	error(errno, "gettimeofday");
	sleep(g->ReportFreq);
	return;
    }
    freq.tv_sec = g->ReportFreq;
    freq.tv_usec = 0;
    timeradd(&now, &freq, &next);
    while (timercmp(&now, &next, <) > 0)
    {
	timersub(&next, &now, &left);
	handle_events(g, &left);
	if (gettimeofday(&now, NULL) < 0)
	{
	    error(errno, "gettimeofday");
	    timersub(&next, &now, &left);
	    sleep(g->ReportFreq - left.tv_sec);
	    return;
	}
    }
}

void		report_sessions(glob_t *g)
{
    time_t	now = time(NULL);
    sess_t	*sp;
    int		i, nb = 0;

    trace(TL_EVNT, "freq=%d", g->ReportFreq);
    for (i = 0; i < g->MaxActive; i++)
    {
	sp = &g->sessions[i];
	if (sp->name[0] == '\0')
	    continue;
	if ((now - sp->mtime) > g->SessMaxAge)
	    sp->name[0] = '\0';
	else
	    nb++;
    }
    printf("%d\n", nb);
    if (ferror(stdout))
	errexit(EX_PIPE, errno, "cannot write number-of-PHP-sessions (%d)", nb);
}

/*
 *=====	Program start and end functions ================================
 */
void 		trap_sig(int sig)
{
    info("received signal %s", sigstr(&globals, sig));
    globals.sig = sig;
}

/*
 *  Two tasks in this function:
 *	1: on parse_conf at init, check config values
 *	2: at startup (nv = NULL), apply config values
 *	3: on parse_conf at config-reload, update config values
 */
int		apply_conf(glob_t *g, cfgval_t *nv)
{
    /* If you change this array, also update sigv()'s table */
    struct trap {
	int	sig;
	void	(*def)(int);
    } 		traps[] = {
			{ SIGHUP,  SIG_IGN },
			{ SIGUSR1, SIG_DFL },
			{ SIGUSR2, SIG_DFL }
    };
    char	*newDir;
    int		i, newRld;

    /*
     *	Handle Reload signal setup/update
     */
    if (nv != NULL)	/* task 1 */
    {
	newDir = ValSessDir(nv) != STRIVAL ? ValSessDir(nv) : g->DefSessDir;

	if (access(newDir, R_OK|X_OK) != 0)	/* SessDir not usablae */
	{
	    char    refDir[32];

	    if (g->RefSessDir > 0)
		snprintf(refDir, sizeof refDir, "line %d", g->RefSessDir);
	    else
		strcpy(refDir, "default");

	    if (g->SessDir == STRIVAL)
	        errexit(EX_CONF, 0, "in file %s, %s (%s) value \"%s\" is not a usable directory",
		    g->cfg_path, g->VarSessDir, refDir, newDir);
	}
	if (g->SessDir == STRIVAL)	/* task 1 check completed */
	    return 0;

	/* task 3: apply update */
	newRld = ValReload(nv) != NUMIVAL ? ValReload(nv) : g->DefReload;
	if (newRld == g->SigReload)
		return 0;	/* No change needed in sig setup */

	/*  If newRld was not already setup, set it up */
	if (newRld != g->SigReload)
	{
	    signal(newRld, trap_sig);
	    siginterrupt(newRld, 1);
	}
	/* Set any other sig back to default */
	for (i = 0; i < sizeof traps / sizeof(struct trap); i++)
	{
	    if (traps[i].sig != newRld)
	    {
		signal(traps[i].sig, traps[i].def);
		siginterrupt(traps[i].sig, 0);
	    }
	}
	return 0;
    }
    /* task 2: apply setup */
    for (i = 0; i < sizeof traps / sizeof(struct trap); i++)
    {
	if (traps[i].sig != g->SigReload)
	    signal(traps[i].sig, traps[i].def);
    }
    signal(g->SigReload, trap_sig);
    siginterrupt(g->SigReload, 1);

    return 0;
}

bool		set_glob(glob_t *g)
{
    /*
     *	Propagate config value to globals
     */
    g->pfx_len = strlen(g->SessPrefix);

    return true;
}

void 		terminate(int sig)
{
    info("received SIGTERM");
    globals.sig = sig;
    globals.loop = 0;	/* exit on SIGTERM */
}

int		main(int ac, char **av)
{
    glob_t	*g = &globals;

    parse_args(g, ac, av);
    conf_init(g);
    get_cfgpath(g);
    //g->TraceLevel = 15;
    if (!parse_conf(g, apply_conf, set_glob))
	return EX_CONF;

    info("----------------------------------------");
    info("Starting %s PID=%d - Reload sig is %s", g->prg, getpid(), sigstr(g, g->SigReload));

    if (!isatty(fileno(stdin)))
    {
	signal(SIGINT, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
    }
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, terminate);
    siginterrupt(SIGTERM, 1);
    apply_conf(g, NULL);

    setlinebuf(stdout);
    setup_loop(g);
    g->loop = 1;

    while (g->loop)
    {
	report_sessions(g);
	watch_sessions(g);

	if (g->sig > 0)
	{
	    if (g->sig == g->SigReload)
	    {
		if (parse_conf(g, apply_conf, set_glob))
		{
		    close(g->iwd);
		    close(g->ifd);
		    g->sessions = xfree(g->sessions);
		    setup_loop(g);
		}
	    }
	    g->sig = 0;
	}
    }
    info("exit from main loop (=%d)", g->loop);

    return EX_OK;
}
