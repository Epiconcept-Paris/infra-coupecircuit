/*
 *  sesswatch.c (prototype of nbphpsess.c)
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
#include <sys/inotify.h>
#if 0
#endif

/* Exit codes */
#define EX_OK		0
#define EX_USAGE	1
#define EX_CONF		2
#define EX_PATH		3

#define EX_INOT		4

#define EX_PROG		8
#define EX_NOMEM	9

/* trace levels */
#define TL_CONF		1
#define TL_INOT		2

#define ACTIVE_PATTERN	"s:15:\"iConnectionType\";")

#define LOG_BUF_SIZE	4096

#define CFG_DEFDIR	"/etc/epiconcept"
#define CFGPATH_ENVFMT	"%s_CONF"

/* Parse regexp format (28 chr) for config (%s) values */
#define CFGVAR_REFMT	"^\\s*%s\\s*=\\s*(\\S*)\\s*(#.*)?$"
#define NB_CFGV_RESUBS	3

typedef struct dirent      dent_t;
typedef struct inotify_event ivent_t;

typedef struct	sconvi_s
{
    char	*str;
    int		val;
}		sconvi_t;

typedef union	cfgval_u
{
#   define	STRIVAL	NULL
#   define	NUMIVAL	-1
    char	*s;
    int		i;
}		cfgval_t;

struct	glob_s;	/* Needed for forward ref in cfgvar_t below */

typedef struct	cfgvar_s
{
    char	*name;
    short	isupd;		/* 1 if var updatable on reloads */
    short	isint;		/* 1 if var is int (vs str) */
    int		(*icv)(struct glob_s *, const char *, int);	/* function to convert to int */
    cfgval_t	val;		/* value */
    cfgval_t	def;		/* default */
    regex_t	regexp;		/* compiled regexp for config parsing */
}		cfgvar_t;

typedef struct	sess_s
{
    char	name[40];
    time_t	mtime;
}		sess_t;

typedef	struct	glob_s
{
#define NB_CFGVARS	5
    cfgvar_t	config[NB_CFGVARS];	/* Must be 1st member for init */

    char	*prg;		/* basename from av[0] */
    char	*prg_dir;

    char	*cfg_path;

    int		ifd;
    int		iwd;

    sess_t	*sessions;
    int		nb_sess;

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

/*	When adding to the config variables below, don't forget to:
 *	  - update the NB_CFGVARS macro in glob_t definition above
 *	  - add default values to the CFG_IVALS macro below
 */
#	define SessDir		config[0].val.s
#	define ReportFreq	config[1].val.i
#	define StaleDelay	config[2].val.i
#	define SigReload	config[3].val.i
#	define TraceLevel	config[4].val.i
#	define TlvConv		config[4].icv
#	define CFG_IVALS	{ \
	{.s=STRIVAL},\
	{.i=NUMIVAL},\
	{.i=NUMIVAL},\
	{.i=NUMIVAL},\
	{.i=NUMIVAL}\
    }
    {
	{ "sess_dir",		1, 0, NULL, { .s = STRIVAL },	{ .s = "/var/lib/php/sessions" }, {} },
	{ "report_freq",	1, 1, intv, { .i = NUMIVAL },	{ .i = 3 },		{} },
	{ "stale_delay",	1, 1, intv, { .i = NUMIVAL },	{ .i = 1800 },		{} },
	{ "conf_reload_sig",	1, 1, sigv, { .i = NUMIVAL },	{ .i = SIGUSR1 },	{} },
	{ "dtrace_level",	1, 1, intv, { .i = NUMIVAL },	{ .i = 0 },		{} }
    },
    NULL, NULL, NULL, -1, -1
};

/*
 *  Log and trace macros
 *
 *	info("pid=%d sd=%d net write=0", s->pid, s->netsd);
 *	trace(TL_T1, "output_fd=%d", e->output_fd);
 *	error(errno, "pid=%d sd=%d net write", s->pid, s->netsd);
 *	error(0, "discarding invalid IAC 0x%X", p[1]);
 */
#define info(f,a...)		logmsg(0,__FUNCTION__,__LINE__,"",f,##a)
#define notice(f,a...)		logmsg(0,__FUNCTION__,__LINE__,"NOTICE: ",f,##a)
#define warn(f,a...)		logmsg(0,__FUNCTION__,__LINE__,"WARNING: ",f,##a)
#define report(f,a...)		logmsg(0,__FUNCTION__,__LINE__,"REPORT: ",f,##a)
#define error(e,f,a...)		logmsg(e,__FUNCTION__,__LINE__,"ERROR: ",f,##a)

#define errexit(x,e,f,a...)	xitmsg(x,e,__FUNCTION__,__LINE__,f,##a)

#define trace(l,f,a...)		trcmsg(l,__FUNCTION__,__LINE__,f,##a)
/*
 * ====	Logging and tracing functions ==================================
 */
char		*tstamp(time_t t, char *sep)
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
void		logline(int syserr, const char *fn, int ln, char *tag, char *msg)
{
    FILE	*fp = stderr;

    fp = stderr;
    if (*msg != '\\')
    {
	if (*tag != '\0')
	    fprintf(fp, "%s\t%s%s", tstamp(0, " "), tag, msg);
	else
	    fprintf(fp, "%s\t%s", tstamp(0, " "), msg);
    }
    else
	fputs(msg + 1, fp);

    if (syserr > 0)
	fprintf(fp, ": %s (errno=%d)\n", strerror(syserr), syserr);
    else
	fputs("\n", fp);
    fflush(fp);
}

void		logmsg(int syserr, const char *fn, int ln, char *tag, char *fmt, ...)
{
    va_list	ap;
    char	buf[LOG_BUF_SIZE];
    char	*line, *p;
    int		first = true;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (buf[0] != '\0')
    {
	p = buf;
	while ((line = strsep(&p, "\r\n")) != NULL)
	{
	    if (*line != '\0')
	    {
		logline(first ? syserr : 0, fn, ln, first ? tag : "    ", line);
		first = false;
	    }
	}
    }
}

void		xitmsg(int xcode, int syserr, const char *fn, int ln, char *fmt, ...)
{
    va_list	ap;
    char	buf[LOG_BUF_SIZE];
    char	*line, *p;
    int		first = true;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (buf[0] != '\0')
    {
	p = buf;
	while ((line = strsep(&p, "\r\n")) != NULL)
	{
	    if (*line != '\0')
	    {
		logline(first ? syserr : 0, fn, ln, first ? "" : "    ", line);
		first = false;
	    }
	}
    }
    exit(xcode);
}

void		trcmsg(int level, const char *fn, int ln, char *fmt, ...)
{
    va_list	ap;
    char	buf[LOG_BUF_SIZE];
    char	*line, *p;
    int		first = true;

    if (globals.TraceLevel < 0 || (level & globals.TraceLevel) == 0)
	return;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (buf[0] != '\0')
    {
	p = buf;
	while ((line = strsep(&p, "\r\n")) != NULL)
	{
	    if (*line != '\0')
	    {
		logline(0, fn, ln, first ? "" : "    ", line);
		first = false;
	    }
	}
    }
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
 *  Return a pointer to 'path' file's content and its len in *plen;
 *  If error or file empty, return NULL
 */
char		*getfile(char *path)
{
    struct stat	st;
    int		fd, len;
    char	*p = NULL;

    if ((fd = open(path, O_RDONLY)) < 0)
	return NULL;
    if (fstat(fd, &st) < 0)
	return NULL;
    len = st.st_size;
    if (len > 0)
    {
	p = xmalloc(len + 1);	/* free: in getfile() caller */
	if (read(fd, p, len) < len)
	    p = xfree(p);
	else
	    p[len] = '\0';
    }
    close(fd);

    return p;
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
	    errexit(EX_PROG, 0, "regcomp error for %s: %s", vp->name, re_err(&vp->regexp, err));
	if (vp->regexp.re_nsub != (NB_CFGV_RESUBS - 1))
	    errexit(EX_PROG, 0, "regcomp requires %d matches for %s", vp->regexp.re_nsub + 1, vp->name);
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
    char	env_var[32];
    char	path[PATH_MAX];
    char	*p;
    int		i;

    /* Make variable name */
    if (snprintf(env_var, sizeof env_var, CFGPATH_ENVFMT, g->prg) >= sizeof env_var)
	errexit(EX_CONF, 0, "cannot make configuration file env variable");
    for (i = 0; i < strlen(g->prg); i++)
	env_var[i] = toupper(env_var[i]);
    //trace(TL_CONF, "env_var = %s", env_var);
    info("env_var = %s", env_var);

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
    errexit(EX_CONF, 0, "cannot find config-file %s.conf in env, %s or in " CFG_DEFDIR, g->prg, g->prg_dir);
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
		errexit(EX_CONF, 0, "non-numeric character '%c' in value at line %d of %s", *p, ln, g->cfg_path);
	    else
		errexit(EX_CONF, 0, "non-numeric character '%c' in value \"%s\"", *p, s);
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

    /* Not founf: build help text for values */
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
    sconvi_t	tbl[] = {
	{ "SIGHUP",	SIGHUP	},
	{ "SIGUSR1",	SIGUSR1	},
	{ "SIGUSR2",	SIGUSR2	},
	{ "HUP",	SIGHUP	},
	{ "USR1",	SIGUSR1	},
	{ "USR2",	SIGUSR2	}
    };
    char	*help = NULL;
    int		val;

    if ((val = stoi(tbl, sizeof tbl / sizeof tbl[0], s, &help, ", ")) != NUMIVAL)
	return val;
    errexit(EX_CONF, 0, "unknown signal name \"%s\" at line %d of %s\nKnown signal values: %s", s, ln, g->cfg_path, help);
    return NUMIVAL;
}

/*
 *  Parse config file (called at init and config reloads)
 */
int		parse_conf(glob_t *g)
{
    regmatch_t	match[NB_CFGV_RESUBS], *mp = &match[1];
#ifdef CFG_IVALS
    cfgval_t	nv[NB_CFGVARS] = CFG_IVALS;
#else
    cfgval_t	nv[NB_CFGVARS];
#endif
    cfgvar_t	*vp;
    char	**lines;
    char	*buf, *p;
    int		ret = 0, nl, ln, iv, err, n;

    get_cfgpath(g);

    trace(TL_CONF, "Reading config from %s", g->cfg_path);
    if ((buf = getfile(g->cfg_path)) == NULL)	/* free: before parse_conf() return */
	errexit(EX_CONF, errno, "cannot read %s", g->cfg_path);

    /* count lines */
    nl = 0;
    for (p = buf; *p != '\0'; p++)
    {
	if (*p == '\n')
	    nl++;
    }
    if (nl == 0)
	errexit(EX_CONF, 0, "config file %s has no newline characters ??", g->cfg_path);

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
    for (iv = 0; iv < NB_CFGVARS; iv++)
    {
	if (g->config[iv].isint)
	    nv[iv].i = NUMIVAL;
	else
	    nv[iv].s = STRIVAL;
    }
#endif
    for (ln = 0; ln < nl; ln++)
    {
	if (lines[ln][0] == '\0' || lines[ln][0] == '#')
	    continue;	/* empty or comment line */

	/*
	 *  Look for all known cfgvar names
	 */
	for (iv = 0; iv < NB_CFGVARS; iv++)
	{
	    vp = &g->config[iv];
	    if ((err = regexec(&vp->regexp, lines[ln], NB_CFGV_RESUBS, match, 0)) == 0)
	    {
		xasprintf(&p, "%.*s", mp->rm_eo - mp->rm_so, lines[ln] + mp->rm_so);	/* free: just below */
		if (vp->isint)
		{
		    n = vp->icv(g, p, ln);

		    xfree(p);	/* not needed for integer */
		    if (nv[iv].i != NUMIVAL)
			notice("in %s line %d, %s redefined: %d -> %d", g->cfg_path, 1 + ln, vp->name, nv[iv].i, n);
		    else
			trace(TL_CONF, "in %s line %d: %s = %d", g->cfg_path, 1 + ln, vp->name, n);
		    nv[iv].i = n;
		}
		else
		{
		    if (nv[iv].s != STRIVAL)
		    {
			notice("in %s line %d, %s redefined: \"%s\" -> \"%s\"", g->cfg_path, 1 + ln, vp->name, nv[iv].s, p);
			xfree(nv[iv].s);	/* free: defined again */
		    }
		    else
			trace(TL_CONF, "in %s line %d: %s = \"%s\"", g->cfg_path, 1 + ln, vp->name, p);
		    nv[iv].s = p;
		}
		break;	/* Found */
	    }
	    else if (err != REG_NOMATCH)
		warn("parse error in %s line %d for %s: %s", g->cfg_path, 1 + ln, vp->name, re_err(&vp->regexp, err));
	}
	if (iv >= NB_CFGVARS)
	    trace(TL_CONF, "no match in %s line %d \"%s\"", g->cfg_path, 1 + ln, lines[ln]);
    }
    xfree(lines);
    xfree(buf);		/* from getfile() */

    /*
     *	One last loop on cfgvars for updatable / defaults
     */
    for (iv = 0; iv < NB_CFGVARS; iv++)
    {
	vp = &g->config[iv];
	if (vp->isint)
	{
	    n = nv[iv].i != NUMIVAL ? nv[iv].i : vp->def.i;
	    if (vp->val.i == NUMIVAL || vp->isupd)
		vp->val.i = n;
	    else if (nv[iv].i == NUMIVAL || vp->val.i != nv[iv].i)
		notice("config %s will only be updated to %d at %s restart", vp->name, n, g->prg);
	    trace(TL_CONF, "config['%s'] = %d", vp->name, vp->val.i);
	}
	else
	{
	    p = nv[iv].s != STRIVAL ? nv[iv].s : vp->def.s;
	    if (vp->val.s == STRIVAL || vp->isupd)
	    {
		if (vp->val.s != STRIVAL)
		{
		    if (strcmp (vp->val.s, p) != 0)	/* value changed */
		    {
			if (strcmp(vp->name, "sess_dir") == 0)
			{
			    info("sess_dir changed from \"%s\" to \"%s\"", vp->val.s, p);
			    ret = 1;
			}
		    }
		    xfree(vp->val.s);
		}
		vp->val.s = xstrdup(p);
	    }
	    else if (nv[iv].s == STRIVAL || strcmp(vp->val.s, nv[iv].s) != 0)
		notice("config %s will only be updated to \"%s\" at %s restart", vp->name, p, g->prg);
	    trace(TL_CONF, "config['%s'] = \"%s\"", vp->name, vp->val.s);
	}
    }
    return ret;
}

/*
 *=====	Parse command line and check paths =============================
 */
void		parse_args(glob_t *g, int ac, char **av)
{
    char	*exe, *p;

    exe = getfile("/proc/self/exe");	/* free: just below */
    if ((p = strrchr(av[0], '/')) != NULL)
    {
	xasprintf(&g->prg_dir, "%.*s", p - av[0], av[0]);	/* free: never (init) */
	g->prg = ++p;
    }
    else
    {
	g->prg = av[0];
	if ((p = strrchr(exe, '/')) == NULL)
	    errexit(EX_PROG, 0, "no '/' in binary path %s ??", exe);
	xasprintf(&g->prg_dir, "%.*s", p - exe, exe);	/* free: never (init) */
    }
    xfree(exe);				/* free from getfile() */

    trace(TL_CONF, "prg=% prg_dir=%s", g->prg, g->prg_dir);
}

/*
 *=====	Main scan ======================================================
 */
int		invalid_sess(glob_t *g, char *name)
{
    struct stat	st;
    time_t	now;
    char	*p;

    /* 'name' must be 37 chr long */
    if (strlen(name) != (5 + 32))
	return 1;

    /* 'name' must start with "sess_" */
    if (strncmp(name, "sess_", 5) != 0)
	return 1;

    /* the rest of name must be hexchars */
    p = name + 5;
    while (p != '\0')
    {
	if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f')))
	    return 1;
	p++;
    }

    /* file mtime must be less than StaleDelay old */
    if (stat(name, &st) < 0)
	return 1;

    now = time(NULL);
    if ((now - st.st_mtime) > g->StaleDelay)
	return 1;

    return 0;
}

int		active_session(char *name)
{
    return 0;
}

int		add_session(glob_t *g, char *name)
{
    return 0;
}

int		del_session(glob_t *g, char *name)
{
    return 0;
}

void		scan_dir(glob_t *g)
{
    DIR		*dp;
    dent_t	*ep;

    if ((dp = opendir(".")) != NULL)
    {
	while ((ep = readdir(dp)) != NULL)
	{
	    info("name=%s", ep->d_name);
	    if (ep->d_type != DT_REG)
		continue;
	    if (invalid_sess(g, ep->d_name))
		continue;
	}
	closedir(dp);
    }
}

void		setup_loop(glob_t *g)
{
    int		 n;
#if 0
    char	buf[32];
    int		fd;

    if ((fd = open("/proc/sys/fs/inotify/max_user_watches", O_RDONLY)) < 0)
	errexit(EX_INOT, errno, "cannot open max_user_watches");

    memset(buf, '\0', sizeof buf);
    if ((n = read(fd, buf, sizeof buf)) < 2)
    {
	close(fd);
	errexit(EX_INOT, n < 0 ? errno : 0, "cannot read max_user_watches");
    }
    n = atoi(buf);
    n /= 64;
    n *= 63;
    g->nb_sess = n;
#endif
    n = 16384;
    if (g->sessions == NULL)
	g->sessions = xmalloc(sizeof(sess_t) * n);
    if (chdir(g->SessDir) < 0)
	error(errno, "chdir %s", g->SessDir);

    info("Watching directory \"%s\"", g->SessDir);

    if ((g->ifd = inotify_init()) < 0)
	errexit(EX_INOT, errno, "inotify_init");

    if ((g->iwd = inotify_add_watch(g->ifd, ".", IN_MODIFY|IN_CLOSE_WRITE|IN_CLOSE_NOWRITE|IN_OPEN|IN_CREATE|IN_DELETE)) < 0)
	errexit(EX_INOT, errno, "inotify_add_watch \".\"");

    g->loop = 1;
}

void		main_loop(glob_t *g)
{
    struct stat	st;
    ivent_t	 *evp;
    char	evbuf[512], *name;
    int		evn;

    evp = (ivent_t *)evbuf;
    while ((evn = read(g->ifd, evbuf, sizeof evbuf)) >= (int)(sizeof *evp))
    {
	name = evp->len > 0 ? evp->name : "";
	//info("wd=%d mask=0x%x len=%d name=%s\n", evp->wd, evp->mask, evp->len, name);
	if ((evp->mask & IN_MODIFY))
	{
	    if (evp->len <= 0)
		error(errno, "wd=%d mask=0x%08X MODIFY no file", evp->wd, evp->mask);
	    else if (stat(name, &st) < 0)
		error(errno, "wd=%d mask=0x%08X MODIFY cannot stat \"%s\"", evp->wd, evp->mask, name);
	    else
		info("wd=%d mask=0x%08X MODIFY \"%s\" size=%ld", evp->wd, evp->mask, name, st.st_size);
	}
	if ((evp->mask & IN_CLOSE_WRITE))
	{
	    if (evp->len <= 0)
		info("wd=%d mask=0x%08X CLOSE_WRITE no file", evp->wd, evp->mask);
	    else if (stat(name, &st) < 0)
		error(errno, "wd=%d mask=0x%08X CLOSE_WRITE cannot stat \"%s\"", evp->wd, evp->mask, name);
	    else
		info("wd=%d mask=0x%08X CLOSE_WRITE \"%s\" size=%ld", evp->wd, evp->mask, name, st.st_size);
	}
	if ((evp->mask & IN_CLOSE_NOWRITE))
	{
	    if (evp->len <= 0)
		info("wd=%d mask=0x%08X CLOSE_NOWRITE no file", evp->wd, evp->mask);
	    else if (stat(name, &st) < 0)
		error(errno, "wd=%d mask=0x%08X CLOSE_NOWRITE cannot stat \"%s\"", evp->wd, evp->mask, name);
	    else
		info("wd=%d mask=0x%08X CLOSE_NOWRITE \"%s\" size=%ld", evp->wd, evp->mask, name, st.st_size);
	}
	if ((evp->mask & IN_OPEN))
	{
	    if (evp->len <= 0)
		info("wd=%d mask=0x%08X OPEN no file", evp->wd, evp->mask);
	    else if (stat(name, &st) < 0)
		error(errno, "wd=%d mask=0x%08X OPEN cannot stat \"%s\"", evp->wd, evp->mask, name);
	    else
		info("wd=%d mask=0x%08X OPEN \"%s\" size=%ld", evp->wd, evp->mask, name, st.st_size);
	}
	if ((evp->mask & IN_CREATE))
	{
	    if (evp->len <= 0)
		info("wd=%d mask=0x%08X CREATE no file", evp->wd, evp->mask);
	    else if (stat(name, &st) < 0)
		error(errno, "wd=%d mask=0x%08X CREATE cannot stat \"%s\"", evp->wd, evp->mask, name);
	    else
		info("wd=%d mask=0x%08X CREATE \"%s\" size=%ld", evp->wd, evp->mask, name, st.st_size);
	}
	if ((evp->mask & IN_DELETE))
	{
	    if (evp->len <= 0)
		info("wd=%d mask=0x%08X DELETE no file", evp->wd, evp->mask);
	    else
		info("wd=%d mask=0x%08X DELETE \"%s\"", evp->wd, evp->mask, name);
	}
    }
    if (evn < 0)
	error(errno, "read ifd=%d", g->ifd);
}

/*
 *=====	Program start and end functions ================================
 */
void 		trap_sig(int sig)
{
    globals.sig = sig;
}

void 		terminate(int sig)
{
    globals.sig = sig;
    globals.loop = 0;	/* exit on SIGTERM */
}

int main(int ac, char **av)
{
    glob_t	*g = &globals;

    parse_args(g, ac, av);
    conf_init(g);
    //g->TraceLevel = 15;
    parse_conf(g);

    if (g->SigReload != SIGHUP)
	signal(SIGHUP, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, terminate);
    signal(g->SigReload, trap_sig);
    siginterrupt(SIGTERM, 1);
    siginterrupt(g->SigReload, 1);

    setup_loop(g);
    while (g->loop)
    {
	if (g->sig == g->SigReload)
	{
	    if (parse_conf(g) > 0)
		close(g->ifd);
		setup_loop(g);
	}
	main_loop(g);
    }
    return EX_OK;
}
