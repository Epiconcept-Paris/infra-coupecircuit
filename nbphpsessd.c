/*
 *	nbphpsessd.c
 *
 *	- become daemon
 *	- Setup av[1] and av[2] connected by pipes
 *	- Connect stderr of av[1] and av[2] to log-file
 *	- optional report-file connected to fd=2 (av[1]) and fd=1,2 (av[2])
 *	- Main loop: wait for log, subproc and signals
 *
 *	- watch and restart both av[1] and av[2] if any dies
 *	- kill them both if SIGTERM, pass on SIGUSR1 (session ?)
 */
#define _GNU_SOURCE
#define _BSD_SOURCE
#define _POSIX_SOURCE

#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <regex.h>
#include <signal.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/wait.h>
#if 0
#endif

/* Exit codes */
#define EX_OK		0
#define EX_USAGE	1
#define EX_CONF		2
#define EX_PATH		3

#define EX_PIPE		4
#define EX_FORK		5
#define EX_EXEC		6

#define EX_PROG		8
#define EX_NOMEM	9

/* trace levels */
#define TL_1		1
#define TL_2		2
#define TL_3		4
#define TL_CONF		8

#define NB_CHILDREN	2
#if NB_CHILDREN != 2
#error "This program is designed for 2 children"
#endif

#define LOG_BUF_SIZE	4096

#define CFG_DEFDIR	"/etc/epiconcept"
#define CFGPATH_ENVFMT	"%s_CONF"

/* Parse regexp format (28 chr) for config (%s) values */
#define CFGVAR_REFMT	"^\\s*%s\\s*=\\s*(\\S*)\\s*(#.*)?$"
#define NB_CFGV_RESUBS	3

typedef struct timeval timeval_t;

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

typedef struct	child_s
{
    char	*arg;		/* from commande line */
    char	*path;		/* actual exec path */
    char	*name;		/* basename */
    pid_t	pid;
    time_t	kill_time;
    FILE	*out_fp;
    FILE	*err_fp;
}		child_t;

typedef	struct	glob_s
{
#define NB_CFGVARS	10
    cfgvar_t	config[NB_CFGVARS];	/* Must be 1st member for init */

    char	*prg;		/* basename from av[0] */
    char	*prg_dir;
    char	*pkg;		/* our package name (final 'd' removed) */

    time_t	p_start;
    child_t	children[NB_CHILDREN];

    char	*log_path;
    char	*rep_path;
    FILE	*log_fp;
    FILE	*rep_fp;

    char	*pid_path;
    char	*cfg_path;
    char	*cfg_env;

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
int	facv(glob_t *, const char *, int);
int	lvlv(glob_t *, const char *, int);

glob_t		globals = {

/*	When adding to the config variables belon, don't forget to:
 *	  - update the NB_CFGVARS macro in glob_t definition above
 *	  - add default values to the CFG_IVALS macro below
 */
#	define BinDir		config[0].val.s
#	define LogDir		config[1].val.s
#	define RunDir		config[2].val.s
#	define SessDir		config[3].val.s
#	define LogWait		config[4].val.i
#	define TraceLevel	config[5].val.i
#	define TlvConv		config[5].icv
#	define SigReload	config[6].val.i
#	define SigRotate	config[7].val.i
#	define SyslogFac	config[8].val.i
#	define SyslogLvl	config[9].val.i
#	define CFG_IVALS	{ \
	{.s=STRIVAL},\
	{.s=STRIVAL},\
	{.s=STRIVAL},\
	{.s=STRIVAL},\
	{.i=NUMIVAL},\
	{.i=NUMIVAL},\
	{.i=NUMIVAL},\
	{.i=NUMIVAL},\
	{.i=NUMIVAL},\
	{.i=NUMIVAL}\
    }
    {
	{ "bin_dir",		0, 0, NULL, { .s = STRIVAL },	{ .s = "/usr/bin" },	{} },
	{ "log_dir",		0, 0, NULL, { .s = STRIVAL },	{ .s = "/var/log/%s" },	{} },
	{ "run_dir",		0, 0, NULL, { .s = STRIVAL },	{ .s = "/run/%s" },	{} },
	{ "sess_dir",		1, 0, NULL, { .s = STRIVAL },	{ .s = "/var/lib/php/sessions" }, {} },
	{ "log_wait",		1, 1, intv, { .i = NUMIVAL },	{ .i = 5 },		{} },
	{ "dtrace_level",	1, 1, intv, { .i = NUMIVAL },	{ .i = 0 },		{} },
	{ "conf_reload_sig",	1, 1, sigv, { .i = NUMIVAL },	{ .i = SIGUSR1 },	{} },
	{ "log_rotate_sig",	1, 1, sigv, { .i = NUMIVAL },	{ .i = SIGUSR2 },	{} },
	{ "syslog_facility",	1, 1, facv, { .i = NUMIVAL },	{ .i = LOG_LOCAL0 },	{} },
	{ "syslog_level",	1, 1, lvlv, { .i = NUMIVAL },	{ .i = LOG_CRIT },	{} }
    }
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
char		*tstamp(char *sep)	/* Only for logline() just below */
{
    static char	buf[32];
    struct tm	*tp;
    time_t	t;

    t = time(NULL);
    tp = localtime(&t);
    snprintf(buf, sizeof buf, "%04d-%02d-%02d%s%02d:%02d:%02d",
	 tp->tm_year + 1900, tp->tm_mon + 1, tp->tm_mday, sep, tp->tm_hour, tp->tm_min, tp->tm_sec);

    return buf;
}

/*  Log line (called by logmsg(), trcmsg() and xitmsg()) */
void		logline(int syserr, const char *fn, int ln, char *tag, char *msg)
{
    FILE	*fp;

    if (globals.log_fp != NULL)
    {
	fp = globals.log_fp;
	if (*msg == '|')
	    fprintf(fp, "%s\t%s(line=%d)\t%s%s", tstamp(" "), fn, ln, tag, msg);
	else
	    fprintf(fp, "%s\t%s%s", tstamp(" "), tag, msg);
    }
    else
    {
	fp = stderr;
	if (*msg != '\\')
	{
	    if (*tag != '\0')
	    {
		if (globals.prg != NULL)
		    fprintf(fp, "%s %s%s", globals.prg, tag, msg);
		else
		    fprintf(fp, "%s%s", tag, msg);
	    }
	    else
	    {
		if (globals.prg != NULL)
		    fprintf(fp, "%s: %s", globals.prg, msg);
		else
		    fputs(msg, fp);
	    }
	}
	else
	    fputs(msg + 1, fp);
    }
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
    unlink(globals.pid_path);
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
 */
void		set_nonblock(int fd)
{
    int		arg;

    if ((arg = fcntl(fd, F_GETFL, NULL)) < 0 || fcntl(fd, F_SETFL, arg | O_NONBLOCK) < 0)
	error(errno, "fcntl");
}

void		close_onexec(int fd, int close)
{
    if (fcntl(fd, F_SETFD, close ? FD_CLOEXEC : 0) < 0)
	error(errno, "fcntl");
}

/*
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
 * ====	Process utilities ==============================================
 */
pid_t		dead_wait(char *reason)
{
    pid_t	pid;
    int		status;

    reason[0] = '\0';
    if ((pid = waitpid(-1, &status, WNOHANG)) < 0)
    {
	if (errno != ECHILD)
	    error(errno, "waitpid");
    }
    else if (pid > 0)
    {
	if (WIFSIGNALED(status))
	{
	    int  sig = WTERMSIG(status);
	    char *report = "";

	    if (sig != SIGINT && sig != SIGKILL && sig != SIGTERM)
		report = "!";
	    sprintf(reason, "%ssignal=%d", report, sig);
	}
	else if (WIFEXITED(status))
	    sprintf(reason, "exit=%d", WEXITSTATUS(status));
	else if (WIFSTOPPED(status))
	    sprintf(reason, "stop=%d", WSTOPSIG(status));
	else
	    sprintf(reason, "status=0x%X", status);
    }
    return pid;
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
	    snprintf(def, sizeof def, vp->def.s, g->pkg);
	    vp->def.s = xstrdup(def);	/* free: never (init) */
	}
    }
}

void		set_cfg_env(glob_t *g, char *var)
{
    char	*env;

    xasprintf(&env, "%s=%s", var, g->cfg_path);
    if (putenv(env) != 0)
	errexit(EX_NOMEM, 0, "unable to allocate memory");
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

    if (g->cfg_path != NULL)	/* Was set by parse_args */
	return;

    /* Make variable name */
    if (snprintf(env_var, sizeof env_var, CFGPATH_ENVFMT, g->pkg) >= sizeof env_var)
	errexit(EX_CONF, 0, "cannot make configuration file env variable");
    for (i = 0; i < strlen(g->pkg); i++)
	env_var[i] = toupper(env_var[i]);
    trace(TL_CONF, "env var = %s", env_var);

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
    snprintf(path, sizeof path, "%s/%s.conf", g->prg_dir, g->pkg);
    trace(TL_CONF, "trying cfg_path = %s", path);
    if (access(path, R_OK) == 0)
    {
	g->cfg_path = xstrdup(path);	/* free: never (init 2) */
	set_cfg_env(g, env_var);
	return;
    }

    /* Try from default config dir */
    snprintf(path, sizeof path, CFG_DEFDIR "/%s.conf", g->pkg);
    trace(TL_CONF, "trying cfg_path = %s", path);
    if (access(path, R_OK) == 0)
    {
	g->cfg_path = xstrdup(path);	/* free: never (init 3) */
	set_cfg_env(g, env_var);
	return;
    }
    errexit(EX_CONF, 0, "cannot find config-file %s.conf in args, env, %s or " CFG_DEFDIR, g->pkg, g->cfg_path);
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
	if (*p != '-' && (*p <= '0' || *p >= '9'))
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

/*	Convert syslog facility name to value  */

int		facv(glob_t *g, const char *s, int ln)
{
    sconvi_t	tbl[] = {
	{ "DAEMON",	LOG_DAEMON },
	{ "LOCAL0",	LOG_LOCAL0 },
	{ "LOCAL1",	LOG_LOCAL1 },
	{ "LOCAL2",	LOG_LOCAL2 },
	{ "LOCAL3",	LOG_LOCAL3 },
	{ "LOCAL4",	LOG_LOCAL4 },
	{ "LOCAL5",	LOG_LOCAL5 },
	{ "LOCAL6",	LOG_LOCAL6 },
	{ "LOCAL7",	LOG_LOCAL7 },
	{ "USER",	LOG_DAEMON }
    };
    char	*help = NULL;
    int		val;

    if ((val = stoi(tbl, sizeof tbl / sizeof tbl[0], s, &help, ", ")) != NUMIVAL)
	return val;
    errexit(EX_CONF, 0, "unknown syslog facility \"%s\" at line %d of %s\nKnown facility values: %s", s, ln, g->cfg_path, help);
    return NUMIVAL;
}

/*	Convert syslog level name to value  */

int		lvlv(glob_t *g, const char *s, int ln)
{
    sconvi_t	tbl[] = {
	{ "ALERT",	LOG_ALERT	},
	{ "CRIT",	LOG_CRIT	},
	{ "ERR",	LOG_ERR		},
	{ "ERROR",	LOG_ERR		},
	{ "WARN",	LOG_WARNING	},
	{ "WARNING",	LOG_WARNING	},
	{ "NOTICE",	LOG_NOTICE	},
	{ "INFO",	LOG_INFO	},
	{ "DEBUG",	LOG_DEBUG	}
    };
    char	*help = NULL;
    int		val;

    if ((val = stoi(tbl, sizeof tbl / sizeof tbl[0], s, &help, ", ")) != NUMIVAL)
	return val;
    errexit(EX_CONF, 0, "unknown syslog level \"%s\" at line %d of %s\nKnown level values: %s", s, ln, g->cfg_path, help);
    return NUMIVAL;
}

/*
 *  Parse config file (called at init and config reloads)
 */
void		parse_conf(glob_t *g)
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
    int		nl, ln, iv, err, n;

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
			void	kill_children(glob_t *, int);

			if (strcmp(vp->name, "sess_dir") == 0)
			    kill_children(g, SIGTERM);
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
}

/*
 *=====	Parse command line and check paths =============================
 */
char		*check_abs(char *p)
{
    if (*p != '/')
	errexit(EX_USAGE, 0, "specified path \"%s\" must be absolute", p);
    return p;
}

void		parse_args(glob_t *g, int ac, char **av)
{
    char	*exe, *p;
    int		argerr = 0, len, val, i;

    exe = getfile("/proc/self/exe");	/* free: just below */
    if ((p = strrchr(av[0], '/')) != NULL)
    {
	*p = '\0';
	g->prg = ++p;
	g->prg_dir = xstrdup(av[0]);	/* free: never (init) */
    }
    else
    {
	g->prg = av[0];
	if ((p = strrchr(exe, '/')) == NULL)
	    errexit(EX_PROG, 0, "no '/' in binary path %s ??", exe);
	xasprintf(&g->prg_dir, "%.*s", p - exe, exe);	/* free: never (init) */
    }
    xfree(exe);				/* free from getfile() */
    if ((len = strlen(g->prg)) > 0)
    {
	if (g->prg[len - 1] == 'd')	/* Undaemonize our name */
	    len--;
	xasprintf(&g->pkg, "%.*s", len, g->prg);	/* free: never (init) */
    }
    trace(TL_CONF, "prg=% prg_dir=%s pkg=%s", g->prg, g->prg_dir, g->pkg);

    while ((val = getopt(ac, av, "f:l:r:t:")) != EOF)
    {
	switch (val)
	{
	    case 'f':	g->cfg_path = xstrdup(check_abs(optarg));	break;	/* free: never (init) */
	    case 'l':	g->log_path = xstrdup(check_abs(optarg));	break;	/* free: never (init) */
	    case 'r':	g->rep_path = xstrdup(check_abs(optarg));	break;	/* free: never (init) */
	    case 't':	g->TraceLevel = g->TlvConv(g, optarg, 0);	break;
	    default:	argerr = 1;		break;
	}
    }
    ac -= optind;
    if (argerr)
	errexit(EX_USAGE, 0, "\\Usage: %s [-f conf-file] [-l log-file] [-r report-file] [watch-prog [report-prog]]", g->prg);

    for (i = 0; i < NB_CHILDREN; i++)
    {
	if (ac < 1)
	{
	    switch (i)
	    {
		case 0:	p = xstrdup(g->pkg);				break;	/* free: never (init) */
		case 1:	xasprintf(&p, "%s.sh", g->children[0].arg);	break;	/* free: never (init) */
	    }
	}
	else
	{
	    p = xstrdup(av[optind]);	/* free: never (init) */
	    optind++;
	    ac--;
	}
	g->children[i].arg = p;
	trace(TL_CONF, "arg[%d]=\"%s\"", i + 1, p);
    }
    if (ac > 0)
	notice("ignoring %d extra arguments", ac);
}

char		*path_split(char *path, char **file)
{
    static char	dir[PATH_MAX];
    char	*p;

    if ((p = strrchr(path, '/')) == NULL)
	errexit(EX_PROG, 0, "cannot find '/' in path \"%s\"", path);
    strncpy(dir, path, p - path);
    dir[p - path] = '\0';
    *file = ++p;

    return dir;
}

/*
 *  Set and check paths of:
 *
 *	log-file
 *	report-file (if specified)
 *	pid-file (in run-dir)
 *	child 0 exec
 *	child 1 exec
 */
void		check_paths(glob_t *g)
{
    char	*spec, *dir, *file;
    int		i;

    /*
     *	Log-file. Try:
     *	    file given with -l
     *	    <pkg>.log in log_dir
     *	Both file (if exists) and directory must be writable
     */
    spec = "specified";
    if (g->log_path == NULL)	/* Was not in command line */
    {
	xasprintf(&g->log_path, "%s/%s.log", g->LogDir, g->pkg);	/* free: never (init or abort) */
	spec = "assembled";
    }
    trace(TL_CONF, "trying log_path = %s", g->log_path);
    if (access(g->log_path, W_OK) != 0)		/* file not writable */
    {
	if (access(g->log_path, F_OK) == 0)	/* file exists, not writable */
	    errexit(EX_PATH, 0, "cannot write to %s log-file %s", spec, g->log_path);
    }
    dir = path_split(g->log_path, &file);	/* Get dir and file parts */
    trace(TL_CONF, "trying log_dir = %s", dir);
    if (access(dir, W_OK) != 0)		/* dir not writable */
	errexit(EX_PATH, 0, "cannot create log-files in dir %s", dir);

    /*
     *  Report-file: check that arg and its dir are writable
     */
    if (g->rep_path != NULL)	/* Only from command line */
    {
	trace(TL_CONF, "trying rep_path = %s", g->rep_path);
	if (access(g->rep_path, W_OK) != 0)	/* file not writable */
	{
	    if (access(g->rep_path, F_OK) == 0)	/* file exists, not writable */
		errexit(EX_PATH, 0, "cannot write to specified report-file %s", g->rep_path);
	}
	dir = path_split(g->rep_path, &file);	/* Get dir and file parts */
	trace(TL_CONF, "trying rep_dir = %s", dir);
	if (access(dir, W_OK) != 0)			/* dir not writable */
	    errexit(EX_PATH, 0, "cannot create report-files in dir %s", dir);
    }

    /*
     *	Pid-file: just check run_dir is writable
     */
    trace(TL_CONF, "trying run_dir = %s", g->RunDir);
    if (access(g->RunDir, W_OK) != 0)
	errexit(EX_PATH, 0, "cannot write to directory %s", g->RunDir);
    xasprintf(&g->pid_path, "%s/%s.pid", g->RunDir, g->prg);

    /*
     *	Path to children. Try:
     *	    arg if absolute
     *	    prg_dir
     *	    bin_dir
     */
    for (i = 0; i < NB_CHILDREN; i++)
    {
	child_t	*cp = &g->children[i];
	char	path[PATH_MAX];

	if ((file = strrchr(cp->arg, '/')) != NULL)
	    file++;
	else
	    file = cp->arg;
	if (cp->arg[0] == '/')	/* Absolute args */
	{
	    trace(TL_CONF, "trying path[%d] = %s", i, cp->arg);
	    if (access(cp->arg, X_OK) != 0)	/* file not executable */
		errexit(EX_PATH, 0, "cannot execute %s", cp->arg);
	    cp->path = xstrdup(cp->arg);	/* free: never (init) */
	    cp->name = xstrdup(file);		/* free: never (init) */
	    continue;
	}

	snprintf(path, sizeof path, "%s/%s", g->prg_dir, cp->arg);
	trace(TL_CONF, "trying path[%d] = %s", i, path);
	if ((cp->path = realpath(path, NULL)) != NULL)	/* free: never (init) */
	{
	    if (access(cp->path, X_OK) == 0)	/* file is executable */
	    {
		cp->name = xstrdup(file);		/* free: never (init) */
		continue;
	    }
	    xfree(cp->path);	/* from realpath() */
	}

	xasprintf(&cp->path, "%s/%s", g->BinDir, file);
	trace(TL_CONF, "trying path[%d] = %s", i, cp->path);
	if (access(cp->path, X_OK) == 0)	/* file is executable */
	{
	    cp->name = xstrdup(file);		/* free: never (init) */
	    continue;
	}
	xfree(cp->path);	/* from xasprintf() */
	errexit(EX_PATH, 0, "cannot find %s in %s or %s", cp->arg, g->prg_dir, g->BinDir);
    }
}

/*
 *=====	Handle logs open / write =======================================
 */
void		log_sys(glob_t *g, const char *fmt, ...)
{
    va_list	ap;

    va_start(ap, fmt);
    openlog(g->prg, LOG_PID, g->SyslogFac);
    syslog(g->SyslogLvl, fmt, ap);
    closelog();
    va_end(ap);
}

void		open_logs(glob_t *g)
{
    char	*rep = g->rep_path != NULL ? g->rep_path : "/dev/null";

    if (g->rep_fp != NULL)
    {
	fclose(g->rep_fp);
	g->rep_fp = NULL;
    }
    if ((g->rep_fp = fopen(rep, "a")) == NULL)
       log_sys(g, "cannot (re)open %s: %s (errno=%d)", rep, strerror(errno), errno);

    if (g->log_fp != NULL)
    {
	fclose(g->log_fp);
	g->log_fp = NULL;
    }
    if ((g->log_fp = fopen(g->log_path, "a")) == NULL)
       log_sys(g, "cannot (re)open %s: %s (errno=%d)", g->log_path, strerror(errno), errno);
}

int		prepare_fdset(glob_t *g, fd_set *readfd)
{
    int		max = 0, fd;

    FD_ZERO(readfd);

    if (g->children[0].err_fp != NULL)
    {
	fd = fileno(g->children[0].err_fp);
	FD_SET(fd, readfd);
	if (fd > max)
	    max = fd;
    }
    if (g->children[1].out_fp != NULL)
    {
	fd = fileno(g->children[1].out_fp);
	FD_SET(fd, readfd);
	if (fd > max)
	    max = fd;
    }
    if (g->children[1].err_fp != NULL)
    {
	fd = fileno(g->children[1].err_fp);
	FD_SET(fd, readfd);
	if (fd > max)
	    max = fd;
    }
    return max;
}

void		get_put_log(FILE *from, FILE *to, char *name, char *tag)
{
    char	buf[LOG_BUF_SIZE];

    if (fgets(buf, sizeof buf, from) != NULL)
	fprintf(to, "%s\t%s %s: %s", tstamp(" "), name, tag, buf);
}

void		handle_logs(glob_t *g)
{
    timeval_t	timeout;
    fd_set	readfd;
    int		ret, max;

    timeout.tv_sec = g->LogWait;
    timeout.tv_usec = 0;
    max = prepare_fdset(g, &readfd);
    if ((ret = select(max + 1, &readfd, NULL, NULL, &timeout)) < 0)
    {
	if (errno == EINTR)
	{
	    if (g->sig == 0)
		error(0, "select interrupted with no signal ?");
	}
	else if (errno == EBADF)
	{
	    /*	Bad file descriptor: try to find which */
	    int	fd, n = getdtablesize();

	    for (fd = 0; fd < n; fd++)
	    {
		if (FD_ISSET(fd, &readfd) && fcntl(fd, F_GETFL, NULL) == -1 && errno == EBADF)
		    error(0, "fd=%d was in fdsets but is closed", fd);
	    }
	    error(0, "select max=%d", max);
	}
	else
	    error(errno, "select");
    }
    else if (ret > 0)
    {
	FILE	*fp;

	fp = g->children[0].err_fp;
	if (fp != NULL && FD_ISSET(fileno(fp), &readfd))
	    get_put_log(fp, g->log_fp, g->children[0].name, "errlog");

	fp = g->children[1].out_fp;
	if (fp != NULL && FD_ISSET(fileno(fp), &readfd))
	    get_put_log(fp, g->rep_path != NULL ? g->rep_fp : g->log_fp, g->children[1].name, "report");

	fp = g->children[1].err_fp;
	if (fp != NULL && FD_ISSET(fileno(fp), &readfd))
	    get_put_log(fp, g->log_fp, g->children[1].name, "errlog");
    }
}

/*
 *=====	Handle children creation / burial ==============================
 */
void		kill_children(glob_t *g, int sig)
{
    int		i;

    for (i = 0; i < NB_CHILDREN; i++)
    {
	child_t	*cp = &g->children[i];

	if (cp->pid > 0 && cp->kill_time == 0)
	{
	    kill(cp->pid, sig);
	    cp->kill_time = time(NULL);
	}
    }
}

void		bury_children(glob_t *g)
{
    pid_t	pid;
    char	reason[32];
    int		i;

    while ((pid = dead_wait(reason)) > 0)
    {
	for (i = 0; i < NB_CHILDREN; i++)
	{
	    child_t	*cp = &g->children[i];

	    if (pid == cp->pid)
	    {
		char    *msg = "%s PID=%d stopped (%s)";

		if (reason[0] == '!')
		    report(msg, cp->name, pid, reason + 1);
		else
		    info(msg, cp->name, pid, reason);

		cp->pid = 0;
		cp->kill_time = 0;
		if (cp->out_fp != NULL)
		{
		    fclose(cp->out_fp);
		    cp->out_fp = NULL;
		}
		fclose(cp->err_fp);
		cp->err_fp = NULL;
	    }
	    else
		report("unknown process PID=%d termination (%s)", pid, reason);
	}
    }
    return;
}

void		handle_children(glob_t *g)
{
    int		i, pipes[8];

    bury_children(g);
    /* If any child still active, wait until it dies */
    for (i = 0; i < NB_CHILDREN; i++)
    {
	child_t	*cp = &g->children[i];

	if (cp->pid > 0)
	{
	    time_t	t = time(NULL);

	    if (cp->kill_time > 0 && t >= (cp->kill_time + 10))
	    {
		kill(cp->pid, SIGKILL);
		cp->kill_time = t;
	    }
	    return;
	}
    }
    /*
     *	Reminder: pipe[0] is read-end, pipe[1] is write-end
     *
     *	Open pipes. We need a pair for each of
     *	  - main pipe01 for stdout from(1) child0 to(0) child1 stdin
     *	  - pipe23 for stderr from(3) child0 stderr to(2) us
     *	  - pipe45 for stdout from(5) child1 stdout to(4) us
     *	  - pipe67 for stderr from(7) child1 stderr to(6) us
     */
    for (i = 0; i < (sizeof pipes / (2 * sizeof(int))); i++)
    {
	if (pipe2(pipes + (2 *i), O_DIRECT) < 0)
	    errexit(EX_PIPE, errno, "cannot create pipes[%d] - Aborting", i);
    }
    /* Start children */
    for (i = 0; i < NB_CHILDREN; i++)
    {
	child_t	*cp = &g->children[i];
	int	pid;

	if ((pid = fork()) == 0)
	{
	    fclose(g->rep_fp);
	    fclose(g->log_fp);
	    if (i == 0)
	    {
		/* stdin:-, stdout:1, stderr:3 */
		dup(pipes[1]);
		dup(pipes[3]);
	    }
	    else if (i == 1)
	    {
		/* stdin:0, stdout:5, stderr:7 */
		fclose(stdin);
		dup(pipes[0]);
		dup(pipes[5]);
		dup(pipes[7]);
	    }
	    for (i = 0; i < (sizeof pipes / sizeof(int)); i++)
		close(pipes[i]);
	    execl(cp->path, cp->path, NULL);
	    log_sys(g, "cannot exec %s: %s (errno=%d)", cp->path, strerror(errno), errno);
	    exit(EX_EXEC);
	}
	else if (pid > 0)
	{
	    if (i == 0)
	    {
		close(pipes[0]);
		close(pipes[1]);
		cp->err_fp = fdopen(dup(pipes[2]), "a");
		close(pipes[2]);
		close(pipes[3]);
	    }
	    else if (i == 1)
	    {
		cp->out_fp = fdopen(dup(pipes[4]), "a");
		close(pipes[4]);
		close(pipes[5]);
		cp->err_fp = fdopen(dup(pipes[6]), "a");
		close(pipes[6]);
		close(pipes[7]);
	    }
	    cp->pid = pid;
	    cp->kill_time = 0;
	    info("started %s (PID=%d)\n", cp->name, pid);
	}
	else	/* we should close pipes, but exit anyhow */
	    errexit(EX_FORK, errno, "cannot fork child%d (%s) - Aborting", i, cp->name);
    }
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

void		write_pid(glob_t *g)
{
/* XXX */
}

int		main(int ac, char **av)
{
    glob_t	*g = &globals;
    pid_t	pid;

    parse_args(g, ac, av);
    conf_init(g);
    parse_conf(g);
    check_paths(g);

    if ((pid = fork()) == 0)
    {
	int	max = getdtablesize(), errs = 0, fd;

	write_pid(g);
	fclose(stdin);	/* 0 */
	fclose(stdout);	/* 1 */
	fclose(stderr);	/* 2 */
	for (fd = 3; fd < max; fd++)
	{
	    if (close(fd) < 0)
		errs++;
	    if (errs > 10)
		break;
	}
	setsid();
	chdir(g->SessDir);

	if (g->SigReload != SIGHUP && g->SigRotate != SIGHUP)
	    signal(SIGHUP, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, terminate);
	signal(g->SigReload, trap_sig);
	signal(g->SigRotate, trap_sig);
	siginterrupt(SIGTERM, 1);
	siginterrupt(g->SigReload, 1);
	siginterrupt(g->SigRotate, 1);

	fopen("/dev/null", "r");	/* daemon's stdin */
	if (g->rep_path == NULL)
	    fopen("/dev/null", "w");	/* daemon's stdout */

	while (g->loop)
	{
	    if (g->sig == g->SigReload)
	    {
		parse_conf(g);
		kill_children(g, g->SigReload);
	    }
	    else if (g->sig == g->SigRotate)
		open_logs(g);
	    else if (g->sig == SIGTERM)
		kill_children(g, SIGTERM);

	    handle_logs(g);		/* includes 1st opens */
	    handle_children(g);		/* includes 1st forks */
	}
	unlink(g->pid_path);
    }
    else if (pid > 0)
	printf("%s started (PID=%d)\n", g->prg, pid);
    else
	errexit(EX_FORK, errno, "fork");

     return EX_OK;
}
