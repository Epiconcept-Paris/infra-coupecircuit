/*
 *  nbphpsessd.c
 *
 *	(C) 2020 by Christophe de Traversay <devel@traversay.com>
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
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/wait.h>

/* Exit codes */
#define EX_OK		0
#define EX_USAGE	1
#define EX_CONF		2
#define EX_PATH		3
#define EX_PID		4

#define EX_PIPE		5
#define EX_FORK		6
#define EX_EXEC		7

#define EX_NOMEM	8
#define EX_LOGIC	9

/* Trace levels */
/* If changed, also update trace_level's config-var help  */
#define TL_CONF		1
#define TL_EXEC		2
#define TL_LOGS		4
#define TL_DEBUG	8

/* global config errors */
#define ERR_CFG_NUM	1
#define ERR_CFG_SIG	2
#define ERR_CFG_FAC	3
#define ERR_CFG_LVL	4

#define NB_CHILDREN	2
#if NB_CHILDREN != 2
#error "This program is designed for 2 children"
#endif

#define FORK_DELAY	10

#define LOG_BUF_SIZE	(4 * 1024)

#define CFG_DEFDIR	"/etc/epiconcept"
#define CFGPATH_ENVFMT	"%s_CONF"

/* Parse regexp format (28 chr) for config (%s) values */
#define CFGVAR_REFMT	"^\\s*%s\\s*=\\s*(\\S*)\\s*(#.*)?$"
#define NB_CFGV_RESUBS	3

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

typedef struct	child_s		/* child processes */
{
    char	*arg;		/* from commande line */
    char	*path;		/* actual exec path */
    char	*name;		/* basename */
    pid_t	pid;
    time_t	kill_time;
    FILE	*out_fp;
    FILE	*err_fp;
}		child_t;

/*  Any change to struct glob_s MUST be reflected in 'globals' init below */

typedef	struct	glob_s		/* global variables */
{
#   define NB_CFGVARS	13
    cfgvar_t	config[NB_CFGVARS];	/* Must be 1st member for init */

    char	*cfg_arg;
    char	*cfg_path;
    int		cfgerr;

    char	*prg;		/* basename from av[0] */
    char	*prg_dir;

    char	*pkg;		/* our package name (final 'd' removed) */

    time_t	fork_time;
    int		fork_delay;
    int		fork_tries;

    child_t	children[NB_CHILDREN];

    char	*rep_arg;
    char	*rep_path;
    FILE	*rep_fp;

    char	*log_arg;
    char	*log_path;
    FILE	*log_fp;

    char	*pid_path;
    bool	kill_prg;

    FILE	*fp0;
    int		sig;
    int		loop;
}		glob_t;

/*
 *{ Initialize (the beginning of) 'globals'
 *
 *	used as 'globals' only in main(), signal handlers and log functions
 *	used as 'glob_t *g' everywhere else
 */
static int	intv(glob_t *, const char *, int);
static int	sigv(glob_t *, const char *, int);
static int	facv(glob_t *, const char *, int);
static int	lvlv(glob_t *, const char *, int);

glob_t		globals = {

	/*	When adding to the config variables belon, don't forget to:
	 *	  - update the NB_CFGVARS macro in glob_t definition above
	 *	  - add default values to the CFG_IVALS macro below
	 */
#	define TlvConv		config[0].icv

#	define TraceLevel	config[0].val.i
#	define BinDir		config[1].val.s
#	define LogDir		config[2].val.s
#	define RunDir		config[3].val.s
#	define WorkDir		config[4].val.s
#	define LogWait		config[5].val.i
#	define ChildLinger	config[6].val.i
#	define ChildDelay	config[7].val.i
#	define ChildRetries	config[8].val.i
#	define SyslogFac	config[9].val.i
#	define SyslogLvl	config[10].val.i
#	define SigReload	config[11].val.i
#	define SigRotate	config[12].val.i

#	define VarWorkDir	config[4].name
#	define VarReload	config[11].name
#	define VarRotate	config[12].name

#	define DefWorkDir	config[4].def.s
#	define DefReload	config[11].def.i
#	define DefRotate	config[12].def.i

#	define RefWorkDir	config[4].line
#	define RefReload	config[11].line
#	define RefRotate	config[12].line

#	define ValTraceLevel(v)	v[0].i
#	define ValWorkDir(v)	v[4].s
#	define ValReload(v)	v[11].i
#	define ValRotate(v)	v[12].i

#	define CFG_IVALS	{ \
	{.i=NUMIVAL},\
	{.s=STRIVAL}, {.s=STRIVAL}, {.s=STRIVAL}, {.s=STRIVAL},\
	{.i=NUMIVAL}, {.i=NUMIVAL}, {.i=NUMIVAL}, {.i=NUMIVAL},\
	{.i=NUMIVAL}, {.i=NUMIVAL}, {.i=NUMIVAL}, {.i=NUMIVAL} \
    }
    {
	{ "trace_level",	1, 1, intv, { .i = NUMIVAL },	{ .i = 0 },		0, {},
				"trace level (1:conf, 2:exec 4:logs)" },
	{ "bin_dir",		0, 0, NULL, { .s = STRIVAL },	{ .s = "/usr/local/lib/%s" },	0, {},
				"where to find binaries if nowhere else" },
	{ "log_dir",		0, 0, NULL, { .s = STRIVAL },	{ .s = "/var/log/%s" },	0, {},
				"where to put log-file if not -l" },
	{ "run_dir",		0, 0, NULL, { .s = STRIVAL },	{ .s = "/run/%s" },	0, {},
				"where to put pid-file" },
	{ "work_dir",		1, 0, NULL, { .s = STRIVAL },	{ .s = "/usr/local/lib/%s" }, 0, {},
				"working directory" },
	{ "log_wait",		1, 1, intv, { .i = NUMIVAL },	{ .i = 5 },		0, {},
				"how long max to wait for logs in loop" },
	{ "child_linger",	1, 1, intv, { .i = NUMIVAL },	{ .i = 10 },		0, {},
				"delay between SIGTERM and SIGKILL for children" },
	{ "child_delay",	1, 1, intv, { .i = NUMIVAL },	{ .i = FORK_DELAY },	0, {},
				"delay between consecutive forks of children" },
	{ "child_retries",	1, 1, intv, { .i = NUMIVAL },	{ .i = 10 },		0, {},
				"maximum number of fork retries" },
	{ "syslog_facility",	1, 1, facv, { .i = NUMIVAL },	{ .i = LOG_LOCAL0 },	0, {},
				"syslog facility if cannot exec or rotate log" },
	{ "syslog_level",	1, 1, lvlv, { .i = NUMIVAL },	{ .i = LOG_CRIT },	0, {},
				"syslog level if cannot exec or rotate log" },
	{ "conf_reload_sig",	1, 1, sigv, { .i = NUMIVAL },	{ .i = SIGUSR1 },	0, {},
				"conf-reload signal (SIGxxx also accepted)" },
	{ "log_rotate_sig",	1, 1, sigv, { .i = NUMIVAL },	{ .i = SIGUSR2 },	0, {},
				"log-rotate signal (SIGxxx also accepted)" }
    }
};
/*} End init globals */

/*
 *===== Start common code { ============================================
 *
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
static char	*tstamp(time_t t, char *sep)	/* Only for loglines() just below */
{
    static char	buf[32];
    struct tm	*tp;
    timeval_t	tv;
    int		len;

    if (t == 0)
	gettimeofday(&tv, NULL);
    tp = localtime(t == 0 ? &tv.tv_sec : &t);
    len = snprintf(buf, sizeof buf, "%04d-%02d-%02d%s%02d:%02d:%02d",
	 tp->tm_year + 1900, tp->tm_mon + 1, tp->tm_mday, sep, tp->tm_hour, tp->tm_min, tp->tm_sec);
    if (globals.TraceLevel > 0)
	len += snprintf(buf + len, sizeof buf - len, ".%03ld", t == 0 ? tv.tv_usec / 1000 : 0);

    return buf;
}

/*  Return fd type (cached) */
static char	fd_type(int fd)
{
    struct stat st;
    struct f_type
    {
	int	mask;
	char	type;
    }		tbl[] = {
	{ S_IFSOCK,	's' },	/* socket */
	{ S_IFLNK,	'l' },	/* symlink (never: would need lstat() */
	{ S_IFREG,	'f' },	/* file */
	{ S_IFBLK,	'b' },	/* bdev (unlikely) */
	{ S_IFDIR,	'd' },	/* dir */
	{ S_IFCHR,	'c' },	/* cdev (most probably tty) */
	{ S_IFIFO,	'p' }	/* pipe (or fifo) */
    };
    static char	ift = '\0';
    static int	ifd = -1;
    int		i;

    if (fd == ifd && ift != '\0')
	return ift;

    if (fstat(fd, &st) < 0)
	return 'e';

    for (i = 0; i < (sizeof tbl / sizeof(struct f_type)); i++)
    {
	if (((st.st_mode & S_IFMT) == tbl[i].mask))
	    return ifd = fd, ift = tbl[i].type;
    }
    return 'u';
}

/*  Log line (called by logmsg(), trcmsg() and xitmsg()) */
static void	loglines(int syserr, const char *fn, int ln, char *tag, char *msg)
{
    bool	log = (globals.log_fp != NULL);
    FILE	*fp = log ? globals.log_fp : stderr;
    char	*line, *p, ft = fd_type(fileno(fp));
    int		nl;

    if (*msg == '\0')
	return;

    nl = 0;
    p = msg;
    while ((line = strsep(&p, "\r\n")) != NULL)
    {
	if (*line == '\0')	/* discard empty lines */
	    continue;

	/* prefix for all lines */
	if (log || ft == 'f')
	    fprintf(fp, "%s\t", tstamp(0, " "));

	/* prefixes */
	if (nl == 0)		/* 1st line */
	{
	    if (!log && ft == 'c')
	    {
		if (*line != '\\')	/* add ':' only for info() */
		    fprintf(stderr, "%s%s", globals.prg, (tag != NULL && *tag == '\0') ? ": " : " ");
		else
		    line++;
	    }
	    if (tag == NULL)		/* trace */
		fprintf(fp, "%s:%d ", fn, ln);
	    else if (*tag != '\0')	/* all others but info */
		fputs(tag, fp);
	}
	else
	    fputs("    ", fp);	/* 4 spaces */

	/* line as received */
	fputs(line, fp);

	/* suffix for 1st line: possible system error */
	if (nl == 0 && syserr > 0)
	    fprintf(fp, ": %s (errno=%d)", strerror(syserr), syserr);

	fputc('\n', fp);
	fflush(fp);
	nl++;
    }
}

static void	logmsg(int x, const char *fn, int ln, char *tag, char *fmt, ...)
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
    loglines(tag != NULL ? x : 0, fn, ln, tag, buf);	/* x is errno or 0 */
}

static void	xitmsg(int xcode, int syserr, const char *fn, int ln, char *fmt, ...)
{
    va_list	ap;
    char	buf[LOG_BUF_SIZE];

    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    /* force trace if EX_LOGIC */
    loglines(syserr, fn, ln, xcode == EX_LOGIC ? NULL : "", buf);
    if (globals.log_fp != NULL || fd_type(fileno(stderr)) != 'c')
	info("exiting with code=%d", xcode);

    exit(xcode);
}

/*
 * ====	Memory allocation functions ====================================
 */
static void	*xmalloc(size_t u)
{
    void	*ret;

    if ((ret = malloc(u)) == NULL)
	errexit(EX_NOMEM, 0, "unable to alloc %u bytes", u);
    return ret;
}

static void	*xfree(void *ptr)
{
    if (ptr != NULL)
	free(ptr);

    return NULL;
}

static void	*xstrdup(const char *str)
{
    void	*ret;

    if (str == NULL)
	errexit(EX_NOMEM, 0, "called with NULL argument");
    if ((ret = strdup(str)) == NULL)
	errexit(EX_NOMEM, 0, "unable to alloc %u bytes", strlen(str));

    return ret;
}

static int	xasprintf(char **buf, const char *fmt, ...)
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
static char	*getfile(char *path, int *plen)
{
    struct stat	st;
    char	buf[LOG_BUF_SIZE], *big = NULL;
    int		fd, len = 0, sz = sizeof buf;

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
	if (plen == NULL && memchr(big, '\0', len) != NULL)
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
 *  Set non-blocking mode on fd
 */
static void	set_nonblock(int fd)
{
    int		arg;

    if ((arg = fcntl(fd, F_GETFL, NULL)) < 0 || fcntl(fd, F_SETFL, arg | O_NONBLOCK) < 0)
	error(errno, "fcntl");
}

/*
 *  Return basename of a path, or path itself if no '/' in it
 */
static char	*base_name(char *path)
{
    char	*p = strrchr(path, '/');

    return p == NULL ? path : p + 1;
}

/*
 * ====	Process utilities ==============================================
 */
static pid_t	dead_wait(char *reason)
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
 * ====	Handle configuration file and variables ========================
 *
 *  Return regcomp / regex error string
 */
static char	*re_err(regex_t *rep, int errcode)
{
    static char	msg[1024];

    regerror(errcode, rep, msg, sizeof msg);

    return msg;
}

/*
 *  Compile regexps in 'globals.config'
 */
static void	conf_init(glob_t *g)
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
	    snprintf(def, sizeof def, vp->def.s, g->pkg);
	    vp->def.s = xstrdup(def);	/* free: never (init) */
	}
    }
}

static void	set_cfg_env(glob_t *g, char *var)
{
    char	*env;

    if (strcmp(g->prg, g->pkg) == 0)
	return;
    xasprintf(&env, "%s=%s", var, g->cfg_path);
    if (putenv(env) != 0)
	errexit(EX_NOMEM, 0, "unable to allocate memory");
}

/*
 *  Determine config path
 */
static void	get_cfgpath(glob_t *g)
{
    char	path[PATH_MAX];
    char	cfgfile[NAME_MAX];
    char	env_var[32];
    char	*p;
    int		i;

    /* Make variable name */
    if (snprintf(env_var, sizeof env_var, CFGPATH_ENVFMT, g->pkg) >= sizeof env_var)
	errexit(EX_CONF, 0, "env variable name for config-file is too long");
    for (i = 0; i < strlen(g->pkg); i++)
	env_var[i] = toupper(env_var[i]);
    trace(TL_CONF, "env_var = %s", env_var);

    if (g->cfg_arg != NULL)	/* Was set by parse_args */
    {
	char	real[PATH_MAX], *bad = NULL;

	if (g->cfg_arg[0] == '/')
	{
	    trace(TL_CONF, "trying cfg_path = %s", g->cfg_arg);
	    if (access(g->cfg_arg, R_OK) == 0)
	    {
		g->cfg_path = g->cfg_arg;
		g->cfg_arg = NULL;
		set_cfg_env(g, env_var);
		return;
	    }
	    bad = g->cfg_arg;
	}
	else
	{
	    if ((realpath(g->cfg_arg, real)) != NULL)
	    {
		trace(TL_CONF, "trying cfg_path = %s", real);
		if (access(real, R_OK) == 0)
		{
		    g->cfg_path = xstrdup(real);
		    g->cfg_arg = xfree(g->cfg_arg);
		    set_cfg_env(g, env_var);
		    return;
		}
		bad = real;
	    }
	    else if ((p = strrchr(g->cfg_arg, '/')) == NULL)
		strcpy(cfgfile, p + 1);
	    else
		bad = g->cfg_arg;;
	}
	if (bad != NULL)
	    errexit(EX_CONF, 0, "cannot access config-file %s", bad);
	g->cfg_arg = xfree(g->cfg_arg);
    }
    else
	snprintf(cfgfile, sizeof cfgfile, "%s.conf", g->pkg);

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
    snprintf(path, sizeof path, "%s/%s", g->prg_dir, cfgfile);
    trace(TL_CONF, "trying cfg_path = %s", path);
    if (access(path, R_OK) == 0)
    {
	g->cfg_path = xstrdup(path);	/* free: never (init 2) */
	set_cfg_env(g, env_var);
	return;
    }

    /* Try from default config dir */
    snprintf(path, sizeof path, CFG_DEFDIR "/%s", cfgfile);
    trace(TL_CONF, "trying cfg_path = %s", path);
    if (access(path, R_OK) == 0)
    {
	g->cfg_path = xstrdup(path);	/* free: never (init 3) */
	set_cfg_env(g, env_var);
	return;
    }
    p = g->cfg_arg != NULL ? "args, " : "";
    errexit(EX_CONF, 0, "cannot find config-file %s in %senv, %s or in " CFG_DEFDIR, cfgfile, p, g->prg_dir);
}

/*
 *  String to integer conversion functions
 *
 *	Check integer value
 */
static int	intv(glob_t *g, const char *s, int ln)
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
static int	stoi(sconvi_t *tbl, int sz, const char *s, char **help, char *sep)
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
static int	sigv(glob_t *g, const char *s, int ln)
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
static char	*sigstr(glob_t *g, int sig)
{
    static char	def[16];

    def[0] = '\0';
    /* The uglyness of the hack appears in the mandatory cast below */
    if (sigv(g, (const char *)&def, sig) != sig)
	snprintf(def, sizeof def, "sig%d", sig);

    return def;
}

/*	Convert syslog facility name to value  */
static int	facv(glob_t *g, const char *s, int ln)
{
    static sconvi_t	tbl[] = {
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

    g->cfgerr = ERR_CFG_FAC;
    warn("unknown syslog facility \"%s\" at line %d of %s\nKnown facility values: %s",
	s, ln, g->cfg_path, help);

    return NUMIVAL;
}

/*	Convert syslog level name to value  */
static int	lvlv(glob_t *g, const char *s, int ln)
{
    static sconvi_t	tbl[] = {
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

    g->cfgerr = ERR_CFG_LVL;
    warn("unknown syslog level \"%s\" at line %d of %s\nKnown level values: %s",
	s, ln, g->cfg_path, help);

    return NUMIVAL;
}

/*
 *  Parse config file (called at init and config reloads)
 */
static bool	parse_conf(glob_t *g, int(*apply)(glob_t *, cfgval_t *), bool(*end)(glob_t *))
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
 *  Show all config variables, their updatability
 *  and type, default value and help
 */
static void	config_help(glob_t *g)
{
    cfgvar_t	*vp;
    char	*def[NB_CFGVARS];
    int		i, nw = 4, dw = 7, cw = 7, len;

    /* Let the maniac loose: compute column widths */
    for (i = 0; i < NB_CFGVARS; i++)
    {
	vp = &g->config[i];
	if (vp->isint)
	    xasprintf(&def[i], "%d", vp->def.i);	/* free: never (init) */
	else if (strchr(vp->def.s, '%') != NULL)
	    xasprintf(&def[i], vp->def.s, g->pkg);	/* free: never (init) */
	else
	    def[i] = vp->def.s;
    }
    for (i = 0; i < NB_CFGVARS; i++)
    {
	vp = &g->config[i];
	if ((len = strlen(vp->name)) > nw)
	    nw = len;
	if ((len = strlen(def[i])) > dw)
	    dw = len;
	if ((len = strlen(vp->help)) > cw)
	    cw = len;
    }

    /* Header */
    printf("Configuration variables (in %s.conf):\n", g->pkg);
    printf("  %-*s isInt isUpd %-*s %-*s\n", nw, "Name", dw, "Default", cw, "Comment");
    fputs("  ", stdout);
    for (i = 0; i < nw; i++)
	putchar('-');
    fputs(" ----- ----- ", stdout);
    for (i = 0; i < dw; i++)
	putchar('-');
    putchar(' ');
    for (i = 0; i < nw; i++)
	putchar('-');
    putchar('\n');

    /* Values */
    for (i = 0; i < NB_CFGVARS; i++)
    {
	cfgvar_t*   vp;
	char	    idef[32];

	vp = &g->config[i];
	if (vp->isint)
	    snprintf(idef, sizeof idef, "%d", vp->def.i);
	printf("  %-*s   %c     %c   %-*s %-*s\n", nw, vp->name, vp->isint ? 'y' : ' ', vp->isupd ? 'y' : ' ', dw, def[i], cw, vp->help);
    }
    exit(EX_OK);
}

/*
 *===== End common code } ==============================================
 */

/*
 *{==== Parse command line and check paths =============================
 */
void		parse_args(glob_t *g, int ac, char **av)
{
    char	real[PATH_MAX];
    char	*path, *exe, *p;
    int		argerr = 0, len, val, i;

    exe = NULL;
    if (av[0][0] != '/')
    {
	char	*name = "/proc/self/exe";

	if (realpath(av[0], real) == NULL)
	{
	    if ((exe = getfile(name, NULL)) == NULL)		/* free: just below */
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

    if ((len = strlen(g->prg)) > 0)
    {
	if (g->prg[len - 1] == 'd')	/* Undaemonize our name */
	    len--;
	xasprintf(&g->pkg, "%.*s", len, g->prg);	/* free: never (init) */
    }

    while ((val = getopt(ac, av, "cf:hkl:r:t:")) != EOF)
    {
	switch (val)
	{
	    case 'f':	g->cfg_arg = xstrdup(optarg);	break;	/* free: in get_cfgpath() */
	    case 'l':	g->log_arg = xstrdup(optarg);	break;	/* free: in get_logpath() */
	    case 'r':	g->rep_arg = xstrdup(optarg);	break;	/* free: in get_reppath() */
	    case 't':	g->TraceLevel = g->TlvConv(g, optarg, 0);	break;

	    /* Interactive */
	    case 'k':	g->kill_prg = true;	break;	/* exits */
	    case 'c':	config_help(g);		break;	/* exits */
	    case 'h':	argerr = -1;		break;
	    default:	argerr = 1;		break;
	}
    }
    ac -= optind;

    trace(TL_CONF, "prg_dir=%s prg=%s pkg=%s", g->prg_dir, g->prg, g->pkg);
    if (argerr != 0)
	errexit(argerr < 0 ? EX_OK : EX_USAGE, 0,
	    "\\Usage: %s [-f conf-file] [-l log-file] [-r report-file] [-t trace-level] [watcher [reporter]]\n"
	    "   %s -k\t\t# kill the running %s\n"
	    "   %s -c\t\t# show config-variable help",
	    g->prg, g->prg, g->prg, g->prg);

    for (i = 0; i < NB_CHILDREN; i++)
    {
	child_t	*cnp = g->children;

	if (ac < 1)
	{
	    switch (i)
	    {
		case 0:	p = xstrdup(g->pkg);			break;	/* free: in get_cldpaths() */
		case 1:	xasprintf(&p, "%s.sh", cnp[0].arg);	break;	/* free: in get_cldpaths() */
	    }
	}
	else
	{
	    p = xstrdup(av[optind]);	/* free: in get_cldpaths() */
	    optind++;
	    ac--;
	}
	cnp[i].arg = p;
	trace(TL_CONF, "arg[%d]=\"%s\"", i + 1, p);
    }
    if (ac > 0)
	notice("ignoring %d extra arguments", ac);
}

void		check_pidfile(glob_t *g)
{
    FILE	*fp;
    char	real[PATH_MAX];
    char	*path, *dir;

    if (g->RunDir[0] != '/')
    {
	if (realpath(g->RunDir, real) == NULL)
	    errexit(EX_PATH, errno, "cannot access run_dir directory \"%s\"", g->RunDir);
	dir = real;
    }
    else
	dir = g->RunDir;

    /*
     *	PID file: check that run_dir is writable
     */
    trace(TL_CONF, "trying run_dir = %s", dir);
    if (access(dir, W_OK) != 0 && !g->kill_prg)
	errexit(EX_PATH, 0, "cannot write to directory %s", dir);
    xasprintf(&path, "%s/%s.pid", dir, g->prg);	/* free: never (init) */
    if ((fp = fopen(path, "r")) != NULL)
    {
	char	buf[16];
	pid_t	pid;

	pid = fgets(buf, sizeof buf, fp) != NULL ? atoi(buf) : 0;
	fclose(fp);
	if (pid > 0)
	{
	    if (g->kill_prg)
	    {
		if (kill(pid, SIGTERM) < 0)
		{
		    if (errno == ESRCH)
		    {
			info("removing stale %s (PID=%d)", path, pid);
			unlink(path);
			exit(EX_OK);
		    }
		    else
			errexit(EX_PID, errno, "error on kill(%d,SIGTERM)", pid);
		}
		info("sent SIGTERM to PID=%d", pid);
		exit(EX_OK);
	    }
	    errexit(EX_PID, 0, "%s exists (PID=%d); already running ?", path, pid);
	}
    }
    if (g->kill_prg)
	errexit(EX_PID, 0, "no pidfile %s", path);

    g->pid_path = path;
}

/*
 *  Check write perms on arg and its directory
 *  If arg does not start with /, canonize in in static dir -> *pp
 *  If write allowed on arg, return true, false otherwise
 *  If neither file nor directory are writable *dp is NULL and *fp = arg
 *  If file is writable but not directory, directory part is returned in *dp
 *  and *fp contains the file-only part of arg
 */
bool		check_write(char *arg, char **pp, char **dp, char **fp)
{
    static char	full[PATH_MAX], dir[PATH_MAX];
    char	*p, *f;

    *fp = *pp = p = arg;
    *dp = NULL;
    if (*arg != '/')	/* Path is not absolute: make it so */
    {
	if (realpath(arg, full) == NULL)
	{
	    if (errno == EACCES)
		return false;
	    if (errno != ENOENT)
		errexit(EX_PATH, errno, "realpath(\"%s\",...)", arg);
	}
	*fp = *pp = p = full;
    }

    trace(TL_CONF, "trying write on %s", p);
    if (access(p, W_OK) != 0)			/* file not writable */
    {
	if (access(p, F_OK) == 0)		/* and it exists: abort */
	    return false;
    }

    if ((f = strrchr(p, '/')) == NULL)		/* should not happen ! */
	errexit(EX_LOGIC, 0, "cannot find again last '/' in %s", p);
    strncpy(dir, p, f - p);
    *dp = dir;
    *fp = ++f;

    trace(TL_CONF, "trying write on dir %s", dir);
    return access(dir, W_OK) == 0;
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
void		get_logpath(glob_t *g)
{
    char	logfile[PATH_MAX];
    char	*spec, *arg, *path, *dir, *file;

    /*
     *	Log-file
     *	If arg
     *	    if absolute, check arg and dir or fail
     *	    if relative, check arg = LogDir + rel file
     *	if fail
     *	    check arg = LogDir + pkg.log
     *	if still fail, report and exit
     */
    arg = path = dir = file = NULL;
    spec = "assembled";
    if (g->log_arg != NULL)
    {
	if (check_write(g->log_arg, &path, &dir, &file))
	{
	    g->log_path = xstrdup(path);
	    g->log_arg = xfree(g->log_arg);
	    return;
	}
	if (g->log_arg[0] == '/')
	{
	    /* keep arg,path,dir,file for error reporting */
	    arg = g->log_arg;
	    spec = "specified";
	}
	else
	{
	    strcpy(logfile, g->log_arg);
	    g->log_arg = xfree(g->log_arg);
	}
    }
    else
	snprintf(logfile, sizeof logfile, "%s.log", g->pkg);

    if (arg == NULL)		/* here if g->log_arg = NULL or assembled failed */
    {
	xasprintf(&arg, "%s/%s", g->LogDir, logfile);	/* free: never (init or abort) */
	if (check_write(arg, &path, &dir, &file))
	{
	    g->log_path = xstrdup(path);
	    return;
	}
    }
    if (dir == NULL)
	errexit(EX_PATH, 0, "cannot write to %s log-file %s", spec, path);
    else
	errexit(EX_PATH, 0, "cannot create log-files in dir %s", dir);

    xfree(arg);
}

void		get_reppath(glob_t *g)
{
    char	*spec, *arg, *path, *dir, *file;
    int		ok;

    if (g->rep_arg == NULL)	/* Only from command line */
	return;

    arg = path = dir = file = NULL;
    spec = "assembled";
    /*
     *  Report-file: check that arg and its dir are writable
     */
    if (g->rep_arg[0] == '/')
    {
	if ((ok = check_write(g->rep_arg, &path, &dir, &file)))
	{
	    g->rep_path = xstrdup(path);
	    g->rep_arg = xfree(g->rep_arg);
	    return;
	}
	/* keep arg,path,dir,file for error reporting */
	spec = "specified";
	arg = g->rep_arg;
    }
    else
    {
	xasprintf(&arg, "%s/%s", g->LogDir, g->rep_arg);
	g->rep_arg = xfree(g->rep_arg);

	if ((ok = check_write(arg, &path, &dir, &file)))
	{
	    g->rep_path = xstrdup(path);
	    return;
	}
	/* keep arg,path,dir,file for error reporting */
    }
    if (dir == NULL)
	errexit(EX_PATH, 0, "cannot write to %s report-file %s", spec, path);
    else
	errexit(EX_PATH, 0, "cannot create report-files in dir %s", dir);
    xfree(arg);
}

void		get_cldpaths(glob_t *g)
{
    char	path[PATH_MAX], real[PATH_MAX];
    char	*file;
    int		i;

    /*
     *	Path to children. Try:
     *	    arg if absolute
     *	    prg_dir
     *	    bin_dir
     */
    for (i = 0; i < NB_CHILDREN; i++)
    {
	child_t	*cp = &g->children[i];

	file = base_name(cp->arg);

	/* arg is absolute path: check */
	if (cp->arg[0] == '/')	/* Absolute args */
	{
	    trace(TL_CONF, "trying path[%d] = %s", i, cp->arg);
	    if (access(cp->arg, X_OK) != 0)	/* file not executable */
		errexit(EX_PATH, 0, "cannot execute %s", cp->arg);
	    cp->path = cp->arg;
	    cp->arg = NULL;			/* free for parse_args() */
	    cp->name = xstrdup(file);		/* free: never (init) */
	    continue;
	}

	/* check arg in prg_dir */
	snprintf(path, sizeof path, "%s/%s", g->prg_dir, cp->arg);
	if (realpath(path, real) != NULL)
	{
	    trace(TL_CONF, "trying path[%d] = %s", i, real);
	    if (access(real, X_OK) == 0)	/* file is executable */
	    {
		cp->path = xstrdup(real);		/* free: never (init) */
		cp->name = xstrdup(file);		/* free: never (init) */
		cp->arg = xfree(cp->arg);		/* free for parse_args() */
		continue;
	    }
	}

	/* check arg in BinDir */
	snprintf(path, sizeof path, "%s/%s", g->BinDir, file);
	trace(TL_CONF, "trying path[%d] = %s", i, cp->path);
	if (access(path, X_OK) == 0)	/* file is executable */
	{
	    cp->path = xstrdup(path);		/* free: never (init) */
	    cp->name = xstrdup(file);		/* free: never (init) */
	    cp->arg = xfree(cp->arg);		/* free for parse_args() */
	    continue;
	}
	errexit(EX_PATH, 0, "cannot find %s in %s or %s", cp->arg, g->prg_dir, g->BinDir);
    }
}
/*} End parse command line */

/*
 *{==== Handle logs open / write =======================================
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
    char	*rep_path = g->rep_path != NULL ? g->rep_path : g->log_path;

    if (g->rep_fp != NULL)
    {
	fclose(g->rep_fp);
	g->rep_fp = NULL;
    }
    if ((g->rep_fp = fopen(rep_path, "a")) == NULL)
       log_sys(g, "cannot (re)open %s: %s (errno=%d)", rep_path, strerror(errno), errno);

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
    child_t	*cp;

    FD_ZERO(readfd);

    cp = &g->children[0];
    if (cp->err_fp != NULL)
    {
	fd = fileno(cp->err_fp);
	FD_SET(fd, readfd);
	if (fd > max)
	    max = fd;
    }
    cp = &g->children[1];
    if (cp->out_fp != NULL)
    {
	fd = fileno(cp->out_fp);
	FD_SET(fd, readfd);
	if (fd > max)
	    max = fd;
    }
    if (cp->err_fp != NULL)
    {
	fd = fileno(cp->err_fp);
	FD_SET(fd, readfd);
	if (fd > max)
	    max = fd;
    }
    trace(TL_LOGS, "max=%d", max);
    return max;
}

void		get_put_log(FILE **from, FILE *to, char *name, char *tag)
{
    char	buf[LOG_BUF_SIZE], *eol;
    int		in, out;
    int		all = 0, loops = 0, empty = 0, nonl = 0, nlonly = 0;

    trace(TL_LOGS, "%s %s", name, tag);
    while (fgets(buf, sizeof buf, *from) != NULL)
    {
	loops++;
	if ((in = strlen(buf)) == 0)	/* ignore empty lines */
	{
	    empty++;
	    continue;
	}
	/* so in > 0 */
	all += in;
	if (buf[0] == '\n' && in == 1)	/* ignore lines with NL only */
	{
	    nlonly++;
	    continue;
	}
	if (buf[in - 1] != '\n')	/* add NL if missing at end */
	{
	    eol = "\n";
	    nonl++;
	}
	else
	    eol = "";

	out = fprintf(to, "%s %s %s: %s%s", tstamp(0, " "), name, tag, buf, eol);
	trace(TL_LOGS, "from fd=%d: %d bytes to fd=%d: %d bytes", fileno(*from), in, fileno(to), out);
    }
    fflush(to);
    if (loops > 1 || all == 0 || empty > 0 || nlonly > 0 || nonl > 0)
	trace(TL_DEBUG, "%d %s-%s fgets loops (all=%d), empty:%d nlonly:%d nonl:%d", loops, name, tag, all, empty, nlonly, nonl);

    /* eof or error */
    if (ferror(*from))
    {
	if (errno == EAGAIN)
	{
	    clearerr(*from);
	    return;
	}
	error(errno, "error reading %s %s fd=%d", name, tag, fileno(*from));
    }
    else if (feof(*from))
    {
	if (globals.loop > 0)
	    warn("EOF from %s %s fd=%d", name, tag, fileno(*from));
    }
    else
	warn("unexpected error from %s %s fd=%d", name, tag, fileno(*from));

    fclose(*from);
    *from = NULL;
}

void		handle_logs(glob_t *g)
{
    timeval_t	timeout;
    fd_set	readfd;
    int		ret, max;

    timeout.tv_sec  = g->loop > 0 ? g->LogWait : 0;
    timeout.tv_usec = g->loop > 0 ? 0 : (500 * 1000);
    max = prepare_fdset(g, &readfd);
    if (max == 0)
	timeout.tv_sec = 1;
    trace(TL_LOGS, "before select (max = %d, timeout = %d)", max, timeout.tv_sec);
    if ((ret = select(max + 1, &readfd, NULL, NULL, &timeout)) < 0)
    {
	trace(TL_LOGS, "select errno=%d", errno);
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
	child_t	*cp;

	trace(TL_LOGS, "after select ret=%d", ret);
	cp = &g->children[0];
	if (cp->err_fp != NULL && FD_ISSET(fileno(cp->err_fp), &readfd))
	    get_put_log(&cp->err_fp, g->log_fp, cp->name, "errlog");

	cp = &g->children[1];
	if (cp->out_fp != NULL && FD_ISSET(fileno(cp->out_fp), &readfd))
	    get_put_log(&cp->out_fp, g->rep_fp, cp->name, "report");

	if (cp->err_fp != NULL && FD_ISSET(fileno(cp->err_fp), &readfd))
	    get_put_log(&cp->err_fp, g->log_fp, cp->name, "errlog");
    }
}
/*} End handle logs */

/*
 *{==== Handle children creation / burial ==============================
 */
void		kill_children(glob_t *g, int sig)
{
    int		i;

    for (i = 0; i < NB_CHILDREN; i++)
    {
	child_t	*cp = &g->children[i];

	if (cp->pid > 0 && cp->kill_time == 0)
	{
	    if (sig == SIGTERM)
	    {
		info("killing %s (PID=%d)", cp->name, cp->pid);
		cp->kill_time = time(NULL);
	    }
	    else
		info("sending SIG%s to %s (PID=%d)", sigstr(g, sig), cp->name, cp->pid);
	    kill(cp->pid, sig);
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
		if (cp->err_fp != NULL)
		{
		    fclose(cp->err_fp);
		    cp->err_fp = NULL;
		}
		cp = &g->children[i == 0 ? 1 : 0];	/* other process */
		/* if still running, kill it */
		if (cp->pid > 0 && cp->kill_time == 0)
		{
		    /* TODO: should we use SIGHUP ? */
		    info("killing peer %s (PID=%d)", cp->name, cp->pid);
		    kill(cp->pid, SIGTERM);
		    cp->kill_time = time(NULL);
		}
		break;			/* Process found, abort for() loop */
	    }
	}
	if (i >= NB_CHILDREN)
	    report("unknown process PID=%d termination (%s)", pid, reason);
    }
    return;
}

void		handle_children(glob_t *g)
{
    time_t	t = time(NULL);
    int		I, i, pipes[8], fd0, fd1, fd2;

    trace(TL_EXEC, "pids = %d, %d", g->children[0].pid, g->children[1].pid);
    bury_children(g);

    if (t > (g->fork_time + (2 * g->ChildDelay)))
    {
	g->fork_time = 0;
	g->fork_delay = g->ChildDelay;
	g->fork_tries = 0;
    }
    /* If any child still active, wait until it dies */
    for (i = 0; i < NB_CHILDREN; i++)
    {
	child_t	*cp = &g->children[i];
	time_t	t = time(NULL);

	if (cp->pid > 0)
	{
	    if (cp->kill_time > 0 && t >= (cp->kill_time + g->ChildLinger))
	    {
		info("killing lingering %s (PID=%d) with SIGKILL", cp->name, cp->pid);
		kill(cp->pid, SIGKILL);
		cp->kill_time = t;
	    }
	    return;
	}
    }
    if (g->fork_time > 0)
    {
	if (g->fork_tries > g->ChildRetries)
	    errexit(EX_FORK, 0, "CRITICAL: aborting after %d burst-forks of children processes", g->ChildRetries);
	if (t < (g->fork_time + g->fork_delay))
	{
	    trace(TL_EXEC, "waiting another %d seconds before forking again",
		(g->fork_time + g->fork_delay) - t);
	    return;
	}
	if (g->fork_tries == (g->ChildRetries / 2))
	    g->fork_delay *= 2;

	g->fork_tries++;
    }

    /*
     *	Fork children
     *
     *	First, open pipes. We need a pair for each of
     *	  - main pipe01 for stdout from(1) child0 to(0) child1 stdin
     *	  - pipe23 for stderr from(3) child0 stderr to(2) us
     *	  - pipe45 for stdout from(5) child1 stdout to(4) us
     *	  - pipe67 for stderr from(7) child1 stderr to(6) us
     *
     *	Reminder: pipe[0] is read-end, pipe[1] is write-end
     */
    for (i = 0; i < (sizeof pipes / (2 * sizeof(int))); i++)
    {
	if (pipe(pipes + (2 *i)) < 0)
	    errexit(EX_PIPE, errno, "cannot create pipes[%d] - Aborting", i);
	else
	    trace(TL_LOGS, "pipe%d:r=%d,w=%d", i, pipes[2*i], pipes[(2*i)+1]);
    }

    trace(TL_EXEC, "starting our %d children: %s -> %s",
	NB_CHILDREN, g->children[0].name, g->children[1].name);
    g->fork_time = time(NULL);
    /*
     *  Welcome to the world of multi-process programming !
     *
     *  After the first pass through the loop below, we will have more than
     *	one process executing the same code. So any code not filtered by the
     *	process-unique I variable will run for all processes !
     */
    I = 0;	/* So far, only the parent */
    for (i = 0; i < NB_CHILDREN; i++)
    {
	child_t	*cp = &g->children[i];
	int	pid;

	if (I == 0)	/* Only the parent forks */
	{
	    if ((pid = fork()) < 0)
		errexit(EX_FORK, errno, "cannot fork process %s", cp->name);
	    else if (pid == 0)
		I = i + 1;	/* powerful line: I now has unique value for each process ! */
	    else
		cp->pid = pid;
	}
    }
    /* Note that we need no loop as all this code is executed by all */
    if (I > 0)		/* For all children */
    {
	fclose(g->rep_fp);
	fclose(g->log_fp);
    }
    fd0 = -1; fd1 = -1; fd2 = -1;
    if (I == 1)		/* Child 0 */
    {
	/* stdin:-, stdout:1, stderr:3 */
	fd1 = dup(pipes[1]);
	fd2 = dup(pipes[3]);
    }
    if (I == 2)		/* Child 1 */
    {
	/* stdin:0, stdout:5, stderr:7 */
	fclose(g->fp0);
	fd0 = dup(pipes[0]);
	fd1 = dup(pipes[5]);
	fd2 = dup(pipes[7]);
    }
    if (I > 0)		/* For all children */
    {
	child_t	*cp = &g->children[I - 1];

	for (i = 0; i < (sizeof pipes / sizeof(int)); i++)
	    close(pipes[i]);

	if ((g->TraceLevel & TL_LOGS) != 0)
	{
	    FILE *fp;

	    if ((fp = fopen(g->log_path, "a")) != NULL)
	    {
		if (I == 1)
		    fprintf(fp, "%s\tnew process PID=%d ready for %s fd1=%d fd2=%d (log_fd=%d)\n",
			tstamp(0, " "), getpid(), cp->name, fd1, fd2, fileno(fp));
		else
		    fprintf(fp, "%s\tnew process PID=%d ready for %s fd0=%d fd1=%d fd2=%d (log_fd=%d)\n",
			tstamp(0, " "), getpid(), cp->name, fd0, fd1, fd2, fileno(fp));
		fclose(fp);
	    }
	}
	execl(cp->path, cp->path, NULL);
	log_sys(g, "cannot exec %s: %s (errno=%d), exiting with code=%d",
	    cp->path, strerror(errno), errno, EX_EXEC);
	exit(EX_EXEC);
    }

    /*
     *	Now that all our chilren have gone to live
     *	their own life, let's care of our own :-)
     */
    for (i = 0; i < NB_CHILDREN; i++)
    {
	child_t	*cp = &g->children[i];

	/* Keep in touch with the kids :-) */
	if (i == 0)
	{
	    close(pipes[0]);
	    close(pipes[1]);
	    cp->err_fp = fdopen(dup(pipes[2]), "r");
	    close(pipes[2]);
	    close(pipes[3]);

	    set_nonblock(fileno(cp->err_fp));
	    trace(TL_LOGS, "%s stderr will be received on fd=%d", cp->name, fileno(cp->err_fp));
	}
	if (i == 1)
	{
	    cp->out_fp = fdopen(dup(pipes[4]), "r");
	    close(pipes[4]);
	    close(pipes[5]);
	    cp->err_fp = fdopen(dup(pipes[6]), "r");
	    close(pipes[6]);
	    close(pipes[7]);

	    set_nonblock(fileno(cp->out_fp));
	    set_nonblock(fileno(cp->err_fp));
	    trace(TL_LOGS, "%s stdout will be received on fd=%d", cp->name, fileno(cp->out_fp));
	    trace(TL_LOGS, "%s stderr will be received on fd=%d", cp->name, fileno(cp->err_fp));
	}
	cp->kill_time = 0;
	info("Started %s (PID=%d)\n", cp->name, cp->pid);
    }
}
/*} End handle children */

/*
 *{==== Program start and end functions ================================
 */
void 		trap_sig(int sig)
{
    info("received signal %s", sigstr(&globals, sig));
    globals.sig = sig;
}

/*
 *  Three tasks in this function:
 *	1: on parse_conf at init, check config values
 *	2: after daemon fork (nv = NULL), apply config values
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
    int		newRld, newRot, i;

    if (g->kill_prg)
	return 0;

    /*
     *	Handle Reload and Rotate signals setup/update
     */
    if (nv != NULL)	/* task 1 or 3 */
    {
	newDir = ValWorkDir(nv) != STRIVAL ? ValWorkDir(nv) : g->DefWorkDir;
	newRld = ValReload(nv) != NUMIVAL ? ValReload(nv) : g->DefReload;
	newRot = ValRotate(nv) != NUMIVAL ? ValRotate(nv) : g->DefRotate;

	/*  Keep TraceLevel from command line until config-reload */
	if (g->SigReload == NUMIVAL && g->TraceLevel != NUMIVAL)
	    ValTraceLevel(nv) = g->TraceLevel;

	if (access(newDir, R_OK|X_OK) != 0)	/* WorkDir not usable */
	{
	    char    *fmt;

	    if (g->RefWorkDir > 0)
		fmt = "%s %s=\"%s\" from %s line %d";
	    else
		fmt = "%s default %s=\"%s\" (unassigned in %s)";

	    if (g->WorkDir == STRIVAL)			/* task 1 */
		errexit(EX_CONF, errno, fmt, "cannot access", g->VarWorkDir, newDir, base_name(g->cfg_path), g->RefWorkDir);

	    if (strcmp(g->WorkDir, newDir) != 0)	 /* task 3 */
	    {
		error(errno, fmt, "discarding inaccessible", g->VarWorkDir, newDir, base_name(g->cfg_path), g->RefWorkDir);
		if (ValWorkDir(nv) != STRIVAL)
		    xfree(ValWorkDir(nv));
		ValWorkDir(nv) = xstrdup(g->WorkDir);
	    }
	    newDir = STRIVAL;
	}

	/* Check if new values will be equal */
	if (newRld == newRot)	/* config error: same sigs ! */
	{
	    char    refRld[32], refRot[32], oldRld[16], oldRot[16];

	    if (g->RefReload > 0)
		snprintf(refRld, sizeof refRld, "line %d", g->RefReload);
	    else
		strcpy(refRld, "default");
	    if (g->RefRotate > 0)
		snprintf(refRot, sizeof refRot, "line %d", g->RefRotate);
	    else
		strcpy(refRot, "default");

	    if (g->SigReload == NUMIVAL)	/* Then SigRotate is also (init) */
	        errexit(EX_CONF, 0, "in file %s, %s (%s) and %s (%s) cannot have the same value %s",
		    g->cfg_path, g->VarReload, refRld, g->VarRotate, refRot, sigstr(g, newRld));

	    /* update */
	    strcpy(oldRld, sigstr(g, g->SigReload));
	    strcpy(oldRot, sigstr(g, g->SigRotate));
	    warn("%s (%s) and %s (%s) have the same value %s in new config !\n"
		"Keeping the old %s=%s and %s=%s",
		g->VarReload, refRld, g->VarRotate, refRot, sigstr(g, newRld),
		g->VarReload, oldRld, g->VarRotate, oldRot);
	    return -1;
	}
	if (g->SigReload == NUMIVAL)	/* task 1 check completed */
	    return 0;

	/* task 3: apply update */
	if (newDir != STRIVAL && chdir(newDir) < 0)
	    error(errno, "chdir(\"%s\")", newDir);

	if ((newRld == g->SigReload && newRot == g->SigRotate) ||
	    (newRld == g->SigRotate && newRot == g->SigReload))
		return 0;	/* No change needed in sig setup */

	/*  If newRld was not already setup, set it up */
	if (newRld != g->SigReload && newRld != g->SigRotate)
	{
	    signal(newRld, trap_sig);
	    siginterrupt(newRld, 1);
	}
	/*  If newRot was not already setup, set it up */
	if (newRot != g->SigRotate && newRot != g->SigReload)
	{
	    signal(newRot, trap_sig);
	    siginterrupt(newRot, 1);
	}
	/* Set any other sig back to default */
	for (i = 0; i < sizeof traps / sizeof(struct trap); i++)
	{
	    if (traps[i].sig != newRld && traps[i].sig != newRot)
	    {
		signal(traps[i].sig, traps[i].def);
		siginterrupt(traps[i].sig, 0);
	    }
	}
	return 0;
    }

    /* task 2: apply setup */
    if (chdir(g->WorkDir) < 0)
	error(errno, "chdir to \"%s\"", g->WorkDir);

    for (i = 0; i < sizeof traps / sizeof(struct trap); i++)
    {
	if (traps[i].sig != g->SigReload && traps[i].sig != g->SigRotate)
	    signal(traps[i].sig, traps[i].def);
    }
    signal(g->SigReload, trap_sig);
    signal(g->SigRotate, trap_sig);
    siginterrupt(g->SigReload, 1);
    siginterrupt(g->SigRotate, 1);

    return 0;
}

bool		set_glob(glob_t *g)
{
    /*
     *	Propagate config value to globals
     */
    g->fork_delay = g->ChildDelay;

    return true;
}

void 		terminate(int sig)
{
    info("received SIGTERM");
    globals.sig = sig;
    globals.loop = 0;	/* exit on SIGTERM */
}

void		onexit()
{
    if (globals.pid_path != NULL)
    {
	if (!isatty(0))
	    info("removing %s", globals.pid_path);
	unlink(globals.pid_path);
    }
}

int		main(int ac, char **av)
{
    glob_t	*g = &globals;
    pid_t	pid;

    parse_args(g, ac, av);
    conf_init(g);
    get_cfgpath(g);
    if (!parse_conf(g, apply_conf, set_glob))
	return EX_CONF;
    check_pidfile(g);

    get_logpath(g);
    get_reppath(g);
    get_cldpaths(g);
    trace(TL_CONF, "cfg_path = %s", g->cfg_path);
    trace(TL_CONF, "pid_path = %s", g->pid_path);
    trace(TL_CONF, "log_path = %s", g->log_path);
    trace(TL_CONF, "rep_path = %s", g->rep_path != NULL ? g->rep_path : "\"\"");
    trace(TL_CONF, "child0_path = %s", g->children[0].path);
    trace(TL_CONF, "child1_path = %s", g->children[1].path);

    if ((pid = fork()) == 0)
    {
	int	max = getdtablesize(), errs = 0, fd;

	atexit(onexit);

	trace(TL_EXEC, "becoming a daemon");
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

	g->fp0 = fopen("/dev/null", "r");	/* daemon's fd0 */
	open_logs(g);

	if (g->rep_path != NULL)
	{
	    fprintf(g->rep_fp, "%s ================================================\n", tstamp(0, " "));
	    fflush(g->rep_fp);
	}
	info("================================================");
	info("Starting %s PID=%d - Reload sig is %s", g->prg, getpid(), sigstr(g, g->SigReload));
	trace(TL_LOGS, "rep=%s fd=%d log=%s fd=%d",
	    g->rep_path != NULL ? g->rep_path : g->log_path,
	    fileno(g->rep_fp), g->log_path, fileno(g->log_fp));

	signal(SIGINT, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, terminate);
	siginterrupt(SIGTERM, 1);
	apply_conf(g, NULL);
	g->loop = 1;

	while (g->loop > 0)
	{
	    handle_logs(g);		/* centralize logs */
	    handle_children(g);		/* includes 1st forks */

	    if (g->sig > 0)
	    {
		if (g->sig == g->SigReload)
		{
		    int	old_reload = g->SigReload;

		    if (parse_conf(g, apply_conf, set_glob))
			kill_children(g, old_reload);
		}
		else if (g->sig == g->SigRotate)
		{
		    open_logs(g);
		    trace(TL_LOGS, "rep=%s fd=%d log=%s fd=%d",
			g->rep_path != NULL ? g->rep_path : g->log_path,
			fileno(g->rep_fp), g->log_path, fileno(g->log_fp));
		}
		else if (g->sig == SIGTERM)
		    kill_children(g, SIGTERM);

		g->sig = 0;
	    }
	}
	usleep(500 * 1000);
	handle_logs(g);
	info("exit from main loop (=%d)", g->loop);
    }
    else if (pid > 0)
    {
	FILE	*fp;

	if ((fp = fopen(g->pid_path, "w")) != NULL)
	{
	    fprintf(fp, "%d\n", pid);
	    fclose(fp);
	}
	else
	    errexit(EX_PID, errno, "cannot create \"%s\"", g->pid_path);

	printf("%s started (PID=%d)\n", g->prg, pid);
    }
    else
	errexit(EX_FORK, errno, "cannot fork daemon process");

    return EX_OK;
}
/*} End program start/end */
