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
 *	- kill them both if SIGTERM
 *	- pass on SIGUSR1
 */
#define _GNU_SOURCE
#define _BSD_SOURCE

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
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#if 0
#endif

/* Exit codes */
#define EX_OK		0
#define EX_USAGE	1
#define EX_CONF		2
#define EX_PATH		3
#define EX_FORK		4

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

typedef union	cfgval_u
{
#   define	STRIVAL	NULL
#   define	NUMIVAL	-1
    char	*s;
    int		i;
}		cfgval_t;

typedef struct	cfgvar_s
{
    char	*name;
    short	isupd;		/* 1 if var updatable on reloads */
    short	isint;		/* 1 if var is int (vs str) */
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
}		child_t;

typedef	struct	glob_s
{
#define	BinDir		config[0].val.s
#define	LogDir		config[1].val.s
#define	RunDir		config[2].val.s
#define	SessDir		config[3].val.s
#define	LogWait		config[4].val.i
#define	TraceLevel	config[5].val.i
#define CFG_IVALS	{ {.s=STRIVAL}, {.s=STRIVAL}, {.s=STRIVAL}, {.s=STRIVAL}, {.i=NUMIVAL}, {.i=NUMIVAL} }
#define NB_CFGVARS	6
    cfgvar_t	config[NB_CFGVARS];

    char	buf[32];
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
    int		nb_cv;

    int		loop;
    int		sig;
    time_t	now;
}		glob_t;

/*  'globals' is used in main(), signal handlers and log functions */
glob_t		globals = {
    {
	{ "bin_dir",		0, 0, { .s = STRIVAL },	{ .s = "/usr/bin" },	{} },
	{ "log_dir",		0, 0, { .s = STRIVAL },	{ .s = "/var/log/%s" },	{} },
	{ "run_dir",		0, 0, { .s = STRIVAL },	{ .s = "/run/%s" },	{} },
	{ "sess_dir",		0, 0, { .s = STRIVAL },	{ .s = "/var/lib/php/sessions" }, {} },
	{ "log_wait",		1, 1, { .i = NUMIVAL },	{ .i = 5 },		{} },
	{ "dtrace_level",	1, 1, { .i = NUMIVAL },	{ .i = 0 },		{} }
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

#define trace(l,f,a...)		trcmsg(l,__FUNCTION__,__LINE__,f,##a)

#define errexit(x,e,f,a...)	xitmsg(x,e,__FUNCTION__,__LINE__,f,##a)
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

void		xitmsg(int xcode, int syserr, const char *fn, int ln, char *fmt, ...)
{
    va_list	ap;
    char	buf[LOG_BUF_SIZE];

    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);

    logline(syserr, fn, ln, "ERROR: ", buf);

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

void		dead_care(glob_t *g)
{
    pid_t	pid;
    char	reason[32];
    int		i;

    while ((pid = dead_wait(reason)) > 0)
    {
	for (i = 0; i < (sizeof g->children / sizeof(child_t)); i++)
	{
	    if (pid == g->children[i].pid)
	    {
		char    *msg = "%s PID=%d stopped (%s)";

		if (reason[0] == '!')
		    report(msg, g->children[i].name, pid, reason + 1);
		else
		    info(msg, g->children[i].name, pid, reason);
		g->children[i].pid = 0;
	    }
	    else
		report("unknown process PID=%d termination (%s)", pid, reason);
	}
    }
    return;
}

/*
 * ====	Parse config file ==============================================
 *
 *  Initialize 'globals.config'
 */
char	*re_err(regex_t *rep, int errcode)
{
    static char	msg[1024];

    regerror(errcode, rep, msg, sizeof msg);

    return msg;
}

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

/*
 *  Determine config path
 */
void	get_cfgpath(glob_t *g)
{
    char    ev[32];
    char    path[PATH_MAX];
    char    *p;
    int	    i;

    if (g->cfg_path != NULL)	/* Was set by parse_args */
	return;

    /* Make variable name */
    if (snprintf(ev, sizeof ev, CFGPATH_ENVFMT, g->pkg) >= sizeof ev)
	errexit(EX_CONF, 0, "cannot make configuration file env variable");
    for (i = 0; i < strlen(g->pkg); i++)
	ev[i] = toupper(ev[i]);
    trace(TL_CONF, "env var = %s", ev);

    /* Try from getenv */
    if ((p = getenv(ev)) != NULL)
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
	return;
    }

    /* Try from default config dir */
    snprintf(path, sizeof path, CFG_DEFDIR "/%s.conf", g->pkg);
    trace(TL_CONF, "trying cfg_path = %s", path);
    if (access(path, R_OK) == 0)
    {
	g->cfg_path = xstrdup(path);	/* free: never (init 3) */
	return;
    }
    errexit(EX_CONF, 0, "cannot find config-file %s.conf in args, env, %s or " CFG_DEFDIR, g->pkg, g->cfg_path);
}

/*
 *  Parse config file (called at init and config reloads)
 */
void	parse_conf(glob_t *g)
{
    regmatch_t	match[NB_CFGV_RESUBS], *mp = &match[1];
    cfgval_t	nv[NB_CFGVARS] = CFG_IVALS;
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
		    int	val = atoi(p);

		    xfree(p);	/* not needed for integer */
		    if (nv[iv].i != NUMIVAL)
			notice("in %s line %d, %s redefined: %d -> %d", g->cfg_path, 1 + ln, vp->name, nv[iv].i, val);
		    else
			trace(TL_CONF, "in %s line %d: %s = %d", g->cfg_path, 1 + ln, vp->name, val);
		    nv[iv].i = val;
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
		    xfree(vp->val.s);
		vp->val.s = xstrdup(p);
	    }
	    else if (nv[iv].s == STRIVAL || strcmp(vp->val.s, nv[iv].s) != 0)
		notice("config %s will only be updated to \"%s\" at %s restart", vp->name, p, g->prg);
	    trace(TL_CONF, "config['%s'] = \"%s\"", vp->name, vp->val.s);
	}
    }
}

/*
 *=====	Parse command line and exe filename ============================
 */
char	*check_abs(char *p)
{
    if (*p != '/')
	errexit(EX_USAGE, 0, "specified path \"%s\" must be absolute", p);
    return p;
}

void	parse_args(glob_t *g, int ac, char **av)
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
	    case 't':	g->TraceLevel = atoi(optarg);			break;
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

char    *path_split(char *path, char **file)
{
    static  char    dir[PATH_MAX];
    char    *p;

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
void	check_paths(glob_t *g)
{
    char    *spec, *dir, *file;
    int	    i;

    /*
     *	Log-file. Try:
     *	    file given with -l
     *	    <pkg>.log in log_dir
     */
    spec = " specified";
    if (g->log_path == NULL)	/* Was not in command line */
    {
	xasprintf(&g->log_path, "%s/%s.log", g->LogDir, g->pkg);	/* free: never (init or abort) */
	spec = "";
    }
    trace(TL_CONF, "trying log_path = %s", g->log_path);
    if (access(g->log_path, W_OK) != 0)		/* file not writable */
    {
	if (access(g->log_path, F_OK) == 0)	/* file exists, not writable */
	    errexit(EX_PATH, 0, "cannot write to%s log-file %s", spec, g->log_path);

	dir = path_split(g->log_path, &file);	/* Get dir and file parts */
	trace(TL_CONF, "trying log_dir = %s", dir);
	if (access(dir, W_OK) != 0)		/* dir not writable */
	    errexit(EX_PATH, 0, "cannot create log-file %s in dir %s", file, dir);
    }

    /*
     *  Report-file: check arg or its dir are writable
     */
    if (g->rep_path != NULL)	/* Only from command line */
    {
	trace(TL_CONF, "trying rep_path = %s", g->rep_path);
	if (access(g->rep_path, W_OK) != 0)	/* file not writable */
	{
	    if (access(g->rep_path, F_OK) == 0)	/* file exists, not writable */
		errexit(EX_PATH, 0, "cannot write to specified report-file %s", g->rep_path);

	    dir = path_split(g->rep_path, &file);	/* Get dir and file parts */
	    trace(TL_CONF, "trying rep_dir = %s", dir);
	    if (access(dir, W_OK) != 0)			/* dir not writable */
		errexit(EX_PATH, 0, "cannot create report-file %s in dir %s", file, dir);
	}
    }

    /*
     *	Pid-file: just check run_dir is writable
     */
    trace(TL_CONF, "trying run_dir = %s", g->RunDir);
    if (access(g->RunDir, W_OK) != 0)
	errexit(EX_PATH, 0, "cannot write to directory %s", g->RunDir);

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

void	setup_loop(glob_t *g)
{
/* XXX */
}

void	handle_children(glob_t *g)
{
}

void	handle_logs(glob_t *g)
{
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
    pid_t	pid;

    parse_args(g, ac, av);
    conf_init(g);
    parse_conf(g);
    check_paths(g);
exit(0);
    if ((pid = fork()) == 0)
    {
	int	max = getdtablesize(), errs = 0, fd;

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

	signal(SIGHUP, trap_sig);
	signal(SIGINT, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, terminate);
	signal(SIGTERM, trap_sig);
	siginterrupt(SIGHUP, 1);
	siginterrupt(SIGTERM, 1);
	setup_loop(g);

	while (g->loop)
	{
	    time(&g->now);
	    handle_children(g);
	    handle_logs(g);
	}
    }
    else if (pid > 0)
	printf("%s started (PID=%d)\n", g->prg, pid);
    else
	errexit(EX_FORK, errno, "fork");

     return EX_OK;
}
