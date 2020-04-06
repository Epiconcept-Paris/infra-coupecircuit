/*
 *	nbphpsessd.c
 *
 *	- become daemon
 *	- Setup av[1] and av[2] connected by pipes
 *	- if av[3] passed, it is log file
 *	- optional log connected to fd=2 (av[1]) and fd=1,2 (av[2])
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
#define EX_FORK		2
#define EX_PROG		8
#define EX_NOMEM	9

/* trace levels */
#define TL_1		1
#define TL_2		2
#define TL_3		4
#define TL_4		8

#define LOG_BUF_SIZE	4096

#define CFGPATH_ENVFMT	"%s_CONF"

/* Parse regexp format (28 chr) for config (%s) values */
#define CFGVAR_REFMT	"^\\s*%s\\s*=\\s*(\\S*)\\s*(#.*)?$"
#define NB_CFGV_RESUBS	3

typedef struct	cfgvar_s
{
    char	*name;
    int		isint;
    union val_u
    {
	char	*s;
	int	i;
    }		val;
    union val_u	def;		/* default */
    regex_t	*regexp;	/* compiled regex */
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
    char	*prg;		/* basename from av[0] */
    char	*prg_dir;
    char	*prg_path;	/* actual binary path */
    char	*pkg;		/* our package name (final 'd' removed) */

    time_t	p_start;
    child_t	children[2];

    char	*log_path;
    char	*rep_path;
    FILE	*log_fp;
    FILE	*rep_fp;

    char	*pid_path;
    char	*cfg_path;
    int		nb_cv;
    cfgvar_t	*config;

    int		loop;
    int		sig;
    time_t	now;
}		glob_t;

/*
 *  globals is used in main(), signal handlers and log functions
 */
glob_t		globals;

void		glob_init(glob_t *g)
{
#   define	BinDir		config[0].val.s
#   define	LogDir		config[1].val.s
#   define	RunDir		config[2].val.s
#   define	SessDir		config[3].val.s
#   define	LogWait		config[4].val.i
#   define	TraceLevel	config[5].val.i
    static	cfgvar_t cv[] =
    {
	{ "bin_dir",		0, { NULL },	{ .s = "/usr/bin" },	NULL	},
	{ "log_dir",		0, { NULL },	{ .s = "/var/log/%s" },	NULL	},
	{ "run_dir",		0, { NULL },	{ .s = "/run/%s" },	NULL	},
	{ "sess_dir",		0, { NULL },	{ .s = "/var/lib/php/sessions" }, NULL	},
	{ "log_wait",		1, { .i = -1 },	{ .i = 5 },		NULL	},
	{ "trace_level",	1, { .i = -1 },	{ .i = 0 },		NULL	}
    };
    g->config = cv;
    g->nb_cv = sizeof cv / sizeof(cfgvar_t);
}

/*
 * ====	Logging and tracing functions ==================================
 */
char		*now(char *sep)	/* Only for logline() just below */
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

/*  Log line (called by xitmsg(), logmsg() and trace()) */
void		logline(int syserr, const char *fn, int ln, char *tag, char *msg)
{
    FILE	*fp;

    if (globals.log_fp != NULL)
    {
	fp = globals.log_fp;
	fprintf(fp, "%s\t%s(line=%d)\t%s%s", now(" "), fn, ln, tag, msg);
    }
    else
    {
	fp = stderr;
	fprintf(fp, "%s: %s", globals.prg, msg);
    }
    if (syserr > 0)
	fprintf(fp, ": %s (errno=%d)\n", strerror(syserr), syserr);
    else
	fputs("\n", fp);
    fflush(fp);
}

#define errexit(x,e,f,a...)	xitmsg(x,e,__FUNCTION__,__LINE__,f,##a)
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
 *	info("pid=%d sd=%d net write=0", s->pid, s->netsd);
 *	trace(TL_T1, "output_fd=%d", e->output_fd);
 *	error(errno, "pid=%d sd=%d net write", s->pid, s->netsd);
 *	error(0, "discarding invalid IAC 0x%X", p[1]);
 */
#define info(f,a...)	logmsg(0,__FUNCTION__,__LINE__,"",f,##a)
#define notice(f,a...)	logmsg(0,__FUNCTION__,__LINE__,"NOTICE: ",f,##a)
#define warn(f,a...)	logmsg(0,__FUNCTION__,__LINE__,"WARNING: ",f,##a)
#define report(f,a...)	logmsg(0,__FUNCTION__,__LINE__,"REPORT: ",f,##a)

#define error(e,f,a...)	logmsg(e,__FUNCTION__,__LINE__,"ERROR: ",f,##a)
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

#define trace(l,f,a...)	trcmsg(l,__FUNCTION__,__LINE__,,f,##a)
void		trcmsg(int level, const char *fn, int ln, char *fmt, ...)
{
    va_list	ap;
    char	buf[LOG_BUF_SIZE];
    char	*line, *p;
    int		first = true;

    if ((level & globals.TraceLevel) == 0)
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
	p = xmalloc(len + 1);
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

    /* Try from getenv */
    if ((p = getenv(ev)) != NULL)
    {
	if (access(p, R_OK))
	{
	    g->cfg_path = xstrdup(p);
	    return;
	}
    }
    /* Try from prg_dir */
    snprintf(path, sizeof path, "%s/%s.conf", g->prg_dir, g->pkg); 
    if (access(path, R_OK))
    {
	g->cfg_path = xstrdup(path);
	return;
    }
    /* Try from /etc */
    snprintf(path, sizeof path, "/etc/%s.conf", g->pkg); 
    if (access(path, R_OK))
    {
	g->cfg_path = xstrdup(path);
	return;
    }
    errexit(EX_CONF, 0, "cannot find config-file %s.conf in args, env, %s or /etc", g->prg_dir);
}

char	*re_err(regex_t *rep, int errcode)
{
    static char	msg[1024];

    regerror(errcode, rep, msg, sizeof msg);

    return msg;
}

void	parse_conf(glob_t *g)
{
    regmatch_t	match[NB_CFGV_RESUBS];
    char    *refmt = CFGVAR_REFMT;
    char    re[64];
    char    *buf, *p;
    char    **lines;
    int	    nl, ln, i, err;

    get_cfgpath(g);

    if ((buf = getfile(g->cfg_path)) == NULL)
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

    lines = xmalloc(nl * sizeof *lines);
    ln = 0;
    p = buf;
    while ((lines[ln] = strsep(&p, "\n")) != NULL)
    {
	if (lines[ln][0] == '\0' || lines[ln][0] == '#')
	    continue;	/* empty or comment line */
	if (ln <= nl)
	    ln++;
	else
	    warn("more lines than %d counted in file %s ?", nl, g->cfg_path);
    }
    /* Compile rexexps if needed */
    for (i = 0; i < g->nb_cv; i++)
    {
	snprintf(re, sizeof re, refmt, g->config[i].name);
	if (g->config[i].regexp == NULL)
	{
	    g->config[i].regexp = xmalloc(sizeof(regex_t));
	    if ((err = regcomp(g->config[i].regexp, re, REG_EXTENDED)) != 0)
		errexit(EX_PROG, 0, "regcomp error for %s: %s", g->config[i].name, re_err(g->config[i].regexp, err));
	    if (g->config[i].regexp->re_nsub > (NB_CFGV_RESUBS - 1))
		errexit(EX_PROG, 0, "regcomp requires more than %d matches for %s", NB_CFGV_RESUBS - 1, g->config[i].name);
	}
    }
    for (ln = 0; ln < nl; ln++)
    {
	for (i = 0; i < g->nb_cv; i++)
	{
	    if ((err = regexec(g->config[i].regexp, lines[ln], NB_CFGV_RESUBS, match, 0)) == 0)
	    {
		xasprintf(&p, ".*s", match[1].rm_eo - match[1].rm_so, lines[ln] + match[1].rm_so);
		if (g->config[i].isint)
		{
		    g->config[i].val.i = atoi(p);
		    xfree(p);
		}
		else
		    g->config[i].val.s = p;
	    }
	    else if (err != REG_NOMATCH)
		warn("regexec error line %d for %s: %s", ln, g->config[i].name, re_err(g->config[i].regexp, err));
	    regfree(g->config[i].regexp);
	}
    }
    for (i = 0; i < g->nb_cv; i++)
    {
	if (g->config[i].isint)
	{
	    if (g->config[i].val.i < 0)
		g->config[i].val.i = g->config[i].def.i;
	    info("config['%s'] = %d", g->config[i].name, g->config[i].val.i);
	}
	else
	{
	    if (g->config[i].val.s == NULL)
	    {
		if (strchr(g->config[i].def.s, '%') != NULL)
		    xasprintf(&g->config[i].val.s, g->config[i].def.s, g->pkg);
		else
		    g->config[i].val.s = xstrdup(g->config[i].def.s);
	    }
	    info("config['%s'] = \"%s\"", g->config[i].name, g->config[i].val.s);
	}
    }
    xfree(lines);
}

/*
 *=====	Parse command line and exe filename ============================
 */
void	parse_args(glob_t *g, int ac, char **av)
{
    char	*p;
    int		argerr = 0, len, val;

    g->prg_path = getfile("/proc/self/exe");
    if ((p = strrchr(av[0], '/')) != NULL)
    {
	*p = '\0';
	g->prg = ++p;
	g->prg_dir = xstrdup(av[0]);
    }
    else
    {
	g->prg = av[0];
	if ((p = strrchr(g->prg_path, '/')) == NULL)
	    errexit(EX_PROG, 0, "no '/' in binary path %s ??", g->prg_path);
	xasprintf(&g->prg_dir, "%.*s", p - g->prg_path, g->prg_path);
    }
    if ((len = strlen(g->prg)) > 0)
    {
	if (g->prg[len - 1] == 'd')
	    len--;
	xasprintf(&g->pkg, "%.*s", len, g->prg);
    }

    while ((val = getopt(ac, av, "f:l:r:")) != EOF)
    {
	switch (val)
	{
	    case 'f':	g->cfg_path = xstrdup(optarg);	break;
	    case 'l':	g->log_path = xstrdup(optarg);	break;
	    case 'r':	g->rep_path = xstrdup(optarg);	break;
	    default:	argerr = 1;			break;
	}
    }
    if (argerr || (ac - optind) < 2)
	errexit(EX_USAGE, 0, "Usage: %s [-f conf-file] [-l log-file] [-r report-file] task-prog report-prog", g->prg);
    ac -= optind;
/* XXX */
}

void	check_paths(glob_t *g)
{
}

void	setup_loop(glob_t *g)
{
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

    glob_init(g);
    parse_args(g, ac, av);
    parse_conf(g);
    check_paths(g);

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
