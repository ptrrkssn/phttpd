h59505
s 00643/00000/00000
d D 1.1 98/02/18 17:36:36 rk 1 0
c date and time created 98/02/18 17:36:36 by rk
e
u
U
f e 0
t
T
I 1
/*
** main.c
**
** Copyright (c) 1994-1997 Peter Eriksson <pen@signum.se>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <thread.h>
#include <errno.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <netdb.h>
#include <fcntl.h>
#include <syslog.h>
#include <signal.h>
#include <sys/filio.h>

#include <sys/systeminfo.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <dlfcn.h>

#ifndef RTLD_GLOBAL
#define RTLD_GLOBAL 0
#endif


#define IN_MAIN_C
#include "phttpd.h"

#define CONFIG_FILE     INSTROOT "/etc/phttpd.conf"

#define DEFAULT_LOGFILE "/var/log/phttpd/requests"
#define DEFAULT_PIDFILE "/var/log/phttpd/pid"
#define DEFAULT_ERRFILE "/var/log/phttpd/stderr"
#define DEFAULT_CNTFILE "/var/log/phttpd/counts"




static struct table *global_modules = NULL;


struct options global_cfg_table[] =
{
    { "auth-handlers",     T_TABLE, &auth_handlers_table,	NULL, 0, 0, NULL },
    { "url-handlers",      T_TABLE, &url_handlers_table,	NULL, 0, 0, NULL },
    { "url-redirects",     T_TABLE, &url_redirects_table,	NULL, 0, 0, NULL },
    { "url-permanent-redirects",     T_TABLE, &url_predirects_table,	NULL, 0, 0, NULL },
    { "url-rewrites",      T_TABLE, &url_rewrites_table,	NULL, 0, 0, NULL },
    { "read-authenticate",  T_TABLE, &read_authenticate_table,    NULL, 0, 0, NULL },
    { "write-authenticate",  T_TABLE, &write_authenticate_table,    NULL, 0, 0, NULL },
    { "host-access",        T_TABLE, &host_access_table,          NULL, 0, 0, NULL },
    { "content-language",  T_TABLE, &content_language_table,	NULL, 0, 0, NULL },
    { "url-expand",	   T_TABLE, &url_expand_table,		NULL, 0, 0, NULL },
    { "error-pages",	   T_HTABLE, &error_page_table,		NULL, 0, 0, NULL },
    { "global-modules",	   T_TABLE, &global_modules,            NULL, 0, 0, NULL },

    { "config-file",	   T_FILE,   NULL,			NULL, 'f', 0, NULL, "Path to config file" },
    
    { "database-dir",      T_STRING, &server_home,		NULL, 0, 0, NULL, "Path to database directory" },
    { "server-name",       T_STRING, &server_host,		NULL, 0, 0, NULL, "Official FQDN name of server" },
    { "server-addr",       T_STRING, &server_addr,		NULL, 0, 0, NULL, "Address to bind server to" },
    { "modules-dir",	   T_STRING, &modules_home,             NULL, 0, 0, NULL, "Path to modules directory" },
    { "user-dir",          T_STRING, &user_dir,			NULL, 0, 0, NULL, "Users public directory" },
    { "user-basedir",      T_STRING, &user_basedir,		NULL, 0, 0, NULL, "Base directory for all users" },
    { "logging-file",      T_STRING, &logfile_path,		NULL, 'L', 0, DEFAULT_LOGFILE, "Path to requests logging file" },
    { "counting-file",     T_STRING, &cntfile_path,             NULL, 'C', 0, DEFAULT_CNTFILE, "Path to requests counter database" },
    { "pid-file",          T_STRING, &pidfile_path,             NULL, 'P', 0, DEFAULT_PIDFILE, "Path to PID file" },
    { "stderr-file",       T_STRING, &errfile_path,             NULL, 'E', 0, DEFAULT_ERRFILE, "Path to stderr log file" },
    
    { "web-admin-name",    T_STRING, &web_admin_name,           NULL, 0, 0, NULL,  "Webmaster's name" },
    { "web-admin-home",    T_STRING, &web_admin_home,           NULL, 0, 0, NULL,  "Webmaster's home URL" },
    { "web-admin-email",   T_STRING, &web_admin_email,          NULL, 0, 0, NULL,  "Webmaster's email address" },
    
    { "server-user",       T_STRING, &server_user,		NULL, 'u', 0, NULL, "Server user name or number" },
    { "server-group",      T_STRING, &server_group,		NULL, 'g', 0, NULL, "Server group name or number" },

    { "debug-level",	   T_NUMBER, &debug,			NULL, 'd', 1, NULL, "Debug level" },

    { "fscache-size",      T_NUMBER, &fscache_size,             NULL, 0, 0, NULL, "Fscache size" },
    { "fscache-refresh",   T_NUMBER, &fscache_refresh,          NULL, 0, 0, NULL, "Fscache refresh interval" },
    { "fscache-ttl",       T_NUMBER, &fscache_ttl,              NULL, 0, 0, NULL, "Fscache time-to-live" },
    { "fscache-gc-interval", T_NUMBER, &fscache_gc_interval,    NULL, 0, 0, NULL, "Fscache garbage collect interval" },

    { "hostcache-size",      T_NUMBER, &hostcache_size,             NULL, 0, 0, NULL, "Hostcache size" },
    { "hostcache-refresh",   T_NUMBER, &hostcache_refresh,          NULL, 0, 0, NULL, "Hostcache refresh interval" },
    { "hostcache-ttl",       T_NUMBER, &hostcache_ttl,              NULL, 0, 0, NULL, "Hostcache time-to-live" },
    { "hostcache-gc-interval", T_NUMBER, &hostcache_gc_interval,    NULL, 0, 0, NULL, "Hostcache garbage collect interval" },

    { "usercache-size",      T_NUMBER, &usercache_size,             NULL, 0, 0, NULL, "Usercache size" },
    { "usercache-refresh",   T_NUMBER, &usercache_refresh,          NULL, 0, 0, NULL, "Usercache refresh interval" },
    { "usercache-ttl",       T_NUMBER, &usercache_ttl,              NULL, 0, 0, NULL, "Usercache time-to-live" },
    { "usercache-gc-interval", T_NUMBER, &usercache_gc_interval,    NULL, 0, 0, NULL, "Usercache garbage collect interval" },

    { "urlcache-size",      T_NUMBER, &urlcache_size,             NULL, 0, 0, NULL, "Urlcache size" },
    { "urlcache-refresh",  T_NUMBER, &urlcache_refresh,         NULL, 0, 0, NULL, "Urlcache refresh interval" },
    { "urlcache-ttl",      T_NUMBER, &urlcache_ttl,             NULL, 0, 0, NULL, "Urlcache time-to-live" },
    { "urlcache-gc-interval", T_NUMBER, &urlcache_gc_interval,     NULL, 0, 0, NULL, "Urlcache garbage collect interval" },
    

    { "server-port",       T_NUMBER, &server_port,		NULL, 'p', 8000, NULL, "Servers' TCP port" },

    { "concurrency",       T_NUMBER, &concurrency,		NULL, 0, 0, NULL,   "Threads concurrency level" },
    { "listen-backlog",    T_NUMBER, &n_listen,			NULL, 'b', 1024, NULL, "Listen backlog level" },
    { "socket-sndbuf",     T_NUMBER, &so_sndbuf, 	        NULL, 0, 0, NULL, "Size of socket send buffer" },
    { "socket-rcvbuf",     T_NUMBER, &so_rcvbuf, 	        NULL, 0, 0, NULL, "Size of socket receive buffer" },
    { "gc-time",           T_NUMBER, &gc_time,			NULL, 0, 0, NULL, "Connection time-to-live" },
    { "gc-sleep",          T_NUMBER, &gc_sleep,			NULL, 0, 0, NULL, "Connection garbage collect interval" },
    { "select-timeout",    T_NUMBER, &select_timeout,		NULL, 'T', 0, NULL, "Select timeout limit" },
    { "max-url-size",	   T_NUMBER, &maxurlsize,		NULL, 0, 0, NULL, "Max length of request URL"},
    { "write-needs-auth",  T_BOOL, &write_needs_auth,           NULL, 0, 1, NULL, "Upload may allways needs auth "},
    { "rkmultimode",       T_BOOL, &rkmultimode,		NULL, 0, 0, NULL, "Multimode URL expanding %lx"},
    { "software-virtual-server",       T_BOOL, &softvirtserver,	NULL, 0, 0, NULL, "Enable Sotware-Virtual-Server via HTTP/1.1"},
    { "logheadervolume",       T_BOOL, &logheadervolume,	NULL, 0, 1, NULL, "Add headervolume to size in logfile"},
    { "extended-logging",  T_BOOL, &extended_logging,		NULL, 0, 1, NULL, "Enable extended logging" },
    { "keepalive-connections", T_BOOL, &keepalive_enabled,      NULL, 0, 1, NULL, "Enable Keep-Alive connections" },
    { "bound-threads",	   T_BOOL,   &bound_threads,		NULL, 'B', 1, NULL, "Use bound threads" },
    { "hostname-lookups",  T_BOOL,   &hostname_lookups,         NULL, 'H', 1, NULL, "Perform hostname lookups" },
    { "ident-lookups",  T_BOOL,   &ident_lookups,         NULL, 'I', 1, NULL, "Perform IDENT lookups" },
    { "no-copying-info",   T_BOOL,   &no_copying_info,          NULL, 's', 1, NULL, "Don't display the copying info" },
    { "wait-mode",	   T_BOOL,   &wait_mode,		NULL, 'w', 1, NULL, "Start server in 'wait' mode" },
    
    { NULL,                -1,       NULL,			NULL, 0, 0, NULL, NULL }
};




static char *get_local_hostname(char *buf,
				int size)
{
    struct hostent *hp, hb;
    char hb_buf[1024];
    int i, len, h_errno;

    
    if (sysinfo(SI_HOSTNAME, buf, size) < 0)
	return NULL;

    if (strchr(buf, '.') != NULL)
	return buf;

    hp = s_gethostbyname_r(buf, &hb, hb_buf, sizeof(hb_buf), &h_errno);
    if (hp == NULL)
    {
	syslog(LOG_WARNING, "unable to find FQDN for %s", buf);
	return buf;
    }
    
    if (hp->h_name && strchr(hp->h_name, '.') != NULL)
    {
	len = s_strcpy(buf, size, hp->h_name);
	if (len > 0 && len < size-1)
	    return buf;

	/* else name too long, try to find a shorter in the aliases list */
    }

    if (hp->h_aliases)
	for (i = 0; hp->h_aliases[i]; i++)
	{
	    if (strchr(hp->h_aliases[i], '.') != NULL)
	    {
		len = s_strcpy(buf, size, hp->h_aliases[i]);
		if (len > 0 && len < size-1)
		    return buf;
		
		/* else name too long, try to find a shorter one later */
	    }
	}
    
    syslog(LOG_WARNING, "unable to find FQDN for %s", buf);
    return buf;
}

int uidgid_get(const char *user,
	       const char *group,
	       uid_t *uid,
	       gid_t *gid,
	       struct passwd **pwp,
	       struct passwd *pwb,
	       char *pbuf,
	       int pbuflen)
{
    struct group *grp, grb;
    char gbuf[2048];
    
    
    if (user != NULL)
    {
	if (s_isdigit(user[0]))
	{
	    *uid = atoi(user);
	    *pwp = s_getpwuid_r(*uid, pwb, pbuf, pbuflen);
	}
	else
	{
	    *pwp = s_getpwnam_r(user, pwb, pbuf, pbuflen);

	    if (*pwp == NULL)
		return -1;
	    
	    *uid = (*pwp)->pw_uid;
	}

	if (*pwp)
	    *gid = (*pwp)->pw_gid;
    }


    if (group != NULL)
    {
	if (s_isdigit(group[0]))
	    *gid = atoi(group);
	else
	{
	    grp = s_getgrnam_r(group, &grb, gbuf, sizeof(gbuf));
	    if (grp == NULL)
		return -2;
	    
	    *gid = grp->gr_gid;
	}
    }

    return 0;
}




static int load_global_module(void *value, void *misc)
{
    void *obj;
    char **vp;
    char buf[2048], *cp;
    int (*pm_init)(const char **argv);
    const char *argv[2];

    
    vp = (char **) value;
    if (vp == NULL || vp[0] == NULL)
	return 0;
    cp = vp[0];
    
    
    if (debug > 1)
	fprintf(stderr, "Loading module %s\n", cp);
    

    if (*cp != '/')
    {
	s_strcpy(buf, sizeof(buf), modules_home);
	s_strcat(buf, sizeof(buf), "/");
	s_strcat(buf, sizeof(buf), cp);
    }
    else
	s_strcpy(buf, sizeof(buf), cp);

    
    obj = dlopen(buf, RTLD_NOW+RTLD_GLOBAL);
    if (obj == NULL)
    {
	syslog(LOG_ERR, "load_global_module(\"%s\") failed: %m", cp);
	return 0;
    }

    pm_init = (int (*)(const char **)) dlsym(obj, "pm_init");
    if (pm_init)
    {
	argv[0] = cp;
	argv[1] = NULL;
	
	if ((*pm_init)(argv) < 0)
	{
	    syslog(LOG_ERR, "global module %s init failed: %m", cp);
	    dlclose(obj);
	    return 0;
	}
    }

    return 0;
}

static void load_global_modules(struct table *mt)
{
    if (mt == NULL)
	return;

    tbl_foreach(mt, &load_global_module, NULL);
}


static int setup_server_host(void)
{
    static char host_name[1024];

    
    if (server_host == NULL)
    {
	if (get_local_hostname(host_name, sizeof(host_name)) == NULL)
	{
	    syslog(LOG_ERR, "get_local_hostname() failed: %m");
	    return -1;
	}

	server_host = host_name;
    }

    return 0;
}



static void display_banner(void)
{
    printf("[Phttpd %s - Copyright (c) 1995-1997 Peter Eriksson <pen@signum.se>]\n\n",
    server_version);
}


static void display_copying(void)
{
    puts("\tPhttpd comes with ABSOLUTELY NO WARRANTY. This is free software,");
    puts("\tand you are welcome to redistribute it under certain conditions;");
    puts("\tfor more information about the conditions and non-warranty, see:");
    puts("\n\t\thttp://www.signum.se/phttpd/COPYING.html\n");
    puts("\tor read the file COPYING that should have been part of the");
    puts("\tsoftware distribution - if not send an email to <pen@signum.se>.");
    puts("");
}


static int setup_uidgid(void)
{
    if ( initgroups(server_user,server_gid) < 0 )
    {
	syslog(LOG_ERR, "initgroups(\"%s\", %d) failed: %m",
	       server_user, server_gid);
	return -1;
    }

    if (server_gid != -1)
	if (setegid(server_gid) < 0)
	{
	    syslog(LOG_ERR, "setegid(%d) failed: %m", server_gid);
	    return -1;
	}
    
    if (server_uid != -1)
	if (seteuid(server_uid) < 0)
	{
	    syslog(LOG_ERR, "seteuid(%d) failed: %m", server_uid);
	    return -1;
	}

    return 0;
}



static void create_pidfile(void)
{
    int fd;

    
    if (pidfile_path == NULL)
	return;
    
    fd = fd_open(pidfile_path, O_WRONLY+O_CREAT+O_TRUNC, 0644);
    if (fd < 0)
	syslog(LOG_ERR,
	       "fd_open(\"%s\", O_WRONLY+O_CREAT+O_TRUNC) failed: %m",
	       pidfile_path);
    else
    {
	fd_printf(fd, "%d\n", getpid());
	fd_close(fd);
    }
}



int main(int argc, const char *argv[])
{
    int i, status;
    struct passwd pwb, *pwp = NULL;
    char pbuf[2048];
    sigset_t sig_set;
    int sig;
    struct serverinfo *sip;
    thread_t acthr_id,kill_id;
    

    openlog("phttpd", LOG_PID, LOG_DAEMON);
    
    time(&start_time);
    
    for (i = 1; i < argc && argv[i][0] == '-'; i++)
	if (argv[i][1] == 'd')
	    if (argv[i][2])
		debug = atoi(argv[i]+2);
	    else
		debug = 1;

    
    fd_init();
    
    config_parse_file(CONFIG_FILE, global_cfg_table, 0);

    i = config_parse_argv(argv+1, global_cfg_table);
    if (i++ < 0)
    {
	fprintf(stderr, "phttpd: config_parse_argv() failed\n");
	exit(1);
    }
    
    if (wait_mode)
    {
	listen_sock = 0;

	if (debug == 0)
	    debug = -1;
    }	

    if (server_user == NULL)
    {
	fprintf(stderr, "phttpd: server_user is NULL\n");
	syslog(LOG_ERR, "server_user is NULL");
	exit(1);
    }
    
    if (uidgid_get(server_user, server_group,
		   &server_uid, &server_gid,
		   &pwp, &pwb, pbuf, sizeof(pbuf)) < 0)
    {
	fprintf(stderr, "phttpd: uidgid_get() failed\n");
	
	syslog(LOG_ERR, "uidgid_get(\"%s\", \"%s\") failed",
	       server_user != NULL ? server_user : "",
	       server_group != NULL ? server_group : "");
	
	exit(1);
    }

    if (geteuid() != 0 && server_port < 1024)
	server_port = 8080;
    
    if (setup_server_host() < 0)
    {
	fprintf(stderr, "phttpd: setup_server_host() failed\n");
	exit(1);
    }

    if (listen_sock < 0)
    {
	display_banner();

	if (!no_copying_info)
	    display_copying();

	if (server_port != 80)
	    printf("Server will be started on %s:%d\n",
	    server_host,
	    server_port);
    }
    

    if (i < argc)
	server_home = s_strdup(argv[i]);
    
    if (server_home)
    {
	status = s_chdir(server_home);
	if (status < 0)
	{
	    perror("phttpd: s_chdir");
	    syslog(LOG_ERR, "chdir(\"%s\") failed: %m", server_home);
	    exit(1);
	}
    }

    sip = create_http_server(server_addr, server_port);
    if (sip == NULL)
    {
	fprintf(stderr, "phttpd: create_http_server(%s, %d): failed\n",
		server_addr, server_port);
	exit(1);
    }
    
    if (getuid() == 0)
	if (setup_uidgid() < 0)
	{
	    fprintf(stderr, "phttpd: setup_uidgid() failed\n");
	    exit(1);
	}
   
    if (!debug)
	become_daemon();
    
    if (debug < 0)
	debug = 0;
    
    stderr_open(errfile_path);
    
    syslog(LOG_NOTICE, "restarted");
    
    md_init();
    cn_init();
    
    fscache_init();
    urlcache_init();
    hostcache_init();
    usercache_init();

    log_init(logfile_path, cntfile_path);

    create_pidfile();

    signals_setup(&sig_set);

    if (thr_setconcurrency(concurrency))
	syslog(LOG_WARNING, "thr_setconcurrency() failed: %m");

    load_global_modules(global_modules);

    if (gc_time)
	cn_start_gc();

    start_http_server(sip, NULL, &acthr_id);

    while (1)
    {
#ifdef USE_PTHREADS
	if (sigwait(&sig_set, &sig))
	    sig = -1;
#else
	sig = sigwait(&sig_set);
#endif
	
	if (sig < 0)
	    continue;
	    
	switch (sig)
	{
	  case SIGHUP:	/* Should close and reopen all log files here */
	    if (debug)
		fprintf(stderr, "** Got SIGHUP\n");
	    
	    stderr_open(errfile_path);
	    log_reopen();
	    break;

	  case SIGUSR1:	/* Increase debugging level */
	    debug++;
	    if (debug)
		fprintf(stderr, "** Got SIGUSR1 - debug now at level %d\n",
			debug);
	    break;

	  case SIGUSR2:	/* Decrease debugging level */
	    if (debug > 0)
		debug--;
	    if (debug)
		fprintf(stderr, "** Got SIGUSR2 - debug now at level %d\n",
			debug);
	    break;

	  case SIGTERM:	/* Terminate nicely */
	    if (debug)
		fprintf(stderr, "** Got SIGTERM - terminating\n");
	    
	    syslog(LOG_NOTICE, "server terminating by SIGTERM request");
	    exit(0);
	    break;

	  case SIGINT:  /* restart totally */
            if (debug)
                fprintf(stderr, "** Got SIGINT - restaring\n");

	    sigrelse(SIGTERM);
            syslog(LOG_NOTICE, "server restarted by SIGINT request");
            if (sip->fd > 0 )
              {
		fprintf(stderr, "** killing (from %d of %d main=%d) accept thread ... %d\n",thr_self(),thr_getconcurrency(),thr_main(),acthr_id);

		fprintf(stderr, "** result=%d\n",thr_kill(acthr_id,SIGTERM));
		fprintf(stderr, "** result=%d\n",thr_kill(acthr_id,SIGTERM));

		fprintf(stderr, "** closing socket..%d.\n",sip->fd);
		i=1;
                close(sip->fd);
		sip->fd=-1;
	      }
                fprintf(stderr, "** closing logs...\n");
	    log_close();
                fprintf(stderr, "** exec....\n");
	    if ( argv[0][0]=='/' )
	      execv(argv[0],(char **) argv);
            else
	      execv("/opt/phttpd/sbin/phttpd",(char **) argv);
            exit(99);
            break;

	  case SIGCHLD:
	    break;
	    
	  default:
	    if (debug)
		fprintf(stderr, "** Got unknown signal: %d\n", sig);
	    
	    syslog(LOG_ERR, "unknown signal (%d) received - ignored", sig);
	}
    }
    
    return 0;
}
E 1
