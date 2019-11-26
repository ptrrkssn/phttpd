/*
** phttpd.h
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

#ifndef PHTTPD_H_INCLUDED
#define PHTTPD_H_INCLUDED



#include <thread.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/param.h>

#include "phttpd/server.h"
#include "phttpd/util.h"
#include "phttpd/ident.h"
#include "phttpd/dns.h"
#include "phttpd/signals.h"
#include "phttpd/strutils.h"
#include "phttpd/fdstdio.h"
#include "phttpd/process.h"
#include "phttpd/hashtable.h"
#include "phttpd/cache.h"
#include "phttpd/fscache.h"
#include "phttpd/urlcache.h"
#include "phttpd/table.h"
#include "phttpd/mime.h"
#include "phttpd/url.h"
#include "phttpd/html.h"
#include "phttpd/auth.h"
#include "phttpd/http.h"
#include "phttpd/error.h"
#include "phttpd/config.h"
#include "phttpd/connection.h"
#include "phttpd/modules.h"
#include "phttpd/logger.h"
#include "phttpd/safeio.h"
#include "phttpd/readdir.h"
#include "phttpd/hostcache.h"
#include "phttpd/usercache.h"

#include "phttpd/multi.h"

#include "phttpd/globals.h"
#include "phttpd/macros.h"
#include "phttpd/autofail.h"


#ifndef UI_THREADS
#define fork1()			fork()
#define ctime_r(a,b,c)		ctime_r(a,b)
#endif


extern char server_version[];

#if 0
struct httpinfo;


extern char *server_home;
extern uid_t  server_uid;
extern gid_t  server_gid;
extern char *modules_home;
extern int  n_listen;
extern int  concurrency;
extern int  stack_size;
extern int  max_fds;
extern int  so_sndbuf;
extern int  so_rcvbuf;

extern hashtable_t *virtual_hosts_table;

extern char *web_admin_name;
extern char *web_admin_home;
extern char *web_admin_email;

extern char *default_file_handler;
extern char *default_dir_handler;

#endif

extern int uidgid_get(const char *user,
		      const char *group,
		      uid_t *uid,
		      gid_t *gid,
		      struct passwd **pwp,
		      struct passwd *pwb,
		      char *pbuf,
		      int pbuflen);

extern int phttpd_request(struct connectioninfo *cip);

extern int strmatch(const char *string, const char *pattern);
extern int atotm(const char *date_str, struct tm *date);

#if 0
extern char *get_hostname(struct addressinfo_s *aip);
extern char *get_ident(struct addressinfo_s *aip);
#endif

#endif
