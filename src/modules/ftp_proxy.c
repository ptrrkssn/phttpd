/*
** ftp_proxy.c
**
** Copyright (c) 1995 Peter Eriksson <pen@signum.se>
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
#include <stdlib.h>
#include <string.h>
#include <alloca.h>

#include "phttpd.h"


int pm_init(const char **argv)
{
    const char *name = argv[0];
    
    if (debug > 1)
	fprintf(stderr, "ftp_proxy: pm_init(\"%s\")\n", name);

    return 0;
}

void pm_exit(void)
{
    if (debug > 1)
	fprintf(stderr, "ftp_proxy: pm_exit()\n");
}


static int get_rq(char *in_url,
		  char **host,
		  char **port,
		  char **out_url)
{
    char *cp;

    
    if (strncmp(in_url, "ftp://", 6) != 0)
	return -1;

    cp = in_url+6;
    *host = cp;
    while (*cp && !(*cp == '/' || *cp == ':'))
	++cp;

    if (*cp == 0)
	return 1;

    if (*cp == ':')
    {
	*cp++ = '\0';
	*port = cp;

	while (*cp && *cp != '/')
	    ++cp;

	if (*cp == 0)
	    return 2;
    }
    
    *cp++ = '\0';
    *out_url = cp;

    return 3;
}


int pm_request(struct connectioninfo *cip)
{
    struct httpinfo *hip;
    char *tmp, *host, *port, *url;
    int sock_fd, result, fd, tmpsize;


    fd = cip->fd;
    host = port = url = NULL;
    
    hip = cip->hip;
     
    if (debug > 1)
    {
	fprintf(stderr, "ftp_proxy: pm_request()\n");
	fprintf(stderr, "\thip->method = %s\n", hip->method);
	fprintf(stderr, "\thip->url = %s\n", hip->url);
    }


    tmpsize = strlen(hip->url)+1;
    tmp = (char *) alloca(tmpsize);
    s_strcpy(tmp, tmpsize, hip->url);
    
    if (get_rq(tmp, &host, &port, &url) < 0)
    {
	if (debug > 2)
	    fprintf(stderr, "get_rq(): Failed\n");
	goto Fail;
    }

    if (debug > 2)
	fprintf(stderr, "get_rq(), host=%s, port=%s, url=%s\n",
		host ? host : "<null>",
		port ? port : "<null>",
		url ? url : "<null>");

/* XXX should probably check if this is ourself we are connecting to... */
    
    sock_fd = fd_sconnect(host, port ? port : "21");
    if (sock_fd < 0)
    {
	if (debug > 2)
	    fprintf(stderr, "fd_sconnect(\"%s\") failed\n", host);
	goto Fail;
    }

    if (debug > 4)
	fprintf(stderr, "Ftp query: %s\n", url+1);

    result = 200;
    if (hip->mip)
	http_sendheaders(fd, cip, result, NULL);

    fd_puts("Content-Type: text/html\n\n", fd);
    html_sysheader(fd, "H2", "Ftp Connection");

    fd_puts("Sorry, FTP Proxying is not yet implemented.\n", fd);

    html_sysfooter(fd);
    
    if (debug > 4)
	fprintf(stderr, "ftp_proxy: closing down\n");
    
    fd_close(sock_fd);

    return 200;
    
  Fail:
    return -1;
}

