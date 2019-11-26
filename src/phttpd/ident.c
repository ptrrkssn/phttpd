/*
** ident.c			IDENT (RFC1413) lookup routines
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

#include <errno.h>
#include <string.h>
#include <syslog.h>

#define IN_IDENT_C
#include "phttpd.h"



static void *ident_thread(identinfo_t *iip)
{
    int fd, p1, p2;
    struct sockaddr_in sin;
    char buf[2048];
    char *user = NULL;
    char *os = NULL;
    char *error = NULL;
    char *scp, *cp;
    int saved_errno = 0;
    
    
    sin = iip->remote;
    sin.sin_port = htons(113);
    
    fd = fd_connect((struct sockaddr *) &sin, sizeof(sin));
    if (fd < 0)
    {
	saved_errno = errno;
	error = s_strdup("protocol error: connection refused");
	goto Done;
    }
    
    fd_printf(fd, "%d , %d\n",
	      ntohs(iip->remote.sin_port),
	      ntohs(iip->local.sin_port));
    
    fd_shutdown(fd, 1);

    if (fd_gets(buf, sizeof(buf), fd) == NULL)
    {
	saved_errno = errno;
	error = s_strdup("protocol error: no data");
	goto Done;
    }
    
    cp = strtok_r(buf, ":", &scp);
    if (cp)
    {
	/* Got "port,port" pair */
	
	if (sscanf(cp, " %d , %d ", &p1, &p2) != 2)
	{
	    saved_errno = errno;
	    error = s_strdup("protocol error: port pair format");
	    goto Done;
	}

	if ((p1 != ntohs(iip->remote.sin_port)) ||
	    (p2 != ntohs(iip->local.sin_port)))
	{
	    saved_errno = errno;
	    error = s_strdup("protocol error: invalid ports");
	    goto Done;
	}
	
	cp = strtok_r(NULL, " \t\r\n:", &scp);
	if (cp)
	{
	    /* Got "USERID" or "ERROR" */
	    
	    if (strcasecmp(cp, "USERID") == 0)
	    {
		cp = strtok_r(NULL, " \t\r\n:", &scp);
		if (cp)
		{
		    /* Got OS-name */
		    os = s_strdup(cp);
		    
		    cp = strtok_r(NULL, "\r\n", &scp);
		    if (cp)
		    {
			/* Got ident identifier */
			user = s_strdup(cp);
			goto Done;
		    }
		}
	    }
	    else if (strcasecmp(cp, "ERROR") == 0)
	    {
		cp = strtok_r(NULL, "\r\n", &scp);
		if (cp)
		{
		    error = s_strdup(cp);
		    goto Done;
		}
	    }
	}
    }
    
  Done:
    if (fd >= 0)
	fd_close(fd);
    
    mutex_lock(&iip->mtx);
    
    iip->error = error;
    iip->os = os;
    iip->user = user;
    
    iip->saved_errno = saved_errno;
    iip->state = 1;
    
    cond_broadcast(&iip->cv);
    mutex_unlock(&iip->mtx);

    return NULL;
}



static void _ident_start(identinfo_t *iip)
{
    mutex_init(&iip->mtx, USYNC_THREAD, NULL);
    cond_init(&iip->cv, USYNC_THREAD, NULL);
    
    iip->error = NULL;
    iip->os = NULL;
    iip->user = NULL;

    iip->saved_errno = 0;
    iip->state = 0;
    
    if (thr_create(NULL,
		   0,
		   (void *(*)(void *)) ident_thread,
		   (void *) iip,
		   THR_DETACHED,
		   NULL))
    {
	syslog(LOG_ERR, "thr_create(ident_thread) failed: %m");
    }
}


identinfo_t *ident_lookup(struct sockaddr_in *remote,
			  struct sockaddr_in *local)
{
    identinfo_t *iip;

    iip = s_malloc(sizeof(*iip));

    iip->remote = *remote;
     iip->local = *local;

    _ident_start(iip);
    return iip;
}


int ident_get(identinfo_t *iip,
	      char **error,
	      char **os,
	      char **user)
{
    if (iip == NULL)
	return -1;
    
    mutex_lock(&iip->mtx);
    while (iip->state == 0) {
	cond_wait(&iip->cv, &iip->mtx);
    }
    mutex_unlock(&iip->mtx);

    if (error)
	*error = iip->error;
    if (os)
	*os = iip->os;
    if (user)
	*user = iip->user;

    return iip->saved_errno;
}


void ident_free(identinfo_t *iip)
{
    if (iip == NULL)
	return;
    
    /* Make sure the thread has terminated */
    (void) ident_get(iip, NULL, NULL, NULL);
    
    mutex_destroy(&iip->mtx);
    cond_destroy(&iip->cv);

    s_free(iip->error);
    s_free(iip->os);
    s_free(iip->user);
    s_free(iip);
}


