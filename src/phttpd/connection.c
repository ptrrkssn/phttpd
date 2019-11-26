/*
** connection.c
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

#include <syslog.h>

#include "phttpd.h"

static struct connectioninfo *ciptab;


/* The Garbage Collector Thread - used to clean up hanging connections */
static void *gc_thread(void *misc)
{
    time_t curr_time;
    int i;
    struct connectioninfo *cip;
    
/* added RK: In case that gc_time is less that 10 seconds, forget this gc stuff*/
    if ( gc_time < 10 ) 
    { fprintf(stderr,"gc_thread(): gc_time < 10 sec, no garbage collector started !\n");
      return 0;
    }

  Loop:
    s_sleep(gc_sleep > 0 ? gc_sleep : 60);

    if (debug > 1)
	s_write(2, "gc_thread(): Timeout\n", 21);

    time(&curr_time);
    
    for (i = 0; i < max_fds; i++)
    {
	cip = &ciptab[i];

	mutex_lock(&cip->lock);
	if (cip->inuse == 0)
	{
/* added RK ... */
	    mutex_unlock(&cip->lock);
/* this is wrong ...  return 0; */
	}

	if (cip->inuse != 0 )
	{ if (curr_time - cip->cn_time > gc_time)
	  {
	    syslog(LOG_DEBUG, "terminating connection #%d", cip->request_no);
/* was a BUG, need to free memory ! RK11 */
	    cn_free(cip);
/*	    fd_shutdown(cip->fd, -2);	*/
	  }
	}
	
	mutex_unlock(&cip->lock);
    }
    if (debug > 1)
	s_write(2, "gc_thread(): sleeping\n", 22);
	
    goto Loop;
}


void cn_start_gc(void)
{
    if (thr_create(NULL, 0,
		   (void *(*)(void *)) gc_thread,
		   NULL, THR_DETACHED+THR_DAEMON, NULL))
    {
	syslog(LOG_ERR, "thr_create(gc_thread) failed: %m");
	exit(1);
    }
}


struct connectioninfo *cn_new(int fd)
{
    struct connectioninfo *cip;

    cip = &ciptab[fd];
    mutex_lock(&cip->lock);
    cip->fd = fd;
    cip->bytes=0;
    cip->inuse = 1;
    mutex_unlock(&cip->lock);
    
    time(&cip->cn_time);

    return cip;
}


void cn_init(void)
{
    ciptab = s_malloc(max_fds * sizeof(struct connectioninfo));
}


void cn_free(struct connectioninfo *cip)
{
    int fd;
    
    fd_shutdown(cip->fd, 2);

    http_freeinfo(cip->hip);
    cip->hip = NULL;
    
    si_free(cip->sip);
    cip->sip = NULL;

    dns_free(cip->server);
    dns_free(cip->client);
    cip->server = cip->client = NULL;
    
    ident_free(cip->ident);
    cip->ident = NULL;

    mutex_lock(&cip->lock);
    fd = cip->fd;
    cip->fd = -1;
    cip->inuse = 0;
    mutex_unlock(&cip->lock);
    fd_close(fd);
}


int cn_closeall(void)
{
    int active = 0;
    int i;
    struct connectioninfo *cip;
    
    
    for (i = 0; i < max_fds; i++)
    {
	cip = &ciptab[i];

	mutex_lock(&cip->lock);
	if (cip->inuse)
	{
	    ++active;
	    fd_shutdown(cip->fd, -2);
	}
	mutex_unlock(&cip->lock);
    }

    return active;
}

int cn_active(void)
{
    int active = 0;
    int i;
    struct connectioninfo *cip;
    
    
    for (i = 0; i < max_fds; i++)
    {
	cip = &ciptab[i];

	mutex_lock(&cip->lock);
	if (cip->inuse)
	    ++active;
	mutex_unlock(&cip->lock);
    }

    return active;
}


int cn_foreach(int (*foreach)(struct connectioninfo *cip, void *misc),
	       void *misc)
{
    int i, status = 0;
    struct connectioninfo *cip;
    
    
    for (i = 0; i < max_fds && status == 0; i++)
    {
	cip = &ciptab[i];

	mutex_lock(&cip->lock);
	if (cip->inuse)
	    status = (*foreach)(cip, misc);

	mutex_unlock(&cip->lock);
    }

    return status;
}
