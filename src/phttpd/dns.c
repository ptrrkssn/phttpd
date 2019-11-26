/*
** dns.c			DNS (Domain Name Service) lookup routines.
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

#define IN_DNS_C
#include "phttpd.h"



static void *hostname_thread(dnsinfo_t *dip)
{
    char *hostname = NULL;
    struct hostent *hep;
    void *key;
    int saved_errno = 0;
    

    if ((key = hostcache_lookup_byaddr(&dip->sin.sin_addr, 0, &hep)) != NULL)
    {
	if (hep && hep->h_name)
	    hostname = s_strdup(hep->h_name);
	else
	    saved_errno = -1;
	    
	hostcache_release(key);
    }
    else
	saved_errno = -1;
    
    mutex_lock(&dip->mtx);
    dip->hostname = hostname;
    dip->saved_errno = saved_errno;
    dip->state = 1;
    cond_broadcast(&dip->cv);
    mutex_unlock(&dip->mtx);

    return NULL;
}



dnsinfo_t *dns_lookup_name(struct sockaddr_in *sin)
{
    dnsinfo_t *dip;
    
    dip = s_malloc(sizeof(*dip));
    
    mutex_init(&dip->mtx, USYNC_THREAD, NULL);
    cond_init(&dip->cv, USYNC_THREAD, NULL);

    dip->address = s_strdup(inet_ntoa(sin->sin_addr));
    dip->sin.sin_addr.s_addr=sin->sin_addr.s_addr;

    dip->hostname = NULL;
    dip->state = 0;
    dip->saved_errno = 0;

    if (hostname_lookups == 0)
    {
	dip->state = 1;
	return dip;
    }
    
    if (thr_create(NULL,
		   0,
		   (void *(*)(void *)) hostname_thread,
		   (void *) dip,
		   THR_DETACHED,
		   NULL))
    {
	syslog(LOG_ERR, "thr_create(hostname_thread) failed: %m");
	s_free(dip->address);
	s_free(dip);
	return NULL;
    }

    return dip;
}

char *dns_lookup_servername(dnsinfo_t *dip)
{
    dip->state = 0;
    dip->saved_errno = 0;
    hostname_thread(dip);
    return (dip->hostname);
}

static void *hostaddr_thread(dnsinfo_t *dip)
{
    struct sockaddr_in sin;
    struct hostent *hep;
    void *key;
    int saved_errno = 0;
    

    if ((key = hostcache_lookup_byname(dip->hostname, 0, &hep)) != NULL)
    {
	if (hep && hep->h_addr_list && hep->h_addr_list[0])
	    memcpy(&sin, hep->h_addr_list[0], sizeof(sin));
	else
	    saved_errno = -1;
	    
	hostcache_release(key);
    }
    else
	saved_errno = -1;
    
    mutex_lock(&dip->mtx);
    
    dip->sin = sin;
    dip->address = s_strdup(inet_ntoa(sin.sin_addr));
    dip->saved_errno = saved_errno;
    dip->state = 1;
    
    cond_broadcast(&dip->cv);
    mutex_unlock(&dip->mtx);

    return NULL;
}



dnsinfo_t *dns_lookup_addr(char *hostname)
{
    dnsinfo_t *dip;

    
    dip = s_malloc(sizeof(*dip));
    
    mutex_init(&dip->mtx, USYNC_THREAD, NULL);
    cond_init(&dip->cv, USYNC_THREAD, NULL);

    dip->hostname = s_strdup(hostname);
    memset(&dip->sin, 0, sizeof(dip->sin));
    dip->state = 0;
    dip->saved_errno = 0;
    
    if (thr_create(NULL,
		   0,
		   (void *(*)(void *)) hostaddr_thread,
		   (void *) dip,
		   THR_DETACHED,
		   NULL))
    {
	syslog(LOG_ERR, "thr_create(hostaddr_thread) failed: %m");
	mutex_destroy(&dip->mtx);
	cond_destroy(&dip->cv);
	s_free(dip->hostname);
	s_free(dip);
	return NULL;
    }

    return dip;
}


int dns_get(dnsinfo_t *dip,
	    struct sockaddr_in *sin,
	    char **hostname,
	    char **address,
	    int *port)
{
    mutex_lock(&dip->mtx);
    while (dip->state == 0) {
	cond_wait(&dip->cv, &dip->mtx);
    }
    mutex_unlock(&dip->mtx);

    if (sin)
	*sin = dip->sin;
    if (hostname)
	*hostname = dip->hostname;
    if (address)
	*address = dip->address;
    if (port)
	*port = ntohs(dip->sin.sin_port);
    
    return dip->saved_errno;
}


void dns_free(dnsinfo_t *dip)
{
    if (dip == NULL)
	return;
    
    /* Make sure the thread has terminated */
    (void) dns_get(dip, NULL, NULL, NULL, NULL);

    mutex_destroy(&dip->mtx);
    cond_destroy(&dip->cv);

    s_free(dip->hostname);
    s_free(dip->address);
    s_free(dip);
}


