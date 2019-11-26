/*
** server.c				HTTP Server implementation code.
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
#include <errno.h>
#include <string.h>

#define IN_DNS_C
#include "phttpd.h"



struct serverinfo *si_new(void)
{
    struct serverinfo *sip;
    
    sip = s_malloc(sizeof(sip));
    
    mutex_init(&sip->lock, USYNC_THREAD, NULL);
    sip->use = 1;

    sip->host = NULL;
    sip->url = NULL;
    
    sip->port = -1;
    sip->fd = -1;

    return sip;
}


struct serverinfo *si_dup(struct serverinfo *sip)
{
    mutex_lock(&sip->lock);
    sip->use++;
    mutex_unlock(&sip->lock);

    return sip;
}

void si_free(struct serverinfo *sip)
{
    if (sip == NULL)
	return;
    
    mutex_lock(&sip->lock);
    sip->use--;
    if (sip->use > 0)
    {
	mutex_unlock(&sip->lock);
	return;
    }

    if (sip->host)
	s_free(sip->host);
    if (sip->url)
	s_free(sip->url);
    mutex_destroy(&sip->lock);
    s_free(sip);
}



static void *request_thread(struct connectioninfo *cip)
{
    int len, result = -1;
    int keepalive = 0;
    struct sockaddr_in client_sin, server_sin;
    

    if (debug > 1)
	fprintf(stderr, "request_thread(): Start\n");
    
    fd_reopen(cip->fd, 2, FDT_SOCKET);
    cip->tid = thr_self();

    len = sizeof(server_sin);
    if (getsockname(cip->fd, (struct sockaddr *) &server_sin, &len) < 0)
    {
	syslog(LOG_INFO, "getsockname() failed: %m");
	goto Done;
    }
    
    len = sizeof(client_sin);
    if (getpeername(cip->fd, (struct sockaddr *) &client_sin, &len) < 0)
    {
	syslog(LOG_INFO, "getpeername() failed: %m");
	goto Done;
    }

    cip->server = dns_lookup_name(&server_sin);
    cip->client = dns_lookup_name(&client_sin);


    if (ident_lookups)
	cip->ident = ident_lookup(&server_sin, &client_sin);
    
  Again:
    keepalive = 0;
    result = http_get_request(cip, &keepalive);

    if (keepalive_enabled && keepalive && result > 0 && result < 400 )
    {
	if (debug > 1)
	    fprintf(stderr, "Keepalive, retrying (fd=%d)\n", cip->fd);

	fd_flush(cip->fd);
	
	if (cip->hip)
	{
	    log_connection(cip, result);
    if (debug > 6 )
	fprintf(stderr, "after log: server_url: %s %lx\n",(cip->sip->url)?cip->sip->url:"<NULL>",(long) (cip->server->sin.sin_addr.s_addr));
	    http_freeinfo(cip->hip);
	    cip->hip = NULL;
	}

	goto Again;
    }
    
    if (debug > 1)
	fprintf(stderr, "No keepalive, closing (fd=%d)\n", cip->fd);

  Done:
/*fprintf(stderr,"befor log %s\n",(cip->hip->aip)?"POINTER":"NULL"); */
    if (debug > 8 )
	fprintf(stderr, "calling log_connection\n");

    if (cip->hip)
	log_connection(cip, result);

    if (debug > 6 )
	{
	if ( cip->sip && cip->server )
/*		fprintf(stderr, "after2: server_url: %s %lx\n",(cip->sip->url)?cip->sip->url:"<NULL>",(long) (cip->server->sin.sin_addr.s_addr)); */
		fprintf(stderr, "after2: server_url: %s %lx\n","cip->sip->url?? <NULL>",(long) (cip->server->sin.sin_addr.s_addr));
	}

    if (debug > 8 )
	fprintf(stderr, "calling cn_free\n");
    cn_free(cip);
    
    if (debug > 1)
	fprintf(stderr, "request_thread(): Stop\n");
    
    return NULL;
}


static void *accept_thread(void *info)
{
    static mutex_t req_lock;
    struct connectioninfo *cip;
    int fd;
    struct serverinfo *sip;
    

    sip = (struct serverinfo *) info;
    
  Loop:
    if ( do_restart == 1 ) return NULL;

    fd = accept(sip->fd, NULL, NULL);
    if (fd < 0)
    {
	if (errno != EINTR)
	    syslog(LOG_INFO, "accept() failed: %m");
	goto Loop;
    }

    cip = cn_new(fd);
    
    cip->sip = si_dup(sip);
    
    mutex_lock(&req_lock);
    cip->request_no = ++n_requests;
/* Max request opt restart */
    if ( debug > 4 ) fprintf(stderr,"Req # %d/%d\n",n_requests,restart_requests);
    if ( restart_requests != 0 && n_requests > restart_requests )
    {
/* we need to restart */
	if ( debug > 1 ) 
	{ fprintf(stderr,"Restart_requests %d/%d exeeded\n",n_requests,restart_requests); 
	  syslog(LOG_NOTICE, "MAX Restart_requests exeeded -- reforking");
	}
/* we send outself a signal QUIT */
	sigsend(P_PID,getpid(),SIGQUIT);
    }

    mutex_unlock(&req_lock);

    if (thr_create(NULL,
		   0,
		   (void *(*)(void *)) request_thread,
		   (void *) cip,
		   THR_DETACHED,
		   NULL))
    {
	syslog(LOG_ERR, "thr_create(request_thread) failed: %m");
	exit(1);
    }
    

    goto Loop;
}    

char *make_server_url(char *host, int port)
{
    char server_url[2048];

    if (port == 80)
    {
	s_strcpy(server_url, sizeof(server_url), "http://");
	s_strcat(server_url, sizeof(server_url), host);
    }
    else
    {
        int slen;

	
        s_strcpy(server_url, sizeof(server_url), "http://");
	s_strcat(server_url, sizeof(server_url), host);
	slen = s_strcat(server_url, sizeof(server_url), ":");
	s_sprintf(server_url+slen, sizeof(server_url)-slen, "%d", port);
    }
    
    return s_strdup(server_url);
}


struct serverinfo *create_http_server(char *addr, int port)
{
    struct serverinfo *sip;
    
    sip = si_new();
    sip->fd = create_listen_socket(addr, port);
    if (sip->fd < 0)
    {
	s_free(sip);
	return NULL;
    }

    if (strcmp(addr, "*") == 0)
	addr = server_host;
    
    sip->host = s_strdup(addr);
    sip->port = port;

    sip->url = make_server_url(addr, port);

    if ( debug > 3 )
	fprintf(stderr,"create_http_server: host=%s port=%d url=%s\n",sip->host,sip->port,sip->url);
    
    return sip;
}



int start_http_server(struct serverinfo *sip, thread_t *tidp, thread_t *acthr_id)
{
    if (thr_create(NULL,
		   0,
		   (void *(*)(void *)) accept_thread,
		   (void *) sip,
		   tidp == NULL ? THR_DETACHED : 0,
		   acthr_id))
    {
	syslog(LOG_ERR, "thr_create(accept_thread) failed: %m");
	return -1;
    }

    return 0;
}
