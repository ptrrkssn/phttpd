/*
** server.h				HTTP Server implementation code.
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

#ifndef PHTTPD_SERVER_H
#define PHTTPD_SERVER_H


struct serverinfo
{
    mutex_t lock;
    int use;
    
    char *host;
    int port;
    
    int fd;
    
    char *url;
};

extern struct serverinfo *si_new(void);
extern struct serverinfo *si_dup(struct serverinfo *sip);
extern void si_free(struct serverinfo *sip);
extern char *make_server_url(char *host, int port);

extern struct serverinfo *create_http_server(char *addr, int port);
extern int start_http_server(struct serverinfo *sip, thread_t *tidp, thread_t *acthr_id);

#endif
