/*
** connection.h
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

#ifndef PHTTPD_CONNECTION_H
#define PHTTPD_CONNECTION_H

struct connectioninfo
{
    mutex_t lock;
    int inuse;
    
    int request_no;
    thread_t tid;
    int fd;
    int bytes;

    dnsinfo_t *server;
    dnsinfo_t *client;

    time_t cn_time;		/* start of connection... */
    
    struct httpinfo *hip;
    struct serverinfo *sip;
    
    identinfo_t *ident;
};


extern void cn_start_gc(void);
extern void cn_init(void);

extern struct connectioninfo *cn_new(int fd);
extern void cn_free(struct connectioninfo *cip);

extern int cn_active(void);
extern int cn_closeall(void);

extern int cn_foreach(int (*foreach)(struct connectioninfo *cip, void *misc),
	       void *misc);


#endif
