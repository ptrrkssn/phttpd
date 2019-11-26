/*
** dns.h			DNS (Domain Name Service) lookup routines
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

#ifndef PHTTPD_DNS_H
#define PHTTPD_DNS_H

#ifdef IN_DNS_C

typedef struct dnsinfo
{
    mutex_t mtx;
    cond_t cv;

    struct sockaddr_in sin;
    char *hostname;
    char *address;

    int saved_errno;
    int state;
} dnsinfo_t;

#else

typedef void dnsinfo_t;

#endif

extern dnsinfo_t *dns_lookup_name(struct sockaddr_in *sin);
extern dnsinfo_t *dns_lookup_addr(char *name);
extern char *dns_lookup_servername(dnsinfo_t *dip);

extern int dns_get(dnsinfo_t *hip,
		   struct sockaddr_in *sin,
		   char **hostname,
		   char **address,
		   int *port);

extern void dns_free(dnsinfo_t *hip);

#endif
