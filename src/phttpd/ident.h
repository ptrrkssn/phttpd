/*
** ident.h			IDENT (RFC1413) lookup routines
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

#ifndef PHTTPD_IDENT_H
#define PHTTPD_IDENT_H

#ifdef IN_IDENT_C

typedef struct identinfo
{
    mutex_t mtx;
    cond_t cv;

    struct sockaddr_in remote;
    struct sockaddr_in local;

    char *error;
    char *user;
    char *os;

    int saved_errno;
    int state;
} identinfo_t;

#else

typedef void identinfo_t;

#endif

extern identinfo_t *ident_lookup(struct sockaddr_in *remote,
				 struct sockaddr_in *local);

extern int ident_get(identinfo_t *iip,
		     char **error,
		     char **os,
		     char **user);

extern void ident_free(identinfo_t *iip);

#endif
