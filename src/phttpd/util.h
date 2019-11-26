/*
** util.h			       Misc helper functions.
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

#ifndef PHTTPD_UTIL_H
#define PHTTPD_UTIL_H

extern int create_listen_socket(const char *addr, int port);
extern void stderr_open(const char *path);
extern void become_daemon(void);
extern int base64_decode(const char *b64data, char *buf, int bufsize);

#endif
