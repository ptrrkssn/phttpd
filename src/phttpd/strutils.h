/*
** strutils.h
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

#ifndef PHTTPD_STRUTILS_H
#define PHTTPD_STRUTILS_H


#define GA_UNQUOTE      1
#define GA_DONT_UNQUOTE 0

extern char **strsplit(char *path, int delim, int unquote);
extern void str_to_lower(char *p);
extern char *notslash(char *p);
#endif
