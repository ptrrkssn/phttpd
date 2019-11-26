/*
** auth.h
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

#ifndef PHTTPD_AUTH_H
#define PHTTPD_AUTH_H

#define AUTH_XTYPE_NONE		0
#define AUTH_XTYPE_BIS  	1
#define AUTH_XTYPE_FILE 	2
/* added RK */
#define AUTH_XTYPE_FULLNAME	3

#define ACL_REJECT		0
#define ACL_ALLOW		1
#define ACL_AUTHENTIFICATE	2

struct authinfo
{
    char *type;		/* Authentication type (ie "basic") */
    char *data;		/* Raw, undecoded, authentication data */

    /* Type specific data */
    union
    {
	/* Extracted data for the "basic" type of authentication stuff */
	struct
	{
	    char *username;
	    char *password;
	} basic;
    } u;


    
    int   xtype;    		/* Typ of data in "xinfo" */
    void *xinfo;		/* For user-defined use */
    void (*xfree)(void *);  	/* For freeing the data in xinfo */
    
    /* Called from the CGI module to export information */
    void (*xsetenv)(void *xinfo,
		    char *(*x_setenv)(char **, const char *, const char *),
		    char **envp);


    char *validated_username;
};


extern struct authinfo *auth_new(const char *auth, const char *type);
extern void auth_free(struct authinfo *aip);

struct httpinfo;
extern struct authinfo *auth_get(struct httpinfo *hip);


extern struct table *auth_handlers_table;

struct connectioninfo;
extern int access_check(urlinfo_t *uip, struct connectioninfo *cip);

struct httpinfo;
extern int access_auth(struct httpinfo *hip, struct connectioninfo *cip,
		       const char *acl_path);

#endif
