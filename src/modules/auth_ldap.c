/*
** auth_ldap.c
**
** Copyright (c) 1999 Dr. Roland Kaltefleiter <rk@netuse.de>
** Based on auth_file.c which is ** Copyright (c) 1994-1997 Peter Eriksson <pen@signum.se>
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

#include <stdio.h>
#include <string.h>
#include <crypt.h>

#include <lber.h>
#include <ldap.h>

#include "phttpd.h"



static char *ldap_server;
static int  ldap_port = 389;
static struct table *auth_base_dn_table = NULL;

static struct options authfile_cfg_table[] =
{
    { "ldap-server",	T_STRING, &ldap_server,  NULL },
    { "ldap-port",	T_NUMBER, &ldap_port,  NULL },
    { "base-dn",	T_TABLE, &auth_base_dn_table,  NULL },
    { NULL,             -1,       NULL,		NULL }
};


int pm_init(const char **argv)
{
    char *cfg_path, *cp;
    const char *name = argv[0];
    int clen;

    
    if (debug > 1)
	fprintf(stderr, "*** auth_file/pm_init(\"%s\") called ***\n", name);

    clen = strlen(name)+6;
    cfg_path = s_malloc(clen);
    s_strcpy(cfg_path, clen, name);
    
    cp = strrchr(cfg_path, '.');
    if (cp && strcmp(cp, ".so") == 0)
	*cp = '\0';
    
    s_strcat(cfg_path, clen, ".conf");
    if (config_parse_file(cfg_path, authfile_cfg_table, 0) < 0)
	return -1;
    
    if (config_parse_argv(argv+1, authfile_cfg_table) < 0)
	return -1;

    if ( ldap_server==NULL ) { ldap_server=s_strdup("localhost"); }
    
    return 0;
}


void pm_exit(void)
{
    if (debug > 1)
	fprintf(stderr, "*** auth_file/pm_exit() called ***\n");
    
    s_free(ldap_server);
    tbl_free(auth_base_dn_table,s_free);
    s_free(auth_base_dn_table);

}


static int check_ldap(char *base_dn,
		      struct authinfo *aip,
		      struct connectioninfo *cip)
{
    LDAP *pl;
    LDAPMessage *result = NULL;
    LDAPMessage *e;
    char ldap_filter[1024];
    char *dn;
    char *ldap_attrs[] = { "dn", "uid", NULL };
    int anzahl;
    char *username, *password;

    if (aip == NULL ||
	aip->type == NULL ||
	strcasecmp(aip->type, "basic") != 0 ||
	aip->u.basic.username == NULL ||
	aip->u.basic.password == NULL)
    {
	/* Unknown/bad authentication */
	return -1;
    }

    username = aip->u.basic.username;
    password = aip->u.basic.password;

/* Setup the ldap_filter */
    s_sprintf(ldap_filter,1024,"uid=%s",username);

    if (debug > 3 ) fprintf(stderr, "*** auth_ldap/check_ldap: filter= %s\n",ldap_filter);

/* Now connect to the LDAP-Server */
  if ( (pl=ldap_init(ldap_server, ldap_port)) == NULL )
	{ fprintf(stderr,"ldap_init failed\n"); 
	  return(0); }

  if ( LDAP_SUCCESS!=ldap_search_s(pl,base_dn,LDAP_SCOPE_ONELEVEL,ldap_filter,ldap_attrs,0,&result))
	{ fprintf(stderr,"    ldap_search_s: Not found %s in %s\n",ldap_filter,base_dn); 
	  ldap_unbind(pl);
	  return(0); }

  if ( (anzahl=ldap_count_entries(pl, result)) == 0)
	{ fprintf(stderr,"    ldap_search_s: No such user %s\n",ldap_filter); 
	  ldap_msgfree(result);
	  ldap_unbind(pl);
	  return(0); }

  if ( anzahl!=1 )
	{ fprintf(stderr,"    ldap_search_s: uid (%s) not unique - failed\n",username); 
	  ldap_msgfree(result);
	  ldap_unbind(pl);
	  return(0); }

  if ( (e = ldap_first_entry(pl, result)) == NULL )
	{ fprintf(stderr,"    ldap_first_entry failed ???\n");
	  ldap_msgfree(result);
	  ldap_unbind(pl);
	  return(0); }

/* Get the DN ? */	
  if ( (dn = ldap_get_dn(pl, e )) == NULL )
	{ fprintf(stderr,"    ldap_get_dn: no DN found for uid / dn: %s / %s\n",username,base_dn);
	  ldap_msgfree(result);
	  ldap_msgfree(e);
	  ldap_unbind(pl);
	  return(0); }

  if ( ldap_simple_bind_s(pl, dn, password) == LDAP_SUCCESS && strlen(password)>0 )
	{ /* YES WE ARE OK */
		if ( debug > 3 ) fprintf(stderr," LDAP-AUTH: success dn=%s\n",dn);
		aip->validated_username = s_strdup(aip->u.basic.username);
		ldap_memfree(dn);
		ldap_msgfree(e);
		ldap_msgfree(result);
		ldap_unbind(pl);
		return(1);
	}

  if ( dn!=NULL ) ldap_memfree(dn);
  ldap_msgfree(e);
  ldap_msgfree(result);
  ldap_unbind(pl);

  return 0;
}


int pm_auth(struct authinfo *aip, struct connectioninfo *cip,
	    const char *domain)
{
    char dn_pattern[1024];
    int status=0;
    struct httpinfo *hip = cip->hip;

    
    if (debug > 1)
	fprintf(stderr, "*** auth_file/pm_auth(%s)\n",
		domain);

    if ( auth_base_dn_table )
    {
	if ( url_match(auth_base_dn_table,hip->url,dn_pattern, sizeof(dn_pattern)) )
    		status = check_ldap(dn_pattern,aip, cip);
	else
		fprintf(stderr,"No dn in table for url=%s\n",hip->url);
    }
    else
	fprintf(stderr, " ... no base-dn in cfg\n");

    return status;
}
