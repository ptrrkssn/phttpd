/*
** auth_file.c
**
** Copyright (c) 1994-1996 Peter Eriksson <pen@signum.se>
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

#include "phttpd.h"


static hashtable_t *auth_files_table = NULL;


static struct options authfile_cfg_table[] =
{
    { "auth-files",	T_HTABLE, &auth_files_table,  NULL },
    { NULL,             -1,       NULL,		NULL }
};



static char *mystrcopy(line)
char *line;
{
    char *p;
    int x;

    
    p=line;
    x=0;
    while (x == 0 )
    {
	if ( *p != 0x20 && *p != 0x09 && *p != 0x00 )
	    p++;
	else
	    x=1; 
    }
    if ( *p == 0x00 )
	return NULL;
    while ( ( *p == 0x20 ||  *p == 0x09) &&  *p !=0x00 )
    {
	p++;
    }
    if ( *p == 0x00 )
	return NULL;
    if ( p[strlen(p)-1] == 0x0a )
	p[strlen(p)-1]=0x00;
    
    return p;
}



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
    
    return 0;
}


void pm_exit(void)
{
    if (debug > 1)
	fprintf(stderr, "*** auth_file/pm_exit() called ***\n");
    
    ht_destroy(auth_files_table);
    s_free(auth_files_table);
}


static int check_file(const char *typepath,
		      struct authinfo *aip,
		      struct connectioninfo *cip)
{
    int fd;
    char buf[1024], *up, *pp, *lp;
    const char *path;
    int usecrypt=1;
    int use_gecos_as_host=0, i_use,ip_ok=0;
    char *username, *password;
    char *address,*hostname;
    char *hostacl,**hav;
   
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
    
    /* RK * should be dynamic */
    if ( strncmp(typepath,"plain",5) == 0 || typepath[0]=='/' )
	usecrypt=0;
    else
	if (strncasecmp(typepath,"extended",8)==0)
		use_gecos_as_host=1;
	else
		if (strncasecmp(typepath,"crypt",5)!=0 &&
			strncasecmp(typepath,"passwd",6)!=0 )
			fprintf(stderr, "auth_file: unknown keyword in %s\n",typepath);

    /* Now drop KEYWORD */
    if (  typepath[0]!='/' )
	path=mystrcopy(typepath);
    else
	path=typepath;
    if ( path == NULL )
	path=typepath;
    
    /* Select a MODE, default is name:pw:... (passwd-format) */
    /* key: passwd  OR crypt */
    /* Altername is plain :    name plain text key\n */
    

    if (debug > 2)
	fprintf(stderr, "auth_file: check_file: %s\n",
		path);
    
    fd = fd_open(path, O_RDONLY);
    if (fd < 0)
	return 0;

    while (fd_gets(buf, sizeof(buf), fd))
    {
	up = strtok_r(buf, " \t\n\r:", &lp);
	if (up == NULL || up[0] == '#')
	    continue;

	if (strcmp(up, username) == 0)
	{
	    if (debug > 2)
		fprintf(stderr, "auth_file: check_file: Found user\n");

	    while (lp && *lp && (*lp == ' ' || *lp == '\t'))
		++*lp;

	    if (usecrypt)
		pp = strtok_r(NULL, "\n\r:", &lp);
	    else
		pp = strtok_r(NULL, "\n\r", &lp);
		
	    if (pp == NULL)
	    {
		if (password == NULL || *password == '\0')
		    goto OK;
	    }
	    else
	    {
	 	if (usecrypt==0 &&
		    password != NULL && strcmp(password, pp) == 0)
		    goto OK;
		/* Will use crypt ! Crypt should return 13 character !!  RK */
		if (usecrypt==1 &&
		    password != NULL &&
		    strncmp(crypt(password,pp),pp,13) == 0)
		    goto OK;
	    }
	    
	    break;
	}
    }

    fd_close(fd);
    return 0;

  OK:
    fd_close(fd);

    aip->validated_username = s_strdup(aip->u.basic.username);
    

    /* Now check for PUT access if "usecrypt" is enabled */
    if (usecrypt && pp != NULL)
    {
	pp = strtok_r(NULL, "\n\r:", &lp); /* This is UID */
	if (pp != NULL)
	    pp = strtok_r(NULL, "\n\r:", &lp); /* This is GID */
	if (pp != NULL)
	    pp = strtok_r(NULL, "\n\r:", &lp); /* This is GECOS */
/* we do use this for: use_gecos_as_host == 1 */
        if ( pp != NULL && use_gecos_as_host == 1 )
        {
		if ( ! cip ) return 0;
		ip_ok=0;
		hostacl=s_strdup(pp);
		hav=strsplit(hostacl,'|',0);
    		dns_get(cip->client, NULL, &hostname, &address, NULL);
		if ( debug > 6 ) fprintf(stderr,"use_gecos_as_host: From: %s \n",address);

                for (i_use = 0; hav[i_use]; i_use++)
		{	fprintf(stderr,"                 vs %s %d\n",hav[i_use],strmatch( address,hav[i_use] ));
			if ( strmatch( address,hav[i_use] )!=0 ) { ip_ok=1; break; }
		}
		s_free(hav);
		if ( ip_ok == 0 ) return 0;
        }


	if (pp != NULL)
	    pp = strtok_r(NULL, "\n\r:", &lp); /* This is HOME/PUTDIR */
	if (pp != NULL && strlen(pp) > 0)
	{
	    aip->xtype = AUTH_XTYPE_FILE;
	    aip->xfree = s_free;
	    aip->xinfo = s_strdup(pp);
	}    
    }
    
    return 1;
}


int pm_auth(struct authinfo *aip, struct connectioninfo *cip,
	    const char *domain)
{
    hashentry_t *hep;
    int status;
    
    
    if (debug > 1)
	fprintf(stderr, "*** auth_file/pm_auth(%s)\n",
		domain);


    hep = ht_lookup(auth_files_table, domain, strlen(domain));
    if (hep == NULL)
	return 0;

    status = check_file(hep->data, aip, cip);

    ht_release(hep);
    
    return status;
}
