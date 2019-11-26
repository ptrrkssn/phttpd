/*
** auth.c
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

#include <string.h>
#include <syslog.h>
#include <alloca.h>

#include "phttpd.h"


/* Allocate a new authinfo structure */
struct authinfo *auth_new(const char *type, const char *data)
{
    struct authinfo *aip;
    char buf[2048], *username, *password;

    
    aip = s_malloc(sizeof(*aip));
    
    aip->type = s_strdup(type);
    aip->data = s_strdup(data);

    /* We only handle the Basic authentication type for now */
    if (strcasecmp(aip->type, "basic") != 0)
	return aip;

    if (!base64_decode(data, buf, sizeof(buf)))
	return aip;

    username = buf;
    password = strchr(buf, ':');
    if (password)
	*password++ = '\0';

    aip->u.basic.username = s_strdup(username);
    aip->u.basic.password = s_strdup(password);
	
    aip->xinfo = NULL;
    aip->xfree = NULL;
    aip->xsetenv = NULL;

    return aip;
}


/* Release an authinfo structure */
void auth_free(struct authinfo *aip)
{
    if (aip == NULL)
	return;

    if (aip->type && strcasecmp(aip->type, "basic") == 0)
    {
	s_free(aip->u.basic.username);
	s_free(aip->u.basic.password);
    }
    
    s_free(aip->type);
    s_free(aip->data);
    
    if (aip->xfree)
	(*aip->xfree)(aip->xinfo);
    
    s_free(aip->validated_username);
    s_free(aip);
}


/* Get the authentication information from the HTTP MIME Headers */
struct authinfo *auth_get(struct httpinfo *hip)
{
    char *auth, *type, *data, *authinfo, *cp;
    int alen;
    
    
    /* Is the request coming with an "Authorization:" header? */
    auth = mime_getheader(hip->mip, "AUTHORIZATION", 1);
    if (auth == NULL)
	return NULL;

    if ( debug > 8 ) 
	fprintf(stderr,"Authorization: %s\n",auth);

    S_STRALLOCA(auth, &authinfo, 0, &alen);
    type = strtok_r(authinfo, " \t", &cp);
    data = strtok_r(NULL, " \t", &cp);

    return auth_new(type, data);
}


struct table *auth_handlers_table = NULL;


static int get_acl(int fd,
		   char *pattern,
		   int psize,
		   int *value,
		   urlinfo_t *uip )
{
    char buf[2048], *cp, *tok;
    int key;
    

  Loop:
    if (fd_gets(buf, sizeof(buf), fd) == NULL)
	return 0;

    cp = strchr(buf, '#');
    if (cp)
	*cp = '\0';
    
    cp = buf;
    while (s_isspace(*cp))
	++cp;
    if (*cp == '\0')
	goto Loop;

    tok = strtok_r(buf, " \t\r\n", &cp);
    if (tok == NULL)
    {
	syslog(LOG_ERR, "Invalid ACL file (%s) type entry: %s",
	       uip->access.path, tok);
	goto Loop;
    }

    if (strcmp(tok, "address") == 0)
	key = 1;
    else if (strcmp(tok, "host") == 0)
	key = 2;
    else
	key = -1;
    
    tok = strtok_r(NULL, " \t\r\n", &cp);
    if (tok == NULL)
    {
	syslog(LOG_ERR, "Invalid ACL file (%s) pattern entry: %s",
	       uip->access.path, tok);
	goto Loop;
    }

    s_strcpy(pattern, psize, tok);

    tok = strtok_r(NULL, " \t\r\n", &cp);
    if (tok == NULL ||
	!(strcmp(tok, "allow") == 0 ||
	  strcmp(tok, "reject") == 0 ||
	  strcmp(tok, "auth") == 0 ))
    {
	syslog(LOG_ERR, "Invalid ACL file (%s) value entry: %s",
	       uip->access.path, tok == NULL ? "<null>" : tok);
	goto Loop;
    }

    *value = (strcmp(tok, "allow") == 0) ? ACL_ALLOW : ACL_REJECT;

    if ( strcmp(tok, "auth" ) == 0 ) 
    {
	tok = strtok_r(NULL, " \t\r\n", &cp);
	if ( tok != NULL )
	{
	  uip->auth.source = s_strdup(tok);
	  *value = ACL_AUTHENTIFICATE;

	  if ( cp != NULL )
	     {
		uip->auth.realm = s_strdup(cp);
		if ( uip->auth.realm[strlen(uip->auth.realm)-1] == '\n' )
			uip->auth.realm[strlen(uip->auth.realm)-1]=0x00;
	     }

	  if ( debug > 7 )
	     fprintf(stderr,"ACL-auth: to=%s, realm=%s\n",uip->auth.source, ( uip->auth.realm != NULL ) ? uip->auth.realm : "<NULL>" );

	}
    }
    else
	if ( uip->auth.source != NULL )
	{
/*	  fprintf(stderr,"Need to clean\n"); */
	  s_free(uip->auth.source);
	  uip->auth.source=NULL;
	}

/* This (above) might be a race condition ? Need to check that ! Better: */
/* Select of type of auth to cip ? (not uip ?) */
/* BUG RK TODO... */

    return key;
}


int access_check(urlinfo_t *uip, struct connectioninfo *cip)
{
    char *address = NULL;
    char *hostname = NULL;
    int fd, value, key;
    char pattern[256];
    

    dns_get(cip->client, NULL, &hostname, &address, NULL);
    
    fd = fd_open(uip->access.path, O_RDONLY);
    if (fd == -1)
    {
	syslog(LOG_ERR, "Unable to open ACL file: %s", uip->access.path);
	return 0;
    }

    while ((key = get_acl(fd, pattern, sizeof(pattern), &value, uip )) != 0)
    {
	switch (key)
	{
	  case 1:
	    if (address && strmatch(address, pattern))
	    {
		fd_close(fd);
		return value;
	    }
	    break;

	  case 2:
	    if (hostname && strmatch(hostname, pattern))
	    {
		fd_close(fd);
		return value;
	    }
	    break;
	    
	  default:
	    goto Fail;
	}
    }

  Fail:
    fd_close(fd);
    
    return 0;
}




static const char *auth_gethandler(const char *domain)
{
    int i;
    int len;
    

    len = strlen(domain);
    
    if (auth_handlers_table)
    {
	for (i = 0; i < auth_handlers_table->length; i++)
	{
	    char **pair = auth_handlers_table->value[i];
	    
	    if (debug > 3)
		fprintf(stderr, "       (Checking AUTH %s vs %s)\n",
			domain, pair[0]);

	    if (strmatch(domain, pair[0]))
	    {
	        if (debug > 1)
		    fprintf(stderr, "      (AUTH %s -> Handler %s)\n",
			    domain, pair[1]);
		    
		return pair[1];
	    }
	}
    }

    return NULL;
}



static int auth_call(const char *handler,
		     struct authinfo *aip, struct connectioninfo *cip,
		     const char *domain)
{
    struct modinfo *mp;
    void *mkey;
    int status;
    char buf[2048];
    
    
    while (*handler && *handler == '/')
	++handler;

    s_strcpy(buf, sizeof(buf), modules_home);
    s_strcat(buf, sizeof(buf), "/");
    s_strcat(buf, sizeof(buf), handler);
    
    mp = md_load(buf, &mkey);
    if (mp == NULL)
	return 0;

    if (mp->pm_auth)
	status = mp->pm_auth(aip, cip, domain);
    else
	status = 0;
    
    md_release(mkey);
    return status;
}




/*
** Check the authentication for a specific URL in a certain domain
*/
int access_auth(struct httpinfo *hip, struct connectioninfo *cip,
		const char *domain)
{
    const char *handler;
    int result = 0;

    
    if (hip == NULL || hip->mip == NULL || hip->aip == NULL)
	return 0;
    
    handler = auth_gethandler(domain);
    if (handler)
    {
	if (debug > 2)
	    fprintf(stderr, "*** Calling AUTH handler %s\n", handler);
	
	result = auth_call(handler,
			   hip->aip, cip,
			   domain);
	
	if (result != 1)
	    result = 0;
    }

    return result;
}

