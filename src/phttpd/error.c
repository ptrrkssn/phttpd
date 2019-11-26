/*
** error.c
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

/* The code may look a little ......, but that comes from the handling depending on
** the mode combination, one is running. 23.11.97, rk@netuse.de
*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>

#include "phttpd.h"


hashtable_t *error_page_table = NULL;

/* Returns -1 in case of error, else 0 */
static int make_full_url(struct connectioninfo *cip, char *buf, int len)
{
    int i = 0;
    int x_offset = 0;
    char *hnl,*surl;

    if (cip->hip->orig_url[0] == '/')
    {
/* Depending on the combination of rkmultimode and softvirtserver, we */
/* way to create the URL in the error is different */
      if ( softvirtserver==0)
	{ if ( rkmultimode==0 && cip->sip && cip->sip->url )   
/* Standart (0/0): Just copy.... */
	    i = s_strcpy(buf, len, cip->sip->url);
          else
/* rkmultimode set, NO softvirtserver: do a reverse lookup on the incoming socket */
            {
	      hnl=dns_lookup_servername(cip->server);
              if ( hnl==NULL ) hnl=server_host;
              surl=make_server_url(hnl,cip->sip->port);
              i = s_strcpy(buf, len, surl);
              s_free(surl);
            }
	}
      else
/* yes we have softvirtserver: Just copy  */
	{
	  surl=make_server_url(cip->hip->svsname,cip->sip->port);
	  i = s_strcpy(buf, len, surl);
	  if ( debug >6 ) fprintf(stderr,"error.c: make_server_url=%s (%d)\n",surl,i);
	  s_free(surl);
	}
      }

/* rkmultimode add cip->hip->prelen
** The offsethandler is a little complex here . One could do that allways near the
** accpect in http.c, but the error-case is fewer. So for performance, we do it
** here 
*/
      x_offset=cip->hip->prelen;
     
      if (url_quote(cip->hip->orig_url+x_offset, buf+i, len-i, "?", 0) == NULL)
        return -1;
    
    i = strlen(buf);

    if (cip->hip->orig_request)
    {
	buf[i++] = '?';
	if (url_quote(cip->hip->orig_request, buf+i, len-i, "\"", 1) == NULL)
	    return -1;
	i = strlen(buf);
    }

    buf[i] = '\0';
    if ( debug >6 ) fprintf(stderr,"error.c: exit: buf=%s\n",buf);

    return 0;
}



int error_bad_request(struct connectioninfo *cip,
		      const char *buf)
{
    hashentry_t *hep;
    char buf1[2048];
    int len, code;
    
    
    hep = ht_lookup(error_page_table, "400", 0);
    if (hep == NULL)
	hep = ht_lookup(error_page_table, "*", 1);
	
    if (hep)
    {
	len = s_strcpy(buf1, sizeof(buf1), "code=400&url=");
	
	if (make_full_url(cip, buf1+len, sizeof(buf1)-len) < 0)
	    return -1;

	len = s_strcat(buf1, sizeof(buf1), "request=");
	
	url_quote(buf, buf1+len, sizeof(buf1)-len, "\"", 1);
	
	code = http_redirect(cip, hep->data, buf1, NULL, 302);
	ht_release(hep);
	return code;
    }
    else
	return http_error(cip, 400,
			  "Bad HTTP request:<BR><PRE>%s</PRE>\n", buf);
}



int error_not_found(struct connectioninfo *cip)
{
    char buf1[2048];
    hashentry_t *hep;
    int len, code;
    

    hep = ht_lookup(error_page_table, "404", 0);
    if (hep == NULL)
	hep = ht_lookup(error_page_table, "*", 1);

    if (hep)
    {
	len = s_strcpy(buf1, sizeof(buf1), "code=404&url=");
	
	if (make_full_url(cip, buf1+len, sizeof(buf1)-len) < 0)
	{
	    syslog(LOG_ERR, "error_not_found: make_full_url() failed");
	    return -1;
	}

	code = http_redirect(cip, hep->data, buf1, NULL, 302);
	
	ht_release(hep);
	return code;
    }
    else
    {
	if (make_full_url(cip, buf1, sizeof(buf1)) < 0)
	{
	    syslog(LOG_ERR, "error_not_found: make_full_url() failed");
	    return -1;
	}
	
	return http_error(cip, 404, 
		    "The requested URL, <A HREF=\"%s\">%s</A>, was not found.",
			  buf1, buf1);
    }
}


int error_method_denied(struct connectioninfo *cip)
{
    char buf1[2048];
    hashentry_t *hep;
    int len, code;
    

    hep = ht_lookup(error_page_table, "405", 0);
    if (hep == NULL)
	hep = ht_lookup(error_page_table, "*", 1);
    
    if (hep)
    {
	len = s_strcpy(buf1, sizeof(buf1), "code=405&url=");
	
	if (make_full_url(cip, buf1+len, sizeof(buf1)-len) < 0)
	    return -1;
	
	code = http_redirect(cip, hep->data, buf1, NULL, 302);
	ht_release(hep);
	return code;
    }
    else
    {
	if (make_full_url(cip, buf1, sizeof(buf1)) < 0)
	    return -1;
    
	return http_error(cip, 405, 
			  "Method Denied for URL <A HREF=\"%s\">%s</A>",
			  buf1,buf1);
    }
}

int error_access(struct connectioninfo *cip)
{
    char buf1[2048];
    hashentry_t *hep;
    int len, code;
    
    hep = ht_lookup(error_page_table, "403", 0);
    
    if (hep == NULL)
	hep = ht_lookup(error_page_table, "*", 1);

    if (hep)
    {
	len = s_strcpy(buf1, sizeof(buf1), "code=403&url=");
	
	if (make_full_url(cip, buf1+len, sizeof(buf1)-len) < 0)
	    return -1;

	code = http_redirect(cip, hep->data, buf1, NULL, 302);
	
	ht_release(hep);
	return code;
    }
    else
    {
	if (make_full_url(cip, buf1, sizeof(buf1)) < 0)
	    return -1;
    
	return http_error(cip, 403, 
			  "Access denied for URL <A HREF=\"%s\">%s</A>",
			  buf1, buf1);
    }
}

int error_system(struct connectioninfo *cip,
		 const char *prompt)
{
    return http_error(cip, 500, 
	       "A system error occured:<BR><PRE>%s: %s</PRE>",
	       prompt, strerror(errno));
}
