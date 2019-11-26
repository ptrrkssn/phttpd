/*
** http.c
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <limits.h>
#include <time.h>
#include <syslog.h>

#include <sys/types.h>
#include <sys/stat.h>

#define IN_DNS_C
#include "phttpd.h"



int phttpd_call(const char *module,
		struct connectioninfo *cip)
{
    struct modinfo *mp;
    void *mkey;
    int status;
    char buf[2048];
    
    
    while (*module && *module == '/')
	++module;

    s_strcpy(buf, sizeof(buf), modules_home);
    s_strcat(buf, sizeof(buf), "/");
    s_strcat(buf, sizeof(buf), module);
    
    mp = md_load(buf, &mkey);
    if (mp == NULL)
    {
	return http_error(cip, 500,
  "A system error occured while loading module <B>%s</B>:<BR><PRE>%s</PRE>",
			  module, md_error());
    }

    status = mp->pm_request(cip);
    
    md_release(mkey);
    return status;
}

int phttpd_request(struct connectioninfo *cip)
{
    const char *handler;
    

    if (cip->hip == NULL)
	return -1;
    
    handler = url_gethandler(cip->hip->url);
    if (handler == NULL)
	return -1;
    return phttpd_call(handler, cip);

}


void http_sendlastmodified(int fd, time_t ct)
{
    char buf[64];
    
    fd_puts("Last-Modified: ", fd);
    fd_puts(http_time_r(&ct, buf, sizeof(buf)), fd);
}

char *http_sendheaders(int fd,
		       struct connectioninfo *cip,
		       int code,
		       char *type)
{
    char buf[256];
    time_t ct;
    int keepalive;

    ct = cip->cn_time;

    if (cip->hip && cip->hip->mip)
	keepalive = cip->hip->mip->connection_flags & MCF_KEEPALIVE;
    else
	keepalive = 0;
    
    if (ct == 0)
	time(&ct);

    if (type == NULL)
	switch (abs(code))
	{
	  case 200:
	    type = "OK";
	    break;

	  case 201:
	    type = "Created";
	    break;

	  case 202:
	    type = "Accepted";
	    break;

	  case 203:
	    type = "Provisional Information";
	    break;

	  case 204:
	    type = "No Content";
	    break;

	  case 206:
	    type = "Partial Content";
	    break;

	  case 300:
	    type = "Multiple Choices";
	    break;

	  case 301:
	    type = "Moved Permanently";
	    break;
	    
	  case 302:
	    type = "Moved Temporarily";
	    break;

	  case 303:
	    type = "Method";
	    break;
	    
	  case 304:
	    type = "Not Modified";
	    break;

	  case 400:
	    type = "Bad Request";
	    break;

	  case 401:
	    type = "Unauthorized";
	    break;

	  case 402:
	    type = "Payment Forbidden";
	    break;

	  case 403:
	    type = "Forbidden";
	    break;

	  case 404:
	    type = "Not Found";
	    break;

	  case 405:
	    type = "Method Not Allowed";
	    break;

	  case 406:
	    type = "None Acceptable";
	    break;
	    
	  case 407:
	    type = "Proxy Authentication Required";
	    break;
	    
	  case 408:
	    type = "Request Timeout";
	    break;
	    
	  case 409:
	    type = "Conflict";
	    break;
	    
	  case 410:
	    type = "Gone";
	    break;

	  case 412:
	    type = "Precondition Failed";
	    break;
	    
	  case 500:
	    type = "Internal Server Error";
	    break;
		
	  case 501:
	    type = "Not Implemented";
	    break;
	    
	  case 502:
	    type = "Bad Gateway";
	    break;
	    
	  case 503:
	    type = "Service Unavailable";
	    break;
	    
	  case 504:
	    type = "Gateway Timeout";
	    break;
	    
	  default:
	    type = "?";
	}

    if (cip->hip->version)
    {  if ( strcasecmp(cip->hip->version,"HTTP/1.1") !=0 )
         fd_puts("HTTP/1.0 ", fd);
       else
         fd_puts("HTTP/1.1 ", fd);
    }
    else
         fd_puts("HTTP/1.0 ", fd);

    fd_puti(code, fd);
    fd_putc(' ', fd);
    fd_puts(type, fd);
    fd_putc('\n', fd);
    
    fd_puts("MIME-Version: 1.0\n", fd);
/* Yes, we can that ! rk@netuse.de  check this, only for FILES.so */
/*    fd_puts("Accept-ranges: bytes\n", fd); */

    fd_puts("Date: ", fd);
    fd_puts(http_time_r(&ct, buf, sizeof(buf)), fd);
    
    fd_puts("Server: phttpd/", fd);
    fd_puts(server_version, fd);
    fd_putc('\n', fd);

    if (keepalive && (keepalive_timeout > 0 || keepalive_maxreq > 0))
    {
	fd_puts("Connection: Keep-Alive", fd);
	if (keepalive_timeout > 0)
	    fd_printf(fd, ", timeout=%d", keepalive_timeout);
	if (keepalive_maxreq > 0)
	    fd_printf(fd, ", maxreq=%d", keepalive_maxreq);
	fd_putc('\n', fd);
    }
    
    return type;
}    

int http_unauthorized(struct connectioninfo *cip, const char *realm)
{
    int result;
    int fd = cip->fd;
    struct httpinfo *hip = cip->hip;

    
    if (debug > 1)
	fprintf(stderr, "      Sent UNAUTHORIZED message\n");

    result = 401;

    if (hip->mip != NULL)
    {
	http_sendheaders(fd, cip, result, NULL);
	fd_printf(fd, "WWW-Authenticate: Basic realm=\"%s\"\n", realm);
	fd_putc('\n', fd);
    }

    if(strcasecmp(hip->method, "HEAD") == 0)
       return result;

    html_sysheader(fd, "H2", "Unauthorized");

    fd_printf(fd, "Please send authorization codes for realm \"%s\".\n",
	      realm);

    html_sysfooter(fd);
    
    return result;
}



int http_forbidden(struct connectioninfo *cip)
{
    int result;
    int fd = cip->fd;
    struct httpinfo *hip = cip->hip;

    
    if (debug > 1)
	fprintf(stderr, "      Sent FORBIDDEN message\n");

    result = 403;

    if (hip->mip != NULL)
    {
	http_sendheaders(fd, cip, result, NULL);
	fd_putc('\n', fd);
    }
    
    if(strcasecmp(hip->method, "HEAD") == 0)
       return result;

    html_sysheader(fd, "H2", "Access Denied");

    fd_printf(fd, "Your request to ");
    if (hip->orig_url == NULL)
	fd_printf(fd, "[null]");
    else
	html_href(fd, hip->orig_url, hip->orig_url);
    
    fd_printf(fd, " was denied.\n");

    html_sysfooter(fd);
    
    return result;
}


int http_authenticate(struct connectioninfo *cip,
		      const char *path,
		      const char *realm,
		      char *request)
{

   if ( debug > 5 )
     fprintf(stderr,"--x-- PATH: %s\n",(path!=NULL) ? path : "<NULL>" );
   if (!access_auth(cip->hip, cip, path))
	return http_unauthorized(cip, realm);

   return 0;
}


int http_access(struct connectioninfo *cip,
		urlinfo_t *uip,
		char *request)
{

    if ( access_check(uip, cip) == 0 )
	return error_access(cip);

/* access_check does set uip->source etc and so forces password authentification ! */
/* if wanted -- in http.c http_access MUST be called befor http_authenticate */

    return 0;
}


/*
 *  Extract the request (the part after the first '?') in URL and add
 *  it to the beginning of *REQUESTP.
 */
void
http_extract_request(char *url, char **requestp)
{
    char *cp;

    if (url == NULL)
	return;
    
    cp = strchr(url, '?');
    if (cp != NULL)
    {
	*cp++ = '\0';
	if (requestp == NULL)
	    return;
	
	if (!*requestp)
	{
	    *requestp = s_strdup(cp);
	}
	else
	{
	    char *oldrequest = *requestp;
	    size_t oldlen = strlen(oldrequest);
	    size_t addlen = strlen(cp);

	    *requestp = s_malloc(oldlen + 1 + addlen + 1);
	    memcpy(*requestp, oldrequest, oldlen);
	    *(*requestp + oldlen) = '?';
	    memcpy(*requestp + oldlen + 1, cp, addlen);
	    *(*requestp + oldlen + 1 + addlen) = '\0';
	    s_free(oldrequest);
	}
    }
}



int http_get_request(struct connectioninfo *cip,
		     int *keepalive)
{
    char buf[2048], *lastcp, *url, *req, *realurl;
    char ipnrbuf[18];
    struct httpinfo *hip = NULL;
    int result = -1;
    int headerbytes;
    ucentry_t *ucp;
    urlinfo_t *uip;
    char *realm;
    int len;
    char *p1,*p2,*svpath=NULL, *svport=NULL;
    char *xurl=NULL;
	    
    ucp = NULL;
    uip = NULL;
    
    if (debug > 1)
	fprintf(stderr, "http_get_request(), fd=%d\n", cip->fd);
    
    if ((req = fd_gets(NULL, maxurlsize, cip->fd)) == NULL)
    {
	if (debug > 2)
	    fprintf(stderr, "\t->Returning failed (fd=%d)\n", cip->fd);
	return -1;
    }
    
    hip = s_malloc(sizeof(struct httpinfo));
    headerbytes=strlen(req);
   
    hip->svsname = NULL;
    hip->prefix = NULL;
    hip->method = strtok_r(req, " \t\n\r", &lastcp);
    if (hip->method == NULL)
    {
	http_freeinfo(hip);
	return -1;
    }
    
    url = strtok_r(NULL, " \t\n\r", &lastcp);
    if (url)
	hip->version = s_strdup(strtok_r(NULL, " \t\n\r", &lastcp));

    if (url == NULL)
    {
        http_freeinfo(hip);
	return -1;
    }

/* Get the mimeheader first !! */
    if (hip->version != NULL)
    {
	hip->mip = mime_getheaders(cip->fd);
	if (hip->mip == NULL)
	{
	    error_bad_request(cip, "Invalid MIME headers");
	    goto End;
	}
	hip->mip->headerbytes=hip->mip->headerbytes+headerbytes;
	
	if (  keepalive && hip->mip &&
	      (hip->mip->connection_flags & MCF_KEEPALIVE)  )
	    *keepalive = 1;

	/* Get the client-supplied authentication information */
	hip->aip = auth_get(hip);
    }

/* Clear setup.... */
    hip->prelen=0;

/* Added for Multi-Virtual-Server RK */
/* Some how ugly, might be a nicer way to code this, but it works ! */
/* Maybe one should create differnt global accept code, depending on the
** mode, we are running. This may look nicer, but more code to maintain. 
** 23.11.97 rk@netuse.de
*/

/* We do allways store the ip number of the incoming interface ! */
	if ( mode_dotted == 1 )
		s_sprintf(ipnrbuf, 18, "/%s", inet_ntoa(*(struct in_addr *) &(cip->server->sin.sin_addr.s_addr)));
	else
		s_sprintf(ipnrbuf, 18, "/%08lx", cip->server->sin.sin_addr.s_addr );
	hip->vs_ipnr=s_strdup(ipnrbuf);

/* Next we will check, if we get the incoming hostname (like to be used for svs !) */
	p1=mime_getheader(hip->mip,"HOST",1);
	if ( p1 )
	{
		p2=strchr(p1,':');
		if ( p2 )
			hip->svsname=s_strndup(p1,p2-p1);
		else
			hip->svsname=s_strdup(p1);
			
	}

/* In case, we do NOT get a mime-header-host, we will try to analyze the incoming url for a host[:port] */
	if ( hip->svsname == NULL && hip->version != NULL )
	{
        	if ( strncasecmp(url,"http://",7)== 0 && strlen(url) > 7 )
		{ /* we got request like ... http://host/path HTTP/1.x */
			realurl=url+7;			/* now we are the hostposition */
			svpath=strchr(realurl,'/');	/* Now find the / after host or host:port
							   or we have a NULL, if no host */
			svport=strchr(realurl,':');	/* Do we have a port ? */
			if ( svport == NULL )	svport=svpath;
			if ( svport < svpath )	svpath=svport;

			if ( svpath != NULL && realurl != svpath )
			{
				hip->svstype=SVSINGET;
				hip->svsname=s_strndup(realurl,svpath-realurl);		/* Store the hostname without the optional port */
			}
		}
	}

	if ( svpath == NULL ) svpath=url;

/* In case we cannot retrieve any value, set interface or name */
/* TODO: If not set but needed, we should use some global default: vs_master_name       */

   if ( hip->svsname == NULL )
   {
	if ( strcmp(server_host ,"*") == 0 )
		hip->svsname=s_strdup(dns_lookup_servername(cip->server));
	else
		hip->svsname=s_strdup(server_host);
	if ( debug > 6 )
		fprintf(stderr,"Forced SVS default(hip->svsname) to %s\n",hip->svsname);
   }

	if ( debug > 6 )
		fprintf(stderr,"VirtServer GOT: H: %s SV-Host: %s\n",hip->vs_ipnr,(hip->svsname!=NULL)?hip->svsname:"<NULL>");

/* Now we have set: "/aaxxyyzz" or "/a.b.c.d" in ipnrbuf .
   And hip->svsname is set.
   Now we need to put those parts together, depending on the values of rkmultimode and svs
   Here we also take care of sub_server_home, which is only honored in any virtual
   hosting mode. This make it easier to put ftp-chroot together with docroot.
   subserverhome MUST be like /path or "" .
 */
	xurl=NULL;
	hip->prelen=0;

	str_to_lower(hip->svsname);

/* We need to build xurl ! 				*/
/* Format is [rkmultimode]/[softvirtserver]/path	*/
	if ( debug > 8 )
	{
		fprintf(stderr,"Values:\t ipnrbuf=%s\n",ipnrbuf);
		fprintf(stderr,"       \t svsname=%s\n",hip->svsname);
		fprintf(stderr,"       \t sub_s_h=%s\n",sub_server_home);
		fprintf(stderr,"       \t svpath=%s\n",svpath?svpath:"<NULL>");
		fprintf(stderr,"       \t >svpath=%s\n",svpath?notslash(svpath):"<NULL>");
	}

	if ( rkmultimode && softvirtserver )
	{
		hip->prelen=1+strlen(ipnrbuf)+strlen(hip->svsname)+strlen(sub_server_home);
		len=1+hip->prelen+strlen(svpath);
		xurl=s_malloc(len);
		s_sprintf(xurl, len, "%s/%s%s/%s",ipnrbuf,hip->svsname,sub_server_home,notslash(svpath));
	}
	if ( rkmultimode && ! softvirtserver )
	{
		hip->prelen=strlen(ipnrbuf)+strlen(sub_server_home);
		len=1+hip->prelen+strlen(svpath);
		xurl=s_malloc(len);
		s_sprintf(xurl, len, "%s%s/%s",ipnrbuf,sub_server_home,notslash(svpath));
	}
	if ( ! rkmultimode && softvirtserver )
	{
		hip->prelen=1+strlen(hip->svsname)+strlen(sub_server_home);
		len=1+hip->prelen+strlen(svpath);
		xurl=s_malloc(len);
		s_sprintf(xurl, len, "/%s%s/%s",hip->svsname,sub_server_home,notslash(svpath));
	}
	if ( ! rkmultimode && ! softvirtserver )
	{
		hip->prelen=strlen(sub_server_home);
		len=1+hip->prelen+strlen(svpath);
		xurl=s_malloc(len);
		s_sprintf(xurl, len, "%s/%s",sub_server_home,notslash(svpath));
	}

	if ( xurl[0] != '/' )
	{
		fprintf(stderr,"SERVER INTERNAL ERROR ON xurl BUILD (%s)[%s] !\n",url ? url : "<null>",xurl);
	}
    
    if (debug > 2 )
		fprintf(stderr, "Virtualserver: NEWURL: %s (%d)\n",(xurl!=NULL)?xurl:"-NONE-",hip->prelen);

    /* if we have some virtual hosting mode, save the prefix to the requests hip-> struct. */
    if ( xurl && hip->prelen > 0 ) hip->prefix=s_strndup(xurl,hip->prelen);

    if (debug > 4)
	fprintf(stderr, "Method = %s, URL = %s PL = %d\n",
		hip->method, url ? url : "<null>", hip->prelen);

/* If we had any kind of virtual hosting, xurl now has the expanded URL-Path with host etc
   stripped off. Otherwise xurl==NULL and we will copy url and continue to work with xurl,
   which gives us a simple cleanup...
 */
    if ( xurl == NULL && url != NULL ) xurl=s_strdup(url);
   
/* we have a memleak somewhere........ maybe here */
    if ( cip->hip )
	{  http_freeinfo(cip->hip); 
	   fprintf(stderr,"memleak found: pos 1\n");
	}

    cip->hip = hip;

/* Do not use that new code, seems to be buggy !!!! rk@netuse.de */
#if 0
    hip->orig_url = s_strdup(url);
    hip->orig_request = NULL;
    url_unquote(url, 0);
#else
    http_extract_request(xurl, &hip->request);
    hip->orig_url = s_strdup(xurl);
    hip->orig_request = s_strdup(hip->request);
    url_unquote(xurl, 0);
/* we need to cleanup the url to strip multiple / to a single / 
   we also drop /./ to / and try to handle /../ to move one up, like a unix path.
 */
    url_cleanup(xurl);

    if (debug > 1)
	fprintf(stderr, "(x)url=%s\norig_url=%s\nreq=%s\norig_req=%s\n",
		xurl ? xurl : "<null>",
		hip->orig_url ? hip->orig_url : "<null>",
		hip->request ? hip->request : "<null>",
		hip->orig_request ? hip->orig_request : "<null>");
#endif
    
    if (strcasecmp(hip->method, "PING") == 0)
    {
	if (hip->mip)
	{
	    http_sendheaders(cip->fd, cip, 200, NULL);
	    result = 200;
	    fd_putc('\n', cip->fd);
	}
	fd_puts("PONG\n", cip->fd);
	goto End;
    }
    
    if (hip->mip && (hip->mip->pragma_flags & MPF_NOCACHE))
	ucp = urlcache_lookup(xurl, UCF_ALL+UCF_RELOAD);
    else
	ucp = urlcache_lookup(xurl, UCF_ALL);
			      
    if (ucp == NULL)
	goto End;

/*  XXXX URL (xurl) is now split into url and request part XXXX */
    
    uip = ucp->uip;
    if (uip == NULL)
    {
	urlcache_release(ucp);
	goto End;
    }

    hip->url = s_strdup(uip->rewrite.url);
    
    if (uip->rewrite.request)
    {
	if (hip->request)
	    s_free(hip->request);
	hip->request = s_strdup(uip->rewrite.request);
    }
    
    if (uip->redirect.url)
    {
	result = http_redirect(cip,
			       uip->redirect.url,
			       uip->redirect.request,
  			       hip->request,
			       302);
	goto End;
    }
    
    if (uip->predirect.url)
    {
	result = http_redirect(cip,
			       uip->predirect.url,
			       uip->predirect.request,
  			       hip->request,
			       301);
	goto End;
    }
    
    if (uip->access.path)
    {
	result = http_access(cip, uip, hip->request);
	if (result != 0)
	    goto End;
    }
    

    /* ADDED by RK */

    if (debug > 4)
	fprintf(stderr,"Check write ACCESS\n");
    
    if (write_needs_auth && 
	(strcasecmp(hip->method, "PUT")==0 ||
	 strcasecmp(hip->method, "DELETE")==0))
    {
	if (debug > 4)
	    fprintf(stderr,"We have a write CMD...\n");
	
      if (write_getauthenticate(xurl, buf, sizeof(buf))) 
      {
          uip->auth.source=s_strdup(buf);
          realm = uip->auth.source;
          if (realm)
          {   
              while (*realm && !s_isspace(*realm))
		  ++realm;
              if (s_isspace(*realm))
		  *realm++ = '\0';
              while (*realm && s_isspace(*realm))
		  ++realm;
          }
          uip->auth.realm = realm;
          uip->flags |= UCF_AUTH;
	  if ( debug > 4 )
	      fprintf(stderr,"Using auth for...%s\n",uip->auth.source);
      }
      else
      {
          uip->auth.source=NULL;
	  result = -403;
	  goto End;
      }
    } /* end of write_needs_auth */

    if (uip->auth.source)
    {
	result = http_authenticate(cip,
				   uip->auth.source,
				   uip->auth.realm,
				   hip->request);
	if (result != 0)
	    goto End;
    }

    if (uip->handler)
	result = phttpd_call(uip->handler, cip);

    if (debug > 3)
	fprintf(stderr, "MAIN-RETURN: Result=%d\n", result);

  End:

    if ( xurl ) s_free(xurl);	/* clean up */

    if (result < 0)
	switch (result)
	{
	  case -1:
	    result = error_not_found(cip);
	    break;

	  case -403:
	    result = error_access(cip);
	    break;
	    
	  case -405:
	    result = error_method_denied(cip);
	    break;
	    
	  default:
	    result = error_bad_request(cip, hip->method);
	    syslog(LOG_NOTICE, "bad HTTP request (#%d) method: %s",
		   cip->request_no,
		   hip->method);
	}

    if (ucp)
	urlcache_release(ucp);
    
    if (hip->length == 0)
	*keepalive = 0;
    
    if (debug > 1)
	fprintf(stderr, "http_get_request(), fd=%d, returning %d\n",
		cip->fd, result);
    
    return result;
}


void http_freeinfo(struct httpinfo *hip)
{
    if (hip == NULL)
	return;
    
    s_free(hip->method);
    s_free(hip->url);
    s_free(hip->request);
    s_free(hip->orig_url);
    s_free(hip->orig_request);
    s_free(hip->version);
    s_free(hip->prefix);
    s_free(hip->svsname);
    s_free(hip->vs_ipnr);
    
    if (hip->mip) mime_freeheaders(hip->mip);
    auth_free(hip->aip);
    
    s_free(hip);
}

int http_error(struct connectioninfo *cip,
	       int code,
	       const char *format,
	       ...)
{
    va_list ap;
    char *type, buf[256];
    struct httpinfo *hip = cip->hip;
    char *servername=NULL;
    

    if (hip->mip != NULL)
    {
	type = http_sendheaders(cip->fd, cip, code, NULL);
	fd_puts("Content-Type: text/html\n", cip->fd);
	fd_putc('\n', cip->fd);
    }
    else
    {
        int blen;
      
        blen = s_strcpy(buf, sizeof(buf), "Error Code #");
	s_sprintf(buf+blen, sizeof(buf)-blen, "%d", code);
	type = buf;
    }

    if (strcasecmp(hip->method, "HEAD") == 0)
	return code;
    
    va_start(ap, format);
  
/* TODO ??? Might be buggy due to new svs-creation code...... */ 
    if ( softvirtserver )   servername=s_strdup(hip->svsname);
    else if ( rkmultimode ) servername=s_strdup(dns_lookup_servername(cip->server));

    html_error(cip->fd, servername, type, format, ap);
    
    va_end(ap);
    hip->length = fd_written(cip->fd);
   
    if ( servername != NULL ) s_free(servername); 

    return code;
}

void http_sendlang(int fd, const char *url)
{
    int i;
    char **pair;

    if(content_language_table == NULL)
        return;

    for(i = 0; i < content_language_table->length; ++i)
    {
        pair = content_language_table->value[i];
	if(strmatch(url, pair[0]))
	{
	    fd_puts("Content-Language: ", fd);
	    fd_puts(pair[1], fd);
	    fd_putc('\n', fd);
	    break;
	}
    }
}

/* Send a redirect pointer */
int http_redirect(struct connectioninfo *cip,
		  const char *url,
		  const char *request,
		  const char *orig_req,
		  int code)
{
    char buf1[2048], buf2[2048], buf3[2048];
    int result, len;
    int fd = cip->fd;
    struct httpinfo *hip = cip->hip;


    url = url_quote(url, buf1, sizeof(buf1), "?", 0);
    if (url == NULL)
	return -1;
    
    if (request)
    {
	request = url_quote(request, buf2, sizeof(buf2), "\"", 1);
	if (request == NULL)
	    return -1;
    }

    if (orig_req)
    {
	orig_req = url_quote(orig_req, buf3, sizeof(buf3), "\"", 1);
	if (orig_req == NULL)
	    return -1;
    }
    
    if (debug > 1)
	fprintf(stderr, "      Sent URL REDIRECT (%s -> %s)\n",
		hip->url, url);
	
    result = code;
    
    if (hip->mip != NULL)
    {
	http_sendheaders(fd, cip, result, NULL);
	
	fd_printf(fd, "Location: %s%s%s%s\n",
		  url,
		  (orig_req || request) ? "?" : "",
		  orig_req ? orig_req : "",
		  request ? request : "");
		  

	http_sendlastmodified(fd, cip->cn_time);
	fd_puts("Content-Type: text/html\n\n", fd);
    }
    
    if (strcasecmp(hip->method, "HEAD") == 0)
	return result;
    
    len = fd_written(fd);

    html_sysheader(fd, "H2", "Document moved");
    
    fd_puts("The document has moved to this URL:<P>\n", fd);
    fd_puts("<UL>\n", fd);
    
    fd_printf(fd, "<B><A HREF=\"%s%s%s%s\">%s%s%s%s</A></B>.\n",
	      url,
	      (orig_req || request) ? "?" : "",
	      orig_req ? orig_req : "",
	      request ? request : "",
	      url,
	      (orig_req || request) ? "?" : "",
	      orig_req ? orig_req : "",
	      request ? request : "");
    
    fd_puts("</UL>\n", fd);
    
    html_sysfooter(fd);

    if (logheadervolume)
	hip->length = fd_written(fd);
    else
	hip->length = fd_written(fd) - len; 

    return result;
}


/* Send a 'Not Modified' message */
int http_not_modified(struct connectioninfo *cip)
{
    int result;
    int fd = cip->fd;
    struct httpinfo *hip = cip->hip;

    
    if (debug > 1)
	fprintf(stderr, "      Sent NOT MODIFIED message\n");

    result = 304;

    if (hip->mip != NULL)
    {
	http_sendheaders(fd, cip, result, NULL);
	fd_putc('\n', fd);
    }
    hip->length = fd_written(fd);
    return result;
}


/* Send a 'Precondition Failed' message */
int http_precondition_failed(struct connectioninfo *cip)
{
    int result;
    int fd = cip->fd;
    struct httpinfo *hip = cip->hip;

    
    if (debug > 1)
	fprintf(stderr, "      Sent PRECONDITION FAILED message\n");

    result = 412;

    if (hip->mip != NULL)
    {
	http_sendheaders(fd, cip, result, NULL);
	fd_putc('\n', fd);
    }
    
    if(strcasecmp(hip->method, "HEAD") == 0)
       return result;

    html_sysheader(fd, "H2", "Precondition Failed");

    fd_printf(fd, "The entity which lives at ");
    if (hip->orig_url == NULL)
	fd_printf(fd, "[null]");
    else
	html_href(fd, hip->orig_url, hip->orig_url);
    
    fd_printf(fd, " was changed.\n");

    html_sysfooter(fd);
    hip->length = fd_written(fd);
    
    return result;
}


static const char *const weekday[] =
{
    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};

static const char *const month[] =
{
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};


char *http_time_r(const time_t *btp, char *buf, int bufsize)
{
    struct tm tpb;

    
    if (bufsize < 31)
	return NULL;
    
    if (gmtime_r(btp, &tpb) == NULL)
	return NULL;

    s_sprintf(buf, bufsize, "%s, %02d %s %d %02d:%02d:%02d GMT\n",
	    weekday[tpb.tm_wday],
	    tpb.tm_mday,
	    month[tpb.tm_mon],
	    tpb.tm_year + 1900,
	    tpb.tm_hour,
	    tpb.tm_min,
	    tpb.tm_sec);

    return buf;
}
