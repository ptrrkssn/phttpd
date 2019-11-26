/*
** demo.c
**
** Copyright (c) 1995 Marcus E. Hennecke <marcush@leland.stanford.edu>
** Copyright (c) 1994-1995 Peter Eriksson <pen@signum.se>
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
#include <time.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

 
/* #define IN_DNS_C
#include "phttpd.h" */
 
#include "phttpd.h"

static char *full_name=NULL;

static struct options demo_cfg_table[] =
{
    { "full-name",  T_STRING , &full_name, NULL },
    { NULL,                -1,       NULL,  NULL }
};


int pm_init(const char **argv)
{
    char *cfg_path, *cp;
    const char *name = argv[0];
    int cfgsize;

    if (debug > 1)
	fprintf(stderr, "*** demo/pm_init(\"%s\") called ***\n", argv[0]);


    cfgsize = strlen(name)+6;
    cfg_path = s_malloc(cfgsize);
    s_strcpy(cfg_path, cfgsize, name);
 
    cp = strrchr(cfg_path, '.');
    if (cp && strcmp(cp, ".so") == 0)
        *cp = '\0';
   
    s_strcat(cfg_path, cfgsize, ".conf");
    if (config_parse_file(cfg_path, demo_cfg_table, 0) < 0)
        return -1;

 
    if (config_parse_argv(argv+1, demo_cfg_table) < 0)
    {
        if (debug > 1)
            fprintf(stderr, "config_parse_file() failed\n");
        return -1;
    }


    if (full_name == NULL ) full_name="Not set :-(";

    return 0;
}


void pm_exit(void)
{
    if (debug > 1)
	fprintf(stderr, "*** demo/pm_exit() called ***\n");
}


static int http_get_head(struct connectioninfo *cip)
{
    int result;
    int fd = cip->fd;
    struct httpinfo *hip = cip->hip;
    
    
    if (debug > 1)
	fprintf(stderr, "*** demo/pm_get() called ***\n");

    result = 200;
   
    http_sendheaders(fd, cip, result, NULL);

    fd_puts("Content-Type: text/plain\n\n", cip->fd);

    fd_printf(fd, "Myname: %s ... \n",full_name);
    if ( mime_getheader(hip->mip, "HIER", 1 ) != NULL )
    { 
       fd_printf(fd,"Got: HIER: (%s)\n",mime_getheader(hip->mip, "HIER", 1 ));
    }
    else fd_printf(fd,"Nix da\n");

    hip->length=fd_written(fd);

    return result;
}



int pm_request(struct connectioninfo *cip)
{
    struct httpinfo *hip = cip->hip;
    
    if (strcasecmp(hip->method, "GET") == 0 ||
	strcasecmp(hip->method, "HEAD") == 0)
	return http_get_head(cip);
    else
	return -2;
}
