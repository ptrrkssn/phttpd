/*
** util.c			       Misc helper functions.
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

#include <syslog.h>
#include <string.h>

#include "phttpd.h"


static int get_addr(const char *host, struct in_addr *ia)
{
    if (s_isdigit(*host))
	ia->s_addr = inet_addr(host);
    else
    {
	struct hostent hp;
	int h_errno;
	char buf[2048];
	
	if (gethostbyname_r(host, &hp, buf, sizeof(buf), &h_errno) == NULL)
	    return -1;

	memcpy(ia, hp.h_addr_list[0], hp.h_length);
    }

    return 0;

}

int create_listen_socket(const char *addr, int port)
{
    int one = 1;
    struct sockaddr_in sa_in;

/* fprintf(stderr,"IN...\n");  */
    
    if ((listen_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
	syslog(LOG_ERR, "create_listen_socket(): socket() failed: %m");
	return -1;
    }
    
    /* We ignore any error here - not fatal anyway.. */
    setsockopt(listen_sock,
	       SOL_SOCKET, SO_REUSEADDR, (void *) &one, sizeof(one));
    
    memset(&sa_in, 0, sizeof(sa_in));
    sa_in.sin_family = AF_INET;
    
/* fprintf(stderr,"IN-1...%s\n", (addr == NULL ) ? "<NULL>": addr ); */
    if (addr == NULL || strcmp(addr, "*") == 0)
	sa_in.sin_addr.s_addr = INADDR_ANY;
    else
	get_addr(addr, &sa_in.sin_addr);
/* fprintf(stderr,"IN-2...\n");  */

    sa_in.sin_port = htons(port);
/* fprintf(stderr,"IN-3...\n"); */
    
    if (bind(listen_sock, (struct sockaddr *) &sa_in, sizeof(sa_in)))
    {
	syslog(LOG_ERR, "create_listen_socket(): bind() failed: %m");
	return -1;
    }
/* fprintf(stderr,"IN-4...\n");  */
    
    if (listen(listen_sock, n_listen))
    {
	syslog(LOG_ERR, "create_listen_socket(): listen() failed: %m");
	return -1;
    }

    return listen_sock;
}


void stderr_open(const char *path)
{
    int fd;


    if (debug)
	return;
    
    if (path == NULL)
        path = "/dev/null";

    fd = s_open(path, O_WRONLY+O_APPEND+O_CREAT, 0644);
    if (fd < 0)
    {
	syslog(LOG_ERR, "stderr_init(): %s: %m", path);
    }
    else if (fd != 2)
    {
	s_dup2(fd, 2);
	s_close(fd);
    }
}



void become_daemon(void)
{
    pid_t pid;
    int i, fd;

    
    for (i = 0; i < 2; i++)
	if (i != listen_sock)
	{
	    s_close(i);
	    
	    fd = s_open("/dev/null", O_RDONLY);
	    if (fd != i)
	    {
		s_dup2(fd, i);
		s_close(fd);
	    }
	}
    
    pid = fork();
    if (pid < 0)
    {
	syslog(LOG_ERR, "fork() failed: %m");
	exit(1);
    }
    else if (pid > 0)
	_exit(0);
    
    setsid();
}


static char b64tab[] =
{
    'A','B','C','D','E','F','G','H','I','J','K','L','M',
    'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
    'a','b','c','d','e','f','g','h','i','j','k','l','m',
    'n','o','p','q','r','s','t','u','v','w','x','y','z',
    '0','1','2','3','4','5','6','7','8','9','+','/', 0
};

static int b64tonum(int c)
{
    char *cp;


    cp = strchr(b64tab, c);
    if (cp == NULL)
	return -1;

    return cp - b64tab;
}


int base64_decode(const char *b64data, char *buf, int bufsize)
{
    int state, i;
    char *end;

    end = buf + bufsize;
    

    state = 0;
    i = 0;
    while (s_isspace(b64data[i]))
	++i;
    
    while (b64data[i] && b64data[i+1] &&
	   b64data[i+2] && b64data[i+3] && buf + 4 < end)
    {
	*buf = ((b64tonum(b64data[i]) << 2) +
		(b64tonum(b64data[i+1]) >> 4));
	
	if (*buf == -1)
	    break;
	++buf;
	
	*buf = ((b64tonum(b64data[i+1]) << 4) +
		  (b64tonum(b64data[i+2]) >> 2));
	
	if (*buf == -1)
	    break;
	++buf;
	
	*buf = ((b64tonum(b64data[i+2]) << 6) +
		  b64tonum(b64data[i+3]));

	if (*buf == -1)
	    break;
	++buf;
	
	i += 4;
    }

    *buf = '\0';

    return 1;
}

