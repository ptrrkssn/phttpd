# Top level makefile for phttpd
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

##
## Where all files are to be installed/located
##
INSTROOT  = /opt/phttpd
DOINSTROOT  = /opt/phttpd
#DOINSTROOT  = ../in/opt/phttpd

##
## Which Make to use
##
MAKE = make

##
## Common C compiler flags for all compilers.
##
## Add "-DUNIXWARE" if compiling under UnixWare.
##
## Add "-DHAVE_VSNPRINTF" if your Unix have the __vsnprintf() function.
## (Solaris 2.5.1 does)
#
#COMCFLAGS = -DINSTROOT='\"'$(INSTROOT)'\"' -DINCLUDE_ALLOC_STATS -DUSE_RK_ADDONS
COMCFLAGS = -DINSTROOT='\"'$(INSTROOT)'\"' -DUSE_RK_ADDONS



##
## Uncomment this to link with the Electric Fence malloc debugger
## (an MT-Safe version is available by FTP from ftp.lysator.liu.se in
##  the directory pub/libraries)
##
# LIBEFENCE = -L/opt/gnu/lib -lefence


##
## Sun/Solaris - Gnu CC
##
## Add "-msupersparc" to CFLAGS if compiling for a SuperSPARC machine.
##
CC        = gcc -Wall
CFLAGS    = -g -O2 $(COMCFLAGS) -DUSE_GETDENTS -DUI_THREADS
LIBCFLAGS = -fpic
XOBJS     = solaris.o
LIBS      = -lmalloc -lpthread -lsocket -lnsl -ldl 
MODLD	   = /usr/ccs/bin/ld -s -G -z text


##
## Sun/Solaris - SparcWorks C
##
#CC        = cc
#CFLAGS    = -g -O -fast $(COMCFLAGS) -DUSE_GETDENTS -DUI_THREADS
#LIBCFLAGS = -Kpic
#XOBJS     = solaris.o
#LIBS      = -lthread -lnsl -lsocket -ldl
#MODLD	   = /usr/ccs/bin/ld -G -z text


##
## Sun/Solaris - Apogee C
##
#CC        = apcc
#CFLAGS    = -g -O $(COMCFLAGS) -DUSE_GETDENTS -DUI_THREADS
#LIBCFLAGS = -pic
#XOBJS 	   = solaris.o
#LIBS      = -lthread -lnsl -lsocket -ldl
#MODLD	   = /usr/ccs/bin/ld -G -z text


##
## UnixWare - Gnu CC
##
#CC        = gcc -Wall
#CFLAGS    = -g -O $(COMCFLAGS) -DUSE_GETDENTS -DUI_THREADS
#LIBCFLAGS = -fpic
#XOBJS	   =  unixware.o
#LIBS      = -lthread -lnsl -lsocket -ldl
#MODLD	   = /usr/ccs/bin/ld -G -z text

##
## Digital Unix 4.0 - cc
##
#CC      = cc -pthread
#CFLAGS  = -I../spilt -O $(COMCFLAGS) 
#LIBCFLAGS =
#XOBJS	= spilt_thread.o osf.o
#LIBS    = -lpthread
#MODLD	= ld -shared -expect_unresolved '*'
 
##
## IRIX 5.3 - pgcc
##
# CC	    = pgcc -Wall
# CFLAGS    = -I../spilt -O $(COMCFLAGS) -I/usr/local/pthreads/include -g  -D_SGI_MP_SOURCE -D_SGI_REENTRANT_FUNCTIONS 
# LIBCFLAGS = 
# XOBJS	    = spilt_thread.o irix.o hackpthreads.o
# LIBS      = -lpthread -ldl

##
## IRIX 6.2 - cc
##
# CC	    = cc
# CFLAGS    = -I../spilt -O $(COMCFLAGS) -D_SGI_MP_SOURCE -D_SGI_REENTRANT_FUNCTIONS -Wl,-woff,85
# LIBCFLAGS =
# XOBJS	    = spilt_thread.o irix.o hackpthreads.o
# LIBS      = -lpthread -ldl


INSTALL   = /usr/ucb/install
TAR       = tar


##### You should not have to modify anything below this line ###############


all:	phttpd modules ackpfd utils ptester dhttpd tests

install.all:	install install.conf install.etc install.header

install:	install.bin install.doc install.icons

install.srv:	phttpd
	@$(INSTALL) -d -m 0755 $(DOINSTROOT)/sbin
	$(INSTALL) -c -m 0755 src/phttpd/phttpd $(DOINSTROOT)/sbin

install.modules: modules
	@$(INSTALL) -d -m 0755 $(DOINSTROOT)/modules	
	$(INSTALL) -c -m 0755 src/modules/*.so $(DOINSTROOT)/modules

install.bin: install.srv install.modules ackpfd utils ptester dhttpd
	@$(INSTALL) -d -m 0755 $(DOINSTROOT)/bin
	$(INSTALL) -c -m 0755 src/ackpfd/ackpfd $(DOINSTROOT)/sbin
	$(INSTALL) -c -m 0755 src/dhttpd/dhttpd $(DOINSTROOT)/sbin
	$(INSTALL) -c -m 0755 src/ptester/ptester $(DOINSTROOT)/bin
	$(INSTALL) -c -m 0755 src/utils/logcvt-ip2n $(DOINSTROOT)/bin
	$(INSTALL) -c -m 0755 src/utils/htmlencode $(DOINSTROOT)/bin
	$(INSTALL) -c -m 0755 src/utils/httpdecode $(DOINSTROOT)/bin
	$(INSTALL) -c -m 0755 etc/rotate.logs $(DOINSTROOT)/bin
#	$(INSTALL) -c -m 0644 etc/purify.options $(DOINSTROOT)/bin/.purify
#	$(INSTALL) -c -m 0644 etc/purify.options $(DOINSTROOT)/sbin/.purify

install.header:
	@$(INSTALL) -d -m 0755 $(DOINSTROOT)/include
	@$(INSTALL) -d -m 0755 $(DOINSTROOT)/include/phttpd
	@$(INSTALL) -d -m 0755 $(DOINSTROOT)/include/modules
	$(INSTALL) -c -m 0755 src/phttpd.h $(DOINSTROOT)/include
	$(INSTALL) -c -m 0755 src/phttpd/auth.h $(DOINSTROOT)/include/phhtpd
	$(INSTALL) -c -m 0755 src/phttpd/autofail.h $(DOINSTROOT)/include/phhtpd
	$(INSTALL) -c -m 0755 src/phttpd/cache.h $(DOINSTROOT)/include/phhtpd
	$(INSTALL) -c -m 0755 src/phttpd/config.h $(DOINSTROOT)/include/phhtpd
	$(INSTALL) -c -m 0755 src/phttpd/connection.h $(DOINSTROOT)/include/phhtpd
	$(INSTALL) -c -m 0755 src/phttpd/dns.h $(DOINSTROOT)/include/phhtpd
	$(INSTALL) -c -m 0755 src/phttpd/error.h $(DOINSTROOT)/include/phhtpd
	$(INSTALL) -c -m 0755 src/phttpd/fdstdio.h $(DOINSTROOT)/include/phhtpd
	$(INSTALL) -c -m 0755 src/phttpd/fscache.h $(DOINSTROOT)/include/phhtpd
	$(INSTALL) -c -m 0755 src/phttpd/globals.h $(DOINSTROOT)/include/phhtpd
	$(INSTALL) -c -m 0755 src/phttpd/hashtable.h $(DOINSTROOT)/include/phhtpd
	$(INSTALL) -c -m 0755 src/phttpd/hostcache.h $(DOINSTROOT)/include/phhtpd
	$(INSTALL) -c -m 0755 src/phttpd/html.h $(DOINSTROOT)/include/phhtpd
	$(INSTALL) -c -m 0755 src/phttpd/http.h $(DOINSTROOT)/include/phhtpd
	$(INSTALL) -c -m 0755 src/phttpd/ident.h $(DOINSTROOT)/include/phhtpd
	$(INSTALL) -c -m 0755 src/phttpd/logger.h $(DOINSTROOT)/include/phhtpd
	$(INSTALL) -c -m 0755 src/phttpd/macros.h $(DOINSTROOT)/include/phhtpd
	$(INSTALL) -c -m 0755 src/phttpd/mime.h $(DOINSTROOT)/include/phhtpd
	$(INSTALL) -c -m 0755 src/phttpd/modules.h $(DOINSTROOT)/include/phhtpd
	$(INSTALL) -c -m 0755 src/phttpd/multi.h $(DOINSTROOT)/include/phhtpd
	$(INSTALL) -c -m 0755 src/phttpd/process.h $(DOINSTROOT)/include/phhtpd
	$(INSTALL) -c -m 0755 src/phttpd/readdir.h $(DOINSTROOT)/include/phhtpd
	$(INSTALL) -c -m 0755 src/phttpd/safeio.h $(DOINSTROOT)/include/phhtpd
	$(INSTALL) -c -m 0755 src/phttpd/server.h $(DOINSTROOT)/include/phhtpd
	$(INSTALL) -c -m 0755 src/phttpd/signals.h $(DOINSTROOT)/include/phhtpd
	$(INSTALL) -c -m 0755 src/phttpd/strutils.h $(DOINSTROOT)/include/phhtpd
	$(INSTALL) -c -m 0755 src/phttpd/table.h $(DOINSTROOT)/include/phhtpd
	$(INSTALL) -c -m 0755 src/phttpd/url.h $(DOINSTROOT)/include/phhtpd
	$(INSTALL) -c -m 0755 src/phttpd/urlcache.h $(DOINSTROOT)/include/phhtpd
	$(INSTALL) -c -m 0755 src/phttpd/usercache.h $(DOINSTROOT)/include/phhtpd
	$(INSTALL) -c -m 0755 src/phttpd/util.h $(DOINSTROOT)/include/phhtpd

install.demo:
	@$(INSTALL) -d -m 0755 $(DOINSTROOT)/demo
	@$(INSTALL) -d -m 0755 $(DOINSTROOT)/demo/src
	@$(INSTALL) -d -m 0755 $(DOINSTROOT)/demo/src/modules
	$(INSTALL) -c -m 0755 src/modules/demo.c $(DOINSTROOT)/demo/src/modules
	$(INSTALL) -c -m 0755 src/modules/Makefile.demo $(DOINSTROOT)/demo/src/modules

install.conf:
	@$(INSTALL) -d -m 0755 $(DOINSTROOT)/modules
	@$(INSTALL) -d -m 0755 $(DOINSTROOT)/etc
	$(INSTALL) -m 0755 config/modules/*.conf $(DOINSTROOT)/modules
	$(INSTALL) -c -m 0644 config/phttpd.conf $(DOINSTROOT)/etc

install.doc:
	@$(INSTALL) -d -m 0755 $(DOINSTROOT)/db
	@$(INSTALL) -d -m 0755 $(DOINSTROOT)/db/phttpd
	@$(INSTALL) -d -m 0755 $(DOINSTROOT)/db/phttpd/doc
	@$(INSTALL) -d -m 0755 $(DOINSTROOT)/db/phttpd/doc/user
	@$(INSTALL) -d -m 0755 $(DOINSTROOT)/db/phttpd/doc/admin
	@$(INSTALL) -d -m 0755 $(DOINSTROOT)/db/phttpd/examples
	$(INSTALL) -c -m 0644 doc/phttpd/*.html $(DOINSTROOT)/db/phttpd
	$(INSTALL) -c -m 0644 doc/phttpd/*.gif $(DOINSTROOT)/db/phttpd
	$(INSTALL) -c -m 0644 examples/*.shtml $(DOINSTROOT)/db/phttpd/examples
	$(INSTALL) -c -m 0644 examples/*.map $(DOINSTROOT)/db/phttpd/examples
	$(INSTALL) -c -m 0644 examples/*.txt $(DOINSTROOT)/db/phttpd/examples
	$(INSTALL) -c -m 0644 examples/*.acl $(DOINSTROOT)/db/phttpd/examples
	$(INSTALL) -c -m 0755 examples/*.cgi $(DOINSTROOT)/db/phttpd/examples
	rm -fr $(DOINSTROOT)/db/phttpd/doc/admin
	cp -r doc/admin $(DOINSTROOT)/db/phttpd/doc
	rm -fr $(DOINSTROOT)/db/phttpd/doc/user
	cp -r doc/user $(DOINSTROOT)/db/phttpd/doc

install.icons:
	@$(INSTALL) -d -m 0755 $(DOINSTROOT)/db
	@$(INSTALL) -d -m 0755 $(DOINSTROOT)/db/icons
	$(INSTALL) -c -m 0644 icons/* $(DOINSTROOT)/db/icons

install.etc:
	@if [ `id | awk '{print index($$1, "root")}'` -eq 0 ]; then \
		echo "Seeing as you aren't root I shall not install /etc/init.d/phttpd" ; \
	else \
		$(INSTALL) -c -m 0755 etc/phttpd.init /etc/init.d/phttpd ; \
	fi

#

phttpd:
	@(cd src/phttpd ; $(MAKE) all CC="$(CC)" CFLAGS="$(CFLAGS) -D_REENTRANT -I.." LIBS="$(LIBS) $(LIBEFENCE)" XOBJS="$(XOBJS)")

modules:
	@(cd src/modules ; $(MAKE) all CC="$(CC)" CFLAGS="$(LIBCFLAGS) $(CFLAGS) -D_REENTRANT -I.." LINKER="$(MODLD)" LIBS="$(LIBS) $(LIBEFENCE)")

ackpfd:
	@(cd src/ackpfd ; $(MAKE) all CC="$(CC)" CFLAGS="$(CFLAGS)" LIBS="$(LIBS) $(LIBEFENCE)")

utils:
	@(cd src/utils ; $(MAKE) all CC="$(CC)" CFLAGS="$(CFLAGS)" LIBS="$(LIBS) $(LIBEFENCE)")

ptester:
	@(cd src/ptester ; $(MAKE) all CC="$(CC)" CFLAGS="$(CFLAGS) -D_REENTRANT -I.." LIBS="$(LIBS) $(LIBEFENCE)")

dhttpd:
	@(cd src/dhttpd ; $(MAKE) all CC="$(CC)" CFLAGS="$(CFLAGS) -D_REENTRANT -I.." LIBS="$(LIBS) $(LIBEFENCE)")

tests:
	@(cd src/tests ; $(MAKE) all CC="$(CC)" CFLAGS="$(CFLAGS) -D_REENTRANT -I.." LIBS="$(LIBS) $(LIBEFENCE)")

#


clean:
	@echo "Cleaning up..."
	@find . '(' -name '*~' -o -name 'core' -o -name '.nfs*' -o -name '%*' -o -name '#*' ')' -print -exec rm -f {} \;
	@(cd src/phttpd ; $(MAKE) clean)
	@(cd src/ackpfd ; $(MAKE) clean)
	@(cd src/modules ; $(MAKE) clean)
	@(cd src/tests ; $(MAKE) clean)
	@(cd src/utils ; $(MAKE) clean)
	@(cd src/ptester ; $(MAKE) clean)
	@(cd src/dhttpd ; $(MAKE) clean)

#

version:
	(PACKNAME=`basename \`pwd\`` ; echo 'char server_version[] = "'`echo $$PACKNAME | cut -d- -f2`'";' >src/phttpd/version.c)

#

dist:	clean version
	(PACKNAME=`basename \`pwd\`` ; cd .. ; $(TAR) cf - $$PACKNAME | gzip -9 >$$PACKNAME.tar.gz)

#
upload:	dist
	(PACKNAME=`basename \`pwd\`` ; scp ../$$PACKNAME.tar.gz ChangeLog pen@sparky.signum.se:/usr/local/ftp/pub/phttpd)

#
# DO NOT DELETE THIS LINE -- make depend depends on it.
