#
#   Andrew McNab and Shiv Kaushal, University of Manchester.
#   Copyright (c) 2002-7. All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     o Redistributions of source code must retain the above
#       copyright notice, this list of conditions and the following
#       disclaimer. 
#     o Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials
#       provided with the distribution. 
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
#   CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
#   INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
#   MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#   DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
#   BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
#   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
#   TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
#   ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
#   OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
#   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#   POSSIBILITY OF SUCH DAMAGE.
#
#---------------------------------------------------------------
# For more information about GridSite: http://www.gridsite.org/ 
#---------------------------------------------------------------

include ../VERSION

RPMCMD=$(shell if [ -x /usr/bin/rpmbuild ] ; then echo /usr/bin/rpmbuild; else echo rpm; fi)

ifndef MYRPMDIR
export MYRPMDIR=$(shell pwd)/../RPMTMP
endif

ifndef prefix
export prefix=/usr/local
endif

ifndef libdir
export libdir=lib
endif

ifndef httpd_name
export httpd_name=httpd
endif

CURL_CFLAGS=`curl-config --cflags`
CURL_LIBS=`curl-config --libs`
XML2_CFLAGS=`xml2-config --cflags`
XML2_LIBS=`xml2-config --libs`
HTTPD_FLAGS=-I/usr/include/httpd -I/usr/include/apache2 -I/usr/include/apr-0 -I/usr/include/apr-1 -I/usr/include/apr-1.0
GSOAP_CFLAGS=`pkg-config gsoap --cflags`
GSOAP_LIBS=`pkg-config gsoap --libs`
GSOAPSSL_CFLAGS=`pkg-config gsoapssl --cflags`
GSOAPSSL_LIBS=`pkg-config gsoapssl --libs`
CANL_C_CFLAGS=
CANL_C_LIBS=-lcanl_c

ifndef MYCFLAGS
export MYCFLAGS=-I. -I../interface -DPIC -fPIC -DLINUX=2 -D_REENTRANT -D_LARGEFILE64_SOURCE $(HTTPD_FLAGS)
endif

ifndef MYLDFLAGS
export MYLDFLAGS=-L.
endif

-include Makefile.inc

# In order to use libtool versioning correcty, we must have:
#
# current = major + minor + offset
# revision = patch
# age = minor
#
# where offset is a sum of maximal released minor's of all previous major's
#

# counted minors: -
offset=0

version_info:=-version-info $(shell \
	perl -e '$$,=":"; @F=split "\\.","$(PATCH_VERSION)"; print $$F[0]+$$F[1]+${offset},$$F[2],$$F[1]' )

PC_FILES=gridsite-openssl.pc

# caNl adoption part
# caNl library and headers have to be in standard system places.
GRST_X509_OBJS=grst_canl_x509.lo
MOD_GRIDSITE_FILE=canl_mod_gridsite.c
MOD_SSLPRIVATE_HEADER=canl_mod_ssl-private.h
MYCANLLDFLAGS=$(CANL_C_LIBS)

# Print all warnings
ifeq ($(WALL),yes)
MYCFLAGS += -Wall
endif

CFLAGS=-g -O2

CC=gcc
COMPILE=libtool --mode=compile $(CC) $(CFLAGS)
LINK=libtool --mode=link $(CC) $(LDFLAGS)
INSTALL=libtool --mode=install install

GRIDSITE_OBJS=grst_err.lo $(GRST_X509_OBJS) grst_gacl.lo grst_xacml.lo grst_http.lo grst_asn1.lo grst_htcp.lo
GRIDSITE_NOSSL_OBJS=grst_err_nossl.lo grst_gacl_nossl.lo grst_http_nossl.lo grst_xacml_nossl.lo grst_htcp_nossl.lo

#
# Build
#

build: apidoc build-lib htcp mod_gridsite.so urlencode findproxyfile \
       real-gridsite-admin.cgi gridsite-delegation.cgi

build-lib: libgridsite_globus.la libgridsite_globus.a \
           libgridsite.la libgridsite.a \
           libgridsite_nossl.la libgridsite_nossl.a $(PC_FILES)

# First, normal versions using system OpenSSL rather than Globus OpenSSL

libgridsite.a: libgridsite.la

libgridsite.la: $(GRIDSITE_OBJS)
	$(LINK) -rpath $(prefix)/$(libdir) $(version_info) \
          -o $@ $+ -lcrypto ${MYCANLLDFLAGS} $(XML2_LIBS)

grst_err.lo: grst_err.c ../interface/gridsite.h
	$(COMPILE)  $(MYCFLAGS) \
	    -I/usr/kerberos/include \
	    -c $< -o $@

grst_canl_x509.lo: grst_canl_x509.c ../interface/gridsite.h
	$(COMPILE)  $(MYCFLAGS) $(CANL_C_CFLAGS) \
            -I/usr/kerberos/include -c $< -o $@

grst_gacl.lo: grst_gacl.c ../interface/gridsite.h
	$(COMPILE)  $(MYCFLAGS) \
            -I/usr/kerberos/include $(XML2_CFLAGS) -c $< -o $@

grst_xacml.lo: grst_xacml.c ../interface/gridsite.h
	$(COMPILE)  $(MYCFLAGS) \
            -I/usr/kerberos/include $(XML2_CFLAGS) -c $< -o $@

grst_http.lo: grst_http.c ../interface/gridsite.h
	$(COMPILE)  $(MYCFLAGS) \
                        -I/usr/kerberos/include -c $< -o $@

grst_asn1.lo: grst_asn1.c ../interface/gridsite.h
	$(COMPILE)  $(MYCFLAGS) \
            -I/usr/kerberos/include -c $< -o $@

grst_htcp.lo: grst_htcp.c ../interface/gridsite.h
	$(COMPILE)  $(MYCFLAGS) \
            -I/usr/kerberos/include -c $< -o $@

# globus soname for compatibility
libgridsite_globus.a: libgridsite_globus.la

libgridsite_globus.la: $(GRIDSITE_OBJS)
	$(LINK) -rpath $(prefix)/$(libdir) $(version_info) \
         -o $@ $+ -lcrypto ${MYCANLLDFLAGS} $(XML2_LIBS)

# then build versions without OpenSSL

libgridsite_nossl.a: libgridsite_nossl.la

libgridsite_nossl.la: $(GRIDSITE_NOSSL_OBJS)
	$(LINK) -rpath $(prefix)/$(libdir) $(version_info) \
	  -o $@ $+ $(XML2_LIBS)

grst_err_nossl.lo: grst_err.c ../interface/gridsite.h
	$(COMPILE)  $(MYCFLAGS) -DGRST_NO_OPENSSL \
	    -I/usr/kerberos/include -c $< -o $@

grst_gacl_nossl.lo: grst_gacl.c ../interface/gridsite.h
	$(COMPILE)  $(MYCFLAGS) -DGRST_NO_OPENSSL \
            -I/usr/kerberos/include $(XML2_CFLAGS) -c $< -o $@

grst_xacml_nossl.lo: grst_xacml.c ../interface/gridsite.h
	$(COMPILE)  $(MYCFLAGS) -DGRST_NO_OPENSSL \
            -I/usr/kerberos/include $(XML2_CFLAGS) -c $< -o $@

grst_http_nossl.lo: grst_http.c ../interface/gridsite.h
	$(COMPILE)  $(MYCFLAGS) -DGRST_NO_OPENSSL \
            -I/usr/kerberos/include -c $< -o $@

grst_htcp_nossl.lo: grst_htcp.c ../interface/gridsite.h
	$(COMPILE)  $(MYCFLAGS) -DGRST_NO_OPENSSL \
            -I/usr/kerberos/include -c $< -o $@

# now the binary exectuables

gsexec.lo urlencode.lo gridsite-copy.lo findproxyfile.lo showx509exts.lo:
	$(COMPILE) -DVERSION=\"$(PATCH_VERSION)\" $(MYCFLAGS) \
	    -o $@ -c $(subst .lo,.c,$@)

htcp.lo:
	$(COMPILE) -DVERSION=\"$(PATCH_VERSION)\" $(MYCFLAGS) \
	    -o $@ -c $(subst .lo,.c,$@) $(CURL_CFLAGS)

slashgrid.lo: slashgrid.c
	$(COMPILE) -o $@ -c $< $(MYCFLAGS) $(XML2_CFLAGS) -D_FILE_OFFSET_BITS=64 \
          -D_REENTRANT -DFUSE_USE_VERSION=22 -I/usr/kerberos/include \
          $(CURL_CFLAGS)

gsexec:	gsexec.lo gsexec.h
	$(LINK) $< -o $@

urlencode: urlencode.lo libgridsite.la
	$(LINK) -o $@ $< -L. -lgridsite

htcp: htcp.lo libgridsite.la
	$(LINK) -o $@ $+ $(CURL_LIBS)

htcp-static: htcp.lo libgridsite.a
	$(LINK) -o $@ -L. $< \
	    -I/usr/kerberos/include \
            $(CURL_LIBS) -static -lgridsite

gridsite-copy.cgi: gridsite-copy.lo libgridsite.la
	$(LINK) -o $@ $< -L. $(CURL_LIBS) $(MYFCGILIBS) -lgridsite

mod_gridsite.so: ${MOD_GRIDSITE_FILE} ${MOD_SSLPRIVATE_HEADER} \
                 libgridsite.la
	gcc $(CFLAGS) $(MYCFLAGS) -shared -Wl,-soname=gridsite_module \
           -I/usr/kerberos/include \
           $(XML2_CFLAGS) -lcrypto -lssl ${MYCANLLDFLAGS} \
           -DVERSION=\"$(VERSION)\" -o mod_gridsite.so \
           ${MOD_GRIDSITE_FILE} -L./.libs -lgridsite

mod_gridsite_example.so: mod_gridsite_example.c 
	gcc $(CFLAGS) -shared -Wl,-soname=gridsite_example_module \
	   -fPIC $(HTTPD_FLAGS) \
           -DVERSION=\"$(VERSION)\" -o mod_gridsite_example.so \
           mod_gridsite_example.c 

grst_admin_main.lo grst_admin_gacl.lo grst_admin_file.lo:
	$(COMPILE) $(MYCFLAGS) -I/usr/kerberos/include \
          -DVERSION=\"$(VERSION)\" -o $@ -c $(subst .lo,.c,$@)

real-gridsite-admin.cgi: grst_admin_main.lo grst_admin_gacl.lo \
                         grst_admin_file.lo grst_admin.h
	$(LINK) $(MYLDFLAGS) -o real-gridsite-admin.cgi \
            grst_admin_main.lo \
            grst_admin_gacl.lo \
            grst_admin_file.lo \
            -lgridsite

findproxyfile: findproxyfile.lo libgridsite.la
	$(LINK) $(MYLDFLAGS) \
            -o $@ $< -L. -lgridsite

showx509exts: showx509exts.lo libgridsite.la
	$(LINK) $(MYLDFLAGS) \
            -o $@ $< -L. -lgridsite -lssl -lcrypto $(XML2_LIBS) -lz -lm
 
slashgrid: slashgrid.lo libgridsite.la
	$(LINK) $< -o $@ -lfuse $(MYLDFLAGS) \
          -L. $(CURL_LIBS) -lgridsite -lpthread

# This target is used by make-gridsite-spec to test for FUSE include+libs
fuse-test: fuse-test.c
	gcc $(CFLAGS) -lfuse fuse-test.c \
          $(MYCFLAGS) $(MYLDFLAGS) $(XML2_CFLAGS) \
          -D_FILE_OFFSET_BITS=64 -D_REENTRANT -DFUSE_USE_VERSION=22

apidoc:
	date
	doxygen Doxyfile
	mkdir -p ../doc/doxygen
	cp -f doxygen/*.html doxygen/*.css doxygen/*.png ../doc/doxygen
	cd ../doc ; for i in *.1 *.8 ; do ../src/roffit < $$i \
          > $$i.html ; done

gaclexample.lo xacmlexample.lo: gaclexample.c xacmlexample.c
	$(COMPILE) -c $(subst .lo,.c,$@) -o $@ -I../interface \
          -I/usr/kerberos/include

gaclexample: gaclexample.lo libgridsite.la
	$(LINK) -o $@ $< -L. -lgridsite -lssl -lcrypto $(XML2_LIBS) -lz -lm
	    
xacmlexample: xacmlexample.lo libgridsite.a
	$(LINK) -o $@ $< -L. -lgridsite -lssl -lcrypto $(XML2_LIBS) -lz -lm
#
# Delegation machinery, including SOAP delegation portType. To build this
# you either need to use the gLite build environment and set REPOSITORY
# or install gSOAP and set GSOAPDIR to the directory containing
# soapcpp2 and stdsoap2.h (unless GSOAPDIR is set already)
#

ifndef GSOAPDIR
 export GSOAPDIR=/usr
endif

ifndef GRIDSITEDIR
 export GRIDSITEDIR=/usr
endif


DelegationService.wsdl: delegation.h
	$(GSOAPDIR)/bin/soapcpp2 -c delegation.h

gridsite-delegation.cgi: grst-delegation.c delegation.h \
                         DelegationService.wsdl libgridsite.la
	gcc $(CFLAGS) $(MYCFLAGS) $(MYLDFLAGS) -o gridsite-delegation.cgi \
            grst-delegation.c \
            -I/usr/kerberos/include -I. $(GSOAP_CFLAGS) \
            -I$(GRIDSITEDIR)/include \
            -DVERSION=\"$(VERSION)\" -L./.libs \
            soapC.c soapServer.c \
            $(GSOAP_LIBS) -lgridsite
#            -L$(GRIDSITEDIR)/$(libdir)  $(GSOAP_LIBS) \
 #           -lgridsite

htproxyput: htproxyput.c delegation.h DelegationService.wsdl libgridsite.la
	gcc $(CFLAGS) $(MYCFLAGS) $(MYLDFLAGS) -o htproxyput \
            htproxyput.c \
            -I/usr/kerberos/include -I. \
            -DVERSION=\"$(VERSION)\" \
            $(GSOAPSSL_CFLAGS) \
            -I$(GRIDSITEDIR)/include \
            -L./.libs \
            $(STDSOAP2) \
            soapC.c soapClient.c $(GSOAPSSL_LIBS) \
            -lgridsite -lssl -lcrypto

# This target is used by make-gridsite-spec to test for gSOAP include+libs
gsoap-test: gsoap-test.c 
	gcc $(CFLAGS) $(MYCFLAGS) $(MYLDFLAGS) -o gsoap-test \
            gsoap-test.c \
            -I/usr/kerberos/include -I. \
            -DVERSION=\"$(VERSION)\" \
            $(GSOAPSSL_CFLAGS) \
            -I$(GRIDSITEDIR)/include \
            $(STDSOAP2) -L$(GRIDSITEDIR)/$(libdir) \
            $(GSOAPSSL_LIBS) -lz -lssl -lcrypto $(XML2_LIBS) -lm

gridsite-storage.lo: gridsite-storage.c
	$(COMPILE) -o $@ -c $<  $(MYCFLAGS) \
            -I/usr/kerberos/include -I.\
            -I$(GRIDSITEDIR)/include \
            -DVERSION=\"$(VERSION)\" -L. \
            $(CURL_CFLAGS)

gridsite-storage.cgi: gridsite-storage.lo libgridsite.la
	$(LINK) $(MYLDFLAGS) -o $@ $< \
            -L$(GRIDSITEDIR)/$(libdir) \
            -lgridsite $(CURL_LIBS)

%.pc: %.pc.in
	sed -e "s/@version@/$(VERSION)/" -e "s,@prefix@,$(prefix)," -e "s/@libdir@/$(libdir)/" $< > $@

clean:
	rm -rvf doxygen
	rm -rvf .libs
	rm -vf DelegationSoapBinding.* soapC*.c soapH*.h soapS*.c soapStub.h ns.xsd
	rm -vf fuse-test.c gsoap-test.c gridsite.spec
	rm -vf libgridsite*.so* *.cgi mod_gridsite*.so *.a *.o *.la *.lo
	rm -vf gsexec urlencode htcp htcp-static findproxyfile showx509exts slashgrid fuse-test gaclexample xacmlexample htproxyput gsoap-test
	rm -vf gridsite-openssl.pc

distclean:
	rm -rfv ../dist ../gridsite-*.tar.gz $(MYRPMDIR)

#
# Install
#

install: apidoc install-lib
	mkdir -p $(DESTDIR)$(prefix)/include \
                 $(DESTDIR)$(prefix)/$(libdir)/$(httpd_name)/modules \
                 $(DESTDIR)$(prefix)/bin \
                 $(DESTDIR)$(prefix)/sbin \
                 $(DESTDIR)$(prefix)/share/man/man1 \
                 $(DESTDIR)$(prefix)/share/man/man8 \
                 $(DESTDIR)$(prefix)/share/doc/gridsite-$(MINOR_VERSION)
	sed 's/^\(#define GRST_VERSION\).*$$/\1 $(DEFVERSION)/' \
	      ../interface/gridsite.h > $(DESTDIR)$(prefix)/include/gridsite.h
	cp -f ../interface/gridsite-gacl.h $(DESTDIR)$(prefix)/include
	$(INSTALL) urlencode $(DESTDIR)$(prefix)/bin
	$(INSTALL) findproxyfile $(DESTDIR)$(prefix)/bin
	$(INSTALL) real-gridsite-admin.cgi $(DESTDIR)$(prefix)/sbin
	cp -f ../CHANGES ../README ../INSTALL ../LICENSE ../VERSION \
               $(DESTDIR)$(prefix)/share/doc/gridsite-$(MINOR_VERSION)
	cp -f ../doc/index.html ../doc/*.conf ../doc/*.sh ../doc/*.spec \
              mod_gridsite_example.c \
               $(DESTDIR)$(prefix)/share/doc/gridsite-$(MINOR_VERSION)
	for i in htcp.1 htfind.1 htll.1 htls.1 htmkdir.1 htmv.1 htping.1 \
	 htrm.1 urlencode.1 findproxyfile.1 ; do \
	 cp -f ../doc/$$i.html $(DESTDIR)$(prefix)/share/doc/gridsite-$(MINOR_VERSION) ; \
         cp -f ../doc/$$i $(DESTDIR)$(prefix)/share/doc/gridsite-$(MINOR_VERSION) ; \
         cp -f ../doc/$$i $(DESTDIR)$(prefix)/share/man/man1 ; \
         gzip -f $(DESTDIR)$(prefix)/share/man/man1/$$i ; done
	for i in mod_gridsite.8 ; do \
	 cp -f ../doc/$$i.html $(DESTDIR)$(prefix)/share/doc/gridsite-$(MINOR_VERSION) ; \
         cp -f ../doc/$$i $(DESTDIR)$(prefix)/share/doc/gridsite-$(MINOR_VERSION) ; \
         cp -f ../doc/$$i $(DESTDIR)$(prefix)/share/man/man8 ; \
         gzip -f $(DESTDIR)$(prefix)/share/man/man8/$$i ; done
	$(INSTALL) htcp $(DESTDIR)$(prefix)/bin
	ln -sf htcp $(DESTDIR)$(prefix)/bin/htls
	ln -sf htcp $(DESTDIR)$(prefix)/bin/htll
	ln -sf htcp $(DESTDIR)$(prefix)/bin/htrm
	ln -sf htcp $(DESTDIR)$(prefix)/bin/htmkdir
	ln -sf htcp $(DESTDIR)$(prefix)/bin/htmv
	ln -sf htcp $(DESTDIR)$(prefix)/bin/htping
	ln -sf htcp $(DESTDIR)$(prefix)/bin/htfind
	cp -f mod_gridsite.so $(DESTDIR)$(prefix)/$(libdir)/$(httpd_name)/modules

install-lib:
	mkdir -p $(DESTDIR)$(prefix)/$(libdir)/pkgconfig
	$(INSTALL) libgridsite.la $(DESTDIR)$(prefix)/$(libdir)
	$(INSTALL) libgridsite_globus.la $(DESTDIR)$(prefix)/$(libdir)
	$(INSTALL) libgridsite_nossl.la $(DESTDIR)$(prefix)/$(libdir)
	rm -f $(DESTDIR)$(prefix)/$(libdir)/*.la
	cp -f $(PC_FILES) $(DESTDIR)$(prefix)/$(libdir)/pkgconfig

install-slashgrid: slashgrid
	-mkdir -p $(DESTDIR)/etc/rc.d/init.d
	-mkdir -p $(DESTDIR)$(prefix)/share/doc/gridsite-$(MINOR_VERSION)
	-mkdir -p $(DESTDIR)$(prefix)/share/man/man8
	$(INSTALL) slashgrid $(DESTDIR)$(prefix)/sbin
	cp -f slashgrid.init $(DESTDIR)/etc/rc.d/init.d/slashgrid
	cp -f ../doc/slashgrid.8.html $(DESTDIR)$(prefix)/share/doc/gridsite-$(MINOR_VERSION) ; \
	cp -f ../doc/slashgrid.8 $(DESTDIR)$(prefix)/share/doc/gridsite-$(MINOR_VERSION) ; \
	cp -f ../doc/slashgrid.8 $(DESTDIR)$(prefix)/share/man/man8
	gzip -f $(DESTDIR)$(prefix)/share/man/man8/slashgrid.8
	mkdir -p $(DESTDIR)/var/spool/slashgrid

install-ws: gridsite-delegation.cgi htproxyput
	mkdir -p $(DESTDIR)$(prefix)/include \
                 $(DESTDIR)$(prefix)/bin \
                 $(DESTDIR)$(prefix)/sbin \
                 $(DESTDIR)$(prefix)/share/man/man1 \
                 $(DESTDIR)$(prefix)/share/man/man8 \
                 $(DESTDIR)$(prefix)/share/doc/gridsite-$(MINOR_VERSION)
	cp -f ../doc/*.wsdl $(DESTDIR)$(prefix)/share/doc/gridsite-$(MINOR_VERSION)
	for i in htproxyput.1 htproxytime.1 htproxyrenew.1 htproxydestroy.1 \
	 htproxyunixtime.1 htproxyinfo.1 ; do \
	 cp -f ../doc/$$i.html $(DESTDIR)$(prefix)/share/doc/gridsite-$(MINOR_VERSION) ; \
         cp -f ../doc/$$i $(DESTDIR)$(prefix)/share/doc/gridsite-$(MINOR_VERSION) ; \
         cp -f ../doc/$$i $(DESTDIR)$(prefix)/share/man/man1 ; \
         gzip -f $(DESTDIR)$(prefix)/share/man/man1/$$i ; done
	for i in gridsite-delegation.8 ; do \
	 cp -f ../doc/$$i.html $(DESTDIR)$(prefix)/share/doc/gridsite-$(MINOR_VERSION) ; \
         cp -f ../doc/$$i $(DESTDIR)$(prefix)/share/doc/gridsite-$(MINOR_VERSION) ; \
         cp -f ../doc/$$i $(DESTDIR)$(prefix)/share/man/man8 ; \
         gzip -f $(DESTDIR)$(prefix)/share/man/man8/$$i ; done
	cp -f htproxyput $(DESTDIR)$(prefix)/bin
	ln -sf htproxyput $(DESTDIR)$(prefix)/bin/htproxydestroy
	ln -sf htproxyput $(DESTDIR)$(prefix)/bin/htproxytime
	ln -sf htproxyput $(DESTDIR)$(prefix)/bin/htproxyunixtime
	ln -sf htproxyput $(DESTDIR)$(prefix)/bin/htproxyrenew
	ln -sf htproxyput $(DESTDIR)$(prefix)/bin/htproxyinfo
	cp -f gridsite-delegation.cgi $(DESTDIR)$(prefix)/sbin

post-install-debian:
	sed -i \
		-e 's,^\(ServerRoot\) .*,\1 "/etc/$(httpd_name)",' \
		-e 's,/usr/lib/httpd/modules,/usr/$(libdir)/$(httpd_name)/modules,' \
		$(DESTDIR)$(prefix)/share/doc/gridsite-$(MINOR_VERSION)/*.conf

#
# Distributions
#

# source files tarball
dist:
	mkdir -p ../dist/gridsite-$(PATCH_VERSION)/src \
                 ../dist/gridsite-$(PATCH_VERSION)/doc \
                 ../dist/gridsite-$(PATCH_VERSION)/interface \
                 ../dist/gridsite-$(PATCH_VERSION)/project
	cp -f ../VERSION ../README ../LICENSE ../CHANGES ../INSTALL \
                 ../dist/gridsite-$(PATCH_VERSION)
	cp -f ../project/debian.* ../dist/gridsite-$(PATCH_VERSION)/project
	if test -f Makefile.inc; then \
	         cp -f Makefile.inc ../dist/gridsite-$(PATCH_VERSION)/src; \
	fi
	cp -f Makefile grst*.c htcp.c slashgrid.c slashgrid.init \
                 urlencode.c findproxyfile.c gaclexample.c mod_gridsite*.c \
                 htproxyput.c grst_admin.h mod_ap-compat.h \
                 canl_mod_gridsite.c canl_mod_ssl-private.h \
                 gsexec.c gsexec.h gridsite-copy.c gridsite-storage.c \
                 delegation.h \
                 roffit make-gridsite-spec make-debian-files \
                 Doxyfile doxygen.css doxyheader.html \
                 *.pc.in \
                 ../dist/gridsite-$(PATCH_VERSION)/src
	cp -f ../doc/*.html ../doc/*.1 ../doc/*.8 ../doc/*.conf ../doc/*.sh \
              ../doc/*.spec ../doc/*.wsdl \
               ../dist/gridsite-$(PATCH_VERSION)/doc
	cp -f ../interface/*.h \
                 ../dist/gridsite-$(PATCH_VERSION)/interface
	cd ../dist ; tar zcvf ../gridsite-$(PATCH_VERSION).src.tar.gz \
                 gridsite-$(PATCH_VERSION)
	chmod +x ../dist/gridsite-$(PATCH_VERSION)/src/make-debian-files
	rm -Rf ../dist/gridsite-$(PATCH_VERSION)


# binary tarball distribution for htcp users
htcp-bin: htcp
	mkdir -p ../htcp-bin-$(PATCH_VERSION)/bin \
                 ../htcp-bin-$(PATCH_VERSION)/man/man1
	cp -f ../doc/README.htcp-bin ../htcp-bin-$(PATCH_VERSION)
	$(INSTALL) htcp ../htcp-bin-$(PATCH_VERSION)/bin
	cp -f ../doc/htcp.1 ../doc/htrm.1 ../doc/htls.1 ../doc/htmkdir.1 \
              ../doc/htll.1 ../doc/htmv.1 ../doc/htping.1 ../doc/htfind.1 \
              ../htcp-bin-$(PATCH_VERSION)/man/man1
	ln -sf htcp ../htcp-bin-$(PATCH_VERSION)/bin/htls
	ln -sf htcp ../htcp-bin-$(PATCH_VERSION)/bin/htll
	ln -sf htcp ../htcp-bin-$(PATCH_VERSION)/bin/htrm
	ln -sf htcp ../htcp-bin-$(PATCH_VERSION)/bin/htmkdir
	ln -sf htcp ../htcp-bin-$(PATCH_VERSION)/bin/htmv
	ln -sf htcp ../htcp-bin-$(PATCH_VERSION)/bin/htping
	ln -sf htcp ../htcp-bin-$(PATCH_VERSION)/bin/htfind
	cd ../htcp-bin-$(VERSION) ; tar zcvf ../htcp-$(VERSION).bin.tar.gz .
	rm -Rf ../htcp-bin-$(PATCH_VERSION)

rpm-prepare: dist
	export PATCH_VERSION=$(PATCH_VERSION) ; \
	 export MINOR_VERSION=$(MINOR_VERSION) ; \
	 export RELEASE_VERSION=$(RELEASE_VERSION) && \
	 export project=$(project); \
	 ./make-gridsite-spec

rpm: rpm-prepare
	-mkdir -p $(MYRPMDIR)/SOURCES $(MYRPMDIR)/SPECS $(MYRPMDIR)/BUILD \
             $(MYRPMDIR)/SRPMS $(MYRPMDIR)/RPMS/i386 $(MYRPMDIR)/BUILDROOT
	cp -f ../gridsite-$(PATCH_VERSION).src.tar.gz $(MYRPMDIR)/SOURCES
	cp -f gridsite.spec $(MYRPMDIR)/SPECS
	$(RPMCMD) --define "_topdir $(MYRPMDIR)" \
                  -bs --nodeps --buildroot $(MYRPMDIR)/BUILDROOT gridsite.spec

deb-prepare: dist
	export PATCH_VERSION=$(PATCH_VERSION) && \
	 export MINOR_VERSION=$(MINOR_VERSION) && \
	 export RELEASE_VERSION=$(RELEASE_VERSION) && \
	 export project=$(project) && \
	 export top_srcdir=.. && \
	 ./make-debian-files

deb: deb-prepare
	-mkdir -p $(MYRPMDIR)
	tar -xC $(MYRPMDIR) -f ../gridsite-$(PATCH_VERSION).src.tar.gz
	cp ../gridsite-$(PATCH_VERSION).src.tar.gz $(MYRPMDIR)/gridsite_$(PATCH_VERSION).orig.tar.gz
	cp -rf ../debian/ $(MYRPMDIR)/gridsite-$(PATCH_VERSION)/
	(cd $(MYRPMDIR)/gridsite-$(PATCH_VERSION) && \
	pwd && \
	dpkg-buildpackage -S -d -nc -uc -us)

wtf: 
	pwd
	printenv
	ls -lR ../../..
#	ls -l
#	ls -lR /usr/local/
#	ls -lR $(GSOAPDIR)

.PHONY: build build-lib apidoc clean distclean install install-lib install-slashgrid install-ws dist htcp-bin rpm deb wtf post-install-debian
