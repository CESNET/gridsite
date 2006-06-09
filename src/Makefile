#
#   Andrew McNab and Shiv Kaushal, University of Manchester.
#   Copyright (c) 2002-6. All rights reserved.
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

ifndef MYCFLAGS
export MYCFLAGS=-I. -I../interface $(HTTPD_FLAGS) -I/usr/include/httpd -I/usr/include/apr-0 -I/opt/glite/include -fPIC
endif

ifndef MYLDFLAGS
export MYLDFLAGS=-L.
endif

#
# Build
#

build: apidoc build-lib \
       htcp gridsite-copy.cgi mod_gridsite.so \
       urlencode findproxyfile real-gridsite-admin.cgi gsexec

build-lib: libgridsite_globus.so.$(VERSION) libgridsite_globus.a \
           libgridsite.so.$(VERSION) libgridsite.a 

# First, normal versions using system OpenSSL rather than Globus OpenSSL

libgridsite.so.$(VERSION): grst_x509.o grst_gacl.o grst_xacml.o grst_http.o grst_asn1.o grst_htcp.o
	gcc -shared -Wl,-soname,libgridsite.so.$(MINOR_VERSION) \
         -o libgridsite.so.$(PATCH_VERSION) grst_x509.o grst_gacl.o grst_xacml.o grst_http.o grst_asn1.o grst_htcp.o

libgridsite.a: grst_x509.o grst_gacl.o grst_xacml.o grst_http.o grst_asn1.o grst_htcp.o
	ar src libgridsite.a grst_x509.o grst_gacl.o grst_xacml.o grst_http.o grst_asn1.o grst_htcp.o

grst_x509.o: grst_x509.c ../interface/gridsite.h
	gcc -g $(MYCFLAGS) \
            -I/usr/kerberos/include -c grst_x509.c

grst_gacl.o: grst_gacl.c ../interface/gridsite.h
	gcc -g $(MYCFLAGS) \
            -I/usr/kerberos/include `xml2-config --cflags` -c grst_gacl.c

grst_xacml.o: grst_xacml.c ../interface/gridsite.h
	gcc -g $(MYCFLAGS) \
            -I/usr/kerberos/include `xml2-config --cflags` -c grst_xacml.c

grst_http.o: grst_http.c ../interface/gridsite.h
	gcc -g $(MYCFLAGS) \
                        -I/usr/kerberos/include -c grst_http.c

grst_asn1.o: grst_asn1.c ../interface/gridsite.h
	gcc -g $(MYCFLAGS) \
            -I/usr/kerberos/include -c grst_asn1.c

grst_htcp.o: grst_htcp.c ../interface/gridsite.h
	gcc -g $(MYCFLAGS) \
            -I/usr/kerberos/include -c grst_htcp.c

# Then build versions using Globus OpenSSL if configured

ifdef OPENSSL_GLOBUS_LIBS

libgridsite_globus.so.$(VERSION): \
               grst_x509_globus.o grst_gacl_globus.o grst_http_globus.o \
               grst_asn1_globus.o grst_xacml_globus.o grst_htcp_globus.o
	gcc -shared -Wl,-soname,libgridsite_globus.so.$(MINOR_VERSION) \
         -o libgridsite_globus.so.$(PATCH_VERSION) \
         grst_x509_globus.o grst_gacl_globus.o grst_xacml_globus.o grst_http_globus.o grst_asn1_globus.o

libgridsite_globus.a: grst_x509_globus.o grst_gacl_globus.o grst_http_globus.o grst_asn1_globus.o
	ar src libgridsite_globus.a \
               grst_x509_globus.o grst_gacl_globus.o grst_http_globus.o grst_asn1_globus.o

grst_x509_globus.o: grst_x509.c ../interface/gridsite.h
	gcc -g $(MYCFLAGS) $(OPENSSL_GLOBUS_FLAGS) \
            -I/usr/kerberos/include -c grst_x509.c \
            -o grst_x509_globus.o

grst_gacl_globus.o: grst_gacl.c ../interface/gridsite.h
	gcc -g $(MYCFLAGS) $(OPENSSL_GLOBUS_FLAGS) \
            -I/usr/kerberos/include `xml2-config --cflags` -c grst_gacl.c \
            -o grst_gacl_globus.o

grst_xacml_globus.o: grst_xacml.c ../interface/gridsite.h
	gcc -g $(MYCFLAGS) $(OPENSSL_GLOBUS_FLAGS) \
            -I/usr/kerberos/include `xml2-config --cflags` -c grst_xacml.c \
            -o grst_xacml_globus.o

grst_http_globus.o: grst_http.c ../interface/gridsite.h
	gcc -g $(MYCFLAGS) $(OPENSSL_GLOBUS_FLAGS) \
            -I/usr/kerberos/include -c grst_http.c \
            -o grst_http_globus.o

grst_asn1_globus.o: grst_asn1.c ../interface/gridsite.h
	gcc -g $(MYCFLAGS) $(OPENSSL_GLOBUS_FLAGS) \
            -I/usr/kerberos/include -c grst_asn1.c \
            -o grst_asn1_globus.o

grst_htcp_globus.o: grst_htcp.c ../interface/gridsite.h
	gcc -g $(MYCFLAGS) $(OPENSSL_GLOBUS_FLAGS) \
            -I/usr/kerberos/include -c grst_htcp.c \
            -o grst_htcp_globus.o

else

libgridsite_globus.so.$(VERSION): libgridsite.so.$(VERSION)
	cp -f libgridsite.so.$(VERSION) libgridsite_globus.so.$(VERSION)

libgridsite_globus.a: libgridsite.a
	cp -f libgridsite.a libgridsite_globus.a

endif

gsexec:	gsexec.c gsexec.h
	gcc -g -DVERSION=\"$(PATCH_VERSION)\" $(MYCFLAGS) \
	    -o gsexec gsexec.c

urlencode: urlencode.c libgridsite.a
	gcc -g -DVERSION=\"$(PATCH_VERSION)\" $(MYCFLAGS) \
            -o urlencode urlencode.c -L. \
            -I/usr/kerberos/include -lgridsite

htcp: htcp.c libgridsite.a
	gcc -g -DVERSION=\"$(PATCH_VERSION)\" $(MYCFLAGS) \
	    -o htcp htcp.c -L. \
	    -I/usr/kerberos/include \
            `curl-config --cflags` `curl-config --libs` -lgridsite

gridsite-copy.cgi: gridsite-copy.c libgridsite.a
	gcc -g -DVERSION=\"$(PATCH_VERSION)\" $(MYCFLAGS) \
	    -o gridsite-copy.cgi gridsite-copy.c -L. \
	    -I/usr/kerberos/include \
            `curl-config --cflags` `curl-config --libs` -lgridsite

mod_gridsite.so: mod_gridsite.c mod_ssl-private.h libgridsite.a
	gcc -g $(MYCFLAGS) -shared -Wl,-soname=gridsite_module \
           -I/usr/kerberos/include \
           -I/usr/include/libxml2 \
           -DVERSION=\"$(VERSION)\" -o mod_gridsite.so \
           mod_gridsite.c $(MYLDFLAGS) -lxml2 -lm -lz -lgridsite

real-gridsite-admin.cgi: grst_admin_main.c grst_admin_gacl.c \
                         grst_admin_file.c grst_admin.h
	gcc -g $(MYCFLAGS) $(MYLDFLAGS) -o real-gridsite-admin.cgi \
            grst_admin_main.c \
            grst_admin_gacl.c \
            grst_admin_file.c \
            -I/usr/kerberos/include \
            -DVERSION=\"$(VERSION)\" -lgridsite -lssl -lcrypto -lxml2 -lz -lm

findproxyfile: findproxyfile.c libgridsite.a
	gcc -g -DVERSION=\"$(PATCH_VERSION)\" $(MYCFLAGS) $(MYLDFLAGS) \
            -o findproxyfile findproxyfile.c -L. \
            -I/usr/kerberos/include -lgridsite \
            -lssl -lcrypto -lxml2 -lz -lm

showx509exts: showx509exts.c libgridsite.a
	gcc -g -DVERSION=\"$(PATCH_VERSION)\" $(MYCFLAGS) $(MYLDFLAGS) \
            -o showx509exts showx509exts.c -L. \
            -I/usr/kerberos/include \
            -lgridsite \
            -lssl -lcrypto -lxml2 -lz -lm
 
slashgrid: slashgrid.c
	gcc -g -o slashgrid -lfuse -lpthread slashgrid.c \
          -D_FILE_OFFSET_BITS=64 -D_REENTRANT -DFUSE_USE_VERSION=22 \
          $(MYCFLAGS) $(MYLDFLAGS) \
          -I/usr/kerberos/include `curl-config --cflags` \
          `curl-config --libs` -lgridsite -lxml2

apidoc:
	date
	doxygen Doxyfile
	mkdir -p ../doc/doxygen
	cp -f doxygen/*.html doxygen/*.css doxygen/*.png ../doc/doxygen
	cd ../doc ; for i in *.1 *.8 ; do ../src/roffit < $$i \
          > $$i.html ; done

gaclexample: gaclexample.c libgridsite.a
	gcc -g -o gaclexample gaclexample.c -I. -L. \
            -I/usr/kerberos/include -lgridsite \
            -lssl -lcrypto -lxml2 -lz -lm
	    
xacmlexample: xacmlexample.c libgridsite.a
	gcc -g -o xacmlexample xacmlexample.c -I. -L. \
            -I/usr/kerberos/include -lgridsite \
            -lssl -lcrypto -lxml2 -lz -lm

clean:

#
# Install
#

install: apidoc install-lib
	mkdir -p $(prefix)/include \
                 $(prefix)/lib \
                 $(prefix)/bin \
                 $(prefix)/sbin \
                 $(prefix)/share/man/man1 \
                 $(prefix)/share/man/man8 \
                 $(prefix)/lib/httpd/modules \
                 $(prefix)/share/doc/gridsite-$(MINOR_VERSION)
	cp -f ../interface/gridsite.h $(prefix)/include
	cp -f ../interface/gridsite-gacl.h $(prefix)/include
	cp -f urlencode $(prefix)/bin
	cp -f findproxyfile $(prefix)/bin
	cp -f real-gridsite-admin.cgi $(prefix)/sbin
	cp -f gridsite-copy.cgi $(prefix)/sbin
	cp -f ../CHANGES ../README ../INSTALL ../LICENSE ../VERSION \
               $(prefix)/share/doc/gridsite-$(MINOR_VERSION)
	cp -f ../doc/*.html ../doc/*.conf ../doc/*.1 ../doc/*.8 ../doc/*.sh \
	      ../doc/*.spec \
               $(prefix)/share/doc/gridsite-$(MINOR_VERSION)
	cp -f ../doc/*.1 $(prefix)/share/man/man1
	cp -f ../doc/*.8 $(prefix)/share/man/man8
	gzip -f $(prefix)/share/man/man1/*.1
	gzip -f $(prefix)/share/man/man8/*.8
	cp -f htcp $(prefix)/bin
	ln -sf htcp $(prefix)/bin/htls
	ln -sf htcp $(prefix)/bin/htll
	ln -sf htcp $(prefix)/bin/htrm
	ln -sf htcp $(prefix)/bin/htmkdir
	ln -sf htcp $(prefix)/bin/htmv
	ln -sf htcp $(prefix)/bin/htping
	ln -sf htcp $(prefix)/bin/htfind
	cp -f gsexec $(prefix)/sbin
	cp -f mod_gridsite.so $(prefix)/lib/httpd/modules

install-lib:
	mkdir -p $(prefix)/lib
	cp -f  libgridsite.a $(prefix)/lib
	cp -f  libgridsite.so.$(PATCH_VERSION) $(prefix)/lib
	ln -sf libgridsite.so.$(PATCH_VERSION) \
                                 $(prefix)/lib/libgridsite.so
	ln -sf libgridsite.so.$(PATCH_VERSION) \
                                 $(prefix)/lib/libgridsite.so.$(MAJOR_VERSION)
	ln -sf libgridsite.so.$(PATCH_VERSION) \
                                 $(prefix)/lib/libgridsite.so.$(MINOR_VERSION)
	cp -f  libgridsite_globus.a $(prefix)/lib
	cp -f  libgridsite_globus.so.$(PATCH_VERSION) $(prefix)/lib
	ln -sf libgridsite_globus.so.$(PATCH_VERSION) \
                                 $(prefix)/lib/libgridsite_globus.so
	ln -sf libgridsite_globus.so.$(PATCH_VERSION) \
                                 $(prefix)/lib/libgridsite_globus.so.$(MAJOR_VERSION)
	ln -sf libgridsite_globus.so.$(PATCH_VERSION) \
                                 $(prefix)/lib/libgridsite_globus.so.$(MINOR_VERSION)

install-slashgrid: slashgrid
	cp -f slashgrid $(prefix)/sbin
	cp -f slashgrid.init $(RPM_BUILD_ROOT)/etc/rc.d/init.d/slashgrid
	mkdir -p $(RPM_BUILD_ROOT)/var/spool/slashgrid/headers
	mkdir -p $(RPM_BUILD_ROOT)/var/spool/slashgrid/blocks
	mkdir -p $(RPM_BUILD_ROOT)/var/spool/slashgrid/tmp
	   
#
# Distributions
#

# source files tarball
dist:
	mkdir -p ../dist/gridsite-$(PATCH_VERSION)/src \
                 ../dist/gridsite-$(PATCH_VERSION)/doc \
                 ../dist/gridsite-$(PATCH_VERSION)/interface
	cp -f ../VERSION ../README ../LICENSE ../CHANGES ../INSTALL \
                 ../dist/gridsite-$(PATCH_VERSION)
	cp -f Makefile grst*.c htcp.c slashgrid.c slashgrid.init \
                 urlencode.c findproxyfile.c gaclexample.c mod_gridsite.c \
                 grst_admin.h mod_ssl-private.h \
                 gsexec.c gsexec.h gridsite-copy.c \
                 roffit gridsite.spec \
                 Doxyfile doxygen.css doxyheader.html \
                 ../dist/gridsite-$(PATCH_VERSION)/src
	cp -f ../doc/*.html ../doc/*.1 ../doc/*.8 ../doc/*.conf ../doc/*.sh \
              ../doc/*.spec \
               ../dist/gridsite-$(PATCH_VERSION)/doc
	cp -f ../interface/*.h \
                 ../dist/gridsite-$(PATCH_VERSION)/interface
	cd ../dist ; tar zcvf ../gridsite-$(PATCH_VERSION).src.tar.gz \
                 gridsite-$(PATCH_VERSION)
	rm -Rf ../dist/gridsite-$(PATCH_VERSION)


# binary tarball distribution for htcp users
htcp-bin: htcp
	mkdir -p ../htcp-bin-$(PATCH_VERSION)/bin \
                 ../htcp-bin-$(PATCH_VERSION)/man/man1
	cp -f ../doc/README.htcp-bin ../htcp-bin-$(PATCH_VERSION)
	cp -f htcp ../htcp-bin-$(PATCH_VERSION)/bin
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

# RPM targets: build and RPMs go into subdirectories of ../RPMTMP/
rpm: dist gridsite.spec
	rm -Rf $(MYRPMDIR)/BUILDROOT $(MYRPMDIR)/BUILD
	mkdir -p $(MYRPMDIR)/SOURCES $(MYRPMDIR)/SPECS $(MYRPMDIR)/BUILD \
             $(MYRPMDIR)/SRPMS $(MYRPMDIR)/RPMS/i386 $(MYRPMDIR)/BUILDROOT
	cp -f ../gridsite-$(PATCH_VERSION).src.tar.gz $(MYRPMDIR)/SOURCES
	cp -f gridsite.spec $(MYRPMDIR)/SPECS
	export MYPREFIX=/usr ; export MYVERSION=$(PATCH_VERSION) ; \
         $(RPMCMD) --define "_topdir $(MYRPMDIR)" \
                  -ba --buildroot $(MYRPMDIR)/BUILDROOT gridsite.spec


wtf: 
	pwd
	printenv
	ls -l
	ls -lR /usr/local/
	ls -lR $(GSOAPDIR)


