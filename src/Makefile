#
#   Andrew McNab and Shiv Kaushal, University of Manchester.
#   Copyright (c) 2002-4. All rights reserved.
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
export MYCFLAGS=-I. -I../interface -I/usr/include/httpd -I/usr/include/apr-0 -I/opt/glite/include
endif

ifndef OPENSSL_FLAGS
export OPENSSL_FLAGS=-I/usr/include/openssl
endif

ifndef MYLDFLAGS
export MYLDFLAGS=-L.
# export MYLDFLAGS=-L. -L/opt/glite/lib -lvomsc
endif

ifndef OPENSSL_LIBS
export OPENSSL_LIBS=-L/usr/lib/openssl
endif

#
# Build
#

build: libgridsite.so.$(VERSION) libgridsite.a htcp mod_gridsite.so \
       urlencode findproxyfile real-gridsite-admin.cgi \
       # gridsite-delegation.cgi # htproxyput

libgridsite.so.$(VERSION): grst_x509.o grst_gacl.o grst_http.o
	gcc -shared -Wl,-soname,libgridsite.so.$(MINOR_VERSION) \
         -o libgridsite.so.$(PATCH_VERSION) grst_x509.o grst_gacl.o grst_http.o

libgridsite.a: grst_x509.o grst_gacl.o grst_http.o
	ar src libgridsite.a grst_x509.o grst_gacl.o grst_http.o

grst_x509.o: grst_x509.c ../interface/gridsite.h
	gcc $(MYCFLAGS) $(OPENSSL_FLAGS) \
            -I/usr/kerberos/include -c grst_x509.c

grst_gacl.o: grst_gacl.c ../interface/gridsite.h
	gcc $(MYCFLAGS) $(OPENSSL_FLAGS) \
            -I/usr/kerberos/include `xml2-config --cflags` -c grst_gacl.c

grst_http.o: grst_http.c ../interface/gridsite.h
	gcc $(MYCFLAGS) $(OPENSSL_FLAGS) \
                        -I/usr/kerberos/include -c grst_http.c

urlencode: urlencode.c libgridsite.a
	gcc -DVERSION=\"$(PATCH_VERSION)\" $(MYCFLAGS) \
            -o urlencode urlencode.c -L. \
             $(OPENSSL_FLAGS) -I/usr/kerberos/include -lgridsite

htcp: htcp.c
	gcc -DVERSION=\"$(PATCH_VERSION)\" -I. -o htcp htcp.c \
          `curl-config --cflags` `curl-config --libs` 

mod_gridsite.so: mod_gridsite.c mod_ssl-private.h libgridsite.a
	gcc $(MYCFLAGS) -shared -Wl,-soname=gridsite_module \
            $(OPENSSL_FLAGS) -I/usr/kerberos/include \
           -I/usr/include/libxml2 \
           -DVERSION=\"$(VERSION)\" -o mod_gridsite.so \
           mod_gridsite.c $(MYLDFLAGS) -lxml2 -lm -lz -lgridsite

real-gridsite-admin.cgi: grst_admin_main.c grst_admin_gacl.c \
                         grst_admin_file.c grst_admin.h
	gcc $(MYCFLAGS) $(MYLDFLAGS) -o real-gridsite-admin.cgi \
            grst_admin_main.c \
            grst_admin_gacl.c \
            grst_admin_file.c \
             $(OPENSSL_FLAGS) -I/usr/kerberos/include \
            -DVERSION=\"$(VERSION)\" $(OPENSSL_LIBS) -lgridsite -lssl -lcrypto -lxml2 -lz -lm

findproxyfile: findproxyfile.c libgridsite.a
	gcc -DVERSION=\"$(PATCH_VERSION)\" $(MYCFLAGS) $(MYLDFLAGS) \
            -o findproxyfile findproxyfile.c -L. \
             $(OPENSSL_FLAGS) -I/usr/kerberos/include -lgridsite \
             $(OPENSSL_LIBS) -lssl -lcrypto -lxml2 -lz -lm

apidoc:
	doxygen Doxyfile

gaclexample: gaclexample.c libgridsite.a
	gcc -o gaclexample gaclexample.c -I. -L. \
             $(OPENSSL_FLAGS) -I/usr/kerberos/include -lgridsite \
            -lssl -lcrypto -lxml2 -lz -lm 

#
# Delegation machinery, including SOAP delegation portType. To build this
# you need to install gSOAP and set GSOAPDIR to the directory containing
# soapcpp2 and stdsoap2.h (unless GSOAPDIR is set already)
#

ifndef GSOAPDIR
export GSOAPDIR=/usr/local/lib/gsoap
endif

delegation.wsdl: delegation.h
	ls -lR $(GSOAPDIR)
	$(GSOAPDIR)/bin/soapcpp2 -c delegation.h

libstdsoap2.a: $(GSOAPDIR)/stdsoap2.c
	gcc -c -DWITH_OPENSSL $(GSOAPDIR)/stdsoap2.c
	ar src libstdsoap2.a stdsoap2.o

gridsite-delegation.cgi: grst-delegation.c delegation.h delegation.wsdl \
                         soapC.c soapServer.c
	gcc $(MYCFLAGS) $(MYLDFLAGS) -o gridsite-delegation.cgi \
            grst-delegation.c \
             $(OPENSSL_FLAGS) -I/usr/kerberos/include -I$(GSOAPDIR)/include \
            -DVERSION=\"$(VERSION)\" -L$(GSOAPDIR)/lib \
            soapC.c soapServer.c -lgsoap \
            -lgridsite -lcurl -lz -lssl -lcrypto -lxml2 -lm

htproxyput: htproxyput.c delegation.h delegation.wsdl \
            soapC.c soapServer.c
	gcc $(MYCFLAGS) $(MYLDFLAGS) -o htproxyput \
            htproxyput.c \
             $(OPENSSL_FLAGS) -I/usr/kerberos/include \
            -g -DVERSION=\"$(VERSION)\" \
            -I$(GSOAPDIR)/include -DWITH_OPENSSL -L$(GSOAPDIR)/lib \
            soapC.c soapClient.c -lgsoap \
            -lgridsite -lcurl -lz -lssl -lcrypto -lxml2 -lm

proxyput-example: proxyput-example.c delegation.h delegation.wsdl \
            soapC.c soapServer.c libstdsoap2.a
	gcc $(MYCFLAGS) $(MYLDFLAGS) -o proxyput-example \
            proxyput-example.c \
             $(OPENSSL_FLAGS) -I/usr/kerberos/include \
            -g -DVERSION=\"$(VERSION)\" \
            -I$(GSOAPDIR) -DWITH_OPENSSL \
            soapC.c soapClient.c libstdsoap2.a \
            -lgridsite -lcurl -lz -lssl -lcrypto -lxml2 -lm

clean:

#
# Install
#

install: apidoc
	mkdir -p $(prefix)/include \
                 $(prefix)/lib \
                 $(prefix)/bin \
                 $(prefix)/sbin \
                 $(prefix)/share/man/man1 \
                 $(prefix)/lib/httpd/modules \
                 $(prefix)/share/doc/gridsite-$(PATCH_VERSION)
	cp -f ../interface/gridsite.h $(prefix)/include
	cp -f ../interface/gridsite-gacl.h $(prefix)/include
	cp -f urlencode $(prefix)/bin
	cp -f findproxyfile $(prefix)/bin
	cp -f libgridsite.a $(prefix)/lib
	cp -f real-gridsite-admin.cgi $(prefix)/sbin
	cp -f  libgridsite.so.$(PATCH_VERSION) $(prefix)/lib
	ln -sf libgridsite.so.$(PATCH_VERSION) \
                                 $(prefix)/lib/libgridsite.so
	ln -sf libgridsite.so.$(PATCH_VERSION) \
                                 $(prefix)/lib/libgridsite.so.$(MAJOR_VERSION)
	ln -sf libgridsite.so.$(PATCH_VERSION) \
                                 $(prefix)/lib/libgridsite.so.$(MINOR_VERSION)
	cp -f doxygen/index.html \
              $(prefix)/share/doc/gridsite-$(PATCH_VERSION)/doxygen-index.html
	cp -f doxygen/* $(prefix)/share/doc/gridsite-$(PATCH_VERSION)
	cp -f ../CHANGES ../README ../INSTALL ../LICENSE ../VERSION \
               $(prefix)/share/doc/gridsite-$(PATCH_VERSION)
	cp -f ../doc/*.html ../doc/*.conf ../doc/*.1 ../doc/*.sh \
               $(prefix)/share/doc/gridsite-$(VERSION)
	cp -f ../doc/*.1 $(prefix)/share/man/man1
	gzip -f $(prefix)/share/man/man1/*.1
	cd ../doc ; for i in *.1 ; do ../src/roffit < $$i \
          > $(prefix)/share/doc/gridsite-$(VERSION)/$$i.html ; done
	cp -f htcp $(prefix)/bin
	ln -sf htcp $(prefix)/bin/htls
	ln -sf htcp $(prefix)/bin/htll
	ln -sf htcp $(prefix)/bin/htrm
	ln -sf htcp $(prefix)/bin/htmkdir
	cp -f mod_gridsite.so $(prefix)/lib/httpd/modules

#
# Distributions
#

# source files tarball
dist:
	mkdir -p ../gridsite-$(PATCH_VERSION)/src \
                 ../gridsite-$(PATCH_VERSION)/doc \
                 ../gridsite-$(PATCH_VERSION)/interface
	cp -f ../VERSION ../README ../LICENSE ../CHANGES ../INSTALL \
                 ../gridsite-$(PATCH_VERSION)
	cp -f Makefile grst*.c htproxyput.c proxyput-example.c htcp.c \
                 urlencode.c findproxyfile.c gaclexample.c mod_gridsite.c \
                 delegation.h grst_admin.h mod_ssl-private.h \
                 roffit gridsite.spec \
                 Doxyfile doxygen.css doxyheader.html \
                 ../gridsite-$(PATCH_VERSION)/src
	cp -f ../doc/*.html ../doc/*.1 ../doc/*.conf ../doc/*.sh \
                 ../gridsite-$(PATCH_VERSION)/doc
	cp -f ../interface/*.h \
                 ../gridsite-$(PATCH_VERSION)/interface
	cd .. ; tar zcvf gridsite-$(PATCH_VERSION).src.tar.gz \
                 gridsite-$(PATCH_VERSION)
	rm -Rf ../gridsite-$(PATCH_VERSION)


# binary tarball distribution for htcp users
htcp-bin: htcp
	mkdir -p ../htcp-bin-$(PATCH_VERSION)/bin \
                 ../htcp-bin-$(PATCH_VERSION)/man/man1
	cp -f ../doc/README.htcp-bin ../htcp-bin-$(PATCH_VERSION)
	cp -f htcp ../htcp-bin-$(PATCH_VERSION)/bin
	cp -f ../doc/htcp.1 ../doc/htrm.1 ../doc/htls.1 ../doc/htll.1 \
              ../doc/htmkdir.1	../htcp-bin-$(PATCH_VERSION)/man/man1
	ln -sf htcp ../htcp-bin-$(PATCH_VERSION)/bin/htls
	ln -sf htcp ../htcp-bin-$(PATCH_VERSION)/bin/htll
	ln -sf htcp ../htcp-bin-$(PATCH_VERSION)/bin/htrm
	ln -sf htcp ../htcp-bin-$(PATCH_VERSION)/bin/htmkdir
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

