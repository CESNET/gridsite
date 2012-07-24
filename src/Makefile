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

ifndef MYCFLAGS
export MYCFLAGS=-I. -I../interface -fPIC -DLINUX=2 -D_REENTRANT -D_LARGEFILE64_SOURCE $(HTTPD_FLAGS) 
endif

ifndef MYLDFLAGS
export MYLDFLAGS=-L.
endif

-include Makefile.inc

ifdef OPENSSL_GLOBUS_LIBS
PC_FILES=gridsite-openssl.pc gridsite-globus.pc
else
PC_FILES=gridsite-openssl.pc
endif

#
# Build
#

build: apidoc build-lib \
       htcp gridsite-copy.cgi gridsite-storage.cgi mod_gridsite.so \
       urlencode findproxyfile gsexec real-gridsite-admin.cgi

build-lib: libgridsite_globus.so.$(VERSION) libgridsite_globus.a \
           libgridsite.so.$(VERSION) libgridsite.a \
           libgridsite_nossl.so.$(VERSION) libgridsite_nossl.a $(PC_FILES)

# First, normal versions using system OpenSSL rather than Globus OpenSSL

libgridsite.so.$(VERSION): grst_err.o grst_x509.o grst_gacl.o grst_xacml.o \
                           grst_http.o grst_asn1.o grst_htcp.o
	gcc -shared -Wl,-soname,libgridsite.so.$(MINOR_VERSION) \
         -o libgridsite.so.$(PATCH_VERSION) \
         grst_err.o grst_x509.o grst_gacl.o grst_xacml.o grst_http.o \
         grst_asn1.o grst_htcp.o -lcrypto $(XML2_LIBS)
	ln -sf libgridsite.so.$(VERSION) libgridsite.so
	ln -sf libgridsite.so.$(VERSION) libgridsite.so.$(MINOR_VERSION)

libgridsite.a: grst_err.o grst_x509.o grst_gacl.o grst_xacml.o grst_http.o grst_asn1.o grst_htcp.o
	ar src libgridsite.a grst_err.o grst_x509.o grst_gacl.o grst_xacml.o grst_http.o grst_asn1.o grst_htcp.o

grst_err.o: grst_err.c ../interface/gridsite.h
	gcc -g $(MYCFLAGS) \
	    -I/usr/kerberos/include \
	    -c grst_err.c

grst_x509.o: grst_x509.c ../interface/gridsite.h
	gcc -g $(MYCFLAGS) \
            -I/usr/kerberos/include -c grst_x509.c

grst_gacl.o: grst_gacl.c ../interface/gridsite.h
	gcc -g $(MYCFLAGS) \
            -I/usr/kerberos/include $(XML2_CFLAGS) -c grst_gacl.c

grst_xacml.o: grst_xacml.c ../interface/gridsite.h
	gcc -g $(MYCFLAGS) \
            -I/usr/kerberos/include $(XML2_CFLAGS) -c grst_xacml.c

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

libgridsite_globus.so.$(VERSION): grst_err_globus.o \
               grst_x509_globus.o grst_gacl_globus.o grst_http_globus.o \
               grst_asn1_globus.o grst_xacml_globus.o grst_htcp_globus.o 
	gcc -shared -Wl,-soname,libgridsite_globus.so.$(MINOR_VERSION) \
         -o libgridsite_globus.so.$(PATCH_VERSION) \
         grst_err_globus.o grst_x509_globus.o grst_gacl_globus.o grst_xacml_globus.o \
         grst_http_globus.o grst_asn1_globus.o $(XML2_LIBS) $(OPENSSL_GLOBUS_LIBS)
	ln -sf libgridsite_globus.so.$(VERSION) libgridsite_globus.so

libgridsite_globus.a: grst_err_globus.o grst_x509_globus.o grst_gacl_globus.o grst_http_globus.o grst_asn1_globus.o
	ar src libgridsite_globus.a \
               grst_err_globus.o grst_x509_globus.o grst_gacl_globus.o grst_http_globus.o grst_asn1_globus.o

grst_err_globus.o: grst_err.c ../interface/gridsite.h
	gcc -g $(MYCFLAGS) $(OPENSSL_GLOBUS_FLAGS) \
	    -I/usr/kerberos/include \
	    -c grst_err.c \
	    -o grst_err_globus.o

grst_x509_globus.o: grst_x509.c ../interface/gridsite.h
	gcc -g $(MYCFLAGS) $(OPENSSL_GLOBUS_FLAGS) \
            -I/usr/kerberos/include -c grst_x509.c \
            -o grst_x509_globus.o

grst_gacl_globus.o: grst_gacl.c ../interface/gridsite.h
	gcc -g $(MYCFLAGS) $(OPENSSL_GLOBUS_FLAGS) \
            -I/usr/kerberos/include $(XML2_CFLAGS) -c grst_gacl.c \
            -o grst_gacl_globus.o

grst_xacml_globus.o: grst_xacml.c ../interface/gridsite.h
	gcc -g $(MYCFLAGS) $(OPENSSL_GLOBUS_FLAGS) \
            -I/usr/kerberos/include $(XML2_CFLAGS) -c grst_xacml.c \
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

# then build versions without OpenSSL

libgridsite_nossl.so.$(VERSION): grst_err_nossl.o \
               grst_gacl_nossl.o grst_http_nossl.o \
               grst_xacml_nossl.o grst_htcp_nossl.o 
	gcc -shared -Wl,-soname,libgridsite_nossl.so.$(MINOR_VERSION) \
         -o libgridsite_nossl.so.$(PATCH_VERSION) \
         grst_err_nossl.o grst_gacl_nossl.o grst_xacml_nossl.o \
         grst_http_nossl.o grst_htcp_nossl.o $(XML2_LIBS)
	ln -sf libgridsite_nossl.so.$(VERSION) libgridsite_nossl.so

libgridsite_nossl.a: grst_err_nossl.o grst_gacl_nossl.o grst_http_nossl.o grst_htcp_nossl.o
	ar src libgridsite_nossl.a \
               grst_err_nossl.o grst_gacl_nossl.o grst_http_nossl.o grst_htcp_nossl.o

grst_err_nossl.o: grst_err.c ../interface/gridsite.h
	gcc -g $(MYCFLAGS) -DGRST_NO_OPENSSL \
	    -I/usr/kerberos/include \
	    -c grst_err.c \
	    -o grst_err_nossl.o

grst_gacl_nossl.o: grst_gacl.c ../interface/gridsite.h
	gcc -g $(MYCFLAGS) -DGRST_NO_OPENSSL \
            -I/usr/kerberos/include $(XML2_CFLAGS) -c grst_gacl.c \
            -o grst_gacl_nossl.o

grst_xacml_nossl.o: grst_xacml.c ../interface/gridsite.h
	gcc -g $(MYCFLAGS) -DGRST_NO_OPENSSL \
            -I/usr/kerberos/include $(XML2_CFLAGS) -c grst_xacml.c \
            -o grst_xacml_nossl.o

grst_http_nossl.o: grst_http.c ../interface/gridsite.h
	gcc -g $(MYCFLAGS) -DGRST_NO_OPENSSL \
            -I/usr/kerberos/include -c grst_http.c \
            -o grst_http_nossl.o

grst_htcp_nossl.o: grst_htcp.c ../interface/gridsite.h
	gcc -g $(MYCFLAGS) -DGRST_NO_OPENSSL \
            -I/usr/kerberos/include -c grst_htcp.c \
            -o grst_htcp_nossl.o

# now the binary exectuables

gsexec:	gsexec.c gsexec.h
	gcc -g -DVERSION=\"$(PATCH_VERSION)\" $(MYCFLAGS) \
	    -o gsexec gsexec.c

urlencode: urlencode.c libgridsite.so.$(VERSION)
	gcc -g -DVERSION=\"$(PATCH_VERSION)\" $(MYCFLAGS) \
            -o urlencode urlencode.c -L. \
            -I/usr/kerberos/include \
            -lgridsite

htcp: htcp.c libgridsite.so.$(VERSION)
	gcc -g -DVERSION=\"$(PATCH_VERSION)\" $(MYCFLAGS) \
	    -o htcp htcp.c -L. \
	    -I/usr/kerberos/include \
            $(CURL_CFLAGS) $(CURL_LIBS) \
            -lgridsite

htcp-static: htcp.c libgridsite.a
	gcc -g -DVERSION=\"$(PATCH_VERSION)\" $(MYCFLAGS) \
	    -o htcp-static htcp.c -L. \
	    -I/usr/kerberos/include \
            $(CURL_CFLAGS) $(CURL_LIBS) \
            -lgridsite -static

gridsite-copy.cgi: gridsite-copy.c libgridsite.so.$(VERSION)
	gcc -g -DVERSION=\"$(PATCH_VERSION)\" $(MYCFLAGS) \
	    -o gridsite-copy.cgi gridsite-copy.c -L. \
	    -I/usr/kerberos/include \
            $(CURL_CFLAGS) $(CURL_LIBS) \
            $(MYFCGILIBS) -lgridsite

mod_gridsite.so: mod_gridsite.c mod_ssl-private.h libgridsite.so.$(VERSION)
	gcc -g $(MYCFLAGS) -shared -Wl,-soname=gridsite_module \
           -I/usr/kerberos/include \
           $(XML2_CFLAGS) -lcrypto -lssl \
           -DVERSION=\"$(VERSION)\" -o mod_gridsite.so \
           mod_gridsite.c $(MYLDFLAGS) -lgridsite

mod_gridsite_example.so: mod_gridsite_example.c 
	gcc -g -shared -Wl,-soname=gridsite_example_module \
	   -I/usr/include/httpd -I/usr/include/apr-0 \
           -DVERSION=\"$(VERSION)\" -o mod_gridsite_example.so \
           mod_gridsite_example.c 

real-gridsite-admin.cgi: grst_admin_main.c grst_admin_gacl.c \
                         grst_admin_file.c grst_admin.h
	gcc -g $(MYCFLAGS) $(MYLDFLAGS) -o real-gridsite-admin.cgi \
            grst_admin_main.c \
            grst_admin_gacl.c \
            grst_admin_file.c \
            -I/usr/kerberos/include \
            -DVERSION=\"$(VERSION)\" -lgridsite

findproxyfile: findproxyfile.c libgridsite.so.$(VERSION)
	gcc -g -DVERSION=\"$(PATCH_VERSION)\" $(MYCFLAGS) $(MYLDFLAGS) \
            -o findproxyfile findproxyfile.c -L. \
            -I/usr/kerberos/include -lgridsite

showx509exts: showx509exts.c libgridsite.so.$(VERSION)
	gcc -g -DVERSION=\"$(PATCH_VERSION)\" $(MYCFLAGS) $(MYLDFLAGS) \
            -o showx509exts showx509exts.c -L. \
            -I/usr/kerberos/include \
            -lgridsite \
            -lssl -lcrypto $(XML2_LIBS) -lz -lm
 
slashgrid: slashgrid.c libgridsite.so.$(VERSION)
	gcc -g -o slashgrid -lfuse -lpthread slashgrid.c \
          $(MYCFLAGS) $(MYLDFLAGS) $(XML2_CFLAGS) \
          -D_FILE_OFFSET_BITS=64 -D_REENTRANT -DFUSE_USE_VERSION=22 \
          -I/usr/kerberos/include $(CURL_CFLAGS) \
          -L. $(CURL_LIBS) -lgridsite -lpthread

# This target is used by make-gridsite-spec to test for FUSE include+libs
fuse-test: fuse-test.c
	gcc -g -lfuse fuse-test.c \
          $(MYCFLAGS) $(MYLDFLAGS) $(XML2_CFLAGS) \
          -D_FILE_OFFSET_BITS=64 -D_REENTRANT -DFUSE_USE_VERSION=22

apidoc:
	date
	doxygen Doxyfile
	mkdir -p ../doc/doxygen
	cp -f doxygen/*.html doxygen/*.css doxygen/*.png ../doc/doxygen
	cd ../doc ; for i in *.1 *.8 ; do ../src/roffit < $$i \
          > $$i.html ; done

gaclexample: gaclexample.c libgridsite.a
	gcc -g -o gaclexample gaclexample.c -I../interface -L. \
            -I/usr/kerberos/include -lgridsite \
            -lssl -lcrypto $(XML2_LIBS) -lz -lm
	    
xacmlexample: xacmlexample.c libgridsite.a
	gcc -g -o xacmlexample xacmlexample.c -I../interface -L. \
            -I/usr/kerberos/include -lgridsite \
            -lssl -lcrypto $(XML2_LIBS) -lz -lm
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
                         DelegationService.wsdl libgridsite.so.$(VERSION)
	gcc -g $(MYCFLAGS) $(MYLDFLAGS) -o gridsite-delegation.cgi \
            grst-delegation.c \
            -I/usr/kerberos/include -I. $(GSOAP_CFLAGS) \
            -I$(GRIDSITEDIR)/include \
            -DVERSION=\"$(VERSION)\" -L. \
            soapC.c soapServer.c \
            -L$(GRIDSITEDIR)/$(libdir)  $(GSOAP_LIBS) \
            -lgridsite

htproxyput: htproxyput.c delegation.h DelegationService.wsdl libgridsite.so.$(VERSION)
	gcc -g $(MYCFLAGS) $(MYLDFLAGS) -o htproxyput \
            htproxyput.c \
            -I/usr/kerberos/include -I. \
            -g -DVERSION=\"$(VERSION)\" \
            $(GSOAPSSL_CFLAGS) \
            -I$(GRIDSITEDIR)/include \
            -L. \
            $(STDSOAP2) \
            soapC.c soapClient.c $(GSOAPSSL_LIBS) \
            -lgridsite -lssl -lcrypto
        
# This target is used by make-gridsite-spec to test for gSOAP include+libs
gsoap-test: gsoap-test.c 
	gcc -g $(MYCFLAGS) $(MYLDFLAGS) -o gsoap-test \
            gsoap-test.c \
            -I/usr/kerberos/include -I. \
            -g -DVERSION=\"$(VERSION)\" \
            $(GSOAPSSL_CFLAGS) \
            -I$(GRIDSITEDIR)/include \
            $(STDSOAP2) -L$(GRIDSITEDIR)/$(libdir) \
            $(GSOAPSSL_LIBS) -lz -lssl -lcrypto $(XML2_LIBS) -lm
        
gridsite-storage.cgi: gridsite-storage.c libgridsite.so.$(VERSION)
	gcc -g $(MYCFLAGS) $(MYLDFLAGS) -o gridsite-storage.cgi \
            gridsite-storage.c \
            -I/usr/kerberos/include -I.\
            -I$(GRIDSITEDIR)/include \
            -DVERSION=\"$(VERSION)\" -L. \
            -L$(GRIDSITEDIR)/$(libdir) \
            -lgridsite $(CURL_CFLAGS) $(CURL_LIBS)

%.pc: %.pc.in
	sed -e "s/@version@/$(VERSION)/" -e "s,@prefix@,$(prefix)," -e "s/@libdir@/$(libdir)/" $< > $@

clean:
	rm -rvf doxygen
	rm -vf DelegationSoapBinding.* soapC*.c soapH*.h soapS*.c soapStub.h ns.xsd
	rm -vf fuse-test.c gsoap-test.c gridsite.spec
	rm -vf libgridsite*.so* *.cgi mod_gridsite*.so *.a *.o
	rm -vf gsexec urlencode htcp htcp-static findproxyfile showx509exts slashgrid fuse-test gaclexample xacmlexample htproxyput gsoap-test
	rm -vf gridsite-openssl.pc gridsite-globus.pc

#
# Install
#

install: apidoc install-lib
	mkdir -p $(prefix)/include \
                 $(prefix)/$(libdir)/$(httpd_name)/modules \
                 $(prefix)/bin \
                 $(prefix)/sbin \
                 $(prefix)/share/man/man1 \
                 $(prefix)/share/man/man8 \
                 $(prefix)/share/doc/gridsite-$(MINOR_VERSION)
	sed 's/^\(#define GRST_VERSION\).*$$/\1 $(DEFVERSION)/' \
	      ../interface/gridsite.h > $(prefix)/include/gridsite.h
	cp -f ../interface/gridsite-gacl.h $(prefix)/include
	cp -f urlencode $(prefix)/bin
	cp -f findproxyfile $(prefix)/bin
	cp -f real-gridsite-admin.cgi $(prefix)/sbin
	cp -f gridsite-copy.cgi $(prefix)/sbin
	cp -f gridsite-storage.cgi $(prefix)/sbin
	cp -f ../CHANGES ../README ../INSTALL ../LICENSE ../VERSION \
               $(prefix)/share/doc/gridsite-$(MINOR_VERSION)
	cp -f ../doc/index.html ../doc/*.conf ../doc/*.sh ../doc/*.spec \
              mod_gridsite_example.c \
               $(prefix)/share/doc/gridsite-$(MINOR_VERSION)
	for i in htcp.1 htfind.1 htll.1 htls.1 htmkdir.1 htmv.1 htping.1 \
	 htrm.1 urlencode.1 findproxyfile.1 ; do \
	 cp -f ../doc/$$i.html $(prefix)/share/doc/gridsite-$(MINOR_VERSION) ; \
         cp -f ../doc/$$i $(prefix)/share/doc/gridsite-$(MINOR_VERSION) ; \
         cp -f ../doc/$$i $(prefix)/share/man/man1 ; \
         gzip -f $(prefix)/share/man/man1/$$i ; done
	for i in mod_gridsite.8 gsexec.8 ; do \
	 cp -f ../doc/$$i.html $(prefix)/share/doc/gridsite-$(MINOR_VERSION) ; \
         cp -f ../doc/$$i $(prefix)/share/doc/gridsite-$(MINOR_VERSION) ; \
         cp -f ../doc/$$i $(prefix)/share/man/man8 ; \
         gzip -f $(prefix)/share/man/man8/$$i ; done
	cp -f htcp $(prefix)/bin
	ln -sf htcp $(prefix)/bin/htls
	ln -sf htcp $(prefix)/bin/htll
	ln -sf htcp $(prefix)/bin/htrm
	ln -sf htcp $(prefix)/bin/htmkdir
	ln -sf htcp $(prefix)/bin/htmv
	ln -sf htcp $(prefix)/bin/htping
	ln -sf htcp $(prefix)/bin/htfind
	cp -f gsexec $(prefix)/sbin
	cp -f mod_gridsite.so $(prefix)/$(libdir)/$(httpd_name)/modules

install-lib:
	mkdir -p $(prefix)/$(libdir)/pkgconfig
	cp -f  libgridsite.a $(prefix)/$(libdir)
	cp -f  libgridsite.so.$(PATCH_VERSION) $(prefix)/$(libdir)
	ln -sf libgridsite.so.$(PATCH_VERSION) \
                                 $(prefix)/$(libdir)/libgridsite.so
	ln -sf libgridsite.so.$(PATCH_VERSION) \
                                 $(prefix)/$(libdir)/libgridsite.so.$(MAJOR_VERSION)
	ln -sf libgridsite.so.$(PATCH_VERSION) \
                                 $(prefix)/$(libdir)/libgridsite.so.$(MINOR_VERSION)
	cp -f  libgridsite_globus.a $(prefix)/$(libdir)
	cp -f  libgridsite_globus.so.$(PATCH_VERSION) $(prefix)/$(libdir)
	ln -sf libgridsite_globus.so.$(PATCH_VERSION) \
                                 $(prefix)/$(libdir)/libgridsite_globus.so
	ln -sf libgridsite_globus.so.$(PATCH_VERSION) \
                                 $(prefix)/$(libdir)/libgridsite_globus.so.$(MAJOR_VERSION)
	ln -sf libgridsite_globus.so.$(PATCH_VERSION) \
                                 $(prefix)/$(libdir)/libgridsite_globus.so.$(MINOR_VERSION)
	cp -f  libgridsite_nossl.a $(prefix)/$(libdir)
	cp -f  libgridsite_nossl.so.$(PATCH_VERSION) $(prefix)/$(libdir)
	ln -sf libgridsite_nossl.so.$(PATCH_VERSION) \
                                 $(prefix)/$(libdir)/libgridsite_nossl.so
	ln -sf libgridsite_nossl.so.$(PATCH_VERSION) \
                                 $(prefix)/$(libdir)/libgridsite_nossl.so.$(MAJOR_VERSION)
	ln -sf libgridsite_nossl.so.$(PATCH_VERSION) \
                                 $(prefix)/$(libdir)/libgridsite_nossl.so.$(MINOR_VERSION)
	cp -f $(PC_FILES) $(prefix)/$(libdir)/pkgconfig

install-slashgrid: slashgrid
	-mkdir -p $(RPM_BUILD_ROOT)/etc/rc.d/init.d
	-mkdir -p $(prefix)/share/doc/gridsite-$(MINOR_VERSION)
	-mkdir -p $(prefix)/share/man/man8
	cp -f slashgrid $(prefix)/sbin
	cp -f slashgrid.init $(RPM_BUILD_ROOT)/etc/rc.d/init.d/slashgrid
	cp -f ../doc/slashgrid.8.html $(prefix)/share/doc/gridsite-$(MINOR_VERSION) ; \
	cp -f ../doc/slashgrid.8 $(prefix)/share/doc/gridsite-$(MINOR_VERSION) ; \
	cp -f ../doc/slashgrid.8 $(prefix)/share/man/man8
	gzip -f $(prefix)/share/man/man8/slashgrid.8
	mkdir -p $(RPM_BUILD_ROOT)/var/spool/slashgrid

install-ws: gridsite-delegation.cgi htproxyput
	mkdir -p $(prefix)/include \
                 $(prefix)/bin \
                 $(prefix)/sbin \
                 $(prefix)/share/man/man1 \
                 $(prefix)/share/man/man8 \
                 $(prefix)/share/doc/gridsite-$(MINOR_VERSION)
	cp -f ../doc/*.wsdl $(prefix)/share/doc/gridsite-$(MINOR_VERSION)
	for i in htproxyput.1 htproxytime.1 htproxyrenew.1 htproxydestroy.1 \
	 htproxyunixtime.1 htproxyinfo.1 ; do \
	 cp -f ../doc/$$i.html $(prefix)/share/doc/gridsite-$(MINOR_VERSION) ; \
         cp -f ../doc/$$i $(prefix)/share/doc/gridsite-$(MINOR_VERSION) ; \
         cp -f ../doc/$$i $(prefix)/share/man/man1 ; \
         gzip -f $(prefix)/share/man/man1/$$i ; done
	for i in gridsite-delegation.8 ; do \
	 cp -f ../doc/$$i.html $(prefix)/share/doc/gridsite-$(MINOR_VERSION) ; \
         cp -f ../doc/$$i $(prefix)/share/doc/gridsite-$(MINOR_VERSION) ; \
         cp -f ../doc/$$i $(prefix)/share/man/man8 ; \
         gzip -f $(prefix)/share/man/man8/$$i ; done
	cp -f htproxyput $(prefix)/bin
	ln -sf htproxyput $(prefix)/bin/htproxydestroy
	ln -sf htproxyput $(prefix)/bin/htproxytime
	ln -sf htproxyput $(prefix)/bin/htproxyunixtime
	ln -sf htproxyput $(prefix)/bin/htproxyrenew
	ln -sf htproxyput $(prefix)/bin/htproxyinfo
	cp -f gridsite-delegation.cgi $(prefix)/sbin

post-install-debian:
	sed -i \
		-e 's,^\(ServerRoot\) .*,\1 "/etc/$(httpd_name)",' \
		-e 's,/usr/lib/httpd/modules,/usr/$(libdir)/$(httpd_name)/modules,' \
		$(prefix)/share/doc/gridsite-$(MINOR_VERSION)/*.conf

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
                 htproxyput.c grst_admin.h mod_ssl-private.h \
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

rpm-prepare: dist
	export PATCH_VERSION=$(PATCH_VERSION) ; \
	 export MINOR_VERSION=$(MINOR_VERSION) ; \
	 export RELEASE_VERSION=$(RELEASE_VERSION) && \
	 export project=$(project); \
	 ./make-gridsite-spec

rpm: rpm-prepare
	rm -Rf $(MYRPMDIR)
	mkdir -p $(MYRPMDIR)/SOURCES $(MYRPMDIR)/SPECS $(MYRPMDIR)/BUILD \
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
	rm -Rf $(MYRPMDIR)
	mkdir -p $(MYRPMDIR)
	tar -xC $(MYRPMDIR) -f ../gridsite-$(PATCH_VERSION).src.tar.gz
	cp ../gridsite-$(PATCH_VERSION).src.tar.gz $(MYRPMDIR)/gridsite_$(PATCH_VERSION).orig.tar.gz
	cp -rf ../debian/ $(MYRPMDIR)/gridsite-$(PATCH_VERSION)/
	(cd $(MYRPMDIR)/gridsite-$(PATCH_VERSION) && \
	pwd && \
	dpkg-buildpackage -S -d -uc -us)

wtf: 
	pwd
	printenv
	ls -lR ../../..
#	ls -l
#	ls -lR /usr/local/
#	ls -lR $(GSOAPDIR)

.PHONY: build build-lib apidoc clean install install-lib install-slashgrid install-ws dist htcp-bin rpm deb wtf post-install-debian
