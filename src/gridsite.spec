Name: gridsite
Version: %(echo ${MYVERSION:-1.1.x})
Release: 1
Summary: GridSite
Copyright: Modified BSD
Group: System Environment/Daemons
Source: %{name}-%{version}.src.tar.gz
Prefix: %(echo ${MYPREFIX:-/usr})
URL: http://www.gridsite.org/
Vendor: GridPP
#Requires: libxml2,curl-ssl,mod_ssl
#Buildrequires: libxml2-devel,curl-ssl-devel,httpd-devel
Packager: Andrew McNab <Andrew.McNab@man.ac.uk>

%description
GridSite adds GSI, VOMS and GACL support to Apache 2.0 (mod_gridsite),
a library for manipulating these technologies (libgridsite), and CGI
programs for interactive management of HTTP(S) servers (gridsite-admin.cgi)

See %(echo ${MYPREFIX:-/usr})/share/doc/gridsite-%{version} and
http://www.gridsite.org/ for details.

%package -n htcp
Group: Applications/Internet
Summary: HTTP(S) read/write client
#Requires: curl-ssl

%description -n htcp
htcp is a client to fetch files or directory listings from remote
servers using HTTP or HTTPS, or to put or delete files or directories
onto remote servers using HTTPS. htcp is similar to scp(1), but uses
HTTP/HTTPS rather than ssh as its transfer protocol.

%prep

%setup

%build
cd src
make prefix=$RPM_BUILD_ROOT/%(echo ${MYPREFIX:-/usr}) \
GSOAPDIR=$GSOAPDIR OPENSSL_FLAGS=$OPENSSL_FLAGS \
OPENSSL_LIBS=$OPENSSL_LIBS FLAVOR_EXT=$FLAVOR_EXT

%install
cd src
make install prefix=$RPM_BUILD_ROOT/%(echo ${MYPREFIX:-/usr}) \
GSOAPDIR=$GSOAPDIR OPENSSL_FLAGS=$OPENSSL_FLAGS \
OPENSSL_LIBS=$OPENSSL_LIBS FLAVOR_EXT=$FLAVOR_EXT

%post
/sbin/ldconfig
ln -sf %(echo ${MYPREFIX:-/usr})/share/doc/gridsite-%{version} \
 %(echo ${MYPREFIX:-/usr})/share/doc/gridsite

%postun
rm -f %(echo ${MYPREFIX:-/usr})/share/doc/gridsite

%files
%attr(-, root, root) %(echo ${MYPREFIX:-/usr})/lib/libgridsite.so.%{version}
%attr(-, root, root) %(echo ${MYPREFIX:-/usr})/lib/libgridsite.so
%attr(-, root, root) %(echo ${MYPREFIX:-/usr})/lib/libgridsite_globus.so.%{version}
%attr(-, root, root) %(echo ${MYPREFIX:-/usr})/lib/libgridsite_globus.so
%attr(-, root, root) %(echo ${MYPREFIX:-/usr})/bin/urlencode
%attr(-, root, root) %(echo ${MYPREFIX:-/usr})/bin/findproxyfile
%attr(-, root, root) %(echo ${MYPREFIX:-/usr})/share/doc/gridsite-%{version}
%attr(-, root, root) %(echo ${MYPREFIX:-/usr})/share/man/man1/urlencode.1.gz
%attr(-, root, root) %(echo ${MYPREFIX:-/usr})/share/man/man1/findproxyfile.1.gz
%attr(-, root, root) %(echo ${MYPREFIX:-/usr})/include/gridsite.h
%attr(-, root, root) %(echo ${MYPREFIX:-/usr})/include/gridsite-gacl.h
%attr(-, root, root) %(echo ${MYPREFIX:-/usr})/lib/libgridsite.a
%attr(-, root, root) %(echo ${MYPREFIX:-/usr})/lib/libgridsite_globus.a
%attr(-, root, root) %(echo ${MYPREFIX:-/usr})/lib/httpd/modules/mod_gridsite.so
%attr(-, root, root) %(echo ${MYPREFIX:-/usr})/sbin/real-gridsite-admin.cgi

%files -n htcp
%attr(-, root, root) %(echo ${MYPREFIX:-/usr})/bin/htcp
%attr(-, root, root) %(echo ${MYPREFIX:-/usr})/bin/htls
%attr(-, root, root) %(echo ${MYPREFIX:-/usr})/bin/htll
%attr(-, root, root) %(echo ${MYPREFIX:-/usr})/bin/htrm
%attr(-, root, root) %(echo ${MYPREFIX:-/usr})/bin/htmkdir
%attr(-, root, root) %(echo ${MYPREFIX:-/usr})/share/man/man1/htcp.1.gz
%attr(-, root, root) %(echo ${MYPREFIX:-/usr})/share/man/man1/htrm.1.gz
%attr(-, root, root) %(echo ${MYPREFIX:-/usr})/share/man/man1/htls.1.gz
%attr(-, root, root) %(echo ${MYPREFIX:-/usr})/share/man/man1/htll.1.gz
%attr(-, root, root) %(echo ${MYPREFIX:-/usr})/share/man/man1/htmkdir.1.gz
