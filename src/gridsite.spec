Name: gridsite
Version: %(echo ${MYVERSION:-1.1.x})
Release: %(echo ${MYRELEASE:-1})
Summary: GridSite
License: Modified BSD
Group: System Environment/Daemons
Source: %{name}-%{version}.src.tar.gz
Prefix: %(echo ${MYPREFIX:-/usr})
URL: http://www.gridsite.org/
Vendor: GridPP
Requires: libxml2
#Buildrequires: libxml2-devel,curl-ssl-devel,httpd-devel
Packager: Andrew McNab <Andrew.McNab@manchester.ac.uk>

%description
GridSite adds GSI, VOMS and GACL support to Apache 2.0 (mod_gridsite),
a library for manipulating these technologies (libgridsite), and CGI
programs for interactive management of HTTP(S) servers (gridsite-admin.cgi)

See %{prefix}/share/doc/gridsite-%{version} and
http://www.gridsite.org/ for details.

%package shared
Group: Development/Libraries
Summary: GridSite shared library and core documentation

%description shared
GridSite shared library and core documentation

%package devel
Group: Development/Libraries
Summary: GridSite .a libraries and .h headers

%description devel
GridSite development libraries

%package apache
Group: System Environment/Daemons
Summary: GridSite mod_gridsite module for Apache httpd
Requires: gridsite-shared

%description apache
GridSite Apache module and CGI binaries

%package commands
Group: Applications/Internet
Summary: HTTP(S) read/write client and other GridSite commands
Requires: curl, gridsite-shared

%description commands
htcp is a client to fetch files or directory listings from remote
servers using HTTP or HTTPS, or to put or delete files or directories
onto remote servers using HTTPS. htcp is similar to scp(1), but uses
HTTP/HTTPS rather than ssh as its transfer protocol.

%package gsexec
Group: Applications/Internet
Summary: gsexec binary for the Apache HTTP server

%description gsexec
This package includes the /usr/sbin/gsexec binary which can be installed
to allow the Apache HTTP server to run CGI programs (and any programs
executed by SSI pages) as a user other than the 'apache' user. gsexec
is a drop-in replacement for suexec, with extended functionality for use
with GridSite and Grid Security credentials.

%prep

%setup

%build
cd src
make prefix=$RPM_BUILD_ROOT/%{prefix} \
GSOAPDIR=$GSOAPDIR OPENSSL_FLAGS=$OPENSSL_FLAGS \
OPENSSL_LIBS=$OPENSSL_LIBS FLAVOR_EXT=$FLAVOR_EXT

%install
cd src
make install prefix=$RPM_BUILD_ROOT/%{prefix} \
GSOAPDIR=$GSOAPDIR OPENSSL_FLAGS=$OPENSSL_FLAGS \
OPENSSL_LIBS=$OPENSSL_LIBS FLAVOR_EXT=$FLAVOR_EXT

%post shared
if [ "$UID" = "0" ] ; then
 /sbin/ldconfig
fi

ln -sf %{prefix}/share/doc/gridsite-%{version} \
 %{prefix}/share/doc/gridsite

#%postun
rm -f %{prefix}/share/doc/gridsite

%files shared
%attr(-, root, root) %{prefix}/lib/libgridsite.so.%{version}
%attr(-, root, root) %{prefix}/lib/libgridsite.so
%attr(-, root, root) %{prefix}/lib/libgridsite_globus.so.%{version}
%attr(-, root, root) %{prefix}/lib/libgridsite_globus.so
%attr(-, root, root) %{prefix}/share/doc/gridsite-%{version}

%files devel
%attr(-, root, root) %{prefix}/include/gridsite.h
%attr(-, root, root) %{prefix}/include/gridsite-gacl.h
%attr(-, root, root) %{prefix}/lib/libgridsite.a
%attr(-, root, root) %{prefix}/lib/libgridsite_globus.a

%files apache
%attr(-, root, root) %{prefix}/share/man/man8/mod_gridsite.8.gz
%attr(-, root, root) %{prefix}/lib/httpd/modules/mod_gridsite.so
%attr(-, root, root) %{prefix}/sbin/real-gridsite-admin.cgi
%attr(-, root, root) %{prefix}/sbin/gridsite-copy.cgi

%files commands
%attr(-, root, root) %{prefix}/bin/htcp
%attr(-, root, root) %{prefix}/bin/htls
%attr(-, root, root) %{prefix}/bin/htll
%attr(-, root, root) %{prefix}/bin/htrm
%attr(-, root, root) %{prefix}/bin/htmkdir
%attr(-, root, root) %{prefix}/bin/htmv
%attr(-, root, root) %{prefix}/bin/htping
%attr(-, root, root) %{prefix}/bin/htfind
%attr(-, root, root) %{prefix}/bin/urlencode
%attr(-, root, root) %{prefix}/bin/findproxyfile
%attr(-, root, root) %{prefix}/share/man/man1/htcp.1.gz
%attr(-, root, root) %{prefix}/share/man/man1/htrm.1.gz
%attr(-, root, root) %{prefix}/share/man/man1/htls.1.gz
%attr(-, root, root) %{prefix}/share/man/man1/htll.1.gz
%attr(-, root, root) %{prefix}/share/man/man1/htmkdir.1.gz
%attr(-, root, root) %{prefix}/share/man/man1/htmv.1.gz
%attr(-, root, root) %{prefix}/share/man/man1/htping.1.gz
%attr(-, root, root) %{prefix}/share/man/man1/htfind.1.gz
%attr(-, root, root) %{prefix}/share/man/man1/urlencode.1.gz
%attr(-, root, root) %{prefix}/share/man/man1/findproxyfile.1.gz

%files gsexec
%attr(4510, root, apache) %{prefix}/sbin/gsexec
%attr(-, root, root) %{prefix}/share/man/man8/gsexec.8.gz
