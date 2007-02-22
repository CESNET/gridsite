#
# You can use this spec file and the gSOAP source tar file from sourceforge
# to build a binary development RPM of gSOAP, suitable for building the
# gridsite-ws components. Installing the resulting RPM puts the gSOAP files
# directory in /usr, where the gridsite-ws Makefile expects them by default.
#
# See http://www.gridsite.org/wiki/GSOAP for more about GridSite and gSOAP
#
Name: gsoap-devel
Version: %(echo ${MYVERSION:-2.7.6b})
Release: 1%(sed 's/^\([A-Z]\)[^ ]* \([A-Z]\)[^0-9]*\([0-9][^ ]*\).*/\1\2\3/g' /etc/redhat-release | sed 's/[^A-Z,a-z,0-9]//g')
Summary: gSOAP development compilers/libraries/headers
License: Modified BSD
Group: Development/Libraries
Source: gsoap_%{version}.tar.gz
Prefix: %(echo ${MYPREFIX:-/usr})
URL: http://www.cs.fsu.edu/~engelen/soap.html
Packager: Andrew McNab <Andrew.McNab@manchester.ac.uk>

%description
Enough of gSOAP to build clients and servers based on gSOAP, using its headers
and static libraries. 
By default, everything is installed in /usr/lib|bin|include/ 

%prep

%setup -n gsoap-2.7

%build

./configure --prefix=$RPM_BUILD_ROOT/%{prefix}
make

%install
make install

%files 
%attr(-, root, root) %{prefix}/bin/soapcpp2
%attr(-, root, root) %{prefix}/bin/wsdl2h
%attr(-, root, root) %{prefix}/include/stdsoap2.h
%attr(-, root, root) %{prefix}/lib/libgsoap++.a
%attr(-, root, root) %{prefix}/lib/libgsoap.a
%attr(-, root, root) %{prefix}/lib/libgsoapck++.a
%attr(-, root, root) %{prefix}/lib/libgsoapck.a
%attr(-, root, root) %{prefix}/lib/libgsoapssl++.a
%attr(-, root, root) %{prefix}/lib/libgsoapssl.a
%attr(-, root, root) %{prefix}/lib/pkgconfig/gsoap++.pc
%attr(-, root, root) %{prefix}/lib/pkgconfig/gsoap.pc
%attr(-, root, root) %{prefix}/lib/pkgconfig/gsoapck++.pc
%attr(-, root, root) %{prefix}/lib/pkgconfig/gsoapck.pc
%attr(-, root, root) %{prefix}/lib/pkgconfig/gsoapssl++.pc
%attr(-, root, root) %{prefix}/lib/pkgconfig/gsoapssl.pc
