#
# You should be able to build your own FUSE RPMs for use with SlashGrid
# by fetching an up-to-date stable FUSE tar file from SourceForge,
# putting it in /usr/src/redhat/SOURCES, updating the Version: header in
# this file, and then executing  rpmbuild -ba fuse.spec
#
Name:           fuse
Version:        2.5.3
URL:            http://fuse.sourceforge.net
Source:         %{name}-%{version}.tar.gz
Release:        3%(sed 's/^\([A-Z]\)[^ ]* \([A-Z]\)[^0-9]*\([0-9][^ ]*\).*/\1\2\3/g' /etc/redhat-release | sed 's/[^A-Z,a-z,0-9]//g')_%(uname -r | sed 's/-/_/g')
Summary:        File System in Userspace (FUSE) utilities
Group:          System Environment/Base
License:        GPL
Packager:	Andrew McNab <Andrew.McNab@manchester.ac.uk>
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%description
With FUSE it is possible to implement a fully functional filesystem in a 
userspace program. This package contains the FUSE userspace tools to 
mount a FUSE filesystem.

(This version is designed for use with the SlashGrid daemon:
 http://www.gridsite.org/slashgrid/ )

%package libs
Summary:        File System in Userspace (FUSE) libraries
Group:          System Environment/Libraries
License:        LGPL

%description libs
Devel With FUSE it is possible to implement a fully functional filesystem in a 
userspace program. This package contains the FUSE libraries. 

%package devel
Summary:        File System in Userspace (FUSE) devel files
Group:          Development/Libraries
Requires:	%{name}-libs = %{version}-%{release}
Requires: 	pkgconfig
License:        LGPL

%description devel
With FUSE it is possible to implement a fully functional filesystem in a 
userspace program. This package contains development files (headers, 
pgk-config) to develop FUSE based applications/filesystems.

%prep
%setup -q
#disable device creation during build/install
sed -i 's|mknod|echo Disabled: mknod |g' util/Makefile.in
sed -i 's|install-data-local | |g' util/Makefile.in
sed -i 's| install-data-local| |g' util/Makefile.in

%build
%configure --disable-static 
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
find $RPM_BUILD_ROOT -type f -name "*.la" -exec rm -f {} ';'

# change from 4755 to 0755 to allow stripping (setuid not needed by SlashGrid)
chmod 0755 $RPM_BUILD_ROOT/%{_bindir}/fusermount

%clean
rm -rf $RPM_BUILD_ROOT

%post
mknod --mode=0660 /dev/fuse c 10 229
chown root.root /dev/fuse
depmod

%postun 

%post libs -p /sbin/ldconfig

%postun libs -p /sbin/ldconfig

%files
%doc AUTHORS ChangeLog COPYING FAQ Filesystems NEWS README README.NFS
/sbin/mount.fuse
%attr(0755,root,root) %{_bindir}/fusermount
/lib/modules/%(uname -r)/kernel/fs/fuse/fuse.*o

%files libs
%doc COPYING.LIB
%{_libdir}/libfuse.so.*

%files devel
%defattr(-,root,root,-)
%{_libdir}/libfuse.so
%{_libdir}/pkgconfig/*.pc
%{_includedir}/fuse.h
%{_includedir}/fuse

%changelog

* Sun May 28 2006 Andrew McNab <Andrew.McNab@manchester.ac.uk> 2.5.3-3
- Simplify for use with SlashGrid daemon (which only runs as root) on
  Scientific Linux 3.*/4.* too

* Wed May 03 2006 Peter Lemenkov <lemenkov@newmail.ru> 2.5.3-1%{?dist}
- Update to 2.5.3

* Thu Mar 30 2006 Peter Lemenkov <lemenkov@newmail.ru> 2.5.2-4%{?dist}
- rebuild

* Mon Feb 13 2006 Peter Lemenkov <lemenkov@newmail.ru> - 2.5.2-3
- Proper udev rule

* Mon Feb 13 2006 Peter Lemenkov <lemenkov@newmail.ru> - 2.5.2-2
- Added missing requires

* Tue Feb 07 2006 Peter Lemenkov <lemenkov@newmail.ru> - 2.5.2-1
- Update to 2.5.2
- Dropped fuse-mount.fuse.patch

* Wed Nov 23 2005 Thorsten Leemhuis <fedora[AT]leemhuis[DOT]info> - 2.4.2-1
- Use dist

* Wed Nov 23 2005 Thorsten Leemhuis <fedora[AT]leemhuis[DOT]info> - 2.4.2-1
- Update to 2.4.2 (solves CVE-2005-3531)
- Update README.fedora

* Sat Nov 12 2005 Thorsten Leemhuis <fedora[AT]leemhuis[DOT]info> - 2.4.1-3
- Add README.fedora
- Add hint to README.fedora and that you have to be member of the group "fuse"
  in the description
- Use groupadd instead of fedora-groupadd

* Fri Nov 04 2005 Thorsten Leemhuis <fedora[AT]leemhuis[DOT]info> - 2.4.1-2
- Rename packages a bit
- use makedev.d/40-fuse.nodes
- fix /sbin/mount.fuse
- Use a fuse group to restict access to fuse-filesystems

* Fri Oct 28 2005 Thorsten Leemhuis <fedora[AT]leemhuis[DOT]info> - 2.4.1-1
- Initial RPM release.
