#!/bin/sh
#
#   Copyright (c) 2002-3, Andrew McNab, University of Manchester
#   All rights reserved.
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
#-----------------------------------------------------------------------------
# For more information about GridSite: http://www.gridpp.ac.uk/gridsite/
#-----------------------------------------------------------------------------
#
# This script takes an Apache .tar.gz as the single command line argument,
# unpacks the file, modifies the httpd.spec it contains to work without
# the "-C" option to configure (which RedHat 7.3 doesnt like) and
# outputs source and binary RPMs in SRPMS and RPMS/i386

if [ "$1" = "" ] ; then
 echo Must give a tar.gz file name
 exit
fi

export MYTOPDIR=`pwd`

if [ -x /usr/bin/rpmbuild ] ; then
 export RPMCMD=rpmbuild
else
 export RPMCMD=rpm
fi

echo "$1" | grep '\.tar\.gz$' >/dev/null 2>&1
if [ $? = 0 ] ; then # a gzipped source tar ball

 rm -Rf $MYTOPDIR/BUILD $MYTOPDIR/BUILDROOT $MYTOPDIR/SOURCES
 mkdir -p $MYTOPDIR/SOURCES $MYTOPDIR/SPECS $MYTOPDIR/BUILD \
          $MYTOPDIR/SRPMS $MYTOPDIR/RPMS/i386 $MYTOPDIR/BUILDROOT
 
 shortname=`echo $1 | sed 's:^.*/::' | sed 's:\.tar\.gz$::'`

 cp -f $1 SOURCES

 tar zxvf SOURCES/$shortname.tar.gz $shortname/httpd.spec
 cp -f $shortname/httpd.spec SPECS

 sed -e 's/configure -C /configure /' \
              SPECS/httpd.spec >SPECS/httpd-2.spec

 $RPMCMD --define "_topdir $MYTOPDIR" \
        -ba --buildroot $MYTOPDIR/BUILDROOT SPECS/httpd-2.spec

 exit
fi

echo I dont recognise the file type (must be .tar.gz)

exit
