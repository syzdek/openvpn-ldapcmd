#
#   OpenVPN LDAP Command
#   Copyright (C) 2017 David M. Syzdek <david@syzdek.net>.
#
#   @SYZDEK_BSD_LICENSE_START@
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are
#   met:
#
#      * Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#      * Redistributions in binary form must reproduce the above copyright
#        notice, this list of conditions and the following disclaimer in the
#        documentation and/or other materials provided with the distribution.
#      * Neither the name of David M. Syzdek nor the
#        names of its contributors may be used to endorse or promote products
#        derived from this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
#   IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
#   THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
#   PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL DAVID M. SYZDEK BE LIABLE FOR
#   ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#   CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
#   LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
#   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
#   SUCH DAMAGE.
#
#   @SYZDEK_BSD_LICENSE_END@
#
#   @configure_input@
#
#   Makefile.am - automate compiling on a unix platform
#

# Sub directories
SUBDIRS					=
DIST_SUBDIRS				=


# directory locations
pkgconfdir				= $(sysconfdir)/$(package_tarname)
doxygendir				= $(docdir)/doxygen


# Global flags
AM_LIBS					=
AM_LDFLAGS				=
AM_CFLAGS				= -O2 $(CFLAGS_WARNINGS)
AM_CXXFLAGS				= -O2 @AM_CXXFLAGS@
AM_OBJCFLAGS				= -O2 @AM_OBJCFLAGS@
AM_CPPFLAGS				= -O2 -UPMARK -DHAVE_CONFIG_H=1 \
					  -I$(top_builddir)/include \
					  -I$(top_srcdir)/include \
					  -DSYSCONFDIR="\"$(sysconfdir)\""
ACLOCAL_AMFLAGS				= -I m4 -W all -W error
AM_MAKEINFOFLAGS                        = --no-split
DEFS					=
LDADD					= $(lib_LTLIBRARIES) \
					  $(noinst_LTLIBRARIES) \
					  $(noinst_LIBRARIES)


# automake targets
check_PROGRAMS				=
doc_DATA				= AUTHORS \
					  COPYING \
					  ChangeLog.md \
					  INSTALL \
					  NEWS.md \
					  README.md \
					  doc/openvpn-ldapcmd.schema
doxygen_DATA				=
include_HEADERS				=
lib_LTLIBRARIES				=
libexec_SCRIPT				= src/scripts/openvpn-ldapcmd.profile
man_MANS				=
info_TEXINFOS				=
noinst_DATA				=
noinst_LTLIBRARIES			=
noinst_LIBRARIES			=
noinst_HEADERS				=
noinst_PROGRAMS				=
bin_PROGRAMS				=
bin_SCRIPTS				=
pkgconf_DATA				=
pkgdata_DATA				=
sbin_PROGRAMS				= src/openvpn-ldapcmd
sbin_SCRIPTS				= src/scripts/openvpn-ldapcmd-test.sh


# lists
AM_INSTALLCHECK_STD_OPTIONS_EXEMPT	=
BUILT_SOURCES				=
TESTS					=
XFAIL_TESTS				=
EXTRA_MANS				=
EXTRA_DIST				= \
					  ChangeLog.md \
					  NEWS.md \
					  README.md \
					  doc/openvpn-ldapcmd.schema \
					  src/scripts/openvpn-ldapcmd.profile \
					  src/scripts/openvpn-ldapcmd-test.sh.in \
					  src/utils/Makefile
CLEANFILES				= \
					  $(builddir)/a.out   $(srcdir)/a.out \
					  $(builddir)/*/a.out $(srcdir)/*/a.out \
					  config.h.in~ $(srcdir)/config.h.in~ \
					  $(man_MANS) \
					  $(pkgconf_DATA) \
					  $(pkgdata_DATA) \
					  $(bin_SCRIPTS) \
					  $(sbin_SCRIPTS) \
					  @PACKAGE_TARNAME@-*.tar.* \
					  @PACKAGE_TARNAME@-*.txz \
					  @PACKAGE_TARNAME@-*.zip
DISTCHECK_CONFIGURE_FLAGS		= --enable-strictwarnings \
					  --enable-ldapoptions


# macros for doc/doxygen
if ENABLE_DOXYGEN
#noinst_DATA				+= doc/doxygen/html/index.html
endif


# macros for src/ldapoptions
if ENABLE_LDAPOPTIONS
noinst_PROGRAMS				+= src/ldapoptions
endif
src_ldapoptions_DEPENDENCIES		=
src_ldapoptions_SOURCES			= \
					  $(include_HEADERS) \
					  $(noinst_HEADERS) \
					  src/utils/ldapoptions.c


# macros for src/openvpn-ldapcmd
src_openvpn_ldapcmd_DEPENDENCIES	=
src_openvpn_ldapcmd_SOURCES		= \
					  $(include_HEADERS) \
					  $(noinst_HEADERS) \
					  src/ldapcmd/common.c \
					  src/ldapcmd/common.h \
					  src/ldapcmd/ldapfnc.c \
					  src/ldapcmd/ldapfnc.h \
					  src/ldapcmd/main.c


# Makefile includes
GIT_PACKAGE_VERSION_DIR=include
SUBST_EXPRESSIONS =
include $(srcdir)/@bindletools_srcdir@/build-aux/makefile-autotools.am
include $(srcdir)/@bindletools_srcdir@/build-aux/makefile-subst.am
include $(srcdir)/@bindletools_srcdir@/build-aux/makefile-version.am


# custom targets
.PHONY:

src/scripts/openvpn-ldapcmd-test.sh: Makefile src/scripts/openvpn-ldapcmd-test.sh.in
	@$(do_subst_fn)

# local targets
install-exec-local:

install-data-local:

install-data-hook:

uninstall-local:

clean-local:

distclean-local:
	rm -fR $(srcdir)/autom4te.cache

# end of automake file
