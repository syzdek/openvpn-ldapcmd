#
#   OpenVPN LDAP Command
#   Copyright (C) 2017 David M. Syzdek <david@syzdek.net>
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
#   PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL DAVID M. Syzdek BE LIABLE FOR
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
#   configure.in - automate compiling on a unix platform
#

AC_PREREQ([2.65])


AC_COPYRIGHT([Copyright (C) 2017 David M. Syzdek <david@syzdek.net>.])
AC_REVISION(0.1)
AC_INIT([OpenVPN LDAP Command],[0.0],[david@syzdek.net],[openvpn-ldapcmd])


AC_SUBST([RELEASE_MONTH],["August 2016"])


# directory locations
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_SRCDIR([build-aux/git-tar-name.txt])
#AC_CONFIG_LIBOBJ_DIR(compat)
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])


# determines host type
AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET


# configures for automake
AM_INIT_AUTOMAKE(gnu std-options subdir-objects)


# Compilers
AC_PROG_CC
#AC_PROG_OBJC
AC_PROG_CXX
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_USE_SYSTEM_EXTENSIONS # replaces AC_AIX AC_GNU_SOURCE AC_MINIX
AC_C_BIGENDIAN
AC_C_INLINE
AC_C_RESTRICT
AC_C_VOLATILE
AC_C_CONST


# Version Info:
#    Current    -- the current version number of this API
#    Revision   -- the revision of the implementation of the API version
#    Age        -- How many seqential past API versions is supported by
#                  this implementation
# Format => Current:Revision:Age
# Convenience macro:
#    AC_BINDLE_LIBTOOL_VERSION_INFO(current, revision, age)
AC_BINDLE_LIBTOOL_VERSION_INFO(0, 0, 0)


# binary locations
AC_PATH_PROG([SHELL],   sh bash,        [AC_MSG_ERROR([missing "sh"])], [$PATH])
AC_CHECK_TOOLS(AR,      ar gar,         [AC_MSG_ERROR([missing binutil "ar"])])
AC_CHECK_TOOLS(LD,      ld gld,         [AC_MSG_ERROR([missing binutil "ld"])])
AC_CHECK_TOOLS(NM,      nm gnm,         [AC_MSG_ERROR([missing binutil "nm"])])
AC_CHECK_TOOLS(RANLIB,  ranlib granlib, [AC_MSG_ERROR([missing binutil "ranlib"])])
AC_CHECK_TOOLS(STRIP,   strip gstrip,   [AC_MSG_ERROR([missing binutil "strip"])])


# shell programs
AC_PROG_AWK
AC_PROG_EGREP
AC_PROG_FGREP
AM_PROG_LEX
AC_PROG_LN_S


# GNU Libtool Support
LT_INIT(dlopen disable-fast-install win32-dll)


# check for common functions
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STRERROR_R


# Type checks
AC_TYPE_INT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UID_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T


# check for required functions
AC_CHECK_FUNCS([bzero],          [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([getnameinfo],    [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([gettimeofday],   [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([memmove],        [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([memset],         [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([regcomp],        [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([setenv],         [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([socket],         [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([strchr],         [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([strdup],         [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([strerror],       [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([strncasecmp],    [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([strtol],         [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([strtoumax],      [], [AC_MSG_ERROR([missing required functions])])


# check for required libraries
AC_SEARCH_LIBS([ldap_err2string],  [ldap],   [], [AC_MSG_ERROR([missing required library])])
AC_SEARCH_LIBS([ldap_get_option],  [ldap],   [], [AC_MSG_ERROR([missing required library])])
AC_SEARCH_LIBS([ldap_initialize],  [ldap],   [], [AC_MSG_ERROR([missing required library])])
AC_SEARCH_LIBS([ldap_memfree],     [ldap],   [], [AC_MSG_ERROR([missing required library])])
AC_SEARCH_LIBS([ldap_sasl_bind],   [ldap],   [], [AC_MSG_ERROR([missing required library])])
AC_SEARCH_LIBS([ldap_sasl_bind_s], [ldap],   [], [AC_MSG_ERROR([missing required library])])
AC_SEARCH_LIBS([ldap_set_option],  [ldap],   [], [AC_MSG_ERROR([missing required library])])


# check for headers
AC_CHECK_HEADERS([getopt.h],     [], [AC_MSG_ERROR([missing required headers])])
AC_CHECK_HEADERS([ldap.h],       [], [AC_MSG_ERROR([missing required headers])])
AC_CHECK_HEADERS([stddef.h],     [], [AC_MSG_ERROR([missing required headers])])
AC_CHECK_HEADERS([string.h],     [], [AC_MSG_ERROR([missing required headers])])
AC_CHECK_HEADERS([sys/socket.h], [], [AC_MSG_ERROR([missing required headers])])
AC_CHECK_HEADERS([sys/time.h],   [], [AC_MSG_ERROR([missing required headers])])
AC_CHECK_HEADERS([sys/types.h],  [], [AC_MSG_ERROR([missing required headers])])
AC_CHECK_HEADERS([syslog.h],     [], [AC_MSG_ERROR([missing required headers])])
AC_CHECK_HEADERS([unistd.h],     [], [AC_MSG_ERROR([missing required headers])])


# check for struct members
AC_CHECK_MEMBERS([struct stat.st_blksize], [], [AC_MSG_ERROR([struct missing required members])])


# initiates bindle tools macros
AC_BINDLE(contrib/bindletools)


# determine PACKAGE_VERSION via Git
AC_BINDLE_GIT_PACKAGE_VERSION([contrib/bindletools/build-aux/git-package-version.sh])


# custom configure options
AC_BINDLE_ENABLE_WARNINGS
AC_BINDLE_WITH_DOXYGEN
AC_OPENVPN_LDAPCMD_COMPONENTS


# enables getopt_long if header and functions were found
AC_CHECK_HEADERS([getopt.h], [AC_DEFINE_UNQUOTED(USE_GETOPT_LONG, 1, [Use GNU getopt_long])])


# Creates outputs
AC_CONFIG_FILES([Makefile])
AC_OUTPUT


# Show local config
AC_MSG_NOTICE([ ])
AC_MSG_NOTICE([   OpenVPN LDAP Command $GIT_PACKAGE_VERSION ($GIT_PACKAGE_BUILD)])
AC_MSG_NOTICE([ ])
AC_MSG_NOTICE([   Features:])
AC_MSG_NOTICE([      Doxygen Docs:              ${ENABLE_DOXYGEN}])
AC_MSG_NOTICE([      LDAP Options Utility:      ${ENABLE_LDAPOPTIONS}])
AC_MSG_NOTICE([ ])
AC_MSG_NOTICE([   Options:])
AC_MSG_NOTICE([ ])
AC_MSG_NOTICE([   Please send suggestions to:   $PACKAGE_BUGREPORT])
AC_MSG_NOTICE([ ])
AC_MSG_NOTICE([   run 'make all'])
AC_MSG_NOTICE([ ])


# end of configure.ac
