/*
 *  OpenVPN LDAP Command
 *  Copyright (C) 2017 David M. Syzdek <david@syzdek.net>.
 *
 *  @SYZDEK_BSD_LICENSE_START@
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are
 *  met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of David M. Syzdek nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 *  IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 *  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 *  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL DAVID M. SYZDEK BE LIABLE FOR
 *  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 *  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 *  SUCH DAMAGE.
 *
 *  @SYZDEK_BSD_LICENSE_END@
 */
#ifndef __COMMON_H
#define __COMMON_H 1


///////////////
//           //
//  Headers  //
//           //
///////////////
#ifdef __OVPNLDAPCMD_PMARK
#pragma mark - Headers
#endif

#ifdef HAVE_CONFIG_H
#   include "config.h"
#else
#   include "git-package-version.h"
#endif

#ifdef __APPLE__
#  include "TargetConditionals.h"
#  define USE_CUSTOM_PTHREAD_MUTEX_TIMEDLOCK 1
#  define USE_IPV6 1
#endif

#ifdef TARGET_OS_MAC
#include <libkern/OSAtomic.h>
#endif

#include <inttypes.h>
#include <ldap.h>
#include <assert.h>


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#ifdef __OVPNLDAPCMD_PMARK
#pragma mark - Definitions
#endif

#ifndef PACKAGE_TARNAME
#define PACKAGE_TARNAME "openvpn-ldapcmd"
#endif

#ifndef PROGRAM_NAME
#define PROGRAM_NAME "openvpn-ldapcmd"
#endif

#ifndef PKGCONFDIR
#define PKGCONFDIR "/etc/openvpn"
#endif


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#ifdef __OVPNLDAPCMD_PMARK
#pragma mark - Datatypes
#endif

struct openvpn_ldapcmd
{
   const char  * prog_name;
   LDAP        * ld;
};
typedef struct openvpn_ldapcmd OVPNLDAPCMD;


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#ifdef __OVPNLDAPCMD_PMARK
#pragma mark - Prototypes
#endif

void ovlc_destroy(OVPNLDAPCMD * od);
int ovlc_initialize(OVPNLDAPCMD ** odp, const char * arg1);


#endif /* Header_h */
