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
#ifndef __LDAPFNC_H
#define __LDAPFNC_H 1


///////////////
//           //
//  Headers  //
//           //
///////////////
#ifdef __OVPNLDAPCMD_PMARK
#pragma mark - Headers
#endif

#include "common.h"


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#ifdef __OVPNLDAPCMD_PMARK
#pragma mark - Definitions
#endif


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#ifdef __OVPNLDAPCMD_PMARK
#pragma mark - Datatypes
#endif


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#ifdef __OVPNLDAPCMD_PMARK
#pragma mark - Prototypes
#endif

int ovlc_ldap_initialize(ovlc * od);
int ovlc_ldap_opt_dump(ovlc * od);
void ovlc_ldap_opt_dump_int(ovlc * od, int opt, const char * name);
void ovlc_ldap_opt_dump_str(ovlc * od, int opt, const char * name);
void ovlc_ldap_opt_dump_tim(ovlc * od, int opt, const char * name);
int ovlc_ldap_search_user(ovlc * od);
int ovlc_ldap_set_option_int(LDAP *ld, int option, const int  invalue);
int ovlc_ldap_set_option_str(LDAP *ld, int option, const char * invalue);
int ovlc_ldap_set_option_time(LDAP *ld, int option, const struct timeval *invalue);


#endif /* Header_h */
