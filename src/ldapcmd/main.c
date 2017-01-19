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
/*
 *  Simple Build:
 *     echo '#define GIT_PACKAGE_VERSION_BUILD "n/a"' > git-package-version.h
 *     gcc -W -Wall -O2 -c common.c
 *     gcc -W -Wall -O2 -c ldapfnc.c
 *     gcc -W -Wall -O2 -c main.c
 *     gcc -W -Wall -O2 -lldap -o openvpn-ldapcmd common.o ldapfnc.o main.o
 *
 *  Simple Clean:
 *     rm -f *.o openvpn-ldapcmd git-package-version.h
 *
 *  GNU Libtool Build:
 *     echo '#define GIT_PACKAGE_VERSION_BUILD "n/a"' > git-package-version.h
 *     libtool --tag=CC --mode=compile gcc -W -Wall -g -O2 -c common.c
 *     libtool --tag=CC --mode=compile gcc -W -Wall -g -O2 -c ldapfnc.c
 *     libtool --tag=CC --mode=compile gcc -W -Wall -g -O2 -c main.c
 *     libtool --tag=CC --mode=link    gcc -W -Wall -g -O2 -lldap \
 *        -o openvpn-ldapcmd common.o ldapfnc.o main.o
 *
 *  GNU Libtool Install:
 *     libtool --mode=install install -c openvpn-ldapcmd \
 *        /usr/local/bin/openvpn-ldapcmd
 *
 *  GNU Libtool Clean:
 *     libtool --mode=clean rm -f common.lo
 *     libtool --mode=clean rm -f ldapfnc.lo
 *     libtool --mode=clean rm -f main.lo
 *     libtool --mode=clean rm -f openvpn-ldapcmd
 *     libtool --mode=clean rm -f git-package-version.h
 */
#define __MAIN_C 1
#undef __OVPNLDAPCMD_PMARK

///////////////
//           //
//  Headers  //
//           //
///////////////
#ifdef __OVPNLDAPCMD_PMARK
#pragma mark - Headers
#endif

#include "common.h"
#include "ldapfnc.h"
#include "log.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <getopt.h>
#include <syslog.h>


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#ifdef __OVPNLDAPCMD_PMARK
#pragma mark - Definitions
#endif


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#ifdef __OVPNLDAPCMD_PMARK
#pragma mark - Prototypes
#endif

int main(int argc, char * argv[]);


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#ifdef __OVPNLDAPCMD_PMARK
#pragma mark - Functions
#endif

int main(int argc, char * argv[])
{
   int           rc;
   ovlc        * od;

   // initialize syslog
   openlog(PROGRAM_NAME, LOG_PID, LOG_DAEMON);

   // initialize memory
   if ((rc = ovlc_initialize(&od, argv[0])) != 0)
      return(1);

   // parse CLI arguments
   if ((rc = ovlc_parseopt(od, argc, argv)) != 0)
   {
      ovlc_destroy(od);
      rc = (rc == -1) ? 0 : rc;
      return(rc);
   };

   // initialize LDAP
   if ((rc = ovlc_ldap_initialize(od)) != 0)
   {
      ovlc_destroy(od);
      return(1);
   };

   ovlc_ldap_opt_dump(od);

   // free resources
   ovlc_destroy(od);

   return(0);
}


/* end of source */