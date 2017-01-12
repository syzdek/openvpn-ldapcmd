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

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <getopt.h>


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
void usage(OVPNLDAPCMD * od);
void version(OVPNLDAPCMD * od);


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
   int                    c;
   int                    rc;
   int                    opt_index;
   OVPNLDAPCMD          * od;

   static char          short_opt[] = "c:d:hTVvq+";
   static struct option long_opt[] =
   {
      { "help",          no_argument, 0, 'h'},
      { "version",       no_argument, 0, 'V'},
      { "version-terse", no_argument, 0, 'V'},
      { NULL,            0,           0, 0  }
   };

   assert(argc != 0);
   assert(argv != NULL);

   if ((rc = ovlc_initialize(&od, argv[0])) != 0)
      return(1);

   while((c = getopt_long(argc, argv, short_opt, long_opt, &opt_index)) != -1)
   {
      switch(c)
      {
         case -1:	/* no more arguments */
         case 0:	/* long options toggles */
         break;

         case 'h':
         usage(od);
         ovlc_destroy(od);
         return(0);

         case 'V':
         version(od);
         ovlc_destroy(od);
         return(0);

         default:
         fprintf(stderr, "%s: unrecognized option `--%c'\n", od->prog_name, c);
         fprintf(stderr, "Try `%s --help' for more information.\n", od->prog_name);
         ovlc_destroy(od);
         return(1);
      };
   };

   ovlc_destroy(od);

   return(0);
}


void usage(OVPNLDAPCMD * od)
{
   printf("Usage: %s [OPTIONS]\n", od->prog_name);
   printf("Common Options:\n");
   printf("  -c file                   configuration file\n");
   printf("  -d level                  set debug level\n");
   printf("  -h, --help                print this help and exit\n");
   printf("  -V, --version             print version number and exit\n");
   printf("  -v, --verbose             print verbose messages\n");
   printf("  -T, --version-terse       print version number and exit\n");
   printf("  -q, --quiet, --silent     do not print messages\n");
   printf("\n");
   return;
}


void version(OVPNLDAPCMD * od)
{
   printf("%s (%s) %s\n", od->prog_name, PACKAGE_TARNAME, GIT_PACKAGE_VERSION_BUILD);
   printf("\n");
   return;
};


/* end of source */