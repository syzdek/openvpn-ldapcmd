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
#define __LOG_C 1
#include "log.h"


///////////////
//           //
//  Headers  //
//           //
///////////////
#ifdef __OVPNLDAPCMD_PMARK
#pragma mark - Headers
#endif

#include <syslog.h>
#include <stdio.h>
#include <stdarg.h>


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#ifdef __RACKGNOME_PMARK
#pragma mark - Variables
#endif


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#ifdef __RACKGNOME_PMARK
#pragma mark - Prototypes
#endif


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#ifdef __RACKGNOME_PMARK
#pragma mark - Functions
#endif

void ovlc_log(ovlc * od, int priority, const char *format, ...)
{
   int        verbose;
   va_list    ap;
   FILE     * stream;

   verbose = (od != NULL) ? od->verbose : 2;
   stream  = NULL;

   if (verbose  != 0)
   {
      if (priority <= LOG_WARNING)
         stream = stderr;
      else if (priority <= LOG_NOTICE)
         stream = stdout;
      else if (verbose > 1)
         stream = stdout;
   };

   if ((stream))
   {
      fprintf(stream, "%s: ", PROGRAM_NAME);
      va_start(ap, format);
      vfprintf(stream, format, ap);
      va_end(ap);
      fprintf(stream, "\n");
   };

   va_start(ap, format);
   vsyslog(priority, format, ap);
   va_end(ap);

   return;
}


/* end of source */
