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
#define __LDAPFNC_C 1
#include "ldapfnc.h"


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
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#ifdef __RACKGNOME_PMARK
#pragma mark - Variables
#endif

extern char **environ;


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

int ovlc_ldap_initialize(ovlc * od)
{
   int valint;
   int rc;

   assert(od != NULL);

   if (od->ldap_debug != -1)
   {
      valint = od->ldap_debug;
      if ((rc = ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &valint)) != LDAP_SUCCESS)
      {
         syslog(LOG_ERR, "ldap_set_option(LDAP_OPT_DEBUG_LEVEL): %s", ldap_err2string(rc));
         return(1);
      };
   };

   if ((rc = ldap_initialize(&od->ld, od->ldap_uri)) != LDAP_SUCCESS)
   {
      syslog(LOG_ERR, "ldap_initialize(): %s", ldap_err2string(rc));
      return(1);
   };

   valint = 5;
   if ((rc = ldap_set_option(od->ld, LDAP_OPT_SIZELIMIT, &valint)) != LDAP_SUCCESS)
   {
      syslog(LOG_ERR, "ldap_set_option(LDAP_OPT_SIZELIMIT): %s", ldap_err2string(rc));
      return(1);
   };

   if (od->ldap_deref != -1)
   {
      valint = od->ldap_deref;
      if ((rc = ldap_set_option(od->ld, LDAP_OPT_DEREF, &valint)) != LDAP_SUCCESS)
      {
         syslog(LOG_ERR, "ldap_set_option(LDAP_OPT_DEREF): %s", ldap_err2string(rc));
         return(1);
      };
   };

   if (od->ldap_limit != -1)
   {
      valint = od->ldap_limit;
      if ((rc = ldap_set_option(od->ld, LDAP_OPT_TIMELIMIT, &valint)) != LDAP_SUCCESS)
      {
         syslog(LOG_ERR, "ldap_set_option(LDAP_OPT_TIMELIMIT): %s", ldap_err2string(rc));
         return(1);
      };
   };

   return(0);
}


int ovlc_ldap_opt_dump(ovlc * od)
{
   int     c;
   int     val_int;
   LDAP  * ld;


   ld = ((od)) ? od->ld : NULL;

   printf("LDAP environment variables:\n");
   for(c = 0; environ[c]; c++)
      if (!(strncasecmp("ldap", environ[c], 4)))
         printf("   %s\n", environ[c]);

   printf("\n");
   printf("options:\n");
   ovlc_ldap_opt_dump_int(ld, LDAP_OPT_CONNECT_ASYNC, "LDAP_OPT_CONNECT_ASYNC");
   ovlc_ldap_opt_dump_int(ld, LDAP_OPT_DEBUG_LEVEL,   "LDAP_OPT_DEBUG_LEVEL");
   ovlc_ldap_opt_dump_str(ld, LDAP_OPT_DEFBASE,       "LDAP_OPT_DEFBASE");

   ldap_get_option(ld, LDAP_OPT_DEREF, &val_int);
   printf("   %-35s %i (never %i/searching %i/finding %i/always %i)\n", "LDAP_OPT_DEREF:", val_int, LDAP_DEREF_NEVER, LDAP_DEREF_SEARCHING, LDAP_DEREF_FINDING, LDAP_DEREF_ALWAYS);

   ovlc_ldap_opt_dump_int(ld, LDAP_OPT_DESC,               "LDAP_OPT_DESC");
   ovlc_ldap_opt_dump_str(ld, LDAP_OPT_DIAGNOSTIC_MESSAGE, "LDAP_OPT_DIAGNOSTIC_MESSAGE");
   ovlc_ldap_opt_dump_str(ld, LDAP_OPT_HOST_NAME,          "LDAP_OPT_HOST_NAME");
   ovlc_ldap_opt_dump_str(ld, LDAP_OPT_MATCHED_DN,         "LDAP_OPT_MATCHED_DN");
   ovlc_ldap_opt_dump_tim(ld, LDAP_OPT_NETWORK_TIMEOUT,    "LDAP_OPT_NETWORK_TIMEOUT");
   ovlc_ldap_opt_dump_int(ld, LDAP_OPT_PROTOCOL_VERSION,   "LDAP_OPT_PROTOCOL_VERSION");
   ovlc_ldap_opt_dump_str(ld, LDAP_OPT_REFERRAL_URLS,      "LDAP_OPT_REFERRAL_URLS");
   ovlc_ldap_opt_dump_int(ld, LDAP_OPT_REFERRALS,          "LDAP_OPT_REFERRALS");
   ovlc_ldap_opt_dump_int(ld, LDAP_OPT_RESTART,            "LDAP_OPT_RESTART");
   ovlc_ldap_opt_dump_int(ld, LDAP_OPT_RESULT_CODE,        "LDAP_OPT_RESULT_CODE");
   ovlc_ldap_opt_dump_int(ld, LDAP_OPT_SESSION_REFCNT,     "LDAP_OPT_SESSION_REFCNT");
   ovlc_ldap_opt_dump_int(ld, LDAP_OPT_SIZELIMIT,          "LDAP_OPT_SIZELIMIT");
   ovlc_ldap_opt_dump_int(ld, LDAP_OPT_TIMELIMIT,          "LDAP_OPT_TIMELIMIT");
   ovlc_ldap_opt_dump_tim(ld, LDAP_OPT_TIMEOUT,            "LDAP_OPT_TIMEOUT");
   ovlc_ldap_opt_dump_str(ld, LDAP_OPT_URI,                "LDAP_OPT_URI");

   printf("\n");
   printf("SASL options:\n");
   ovlc_ldap_opt_dump_str(ld, LDAP_OPT_X_SASL_AUTHCID,     "LDAP_OPT_X_SASL_AUTHCID");
   ovlc_ldap_opt_dump_str(ld, LDAP_OPT_X_SASL_AUTHZID,     "LDAP_OPT_X_SASL_AUTHZID");
   ovlc_ldap_opt_dump_str(ld, LDAP_OPT_X_SASL_MECH,        "LDAP_OPT_X_SASL_MECH");
   ovlc_ldap_opt_dump_int(ld, LDAP_OPT_X_SASL_NOCANON,     "LDAP_OPT_X_SASL_NOCANON");
   ovlc_ldap_opt_dump_str(ld, LDAP_OPT_X_SASL_REALM,       "LDAP_OPT_X_SASL_REALM");
   ovlc_ldap_opt_dump_str(ld, LDAP_OPT_X_SASL_USERNAME,    "LDAP_OPT_X_SASL_USERNAME");

   printf("\n");
   printf("TCP options:\n");
   ovlc_ldap_opt_dump_int(ld, LDAP_OPT_X_KEEPALIVE_IDLE,   "LDAP_OPT_X_KEEPALIVE_IDLE");
   ovlc_ldap_opt_dump_int(ld, LDAP_OPT_X_KEEPALIVE_PROBES, "LDAP_OPT_X_KEEPALIVE_PROBES");
   ovlc_ldap_opt_dump_int(ld, LDAP_OPT_X_KEEPALIVE_INTERVAL, "LDAP_OPT_X_KEEPALIVE_INTERVAL");

   printf("\n");
   printf("TLS options:\n");
   ovlc_ldap_opt_dump_str(ld, LDAP_OPT_X_TLS_CACERTDIR,    "LDAP_OPT_X_TLS_CACERTDIR");
   ovlc_ldap_opt_dump_str(ld, LDAP_OPT_X_TLS_CACERTFILE,   "LDAP_OPT_X_TLS_CACERTFILE");
   ovlc_ldap_opt_dump_str(ld, LDAP_OPT_X_TLS_CERTFILE,     "LDAP_OPT_X_TLS_CERTFILE");
   ovlc_ldap_opt_dump_str(ld, LDAP_OPT_X_TLS_CIPHER_SUITE, "LDAP_OPT_X_TLS_CIPHER_SUITE");
   ovlc_ldap_opt_dump_int(ld, LDAP_OPT_X_TLS_CRLCHECK,     "LDAP_OPT_X_TLS_CRLCHECK");
   ovlc_ldap_opt_dump_str(ld, LDAP_OPT_X_TLS_CRLFILE,      "LDAP_OPT_X_TLS_CRLFILE");
   ovlc_ldap_opt_dump_str(ld, LDAP_OPT_X_TLS_DHFILE,       "LDAP_OPT_X_TLS_DHFILE");
   ovlc_ldap_opt_dump_str(ld, LDAP_OPT_X_TLS_KEYFILE,      "LDAP_OPT_X_TLS_KEYFILE");
   ovlc_ldap_opt_dump_int(ld, LDAP_OPT_X_TLS_NEWCTX,       "LDAP_OPT_X_TLS_NEWCTX");
   ovlc_ldap_opt_dump_int(ld, LDAP_OPT_X_TLS_PROTOCOL_MIN, "LDAP_OPT_X_TLS_PROTOCOL_MIN");
   ovlc_ldap_opt_dump_str(ld, LDAP_OPT_X_TLS_RANDOM_FILE,  "LDAP_OPT_X_TLS_RANDOM_FILE");
   ovlc_ldap_opt_dump_int(ld, LDAP_OPT_X_TLS_REQUIRE_CERT, "LDAP_OPT_X_TLS_REQUIRE_CERT");

   printf("\n");

   return(0);
}


void ovlc_ldap_opt_dump_int(LDAP * ld, int opt, const char * name)
{
   int val;
   val = -1;
   ldap_get_option(ld, opt, &val);
   printf("   %-35s %i\n", name, val);
   return;
};


void ovlc_ldap_opt_dump_str(LDAP * ld, int opt, const char * name)
{
   char * val;
   val = NULL;
   ldap_get_option(ld, opt, &val);
   if ((val))
   {
      printf("   %-35s %s\n", name, val);
      ldap_memfree(val);
   }
   else
   {
      printf("   %-35s N/A\n", name);
   };
   return;
};


void ovlc_ldap_opt_dump_tim(LDAP * ld, int opt, const char * name)
{
   struct timeval * val;
   val = NULL;
   ldap_get_option(ld, opt, &val);
   if ((val))
   {
      printf("   %-35s %" PRIuMAX ".%06" PRIuMAX "\n", name, (uintmax_t)val->tv_sec, (uintmax_t)val->tv_usec);
      ldap_memfree(val);
   }
   else
   {
      printf("   %-35s N/A\n", name);
   };
   return;
};


/* end of source */
