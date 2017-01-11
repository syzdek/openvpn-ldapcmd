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

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <ldap.h>
#include <stdarg.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>


char * prog_name;
extern char **environ;


int main(int argc, char * argv[]);
int log_err(const char * fmt, ...);
void ldap_opt_int(LDAP * ld, int opt, const char * name);
void ldap_opt_str(LDAP * ld, int opt, const char * name);


int log_err(const char * buff, ...)
{
   va_list   ap;
   char      fmt[1024];
   snprintf(fmt, sizeof(fmt), "%s: %s\n", prog_name, buff);
   va_start(ap, buff);
      return(vfprintf(stderr, fmt, ap));
   va_end(ap);
   return(0);
}


void ldap_opt_int(LDAP * ld, int opt, const char * name)
{
   int val;
   val = -1;
   ldap_get_option(ld, opt, &val);
   printf("   %-35s %i\n", name, val);
   return;
};


void ldap_opt_str(LDAP * ld, int opt, const char * name)
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


void ldap_opt_tim(LDAP * ld, int opt, const char * name)
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


int main(int argc, char * argv[])
{
   int       rc;
   LDAP    * ld;
   int       val_int;
   int       c;

   prog_name = argv[0];
   if ((prog_name = rindex(argv[0], '/')) != NULL)
      prog_name++;

   opterr = 0;
   while ((c = getopt (argc, argv, "c:h")) != -1)
   {
      switch (c)
      {
         case '?':
         fprintf(stderr, "%s: [ -c file ]\n", prog_name);
         return(1);

         case 'c':
         setenv("LDAPCONF", optarg, 1);
         break;

         default:
         break;
      };
   };

   if ((rc = ldap_initialize(&ld, NULL)) != LDAP_SUCCESS)
   {
      log_err("ldap_initialize(): %s", ldap_err2string(rc));
      return(1);
   };

   c = 1;
   ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &c);

   printf("LDAP environment variables:\n");
   for(c = 0; environ[c]; c++)
      if (!(strncasecmp("ldap", environ[c], 4)))
         printf("   %s\n", environ[c]);

   printf("\n");
   printf("options:\n");
   ldap_opt_int(ld, LDAP_OPT_CONNECT_ASYNC, "LDAP_OPT_CONNECT_ASYNC");
   ldap_opt_int(ld, LDAP_OPT_DEBUG_LEVEL,   "LDAP_OPT_DEBUG_LEVEL");
   ldap_opt_str(ld, LDAP_OPT_DEFBASE,       "LDAP_OPT_DEFBASE");

   ldap_get_option(ld, LDAP_OPT_DEREF, &val_int);
   printf("   %-35s %i (never %i/searching %i/finding %i/always %i)\n", "LDAP_OPT_DEREF:", val_int, LDAP_DEREF_NEVER, LDAP_DEREF_SEARCHING, LDAP_DEREF_FINDING, LDAP_DEREF_ALWAYS);

   ldap_opt_int(ld, LDAP_OPT_DESC,               "LDAP_OPT_DESC");
   ldap_opt_str(ld, LDAP_OPT_DIAGNOSTIC_MESSAGE, "LDAP_OPT_DIAGNOSTIC_MESSAGE");
   ldap_opt_str(ld, LDAP_OPT_HOST_NAME,          "LDAP_OPT_HOST_NAME");
   ldap_opt_str(ld, LDAP_OPT_MATCHED_DN,         "LDAP_OPT_MATCHED_DN");
   ldap_opt_tim(ld, LDAP_OPT_NETWORK_TIMEOUT,    "LDAP_OPT_NETWORK_TIMEOUT");
   ldap_opt_int(ld, LDAP_OPT_PROTOCOL_VERSION,   "LDAP_OPT_PROTOCOL_VERSION");
   ldap_opt_str(ld, LDAP_OPT_REFERRAL_URLS,      "LDAP_OPT_REFERRAL_URLS");
   ldap_opt_int(ld, LDAP_OPT_REFERRALS,          "LDAP_OPT_REFERRALS");
   ldap_opt_int(ld, LDAP_OPT_RESTART,            "LDAP_OPT_RESTART");
   ldap_opt_int(ld, LDAP_OPT_RESULT_CODE,        "LDAP_OPT_RESULT_CODE");
   ldap_opt_int(ld, LDAP_OPT_SESSION_REFCNT,     "LDAP_OPT_SESSION_REFCNT");
   ldap_opt_int(ld, LDAP_OPT_SIZELIMIT,          "LDAP_OPT_SIZELIMIT");
   ldap_opt_int(ld, LDAP_OPT_TIMELIMIT,          "LDAP_OPT_TIMELIMIT");
   ldap_opt_tim(ld, LDAP_OPT_TIMEOUT,            "LDAP_OPT_TIMEOUT");
   ldap_opt_str(ld, LDAP_OPT_URI,                "LDAP_OPT_URI");

   printf("\n");
   printf("SASL options:\n");
   ldap_opt_str(ld, LDAP_OPT_X_SASL_AUTHCID,     "LDAP_OPT_X_SASL_AUTHCID");
   ldap_opt_str(ld, LDAP_OPT_X_SASL_AUTHZID,     "LDAP_OPT_X_SASL_AUTHZID");
   ldap_opt_str(ld, LDAP_OPT_X_SASL_MECH,        "LDAP_OPT_X_SASL_MECH");
   ldap_opt_int(ld, LDAP_OPT_X_SASL_NOCANON,     "LDAP_OPT_X_SASL_NOCANON");
   ldap_opt_str(ld, LDAP_OPT_X_SASL_REALM,       "LDAP_OPT_X_SASL_REALM");
   ldap_opt_str(ld, LDAP_OPT_X_SASL_USERNAME,    "LDAP_OPT_X_SASL_USERNAME");

   printf("\n");
   printf("TCP options:\n");
   ldap_opt_int(ld, LDAP_OPT_X_KEEPALIVE_IDLE,   "LDAP_OPT_X_KEEPALIVE_IDLE");
   ldap_opt_int(ld, LDAP_OPT_X_KEEPALIVE_PROBES, "LDAP_OPT_X_KEEPALIVE_PROBES");
   ldap_opt_int(ld, LDAP_OPT_X_KEEPALIVE_INTERVAL, "LDAP_OPT_X_KEEPALIVE_INTERVAL");

   printf("\n");
   printf("TLS options:\n");
   ldap_opt_str(ld, LDAP_OPT_X_TLS_CACERTDIR,    "LDAP_OPT_X_TLS_CACERTDIR");
   ldap_opt_str(ld, LDAP_OPT_X_TLS_CACERTFILE,   "LDAP_OPT_X_TLS_CACERTFILE");
   ldap_opt_str(ld, LDAP_OPT_X_TLS_CERTFILE,     "LDAP_OPT_X_TLS_CERTFILE");
   ldap_opt_str(ld, LDAP_OPT_X_TLS_CIPHER_SUITE, "LDAP_OPT_X_TLS_CIPHER_SUITE");
   ldap_opt_int(ld, LDAP_OPT_X_TLS_CRLCHECK,     "LDAP_OPT_X_TLS_CRLCHECK");
   ldap_opt_str(ld, LDAP_OPT_X_TLS_CRLFILE,      "LDAP_OPT_X_TLS_CRLFILE");
   ldap_opt_str(ld, LDAP_OPT_X_TLS_DHFILE,       "LDAP_OPT_X_TLS_DHFILE");
   ldap_opt_str(ld, LDAP_OPT_X_TLS_KEYFILE,      "LDAP_OPT_X_TLS_KEYFILE");
   ldap_opt_int(ld, LDAP_OPT_X_TLS_NEWCTX,       "LDAP_OPT_X_TLS_NEWCTX");
   ldap_opt_int(ld, LDAP_OPT_X_TLS_PROTOCOL_MIN, "LDAP_OPT_X_TLS_PROTOCOL_MIN");
   ldap_opt_str(ld, LDAP_OPT_X_TLS_RANDOM_FILE,  "LDAP_OPT_X_TLS_RANDOM_FILE");
   ldap_opt_int(ld, LDAP_OPT_X_TLS_REQUIRE_CERT, "LDAP_OPT_X_TLS_REQUIRE_CERT");

   printf("\n");

   ldap_unbind_ext_s(ld, NULL, NULL);

   return(0);
}
