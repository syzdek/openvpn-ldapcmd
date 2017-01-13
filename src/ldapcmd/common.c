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
#define __COMMON_C 1
#include "common.h"


///////////////
//           //
//  Headers  //
//           //
///////////////
#ifdef __OVPNLDAPCMD_PMARK
#pragma mark - Headers
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <syslog.h>
#include <getopt.h>
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

void ovlc_destroy(ovlc * od)
{
   assert(od != NULL);

   if (od->cmd_arg != NULL)
      free(od->cmd_arg);

   if (od->ldap_basedn != NULL)
      free(od->ldap_basedn);

   if (od->ldap_filter != NULL)
      free(od->ldap_filter);

   if (od->ldap_uri != NULL)
      free(od->ldap_uri);

   if (od->ovpn_untrusted_ip != NULL)
      free(od->ovpn_untrusted_ip);

   if (od->ovpn_trusted_ip != NULL)
      free(od->ovpn_trusted_ip);

   if (od->ovpn_pool_remote_ip != NULL)
      free(od->ovpn_pool_remote_ip);

   if (od->ovpn_pool_remote_ip6 != NULL)
      free(od->ovpn_pool_remote_ip6);

   if (od->ovpn_common_name != NULL)
      free(od->ovpn_common_name);

   if (od->ovpn_username != NULL)
      free(od->ovpn_username);

   if (od->ovpn_password != NULL)
      free(od->ovpn_password);

   if (od->ovpn_profile != NULL)
      free(od->ovpn_profile);

   if (od->ovpn_profiledir != NULL)
      free(od->ovpn_profiledir);

   if (od->prog_conf != NULL)
      free(od->prog_conf);

   if (od->prog_name != NULL)
      free(od->prog_name);

   if (od->ld != NULL)
      ldap_unbind_ext_s(od->ld, NULL, NULL);

   bzero(od, sizeof(ovlc));
   free(od);

   return;
}


int ovlc_parseopt(ovlc * od, int argc, char ** argv)
{
   int           rc;
   int           c;
   int           opt_index;
   char        * endptr;
   struct stat   sb;

   static char          short_opt[] = "a:b:cd:F:f:H:hl:P:p:Q:qs:vVxZ";
   static struct option long_opt[] =
   {
      { "help",          no_argument, 0, 'h'},
      { "version",       no_argument, 0, 'V'},
      { "version-terse", no_argument, 0, 'V'},
      { NULL,            0,           0, 0  }
   };


   assert(od   != NULL);
   assert(argv != NULL);


   while((c = getopt_long(argc, argv, short_opt, long_opt, &opt_index)) != -1)
   {
      switch(c)
      {
         case -1:	/* no more arguments */
         case 0:	/* long options toggles */
         break;

         case 'a':
         if (!(strcasecmp(optarg, "never")))
            od->ldap_deref = LDAP_DEREF_NEVER;
         else if (!(strcasecmp(optarg, "search")))
            od->ldap_deref = LDAP_DEREF_SEARCHING;
         else if (!(strcasecmp(optarg, "find")))
            od->ldap_deref = LDAP_DEREF_FINDING;
         else if (!(strcasecmp(optarg, "always")))
            od->ldap_deref = LDAP_DEREF_ALWAYS;
         else
         {
            fprintf(stderr, "%s: invalid value for `-%c'\n", od->prog_name, c);
            fprintf(stderr, "Try `%s --help' for more information.\n", od->prog_name);
            return(1);
         };
         break;


         case 'b':
         if ((od->ldap_basedn))
            free(od->ldap_basedn);
         if ((od->ldap_basedn = strdup(optarg)) == NULL)
         {
            fprintf(stderr, "%s: strdup(): %s\n", od->prog_name, strerror(errno));
            return(1);
         };
         break;


         case 'c':
         od->continue_on_error = 1;
         break;


         case 'd':
         od->ldap_debug = (int) strtol(optarg, &endptr, 10);
         if (endptr == optarg)
         {
            fprintf(stderr, "%s: invalid value for `-%c'\n", od->prog_name, c);
            fprintf(stderr, "Try `%s --help' for more information.\n", od->prog_name);
            return(1);
         };
         break;


         case 'F':
         if (!(strcasecmp(optarg, "kern")))
            od->syslog_facility = LOG_KERN;
         else if (!(strcasecmp(optarg, "user")))
            od->syslog_facility = LOG_USER;
         else if (!(strcasecmp(optarg, "mail")))
            od->syslog_facility = LOG_MAIL;
         else if (!(strcasecmp(optarg, "daemon")))
            od->syslog_facility = LOG_DAEMON;
         else if (!(strcasecmp(optarg, "auth")))
            od->syslog_facility = LOG_AUTH;
         else if (!(strcasecmp(optarg, "syslog")))
            od->syslog_facility = LOG_SYSLOG;
         else if (!(strcasecmp(optarg, "lpr")))
            od->syslog_facility = LOG_LPR;
         else if (!(strcasecmp(optarg, "news")))
            od->syslog_facility = LOG_NEWS;
         else if (!(strcasecmp(optarg, "uucp")))
            od->syslog_facility = LOG_UUCP;
         else if (!(strcasecmp(optarg, "cron")))
            od->syslog_facility = LOG_CRON;
         else if (!(strcasecmp(optarg, "authpriv")))
            od->syslog_facility = LOG_AUTHPRIV;
         else if (!(strcasecmp(optarg, "ftp")))
            od->syslog_facility = LOG_FTP;
         else if (!(strcasecmp(optarg, "local0")))
            od->syslog_facility = LOG_LOCAL0;
         else if (!(strcasecmp(optarg, "local1")))
            od->syslog_facility = LOG_LOCAL1;
         else if (!(strcasecmp(optarg, "local2")))
            od->syslog_facility = LOG_LOCAL2;
         else if (!(strcasecmp(optarg, "local3")))
            od->syslog_facility = LOG_LOCAL3;
         else if (!(strcasecmp(optarg, "local4")))
            od->syslog_facility = LOG_LOCAL4;
         else if (!(strcasecmp(optarg, "local5")))
            od->syslog_facility = LOG_LOCAL5;
         else if (!(strcasecmp(optarg, "local6")))
            od->syslog_facility = LOG_LOCAL6;
         else if (!(strcasecmp(optarg, "local7")))
            od->syslog_facility = LOG_LOCAL7;
         else
         {
            fprintf(stderr, "%s: invalid value for `-%c'\n", od->prog_name, c);
            fprintf(stderr, "Try `%s --help' for more information.\n", od->prog_name);
            return(1);
         };
         break;


         case 'f':
         if ((rc = stat(optarg, &sb)) == -1)
         {
            fprintf(stderr, "%s: stat(%s): %s\n", od->prog_name, optarg, strerror(errno));
            return(1);
         };
         if ((od->prog_conf))
            free(od->prog_conf);
         if ((od->prog_conf = strdup(optarg)) == NULL)
         {
            fprintf(stderr, "%s: strdup(): %s\n", od->prog_name, strerror(errno));
            return(1);
         };
         if ((rc = setenv("LDAPCONF", optarg, 1)) == -1)
         {
            fprintf(stderr, "%s: setenv(LDAPCONF): %s\n", od->prog_name, strerror(errno));
            return(1);
         };
         break;


         case 'H':
         if ((od->ldap_uri))
            free(od->ldap_uri);
         if ((od->ldap_uri = strdup(optarg)) == NULL)
         {
            fprintf(stderr, "%s: strdup(): %s\n", od->prog_name, strerror(errno));
            return(1);
         };
         break;


         case 'h':
         ovlc_usage(od);
         return(-1);


         case 'l':
         od->ldap_limit = (int) strtol(optarg, &endptr, 10);
         if (endptr == optarg)
         {
            fprintf(stderr, "%s: invalid value for `-%c'\n", od->prog_name, c);
            fprintf(stderr, "Try `%s --help' for more information.\n", od->prog_name);
            return(1);
         };
         break;


         case 'P':
         od->ldap_version = (int) strtol(optarg, &endptr, 10);
         if (endptr == optarg)
         {
            fprintf(stderr, "%s: invalid value for `-%c'\n", od->prog_name, c);
            fprintf(stderr, "Try `%s --help' for more information.\n", od->prog_name);
            return(1);
         };
         break;


         case 'p':
         if ((od->ovpn_profile))
            free(od->ovpn_profile);
         if ((od->ovpn_profile = strdup(optarg)) == NULL)
         {
            fprintf(stderr, "%s: strdup(): %s\n", od->prog_name, strerror(errno));
            return(1);
         };
         break;


         case 'Q':
         if ((rc = stat(optarg, &sb)) == -1)
         {
            fprintf(stderr, "%s: stat(%s): %s\n", od->prog_name, optarg, strerror(errno));
            return(1);
         };
         if ((od->ovpn_profiledir))
            free(od->ovpn_profiledir);
         if ((od->ovpn_profiledir = strdup(optarg)) == NULL)
         {
            fprintf(stderr, "%s: strdup(): %s\n", od->prog_name, strerror(errno));
            return(1);
         };
         break;


         case 'q':
         break;


         case 's':
         if (!(strcasecmp(optarg, "base")))
            od->ldap_scope = LDAP_SCOPE_BASE;
         else if (!(strcasecmp(optarg, "one")))
            od->ldap_scope = LDAP_SCOPE_ONELEVEL;
         else if (!(strcasecmp(optarg, "sub")))
            od->ldap_scope = LDAP_SCOPE_SUBTREE;
         else if (!(strcasecmp(optarg, "child")))
            od->ldap_scope = LDAP_SCOPE_CHILDREN;
         else
         {
            fprintf(stderr, "%s: invalid value for `-%c'\n", od->prog_name, c);
            fprintf(stderr, "Try `%s --help' for more information.\n", od->prog_name);
            return(1);
         };
         break;


         case 'V':
         ovlc_version(od);
         return(-1);


         case 'v':
         od->syslog_option |= LOG_PERROR;
         break;


         case 'Z':
         od->ldap_tls_cert++;
         break;


         default:
         fprintf(stderr, "%s: unrecognized option `--%c'\n", od->prog_name, c);
         fprintf(stderr, "Try `%s --help' for more information.\n", od->prog_name);
         return(1);
      };
   };


   return(0);
}


int ovlc_initialize(ovlc ** odp, const char * arg1)
{
   int           i;
   const char  * str;
   char        * name;
   char        * endptr;
   ovlc        * od;

   assert(odp != NULL);


   // clear unwanted variables from environment
   for (i = 0; environ[i]; i++)
   {
      if ((name = strdup(environ[i])) == NULL)
      {
         fprintf(stderr, "%s: strdup(): %s\n", PROGRAM_NAME, strerror(errno));
         return(1);
      };
      if ((endptr = index(name, '=')) != NULL)
         endptr[0] = '\0';
      if (!(strncmp(name, "LDAP", 4)))
      {
         unsetenv(name);
         i--;
      };
   };


   // allocate configuration memory
   if ((od = malloc(sizeof(ovlc))) == NULL)
   {
      syslog(LOG_ERR, "malloc(): %s", strerror(errno));
      return(-1);
   };
   bzero(od, sizeof(ovlc));


   // store program name
   if ((str = arg1) != NULL)
      if ((str = rindex(arg1, '/')) != NULL)
         str = (str[1] != '\0') ? &str[1] : PROGRAM_NAME;
   str = (str != NULL) ? str : PROGRAM_NAME;
   if ((od->prog_name = strdup(str)) == NULL)
   {
      syslog(LOG_ERR, "strdup(): %s", strerror(errno));
      ovlc_destroy(od);
      return(1);
   };


   // OpenVPN environment variables
   str = ((str = getenv("untrusted_ip")) != NULL) ? str : "";
   if ((od->ovpn_untrusted_ip = strdup(str)) == NULL)
   {
      syslog(LOG_ERR, "strdup(): %s", strerror(errno));
      ovlc_destroy(od);
      return(1);
   };
   str = ((str = getenv("trusted_ip")) != NULL) ? str : "";
   if ((od->ovpn_trusted_ip = strdup(str)) == NULL)
   {
      syslog(LOG_ERR, "strdup(): %s", strerror(errno));
      ovlc_destroy(od);
      return(1);
   };
   str = ((str = getenv("pool_remote_ip")) != NULL) ? str : "";
   if ((od->ovpn_pool_remote_ip = strdup(str)) == NULL)
   {
      syslog(LOG_ERR, "strdup(): %s", strerror(errno));
      ovlc_destroy(od);
      return(1);
   };
   str = ((str = getenv("pool_remote_ip6")) != NULL) ? str : "";
   if ((od->ovpn_pool_remote_ip6 = strdup(str)) == NULL)
   {
      syslog(LOG_ERR, "strdup(): %s", strerror(errno));
      ovlc_destroy(od);
      return(1);
   };
   str = ((str = getenv("common_name")) != NULL) ? str : "";
   if ((od->ovpn_common_name = strdup(str)) == NULL)
   {
      syslog(LOG_ERR, "strdup(): %s", strerror(errno));
      ovlc_destroy(od);
      return(1);
   };


   // parse environment variable (script_type)
   str = ((str = getenv("script_type")) != NULL) ? str : "";
   if (!(strcasecmp(str, "user-pass-verify")))
      od->script_type = UserPassVerify;
   else if (!(strcasecmp(str, "client-connect")))
      od->script_type = ClientConnect;
   else if (!(strcasecmp(str, "client-disconnect")))
      od->script_type = ClientDisconnect;
   else
      od->script_type = Unknown;


   // parse environment variable (verb)
   str = ((str = getenv("verb")) != NULL) ? str : "3";
   od->ovpn_verb = (int) strtol(str, &endptr, 10);
   if (endptr == str)
      od->ovpn_verb = 3;


   // initialize values
   od->ldap_deref       = -1;
   od->ldap_debug       = -1;
   od->ldap_limit       = -1;
   od->ldap_scope       = LDAP_SCOPE_DEFAULT;
   od->ldap_tls_cert    = 0;
   od->ldap_version     = -1;
   od->syslog_facility  = LOG_DAEMON;
   od->syslog_option    = LOG_PID;


   *odp = od;


   return(0);
}


int ovlc_initialize_ldap(ovlc * od)
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


void ovlc_usage(ovlc * od)
{
   printf("Usage: %s [OPTIONS] pattern [file]\n", od->prog_name);
   printf(
          "Where:\n"
          "  pattern                   LDAP search filter containing escape codes\n"
          "  file                      user-pass-verify input or client-connect output\n"

          "Options:\n"
          "  -a deref                  either never (default), always, search, or find\n"
          "  -b basedn                 base dn for search\n"
          "  -c                        return success if LDAP error occurs\n"
          "  -d level                  set debug level\n"
          "  -F facility               syslog facility\n"
          "  -f file                   LDAP/command configuration file\n"
          "  -H URI                    LDAP Uniform Resource Identifier(s)\n"
          "  -h, --help                print this help and exit\n"
          "  -l limit                  time limit for search\n"
          "  -P version                protocol version (default: 3)\n"
          "  -p profile                default account profile (default: none)\n"
          "  -Q dir                    directory containing account profiles\n"
          "  -q, --quiet, --silent     do not print messages\n"
          "  -s scope                  one of base, one, sub or children (search scope)\n"
          "  -v, --verbose             run in verbose mode (diagnostics to stderr)\n"
          "  -V, --version             print version number and exit\n"
          "  -x                        Simple authentication\n"
          "  -Z                        Start TLS request (-ZZ to require)\n"

          "Pattern Codes:\n"
          "  %%%%                        expands to '%%' character\n"
          "  %%c                        expands to common name from SSL certificate\n"
          "  %%I                        expands to session's trusted IP address\n"
          "  %%i                        expands to session's untrusted IP address\n"
          "  %%R                        expands to session's remote pool IPv6 address\n"
          "  %%r                        expands to session's remote pool IPv4 address\n"
          "  %%U                        expands to username\n"
          "  %%u                        expands to username, if available, or common name\n"


          "Exit Codes:\n"
          "  0                         success\n"
          "  1                         general error\n"
          "  2                         bad username/password\n"
          "  3                         bad user configuration\n"
          "  4                         multiple LDAP entries found\n"
          "\n"
   );
   return;
}


void ovlc_version(ovlc * od)
{
   printf("%s (%s) %s\n", od->prog_name, PACKAGE_TARNAME, GIT_PACKAGE_VERSION_BUILD);
   printf("\n");
   return;
};


/* end of source */
