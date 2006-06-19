/*
   Copyright (c) 2002-6, Andrew McNab, University of Manchester
   All rights reserved.

   Redistribution and use in source and binary forms, with or
   without modification, are permitted provided that the following
   conditions are met:

     o Redistributions of source code must retain the above
       copyright notice, this list of conditions and the following
       disclaimer. 
     o Redistributions in binary form must reproduce the above
       copyright notice, this list of conditions and the following
       disclaimer in the documentation and/or other materials
       provided with the distribution. 

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
   CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
   INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
   DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
   BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
   TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
   ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
   OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef VERSION
#define VERSION "0.0.0"
#endif

#define _GNU_SOURCE

#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <getopt.h>

#include "gridsite.h"
  
void printsyntax(char *argv0)
{
  char *p;

  p = rindex(argv0, '/');
  if (p != NULL) ++p;
  else           p = argv0;

  fprintf(stderr, "%s [--outsidecache] [--proxycache=PATH] "
                  "[--delegation-id=DELEGATION-ID] [--user-dn=USER-DN]\n"
                  "(Version: %s)\n", p, VERSION);
}
  
#define GRST_PROXY_CACHE "/var/www/proxycache"
  
int main(int argc, char *argv[])
{
  char  *delegation_id = "_", *proxycache = "", *user_dn = "",
        *proxyfile = NULL;        
  int    c, outsidecache = 0, verbose = 0, option_index;
  struct option long_options[] = {      {"verbose",     	0, 0, 'v'},
                                        {"outsidecache",	0, 0, 0},
                                        {"proxycache",		1, 0, 0},
                                        {"delegation-id",	1, 0, 0},
                                        {"user-dn",		1, 0, 0},
                                        {0, 0, 0, 0}  };

  if (argc == 1)
    {
      printsyntax(argv[0]);
      return 0;
    }

  while (1)
       {
         option_index = 0;
                                                                                
         c = getopt_long(argc, argv, "v", long_options, &option_index);

         if      (c == -1) break;
         else if (c == 0)
           {
             if      (option_index == 1) outsidecache  = 1;
             else if (option_index == 2) proxycache    = optarg;
             else if (option_index == 3) delegation_id = optarg;
             else if (option_index == 4) user_dn       = optarg;
           }
         else if (c == 'v') ++verbose;
       }
       
  if (*user_dn != '\0') /* try to find in proxy cache */
    {
      if ((proxycache == NULL) || (*proxycache == '\0'))
        proxycache = getenv("GRST_PROXY_CACHE");

      if ((proxycache == NULL) || (*proxycache == '\0'))
        proxycache = GRST_PROXY_CACHE;

      proxyfile = GRSTx509CachedProxyFind(proxycache, delegation_id, user_dn);
    }
    
  if (((proxyfile == NULL) || (*proxyfile == '\0')) && outsidecache)
    {
      proxyfile = GRSTx509FindProxyFileName();
    }

  if ((proxyfile != NULL) && (*proxyfile != '\0'))
    {
      puts(proxyfile);
      return 0;   
    }
    
  fputs("No proxy file found\n", stderr);
    
  return 1;
}
