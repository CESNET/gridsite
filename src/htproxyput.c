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

/*

Build with:

gcc -lcurl -lssl -lcrypto -o grst-proxy-put grst-proxy-put.c libgridsite.a

http://www.gridpp.ac.uk/authz/gridsite/

*/

#ifndef VERSION
#define VERSION "0.0.0"
#endif

#define _GNU_SOURCE

#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <getopt.h>

#include <gridsite.h>

#include <stdsoap2.h>

#include "DelegationSoapBinding.nsmap"

#define HTPROXY_PUT		0
#define HTPROXY_RENEW		1
#define HTPROXY_DESTROY		2
#define HTPROXY_TIME		3
#define HTPROXY_UNIXTIME	4

void printsyntax(char *argv0)
{
  char *p;

  p = rindex(argv0, '/');
  if (p != NULL) ++p;
  else           p = argv0;

  fprintf(stderr, "%s [options] URL\n"
          "(Version: %s)\n", p, VERSION);
}
  
int main(int argc, char *argv[])
{
  char  *delegation_id = "", *reqtxt, *certtxt, *valid = NULL, 
        *cert = NULL, *key = NULL, *capath = NULL, *keycert, timestr[81],
        *executable;
  struct ns__putProxyResponse *unused;
  struct tm *finish_tm;
  int    option_index, c, noverify = 0, 
         method = HTPROXY_PUT, verbose = 0, fd, minutes;
  struct soap soap_get, soap_put;
  struct ns__getProxyReqResponse        getProxyReqResponse;
  struct ns__getNewProxyReqResponse     getNewProxyReqResponse;
  struct ns__renewProxyReqResponse      renewProxyReqResponse;
  struct ns__destroyResponse            destroyResponse;
  struct ns__getTerminationTimeResponse getTerminationTimeResponse;
  FILE   *ifp, *ofp;
  struct stat statbuf;
  struct passwd *userpasswd; 
  struct option long_options[] = {      {"verbose",     0, 0, 'v'},
                                        {"cert",        1, 0, 0},
                                        {"key",         1, 0, 0},
                                        {"capath",      1, 0, 0},
                                        {"destroy",     0, 0, 0},
                                        {"time",        0, 0, 0},
                                        {"no-verify",   0, 0, 0},
                                        {"valid",       1, 0, 0},
                                        {"delegation-id",1, 0, 0},
                                        {"put",         0, 0, 0},
                                        {"renew",       0, 0, 0},
                                        {"unixtime",	0, 0, 0},
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
             if      (option_index ==  1) cert            = optarg;
             else if (option_index ==  2) key             = optarg;
             else if (option_index ==  3) capath          = optarg;
             else if (option_index ==  4) method          = HTPROXY_DESTROY;
             else if (option_index ==  5) method          = HTPROXY_TIME;
             else if (option_index ==  6) noverify        = 1;
             else if (option_index ==  7) valid           = optarg;
             else if (option_index ==  8) delegation_id   = optarg;
             else if (option_index ==  9) method          = HTPROXY_PUT;
             else if (option_index == 10) method          = HTPROXY_RENEW;
             else if (option_index == 11) method          = HTPROXY_UNIXTIME;
           }
         else if (c == 'v') ++verbose;
       }

  if (optind + 1 != argc)
    {
      fprintf(stderr, "Must specify a delegation service URL!\n");
      return 1;
    }

  executable = rindex(argv[0], '/');
  if (executable != NULL) executable++;
  else                    executable = argv[0];
  
  if    (strcmp(executable, "htproxydestroy") == 0) method = HTPROXY_DESTROY;
  else if (strcmp(executable, "htproxyrenew") == 0) method = HTPROXY_RENEW;
  else if (strcmp(executable, "htproxytime") == 0)  method = HTPROXY_TIME;
  else if (strcmp(executable, "htproxyunixtime") == 0) 
                                                    method = HTPROXY_UNIXTIME;

  if ((method == HTPROXY_RENEW) && (delegation_id[0] == '\0'))
    {
      fprintf(stderr, "Must give a Delegation ID when renewing\n");
      return 1;
    }
    
  if (valid == NULL) minutes = 60 * 12;
  else minutes = atoi(valid);
  
  if (verbose) fprintf(stderr, "Proxy valid for %d minutes\n", minutes);
 
  ERR_load_crypto_strings ();
  OpenSSL_add_all_algorithms();

  if      ((cert == NULL) && (key != NULL)) cert = key;
  else if ((cert != NULL) && (key == NULL)) key = cert;
  else if ((cert == NULL) && (key == NULL))
    {
      cert = getenv("X509_USER_PROXY");
      if (cert != NULL) key = cert;
      else
        {
          asprintf(&(cert), "/tmp/x509up_u%d", geteuid());
                                                                                
          /* one fine day, we will check the proxy file for 
             expiry too to avoid suprises when we try to use it ... */

          if (stat(cert, &statbuf) == 0) key = cert;
          else
            {
              cert = getenv("X509_USER_CERT");
              key  = getenv("X509_USER_KEY");
                                                                                
              userpasswd = getpwuid(geteuid());
                                                                                
              if ((cert == NULL) &&
                  (userpasswd != NULL) &&
                  (userpasswd->pw_dir != NULL))
                asprintf(&(cert), "%s/.globus/usercert.pem",
                                                    userpasswd->pw_dir);
                                                                                
              if ((key == NULL) &&
                  (userpasswd != NULL) &&
                  (userpasswd->pw_dir != NULL))
                asprintf(&(key), "%s/.globus/userkey.pem",
                                                    userpasswd->pw_dir);
                                                                                
            }
        }
    }
                                                                                
  if (capath == NULL) capath = getenv("X509_CERT_DIR");
  if (capath == NULL) capath = "/etc/grid-security/certificates";

  if (verbose) fprintf(stderr, "key=%s\ncert=%s\ncapath=%s\n",
                       key, cert, capath);

  if (strcmp(key, cert) != 0) /* we have to concatenate for gSOAP */
    {
      keycert = strdup("/tmp/.XXXXXX");
        
      fd = mkstemp(keycert);
      ofp = fdopen(fd, "w");
          
      ifp = fopen(key, "r");          
      while ((c = fgetc(ifp)) != EOF) fputc(c, ofp);          
      fclose(ifp);
          
      ifp = fopen(cert, "r");          
      while ((c = fgetc(ifp)) != EOF) fputc(c, ofp);          
      fclose(ifp);
          
      fclose(ofp);       
          
      if (verbose) fprintf(stderr, "Created %s key/cert file\n", keycert);
    }
  else keycert = key;

  if ((method == HTPROXY_PUT) || (method == HTPROXY_RENEW))
    {
      if (verbose) 
        {
          fprintf(stderr, "Using SOAP delegation protocol\n");
          fprintf(stderr, "Delegation-ID: %s\n", delegation_id);
        }

      soap_init(&soap_get);
  
      if (soap_ssl_client_context(&soap_get,
                                  SOAP_SSL_DEFAULT,
                                  keycert, 
                                  "",
                                  NULL,
                                  capath,
                                  NULL))
        {
          soap_print_fault(&soap_get, stderr);
          return 1;
        } 

      if ((method == HTPROXY_RENEW) && (delegation_id[0] != '\0'))
        {
          if (verbose) fprintf(stderr, "Send renewProxyReq to service\n");

          soap_call_ns__renewProxyReq(&soap_get, 
                                argv[optind],	/* HTTPS url of service */
                                "http://www.gridsite.org/namespaces/delegation-1",
                                delegation_id, 
                                &renewProxyReqResponse);
      
          if (soap_get.error)
            {
              soap_print_fault(&soap_get, stderr);
              return 1;        
            }
       
          reqtxt = renewProxyReqResponse._renewProxyReqReturn;
        }
      else
        {
          if (verbose) fprintf(stderr, "Send getNewProxyReq to service\n");

          soap_call_ns__getNewProxyReq(&soap_get,
                            argv[optind],	/* HTTPS url of service */
                            "http://www.gridsite.org/namespaces/delegation-1",
                            &getNewProxyReqResponse);

          if (soap_get.error)
            {
              soap_print_fault(&soap_get, stderr);
              return 1;        
            }

          reqtxt = getNewProxyReqResponse.getNewProxyReqReturn->proxyRequest;
          delegation_id = 
                   getNewProxyReqResponse.getNewProxyReqReturn->delegationID;
        }
 
      if (verbose) fprintf(stderr, "reqtxt:\n%s", reqtxt);
      
      if (GRSTx509MakeProxyCert(&certtxt, stderr, reqtxt, cert, key, minutes) 
          != GRST_RET_OK)
        {
          return 1;
        }

      soap_init(&soap_put);
  
      if (verbose) fprintf(stderr, "Send putProxy to service:\n%s\n", certtxt);

      if (soap_ssl_client_context(&soap_put,
                                  SOAP_SSL_DEFAULT,
                                  keycert, 
                                  "",
                                  NULL,
                                  capath,
                                  NULL))
        {
          soap_print_fault(&soap_put, stderr);
          return 1;
        } 

      soap_call_ns__putProxy(&soap_put, argv[optind],
                             "http://www.gridsite.org/namespaces/delegation-1",
                             delegation_id, 
                             certtxt, unused);      
      if (soap_put.error)
        {
          soap_print_fault(&soap_put, stderr);
          return 1;        
        }

      puts(delegation_id);

      return 0;
    }  
  else if (method == HTPROXY_DESTROY)
    {
      if (verbose) 
        {
          fprintf(stderr, "Using SOAP proxy destroy protocol\n");
          fprintf(stderr, "Delegation-ID: %s\n", delegation_id);
        }

      soap_init(&soap_put);
  
      if (verbose) fprintf(stderr, "Send destroy to service:\n");

      if (soap_ssl_client_context(&soap_put,
                                  SOAP_SSL_DEFAULT,
                                  keycert, 
                                  "",
                                  NULL,
                                  capath,
                                  NULL))
        {
          soap_print_fault(&soap_put, stderr);
          return 1;
        } 

      soap_call_ns__destroy(&soap_put, argv[optind],
                             "http://www.gridsite.org/namespaces/delegation-1",
                             delegation_id, 
                             &destroyResponse);
      if (soap_put.error)
        {
          soap_print_fault(&soap_put, stderr);
          return 1;        
        }

      return 0;
    }  
  else if ((method == HTPROXY_TIME) || (method == HTPROXY_UNIXTIME))
    {
      if (verbose) 
        {
          fprintf(stderr, "Using SOAP proxy get expiration time protocol\n");
          fprintf(stderr, "Delegation-ID: %s\n", delegation_id);
        }

      soap_init(&soap_put);
  
      if (verbose) fprintf(stderr, "Send get time to service:\n");

      if (soap_ssl_client_context(&soap_put,
                                  SOAP_SSL_DEFAULT,
                                  keycert, 
                                  "",
                                  NULL,
                                  capath,
                                  NULL))
        {
          soap_print_fault(&soap_put, stderr);
          return 1;
        } 

      soap_call_ns__getTerminationTime(&soap_put, argv[optind],
                             "http://www.gridsite.org/namespaces/delegation-1",
                             delegation_id, 
                             &getTerminationTimeResponse);
      if (soap_put.error)
        {
          soap_print_fault(&soap_put, stderr);
          return 1;        
        }


      if (method == HTPROXY_UNIXTIME)
       printf("%ld\n", getTerminationTimeResponse._getTerminationTimeReturn);
      else
        {
          finish_tm = 
           localtime(&(getTerminationTimeResponse._getTerminationTimeReturn));

          strftime(timestr, sizeof(timestr),
                       "%a %b %e %H:%M:%S %Z %Y\n", finish_tm);
                       
          fputs(timestr, stdout);
        }
        
      return 0;
    }  

  /* weirdness */
}

