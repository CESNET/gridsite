/*
   Copyright (c) 2002-4, Andrew McNab, University of Manchester
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

/*---------------------------------------------------------------------------*
 * This program is part of GridSite: http://www.gridpp.ac.uk/authz/gridsite/ *
 *---------------------------------------------------------------------------*/

#ifndef VERSION
#define VERSION "0.0.1"
#endif

#define _GNU_SOURCE
#include <stdio.h>

#include <time.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bio.h>    
#include <openssl/des.h>    
#include <openssl/rand.h>

#include <curl/curl.h>
/* #include <gacl.h> */

#include "gridsite.h"

#include "soapH.h"
#include "delegation.nsmap"

#include <time.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bio.h>    
#include <openssl/des.h>    
#include <openssl/rand.h>

#define GRST_KEYSIZE       512
#define GRST_PROXYCACHE    "/../proxycache/"
#define GRST_SUPPORT_G_HTTPS

#ifdef GRST_SUPPORT_G_HTTPS
void GRSThttpError(char *status)
{
  printf("Status: %s\n", status);
  printf("Server-CGI: GridSite %s\n", VERSION);
  printf("Content-Length: %d\n", 2 * strlen(status) + 58);
  puts("Content-Type: text/html\n");
   
  printf("<head><title>%s</title></head>\n", status);
  printf("<body><h1   >%s</h1   ></body>\n", status);
   
  exit(0);
}

int GRSTmethodPutProxy(char *delegation_id, char *user_dn)
/* return 0 on success; non-zero on error */
{
  int   c, len = 0, i;
  char *docroot, *contentlen, *contenttype, *proxychain, *proxydir;
  FILE *fp;

  if (((contenttype = getenv("CONTENT_TYPE")) == NULL) ||
       (strcmp(contenttype, "application/x-x509-user-cert-chain") != 0))
                               return 2;
  
  contentlen = getenv("CONTENT_LENGTH");
  if (contentlen == NULL) return 2;
  len = atoi(contentlen);
  
  if ((delegation_id == NULL) || (*delegation_id == '\0')) 
                                                    delegation_id = "_";
  
  docroot = getenv("DOCUMENT_ROOT");
  asprintf(&proxydir, "%s/%s", docroot, GRST_PROXYCACHE);

  if ((user_dn == NULL) || (user_dn[0] == '\0') ||
      (GRSTx509CacheProxy(proxydir, delegation_id, user_dn, proxychain) 
                                                      != GRST_RET_OK))
    {
      return GRST_RET_FAILED;
    }
    
  free(proxydir);
      
  return GRST_RET_OK;
}
#endif

int main(int argn, char *argv[])
{
  char      *docroot, *method, *request, *p, *client_dn, *user_dn,
            *delegation_id, *reqtxt, *proxydir;
  struct soap soap;

chdir("/var/tmp");
  
  method  = getenv("REQUEST_METHOD");
  if (strcmp(method, "POST") == 0)
    {
      soap_init(&soap);
      soap_serve(&soap); /* CGI application */
      return 0;
    }
    
#ifdef GRST_SUPPORT_G_HTTPS
  docroot = getenv("DOCUMENT_ROOT");

  request = strdup(getenv("REQUEST_URI"));
  p = index(request, '?');
  if (p != NULL) *p = '\0';

      
  /* non HTTP POST methods - ie special G-HTTPS methods */

  delegation_id = getenv("HTTP_DELEGATION_ID");
  if ((delegation_id == NULL) || (*delegation_id == '\0')) delegation_id = "_";

  user_dn = NULL;
  client_dn = getenv("SSL_CLIENT_S_DN"); 
  if (client_dn != NULL) 
    {
      user_dn = strdup(client_dn);

      /* we assume here that mod_ssl has verified proxy chain already ... */

      p = strstr(user_dn, "/CN=proxy");
      if (p != NULL) *p = '\0';      

      p = strstr(user_dn, "/CN=limited proxy");
      if (p != NULL) *p = '\0';      
    }
  
  if (user_dn == NULL) /* all methods require client auth */
    {
      GRSThttpError("403 Forbidden");
    }  
  else if (strcmp(method, "GET-PROXY-REQ") == 0)
    {
      docroot = getenv("DOCUMENT_ROOT");
      asprintf(&proxydir, "%s/%s", docroot, GRST_PROXYCACHE);
    
      if (GRSTx509MakeProxyRequest(&reqtxt, proxydir,
                                   delegation_id, user_dn) == 0)
        {
          puts("Status: 200 OK");
          puts("Content-Type: application/x-x509-cert-request");
          printf("Content-Length: %d\n\n", strlen(reqtxt));
          fputs(reqtxt, stdout);
          free(proxydir);
          return 0;
        }
      
      puts("Status: 500 Internal Server Error\n");
      free(proxydir);
      return 0;
    }  
  else if (strcmp(method, "PUT-PROXY-CERT") == 0)
    {
      if (GRSTmethodPutProxy(delegation_id, user_dn) == 0)
        {
          puts("Status: 200 OK\n");
          return 0;
        }
        
      puts("Status: 500 Internal Server Error\n");
      return 0;
    }  
  else 
    {
      GRSThttpError("501 Method Not Implemented");
    }
#endif
}

int ns__getProxyReq(struct soap *soap, char *delegation_id,                                        
                                       char **request)
{ 
  char *p, *client_dn, *user_dn, *docroot, *proxydir;
  
  user_dn = NULL;
  client_dn = getenv("SSL_CLIENT_S_DN"); 
  if (client_dn != NULL) 
    {
      user_dn = strdup(client_dn);

      /* we assume here that mod_ssl has verified proxy chain already ... */

      p = strstr(user_dn, "/CN=proxy");
      if (p != NULL) *p = '\0';      

      p = strstr(user_dn, "/CN=limited proxy");
      if (p != NULL) *p = '\0';      
    }

  if ((delegation_id == NULL) || (*delegation_id == '\0')) delegation_id = "_";
  
  docroot = getenv("DOCUMENT_ROOT");
  asprintf(&proxydir, "%s/%s", docroot, GRST_PROXYCACHE);

  if ((user_dn != NULL) && (user_dn[0] != '\0') && 
      (GRSTx509MakeProxyRequest(request, proxydir,  
                                delegation_id, user_dn) == 0))
    {
      return SOAP_OK;
    }
      
  return SOAP_ERR;
} 

int ns__putProxy(struct soap *soap, char *delegation_id, 
                                    char *proxy,
                                    struct ns__putProxyResponse *unused)
{ 
  int   fd, c, len = 0, i;
  char *docroot, *proxydir, *p, *client_dn, *user_dn;
  
  user_dn = NULL;
  client_dn = getenv("SSL_CLIENT_S_DN"); 
  if (client_dn != NULL) 
    {
      user_dn = strdup(client_dn);

      /* we assume here that mod_ssl has verified proxy chain already ... */

      p = strstr(user_dn, "/CN=proxy");
      if (p != NULL) *p = '\0';      

      p = strstr(user_dn, "/CN=limited proxy");
      if (p != NULL) *p = '\0';      
    }
  
  if ((delegation_id == NULL) || (*delegation_id == '\0')) 
                                                    delegation_id = "_";
  
  docroot = getenv("DOCUMENT_ROOT");
  asprintf(&proxydir, "%s/%s", docroot, GRST_PROXYCACHE);

  if ((user_dn == NULL) || (user_dn[0] == '\0') ||
      (GRSTx509CacheProxy(proxydir, delegation_id, user_dn, proxy) 
                                                      != GRST_RET_OK))
    {
      return SOAP_ERR;
    }
      
  return SOAP_OK;
} 

