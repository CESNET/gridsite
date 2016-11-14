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

#include <gridsite.h>

#include "soapH.h"
#include "DelegationSoapBinding.nsmap"

#define GRST_PROXYCACHE    "/../proxycache/"

int main(int argn, char *argv[])
{
  char      *docroot, *method, *request, *p, *client_dn, *user_dn,
            *delegation_id, *reqtxt, *proxydir;
  struct soap soap;

  method = NULL;
  method  = getenv("REQUEST_METHOD");
  if (method != NULL){
    if (strcmp(method, "POST") == 0)
      {
        soap_init(&soap);
        soap_serve(&soap); /* CGI application */
        return 0;
      }    

    puts("Status: 501 Method Not Implemented\n");
    return 0;
  }
  puts("Status: 500 Internal Server Error\n");
  return 0;
}

char *get_dn(void)
{
  int   i;
  char *p, *s, *dn;
   
  for (i=0; ; ++i)
     {  
       asprintf(&p, "GRST_CRED_AURI_%d", i);
       s = getenv(p);
       free(p);
       
       if (s == NULL) break;
       
       if (strncmp(s, "dn:", 3) == 0)
         {
           dn = strdup(&s[2]);
           return dn;
         }
     }
  
  return NULL;  
}

int ns__getProxyReq(struct soap *soap, 
                    char *delegation_id,
                    struct ns__getProxyReqResponse *response)
{ 
  int   i;
  char *p, *user_dn, *docroot, *proxydir, *request;
  
  if ((delegation_id == NULL) || (*delegation_id == '\0')) 
      delegation_id = GRSTx509MakeDelegationID();
  else 
      if (!GRST_is_id_safe(delegation_id))
          return SOAP_ERR;

  if ((user_dn = get_dn()) == NULL) return SOAP_ERR;
      
  docroot = getenv("DOCUMENT_ROOT");
  asprintf(&proxydir, "%s/%s", docroot, GRST_PROXYCACHE);

  if ((user_dn != NULL) && 
      (user_dn[0] != '\0') && 
      (delegation_id != NULL) &&
      (GRSTx509MakeProxyRequestKS(&request, proxydir,
                                delegation_id, user_dn, 0) == 0))
    {
      response->getProxyReqReturn = request;
    
      free(user_dn);
      return SOAP_OK;
    }
      
  free(user_dn);
  return SOAP_ERR;
} 

int ns__getNewProxyReq(struct soap *soap, 
                       struct ns__getNewProxyReqResponse *response)
{
  char *p, *user_dn, *docroot, *proxydir, *request, *delegation_id;

  if ((user_dn = get_dn()) == NULL) return SOAP_ERR;

  delegation_id = GRSTx509MakeDelegationID();
  
  docroot = getenv("DOCUMENT_ROOT");
  asprintf(&proxydir, "%s/%s", docroot, GRST_PROXYCACHE);

  if ((user_dn != NULL) && 
      (user_dn[0] != '\0') && 
      (delegation_id != NULL) &&
      (GRSTx509MakeProxyRequestKS(&request, proxydir,
                                delegation_id, user_dn, 0) == 0))
    {
      response->getNewProxyReqReturn = malloc(sizeof(struct ns__NewProxyReq));      
      response->getNewProxyReqReturn->proxyRequest = request;
      response->getNewProxyReqReturn->delegationID = delegation_id;
    
      free(user_dn);
      return SOAP_OK;
    }

  free(user_dn);
  return SOAP_ERR;
} 
                                 
int ns__putProxy(struct soap *soap, char *delegation_id, 
                                    char *proxy,
                                    struct ns__putProxyResponse *response)
{ 
  int   fd, c, len = 0, i;
  char *docroot, *proxydir, *p, *user_dn;

  if ((delegation_id == NULL) || (*delegation_id == '\0')) 
      delegation_id = GRSTx509MakeDelegationID();
  else 
      if (!GRST_is_id_safe(delegation_id))
          return SOAP_ERR;
  
  if ((user_dn = get_dn()) == NULL) return SOAP_ERR;
  
  docroot = getenv("DOCUMENT_ROOT");
  asprintf(&proxydir, "%s/%s", docroot, GRST_PROXYCACHE);

  if ((user_dn == NULL) || 
      (user_dn[0] == '\0') ||
      (delegation_id == NULL) ||  
      (GRSTx509CacheProxy(proxydir, delegation_id, user_dn, proxy) 
                                                      != GRST_RET_OK))
    {
      free(proxydir);
      free(user_dn);
      return SOAP_ERR;
    }
      
  free(proxydir);
  free(user_dn);
  return SOAP_OK;
} 

int ns__renewProxyReq(struct soap *soap, 
                      char *delegation_id, 
                      struct ns__renewProxyReqResponse *response)
{ 
  int   i;
  char *p, *user_dn, *docroot, *proxydir, *request;

  if (delegation_id == NULL || *delegation_id == '\0')
      return SOAP_ERR;

  if (!GRST_is_id_safe(delegation_id))
      return SOAP_ERR;

  if ((user_dn = get_dn()) == NULL) return SOAP_ERR;
  
  docroot = getenv("DOCUMENT_ROOT");
  asprintf(&proxydir, "%s/%s", docroot, GRST_PROXYCACHE);

  if ((user_dn != NULL) && 
      (user_dn[0] != '\0') && 
      (delegation_id != NULL) &&
      (GRSTx509MakeProxyRequestKS(&request, proxydir,
                                delegation_id, user_dn, 0) == 0))
    {
      response->_renewProxyReqReturn = request;
    
      free(user_dn);
      return SOAP_OK;
    }

  free(user_dn);      
  return SOAP_ERR;
} 

int ns__getTerminationTime(struct soap *soap, 
                           char *delegation_id, 
                           struct ns__getTerminationTimeResponse *response)
{
  char *p, *user_dn, *docroot, *proxydir;
  time_t start, finish;

  if ((delegation_id == NULL) || (*delegation_id == '\0')) 
      delegation_id = GRSTx509MakeDelegationID();
  else 
      if (!GRST_is_id_safe(delegation_id))
          return SOAP_ERR;

  if ((user_dn = get_dn()) == NULL) return SOAP_ERR;  

  docroot = getenv("DOCUMENT_ROOT");
  asprintf(&proxydir, "%s/%s", docroot, GRST_PROXYCACHE);

  if ((user_dn != NULL) && 
      (user_dn[0] != '\0') && 
      (delegation_id != NULL) &&
      (GRSTx509ProxyGetTimes(proxydir, delegation_id, user_dn,
                             &start, &finish) == 0))
    {
      response->_getTerminationTimeReturn = finish;
    
      free(user_dn);
      return SOAP_OK;
    }

  free(user_dn);
  return SOAP_ERR;
}

int ns__destroy(struct soap *soap, 
                char *delegation_id, 
                struct ns__destroyResponse *response)
{
  int   fd, c, len = 0, i;
  char *docroot, *proxydir, *p, *client_dn, *user_dn;

  if ((delegation_id == NULL) || (*delegation_id == '\0')) 
      delegation_id = GRSTx509MakeDelegationID();
  else 
      if (!GRST_is_id_safe(delegation_id))
          return SOAP_ERR;
  
  if ((user_dn = get_dn()) == NULL) return SOAP_ERR;  
  
  docroot = getenv("DOCUMENT_ROOT");
  asprintf(&proxydir, "%s/%s", docroot, GRST_PROXYCACHE);

  if ((user_dn == NULL) || 
      (user_dn[0] == '\0') ||
      (delegation_id == NULL) ||  
      (GRSTx509ProxyDestroy(proxydir, delegation_id, user_dn) 
                                                      != GRST_RET_OK))
    {
      free(proxydir);
      free(user_dn);
      return SOAP_ERR;
    }
      
  free(proxydir);
  free(user_dn);
  return SOAP_OK;
}
