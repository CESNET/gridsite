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

/* 
    Change the hard-coded defaults below to your set up. 
*/

#define LOCALPROXY	"/tmp/x509up"
#define DELEGATIONURL	"https://testing.hep.man.ac.uk/gridsite-delegation.cgi"
#define CAPATH		"/etc/grid-security/certificates"
#define DELEGATIONID    "1234567890"
#define EXPIREMINUTES	60 
  
#ifndef VERSION
#define VERSION "0.0.0"
#endif

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "gridsite.h"

#include "soapH.h"
#include "delegation.nsmap"

int main(int argc, char *argv[])
{
  char *reqtxt, *certtxt;
  struct ns__putProxyResponse *unused;
  struct soap soap_get, soap_put;
 
  ERR_load_crypto_strings ();
  OpenSSL_add_all_algorithms();

  soap_init(&soap_get);
  
  if (soap_ssl_client_context(&soap_get,
                                  SOAP_SSL_DEFAULT,
                                  LOCALPROXY, 
                                  "",
                                  NULL,
                                  CAPATH,
                                  NULL))
        {
          soap_print_fault(&soap_get, stderr);
          return 1;
        } 

  soap_call_ns__getProxyReq(&soap_get, 
                                DELEGATIONURL,	/* HTTPS url of service */
                                "", 		/* no password on proxy */
                                DELEGATIONID, 
                                &reqtxt);
      
  if (soap_get.error)
    {
          soap_print_fault(&soap_get, stderr);
          return 1;        
    }
        
  if (GRSTx509MakeProxyCert(&certtxt, stderr, reqtxt, 
                            LOCALPROXY, LOCALPROXY, EXPIREMINUTES) 
          != GRST_RET_OK)
    {
          return 1;
    }

  soap_init(&soap_put);
  
  if (soap_ssl_client_context(&soap_put,
                                  SOAP_SSL_DEFAULT,
                                  LOCALPROXY, 
                                  "",
                                  NULL,
                                  CAPATH,
                                  NULL))
        {
          soap_print_fault(&soap_put, stderr);
          return 1;
        } 

  soap_call_ns__putProxy(&soap_put, DELEGATIONURL, "", DELEGATIONID, 
                             certtxt, unused);      
  if (soap_put.error)
    {
          soap_print_fault(&soap_put, stderr);
          return 1;        
    }

  return 0;
}

