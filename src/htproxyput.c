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

#include <curl/curl.h>
#include <curl/types.h>
#include <curl/easy.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include <curl/curl.h>
#include <curl/types.h>
#include <curl/easy.h>

#include <getopt.h>

#include "gridsite.h"

#include "soapH.h"
#include "delegation.nsmap"

#define USE_SOAP		0
#define USE_G_HTTPS		1
#define HTPROXY_PUT		0

int debugfunction(CURL *curl, curl_infotype type, char *s, size_t n, void *p)
{
  fwrite(s, sizeof(char), n, (FILE *) p);

  return 0;
}

size_t parsegprheaders(void *ptr, size_t size, size_t nmemb, void *p)
{
  int   i;
  
  if ((size * nmemb > 15) && 
      (strncmp((char *) ptr, "Delegation-ID: ", 15) == 0))
    {
      *((char **) p) = malloc( size * nmemb - 14 );
      
      memcpy(*((char **) p), &(((char *) ptr)[15]), size * nmemb - 15);
  
      for (i=0; i < size * nmemb - 15; ++i) 
        if (((*((char **) p))[i] == '\n') || ((*((char **) p))[i] == '\r'))
          {
            (*((char **) p))[i] = '\0'; /* drop trailing newline */
            break;
          }
          
      (*((char **) p))[size * nmemb - 15] = '\0';
    }
    
  return size * nmemb;
}

struct gprparams { char *req; size_t len; } ;

size_t storegprbody(void *ptr, size_t size, size_t nmemb, void *p)
{
  ((struct gprparams *) p)->req = realloc( ((struct gprparams *) p)->req,
                          ((struct gprparams *) p)->len + size * nmemb + 1);

  memcpy( &((((struct gprparams *) p)->req)[((struct gprparams *) p)->len]),
           ptr, size * nmemb);
         
  ((struct gprparams *) p)->len += size * nmemb;

  return size * nmemb;
}

int GRSTgetProxyReq(CURL *curl, FILE *debugfp, char *delegid, char **reqtxt, 
                    char *requrl, char *cert, char *key)
{
  char     *delheader;
  struct    curl_slist *headerlist = NULL;
  CURLcode  res;
  struct    gprparams params;

  params.req = NULL;
  params.len = 0;

  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) &params);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, storegprbody);

  curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE,  "PEM");
  curl_easy_setopt(curl, CURLOPT_SSLCERT,      cert);

  curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE,   "PEM");
  curl_easy_setopt(curl, CURLOPT_SSLKEY,       key);    
  curl_easy_setopt(curl, CURLOPT_SSLKEYPASSWD, NULL);

//  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, parsegprheaders);
//  curl_easy_setopt(curl, CURLOPT_WRITEHEADER,    (void *) delegid);
  
  curl_easy_setopt(curl, CURLOPT_CAPATH, "/etc/grid-security/certificates/");

  curl_easy_setopt(curl, CURLOPT_URL,           requrl);
  curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET-PROXY-REQ");

  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER,0);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST,0);

  asprintf(&delheader, "Delegation-ID: %s", delegid);
  headerlist = curl_slist_append(headerlist, delheader);                                                                           
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);

  if (debugfp != NULL)
    {
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);       
      curl_easy_setopt(curl, CURLOPT_DEBUGDATA,     debugfp);
      curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, debugfunction);
    }
       
  res = curl_easy_perform(curl);
  
  if (params.req != NULL)
    {
      params.req[params.len] = '\0';
      *reqtxt = params.req;
    }
  else *reqtxt = NULL;
  
  return (int) res;
}

struct ppcparams{ char *cert; size_t len; };

size_t getppcbody(void *ptr, size_t size, size_t nmemb, void *p)
{
  size_t i;
  
  if (((struct ppcparams *) p)->len == 0) return 0;
  
  if (size * nmemb < ((struct ppcparams *) p)->len) i = size * nmemb;
  else                             i = ((struct ppcparams *) p)->len;
  
  memcpy(ptr, ((struct ppcparams *) p)->cert, i);
  
  ((struct ppcparams *) p)->len -= i;   
  ((struct ppcparams *) p)->cert = &((((struct ppcparams *) p)->cert)[i+1]);
     
  return i;
}

int GRSTputProxyCerts(CURL *curl, FILE *debugfp, char *delegid, char *certtxt,
                      char *requrl, char *cert, char *key)
{
  CURLcode    res;
  char       *delheader;
  long        httpcode;
  struct curl_slist *headerlist = NULL;
  struct ppcparams params;

  params.cert = certtxt;
  params.len  = strlen(certtxt);

  curl_easy_setopt(curl, CURLOPT_READDATA,     &params);
  curl_easy_setopt(curl, CURLOPT_READFUNCTION, getppcbody);
  curl_easy_setopt(curl, CURLOPT_INFILESIZE,   strlen(certtxt));
  curl_easy_setopt(curl, CURLOPT_UPLOAD,       1);

  curl_easy_setopt(curl, CURLOPT_NOBODY,       1);  

  curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE,  "PEM");
  curl_easy_setopt(curl, CURLOPT_SSLCERT,      cert);

  curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE,   "PEM");
  curl_easy_setopt(curl, CURLOPT_SSLKEY,       key);    
//  curl_easy_setopt(curl, CURLOPT_SSLKEYPASSWD, NULL);

  curl_easy_setopt(curl, CURLOPT_CAPATH, "/etc/grid-security/certificates/");

  curl_easy_setopt(curl, CURLOPT_URL,           requrl);
  curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT-PROXY-CERT");

  headerlist = curl_slist_append(headerlist, 
                 "Content-Type: application/x-x509-user-cert-chain");
                                   
  asprintf(&delheader, "Delegation-ID: %s", delegid);
  headerlist = curl_slist_append(headerlist, delheader);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
  
curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);

  if (debugfp != NULL)
    {
      curl_easy_setopt(curl, CURLOPT_VERBOSE,       1);       
      curl_easy_setopt(curl, CURLOPT_DEBUGDATA,     debugfp);
      curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, debugfunction);
    } 
     
  res = curl_easy_perform(curl);

  curl_easy_getinfo(curl, CURLINFO_HTTP_CODE, &httpcode);
  
  curl_slist_free_all(headerlist);

  free(delheader);
  
  return (int) res;
}


#if (LIBCURL_VERSION_NUM < 0x070908)
char *make_tmp_ca_roots(char *dir)
/* libcurl before 7.9.8 doesnt support CURLOPT_CAPATH and the directory,
   so we make a temporary file with the concatenated CA root certs: that
   is, all the files in that directory which end in .0 */
{
  int    ofd, ifd, c;
  size_t size;
  char   tmp_ca_roots[] = "/tmp/.ca-roots-XXXXXX", buffer[4096], *s;
  DIR   *rootsDIR;
  struct dirent *root_ent;

  if ((rootsDIR = opendir(dir)) == NULL) return NULL;

  if ((ofd = mkstemp(tmp_ca_roots)) == -1)
    {
      closedir(rootsDIR);
      return NULL;
    }

  while ((root_ent = readdir(rootsDIR)) != NULL)
       {
         if ((root_ent->d_name[0] != '.') &&
             (strlen(root_ent->d_name) > 2) &&
             (strncmp(&(root_ent->d_name[strlen(root_ent->d_name)-2]),
                                                        ".0", 2) == 0))
           {
             asprintf(&s, "%s/%s", dir, root_ent->d_name);
             ifd = open(s, O_RDONLY);
             free(s);

             if (ifd != -1)
               {
                 while ((size = read(ifd, buffer, sizeof(buffer))) > 0)
                                                 write(ofd, buffer, size);

                 close(ifd);
               }
           }
       }

  closedir(rootsDIR);

  if (close(ofd) == 0) return strdup(tmp_ca_roots);

  unlink(tmp_ca_roots); /* try to clean up if errors */

  return NULL;
}
#endif
  
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
        *cert = NULL, *key = NULL, *capath = NULL, *keycert;
  struct ns__putProxyResponse *unused;
  int    option_index, c, protocol = USE_SOAP, noverify = 0, 
         method = HTPROXY_PUT, verbose = 0, fd, minutes;
  struct soap soap_get, soap_put;
  FILE   *ifp, *ofp;
  struct stat statbuf;
  struct passwd *userpasswd; 
  struct option long_options[] = {      {"verbose",     0, 0, 'v'},
                                        {"cert",        1, 0, 0},
                                        {"key",         1, 0, 0},
                                        {"capath",      1, 0, 0},
                                        {"soap",        0, 0, 0},
                                        {"g-https",     0, 0, 0},
                                        {"no-verify",   0, 0, 0},
                                        {"valid",       1, 0, 0},
                                        {"delegation-id",1, 0, 0},
                                        {"put",         0, 0, 0},
                                        {0, 0, 0, 0}  };
  CURL *curl;

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
             if      (option_index == 1) cert      = optarg;
             else if (option_index == 2) key       = optarg;
             else if (option_index == 3) capath    = optarg;
             else if (option_index == 4) protocol  = USE_SOAP;
             else if (option_index == 5) protocol  = USE_G_HTTPS;
             else if (option_index == 6) noverify  = 1;
             else if (option_index == 7) valid     = optarg;
             else if (option_index == 8) delegation_id = optarg;
             else if (option_index == 9) method    = HTPROXY_PUT;
           }
         else if (c == 'v') ++verbose;
       }

  if (optind + 1 != argc)
    {
      fprintf(stderr, "Must specify a target URL!\n");
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

#if (LIBCURL_VERSION_NUM < 0x070908)
  /* libcurl before 7.9.8 doesnt support CURLOPT_CAPATH and the directory */

  if ((capath != NULL) &&
      (stat(capath, &statbuf) == 0) && S_ISDIR(statbuf.st_mode))
    {
      tmp_ca_roots = make_tmp_ca_roots(capath);
      capath = tmp_ca_roots;
    }
#endif

  if (protocol == USE_G_HTTPS)
    {
      if (verbose) fprintf(stderr, "Using G-HTTPS delegation protocol\n");

      if (verbose) fprintf(stderr, "Delegation-ID: %s\n", delegation_id);

      curl_global_init(CURL_GLOBAL_DEFAULT);   
      curl = curl_easy_init();
      
//  curl_easy_setopt(curl, CURLOPT_SSLKEYPASSWD, NULL);

      GRSTgetProxyReq(curl, stderr, delegation_id, &reqtxt, 
                      argv[optind], cert, key);
  
      if (GRSTx509MakeProxyCert(&certtxt, stderr, reqtxt, cert, key, minutes)
          != GRST_RET_OK)     
        {
          return 1;
        }

      GRSTputProxyCerts(curl, stderr, delegation_id, certtxt, 
                        argv[optind], cert, key);

      curl_easy_cleanup(curl);  
      curl_global_cleanup();
  
      return 0;
    }
  else if (protocol == USE_SOAP)
    {
      if (strcmp(key, cert) != 0) /* we have to concatenate for gSOAP */
        {
          keycert = strdup("/tmp/XXXXXX");
        
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

      if (verbose) 
        {
          fprintf(stderr, "Using SOAP delegation protocol\n");
          fprintf(stderr, "Delegation-ID: %s\n", delegation_id);
          fprintf(stderr, "Send getProxyReq to service\n");
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

      soap_call_ns__getProxyReq(&soap_get, 
                                argv[optind],	/* HTTPS url of service */
                                "", 		/* no password on proxy */
                                delegation_id, 
                                &reqtxt);
      
      if (soap_get.error)
        {
          soap_print_fault(&soap_get, stderr);
          return 1;        
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

      soap_call_ns__putProxy(&soap_put, argv[optind], "", delegation_id, 
                             certtxt, unused);      
      if (soap_put.error)
        {
          soap_print_fault(&soap_put, stderr);
          return 1;        
        }

      return 0;
    }  

  /* weirdness */
}

