/*
   Copyright (c) 2002-3, Andrew McNab, University of Manchester
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

   ------------------------------------------------------------------------
    For more information about GridSite: http://www.gridpp.ac.uk/gridsite/
   ------------------------------------------------------------------------
*/ 

#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>       
#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "gridsite.h"

/// Compare X509 Distinguished Name strings
int GRSTx509NameCmp(char *a, char *b)
/**
 *  This function attempts to do with string representations what
 *  would ideally be done with OIDs/values. In particular, we equate
 *  "/Email=" == "/emailAddress=" to deal with this important change
 *  between OpenSSL 0.9.6 and 0.9.7. 
 *  Other than that, it is currently the same as ordinary strcmp(3).
 */
{
   int   ret;
   char *aa, *bb, *p;

   aa = strdup(a);
   while ((p = strstr(aa, "/emailAddress=")) != NULL)
        {
          memmove(&p[6], &p[13], strlen(&p[13]) + 1);
          p[1] = 'E';
        }

   bb = strdup(b);
   while ((p = strstr(bb, "/emailAddress=")) != NULL)
        {
          memmove(&p[6], &p[13], strlen(&p[13]) + 1);
          p[1] = 'E';
        }

   ret = strcmp(aa, bb);

   free(aa);
   free(bb);
                                                                                
   return ret;
}


/// Check critical extensions
/**
 *  Returning GRST_RET_OK if all of extensions are known to us or 
 *  OpenSSL; GRST_REF_FAILED otherwise.   
 *
 *  Since this function relies on functionality (X509_supported_extension)
 *  introduced in 0.9.7, then we do nothing and report an error 
 *  (GRST_RET_FAILED) if one of the associated defines 
 *  (X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION) is absent.
 */

int GRSTx509KnownCriticalExts(X509 *cert)
{
   int  i;
   char s[80];
   X509_EXTENSION *ex;
   
#ifdef X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION        
   for (i = 0; i < X509_get_ext_count(cert); ++i)
      {
        ex = X509_get_ext(cert, i);

        if (X509_EXTENSION_get_critical(ex) &&
                                 !X509_supported_extension(ex))
          {
            OBJ_obj2txt(s, sizeof(s), X509_EXTENSION_get_object(ex), 1);

            if (strcmp(s, GRST_PROXYCERTINFO_OID) != 0) return GRST_RET_FAILED;
          }
      }

   return GRST_RET_OK;
#else
   return GRST_RET_FAILED;
#endif
}

/// ASN1 time string (in a char *) to time_t
/** 
 *  (Use ASN1_STRING_data() to convert ASN1_GENERALIZEDTIME to char * if
 *   necessary)
 */
 
time_t GRSTasn1TimeToTimeT(char *asn1time)
{
   char   zone;
   struct tm time_tm;
  
   if ((sscanf(asn1time, "%02d%02d%02d%02d%02d%02d%c", 
         &(time_tm.tm_year),
         &(time_tm.tm_mon),
         &(time_tm.tm_mday),
         &(time_tm.tm_hour),
         &(time_tm.tm_min),
         &(time_tm.tm_sec),
         &zone) != 7) || (zone != 'Z')) return 0; /* dont understand */
         
   /* time format fixups */
  
   if (time_tm.tm_year < 90) time_tm.tm_year += 100;
   --(time_tm.tm_mon);
  
   return timegm(&time_tm);         
}

/// Check if certificate can be used as a CA to sign standard X509 certs
/*
 *  Return GRST_RET_OK if true; GRST_RET_FAILED if not.
 */

int GRSTx509IsCA(X509 *cert)
{
   int idret, purpose_id;

   purpose_id = X509_PURPOSE_get_by_sname("sslclient");

   /* final argument to X509_check_purpose() is whether to check for CAness */   

   if (X509_check_purpose(cert, purpose_id + X509_PURPOSE_MIN, 1))
        return GRST_RET_OK;
   else return GRST_RET_FAILED;
}   

/// Check certificate chain for GSI proxy acceptability.
/**
 *  Returns X509_V_OK/GRST_RET_OK if valid; OpenSSL X509 errors otherwise.
 *
 *  Inspired by GSIcheck written by Mike Jones, SVE, Manchester Computing,
 *  The University of Manchester.
 *
 *  The GridSite version handles old and new style Globus proxies, and
 *  proxies derived from user certificates issued with "X509v3 Basic
 *  Constraints: CA:FALSE" (eg UK e-Science CA)
 *
 *  We do not check chain links between certs here: this is done by
 *  GRST_check_issued/X509_check_issued in mod_ssl's ssl_engine_init.c
 *
 *  TODO: we do not yet check ProxyCertInfo and ProxyCertPolicy extensions
 *        (although via GRSTx509KnownCriticalExts() we can accept them.)
 */

int GRSTx509CheckChain(int *first_non_ca, X509_STORE_CTX *ctx)
{
   STACK_OF(X509) *certstack;   /* Points to the client's cert chain */
   X509 *cert;                  /* Points to the client's cert */
   int depth;                   /* Depth of cert chain */
   size_t len,len2;             /* Lengths of issuer and cert DN */
   int IsCA;                    /* Holds whether cert is allowed to sign */
   int prevIsCA;                /* Holds whether previous cert in chain is 
                                   allowed to sign */
   int prevIsLimited;		/* previous cert was proxy and limited */
   int i,j;                     /* Iteration variables */
   char *cert_DN;               /* Pointer to current-certificate-in-chain's 
                                   DN */
   char *issuer_DN;             /* Pointer to 
                                   issuer-of-current-cert-in-chain's DN */
   char *proxy_part_DN;         /* Pointer to end part of current-cert-in-chain
                                   maybe eg "/CN=proxy" */
   time_t now;
   
   time(&now);

   *first_non_ca = 0; /* set to something predictable if things fail */

   /* Check for context */
   if (!ctx) return X509_V_ERR_INVALID_CA; 
     /* Can't GSI-verify if there is no context. Here and throughout this
        function we report all errors as X509_V_ERR_INVALID_CA. */
 
   /* Set necessary preliminary values */
   IsCA          = TRUE;           /* =prevIsCA - start from a CA */
   prevIsLimited = 0;
 
   /* Get the client cert chain */
   certstack = X509_STORE_CTX_get_chain(ctx);     /* Get the client's chain  */
   depth     = sk_X509_num(certstack);            /* How deep is that chain? */
 
   /* Check the client chain */
   for (i=depth-1; i >= 0; --i) 
      /* loop through client-presented chain starting at CA end */
      {
        prevIsCA=IsCA;

        /* Check for X509 certificate and point to it with 'cert' */
        if (cert = sk_X509_value(certstack, i))
          {
            /* we check times and reject immediately if invalid */
          
            if (now <
                GRSTasn1TimeToTimeT(ASN1_STRING_data(X509_get_notBefore(cert))))
                  return X509_V_ERR_INVALID_CA;
                
            if (now > 
                GRSTasn1TimeToTimeT(ASN1_STRING_data(X509_get_notAfter(cert))))
                  return X509_V_ERR_INVALID_CA;

            /* If any forebear certificate is not allowed to sign we must 
               assume all decendents are proxies and cannot sign either */
            if (prevIsCA)
              {
                /* always treat the first cert (from the CA files) as a CA */
                if (i == depth-1) IsCA = TRUE;
                /* check if this cert is valid CA for signing certs */
                else IsCA = (GRSTx509IsCA(cert) == GRST_RET_OK);
                
                if (!IsCA) *first_non_ca = i;
              } 
            else 
              {
                IsCA = FALSE; 
                /* Force proxy check next iteration. Important because I can
                   sign any CA I create! */
              }
 
            cert_DN   = X509_NAME_oneline(X509_get_subject_name(cert),NULL,0);
            issuer_DN = X509_NAME_oneline(X509_get_issuer_name(cert),NULL,0);
            len       = strlen(cert_DN);
            len2      = strlen(issuer_DN);

            /* issuer didn't have CA status, so this is (at best) a proxy:
               check for bad proxy extension*/

            if (!prevIsCA)
              {
                if (prevIsLimited) /* we reject proxies of limited proxies! */
                                return X509_V_ERR_INVALID_CA;
              
                /* User not allowed to sign shortened DN */
                if (len2 > len) return X509_V_ERR_INVALID_CA;                           
                  
                /* Proxy subject must begin with issuer. */
                if (strncmp(cert_DN, issuer_DN, len2) != 0) 
                              return X509_V_ERR_INVALID_CA;

                /* Set pointer to end of base DN in cert_DN */
                proxy_part_DN = &cert_DN[len2];

                /* First attempt at support for Old and New style GSI
                   proxies: /CN=anything is ok for now */
                if (strncmp(proxy_part_DN, "/CN=", 4) != 0)
                                         return X509_V_ERR_INVALID_CA;
                                         
                if ((strncmp(proxy_part_DN, "/CN=limited proxy", 17) == 0) &&
                    (i > 0)) prevIsLimited = 1; /* ready for next cert ... */
              } 
          }
      }

   /* Check cert whose private key is being used by client. If previous in 
      chain is not allowed to be a CA then need to check this final cert for 
      valid proxy-icity too */
   if (!prevIsCA) 
     { 
       if (prevIsLimited) return X509_V_ERR_INVALID_CA;
        /* we do not accept proxies signed by limited proxies */
     
       if (cert = sk_X509_value(certstack, 0)) 
         {
           /* Load DN & length of DN and either its issuer or the
              first-bad-issuer-in-chain */
           cert_DN = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
           issuer_DN = X509_NAME_oneline(X509_get_issuer_name(cert),  NULL, 0);
           len = strlen(cert_DN);
           len2 = strlen(issuer_DN);
 
           /* issuer didn't have CA status, check for bad proxy extension */

           if (len2 > len) return X509_V_ERR_INVALID_CA;
             /* User not allowed to sign shortened DN */

           if (strncmp(cert_DN, issuer_DN, len2) != 0) 
                           return X509_V_ERR_INVALID_CA;
             /* Proxy subject must begin with issuer. */

           proxy_part_DN = &cert_DN[len2];                         
             /* Set pointer to end of DN base in cert_DN */
             
           /* Remander of subject must be either "/CN=proxy" or 
              "/CN=limited proxy" (or /CN=XYZ for New style GSI) */
              
           /* First attempt at support for Old and New style GSI
              proxies: /CN=anything is ok for now. */
           if (strncmp(proxy_part_DN, "/CN=", 4) != 0)
                                   return X509_V_ERR_INVALID_CA;
         }
     }
 
   return X509_V_OK; /* this is also GRST_RET_OK, of course - by choice */
}

/// Example VerifyCallback routine

/**
 *   
 */

int GRSTx509VerifyCallback (int ok, X509_STORE_CTX *ctx)
{
   int errnum   = X509_STORE_CTX_get_error(ctx);
   int errdepth = X509_STORE_CTX_get_error_depth(ctx);
   int first_non_ca;

#ifndef X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION
#define X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION 34
#endif

   if (errnum == X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION)
     {
       if (GRSTx509KnownCriticalExts(X509_STORE_CTX_get_current_cert(ctx))
           == GRST_RET_OK)
         {
           ok = TRUE;
           errnum = X509_V_OK;
           X509_STORE_CTX_set_error(ctx, errnum);
         }                               
     }
   else if ((errdepth == 0)       && 
            (errnum == X509_V_OK) && 
            (GRSTx509CheckChain(&first_non_ca, ctx) != X509_V_OK)) ok = FALSE;
   
   
   return ok;
  
// check this 
   
//   if (ok) return GRST_RET_OK;
//   else    return GRST_RET_FAILED;
}

/// Check VOMS signature
/** 
 *  Return GRST_RET_OK if signature starting at *sig matches *data and is 
 *  from VOMS *vo; return GRST_RET_FAILED otherwise.
 */
 
int GRSTx509CheckVomsSig(unsigned char *sig, unsigned int siglen, 
                         unsigned char *data, unsigned int datalen,
                         char *vomsdir, char *vo, char *vomsdn)
{
   int            ret = 0;
   char          *certfilename, *certdn;
   FILE          *fp;
   DIR           *vomsDIR;
   struct dirent *certdirent;
   X509          *cert;
   EVP_PKEY      *pubkey;
   EVP_MD_CTX     ctx;   
   struct stat    statbuf;
   time_t         now;
   
   time(&now);

   vomsDIR = opendir(vomsdir);
   if (vomsDIR == NULL) 
     {
       return GRST_RET_NO_SUCH_FILE;
     }

   while ((certdirent = readdir(vomsDIR)) != NULL)
        {
          certfilename = malloc(strlen(vomsdir) + 
                                strlen(certdirent->d_name) + 2);
                                
          strcpy(certfilename, vomsdir);
          strcat(certfilename, "/");
          strcat(certfilename, certdirent->d_name);
          
          if ((stat(certfilename, &statbuf) != 0) || S_ISDIR(statbuf.st_mode))
            {
              free(certfilename);
              continue;
            }
          
          fp = fopen(certfilename, "r");
          free(certfilename);
          
          if (fp == NULL) continue;
                                  
          cert = PEM_read_X509(fp, NULL, NULL, NULL);
          fclose(fp);
          
          if (cert == NULL) continue;

          certdn = X509_NAME_oneline(X509_get_subject_name(cert),NULL,0);

          if ((now <
     GRSTasn1TimeToTimeT(ASN1_STRING_data(X509_get_notBefore(cert))) ) ||
              (now >
     GRSTasn1TimeToTimeT(ASN1_STRING_data(X509_get_notAfter( cert))) ) ||          
              (GRSTx509NameCmp(certdn, vomsdn) != 0))
            {
              X509_free(cert);
              continue;
            }
                    
          pubkey = X509_extract_key(cert);

          if (pubkey != NULL)
            {   
//              EVP_MD_CTX_init(&ctx);
              EVP_VerifyInit(&ctx, EVP_sha1());
              EVP_VerifyUpdate(&ctx, (unsigned char *) data, datalen);
     
              ret=EVP_VerifyFinal(&ctx, (unsigned char *) sig, siglen, pubkey);
                 
//              EVP_MD_CTX_cleanup(&ctx);
            }

          closedir(vomsDIR); /* we're finished now, one way or the other */

          X509_free(cert);

          /* since we matched cert names and times, we always return */

          if (ret == 1) return GRST_RET_OK;
          else          return GRST_RET_BAD_SIGNATURE;
        }

   closedir(vomsDIR);

   return GRST_RET_CERT_NOT_FOUND; /* didnt find a matching VOMS cert */
}

/// Get the VOMS attributes in the extensions to the given cert
/*
 *  Puts any VOMS credentials found into the Compact Creds string array
 *  starting at *creds. Always returns GRST_RET_OK.
 */

int GRSTx509GetVomsCreds(int *lastcred, int maxcreds, size_t credlen, 
                         char *creds, X509 *cert, X509 *usercert, 
                         char *vomsdir)
{
   int  i, j;   
   unsigned int siglen=-1, datalength=-1, dataoffset = -1;
   char s[80];
   unsigned char *charstr, *p, *time1 = NULL, *time2 = NULL, *vo = NULL,
                 *uri = NULL, *user = NULL, *group = "NULL", *role = "NULL", 
                 *cap = "NULL", *server = NULL, *ucuser, *signature = NULL,
                 *data = NULL, *datalen = NULL;
   X509_EXTENSION *ex;
   ASN1_STRING    *asn1str;
   time_t          now, time1_time = 0, time2_time = 0, 
                   uctime1_time, uctime2_time;

   time(&now);

   uctime1_time = 
        GRSTasn1TimeToTimeT(ASN1_STRING_data(X509_get_notBefore(usercert)));
   uctime2_time =       
        GRSTasn1TimeToTimeT(ASN1_STRING_data(X509_get_notAfter(usercert)));
   ucuser =
        X509_NAME_oneline(X509_get_subject_name(usercert), NULL, 0);

   for (i = 0; i < X509_get_ext_count(cert); ++i)
      {
        ex = X509_get_ext(cert, i);
        
        OBJ_obj2txt(s, sizeof(s), X509_EXTENSION_get_object(ex), 1);

        if (strcmp(s, GRST_VOMS_OID) == 0) /* a VOMS extension */
          {
            asn1str = X509_EXTENSION_get_data(ex);
            charstr = (char *) malloc(ASN1_STRING_length(asn1str) + 1);
            memcpy(charstr, ASN1_STRING_data(asn1str), 
                            ASN1_STRING_length(asn1str));
            charstr[ASN1_STRING_length(asn1str)] = '\0';

            siglen = -1;
            
            if ((sscanf(charstr, "SIGLEN:%u", &siglen) != 1) ||
                (siglen == -1) ||
                ((p = index(charstr, '\n')) == NULL))
              {
                free(charstr);
                continue;
              }
                            
            ++p;

            if (strncmp(p, "SIGNATURE:", sizeof("SIGNATURE:") - 1) != 0)
              {
                free(charstr);
                continue;
              }

            signature = &p[sizeof("SIGNATURE:") - 1];
            
            p = &p[siglen + sizeof("SIGNATURE:") - 1];
            data = p;

            /* nasty pointer arithmetic! */
            dataoffset = (unsigned int) ((long) data - (long) charstr);
            datalength = (unsigned int) 
                            (ASN1_STRING_length(asn1str) - dataoffset);

            if (datalength <= 0)
              {
                free(charstr);
                continue;
              }

            while (1)
             {
               if (strncmp(p, "USER:", sizeof("USER:") - 1) == 0)
                 {
                   p = &p[sizeof("USER:") - 1];
                   while ((*p != '\n') && (*p != '\0') && (*p <= ' ')) ++p;
                   user = p;   
                   p = index(p, '\n');
                   if (p == NULL) break;
                   *p = '\0';
                   ++p;
                 }
               else if (strncmp(p, "TIME1:", sizeof("TIME1:") - 1) == 0)
                 {
                   p = &p[sizeof("TIME1:") - 1];
                   while ((*p != '\n') && (*p != '\0') && (*p <= ' ')) ++p;
                   time1 = p;                
                   p = index(p, '\n');
                   if (p != NULL) *p = '\0';
                  
                   time1_time = GRSTasn1TimeToTimeT(time1);                   
                   if (time1_time < uctime1_time) time1_time = uctime1_time;
                   if (p == NULL) break;
                   ++p;
                 }
               else if (strncmp(p, "TIME2:", sizeof("TIME2:") - 1) == 0)
                 {
                   p = &p[sizeof("TIME2:") - 1];
                   while ((*p != '\n') && (*p != '\0') && (*p <= ' ')) ++p;
                   time2 = p;
                   p = index(p, '\n');
                   if (p != NULL) *p = '\0';

                   time2_time = GRSTasn1TimeToTimeT(time2); 
                   if (time2_time > uctime2_time) time2_time = uctime2_time;
                   if (p == NULL) break;
                   ++p;
                 }
               else if (strncmp(p, "VO:", sizeof("VO:") - 1) == 0)
                 {
                   p = &p[sizeof("VO:") - 1];
                   while ((*p != '\n') && (*p != '\0') && (*p <= ' ')) ++p;
                   vo = p;
                
                   p = index(p, '\n');
                   if (p == NULL) break;
                   *p = '\0';
                   ++p;
                 }
               else if (strncmp(p, "SERVER:", sizeof("SERVER:") - 1) == 0)
                 {
                   p = &p[sizeof("SERVER:") - 1];
                   while ((*p != '\n') && (*p != '\0') && (*p <= ' ')) ++p;
                   server = p;

                   p = index(p, '\n');
                   if (p == NULL) break;
                   *p = '\0';
                   ++p;
                 }
               else if (strncmp(p, "DATALEN:", sizeof("DATALEN:") - 1) == 0)
                 {
                   p = &p[sizeof("DATALEN:") - 1];
                   while ((*p != '\n') && (*p != '\0') && (*p <= ' ')) ++p;
                   datalen = p;                
                   p = index(p, '\n');
                   if (p == NULL) break; 
                   *p = '\0';
                   ++p;
                   break;
                 }
               else /* not something we use */
                 {
                   p = index(p, '\n');
                   if (p == NULL) break;
                   *p = '\0';
                   ++p;
                 }
             }
             
            if (
                (now >= time1_time) &&
                (now <= time2_time) &&
                (signature != NULL) &&
                (data != NULL) &&
                (siglen > 0) &&
                (user != NULL) &&
                (ucuser != NULL) &&
                (strcmp(user, ucuser) == 0) &&
                (GRSTx509CheckVomsSig(signature, siglen, 
                                    &((ASN1_STRING_data(asn1str))[dataoffset]),
                                    datalength, vomsdir, vo, 
                                    server) == GRST_RET_OK)) while (1)
             {
               if (strncmp(p, "GROUP:", sizeof("GROUP:") - 1) == 0)
                 {
                   p = &p[sizeof("GROUP:") - 1];
                   while ((*p != '\n') && (*p != '\0') && (*p <= ' ')) ++p;
                   group = p;
                   role = "NULL";
                   cap = "NULL";

                   p = index(p, '\n');
                   if (p == NULL) break;
                   *p = '\0';
                   ++p;
                 }
               else if (strncmp(p, "ROLE:", sizeof("ROLE:") - 1) == 0)
                 {
                   p = &p[sizeof("ROLE:") - 1];
                   while ((*p != '\n') && (*p != '\0') && (*p <= ' ')) ++p;
                   role = p;

                   p = index(p, '\n');
                   if (p == NULL) break;
                   *p = '\0';
                   ++p;
                 }
               else if (strncmp(p, "CAP:", sizeof("CAP:") - 1) == 0)
                 {
                   p = &p[sizeof("CAP:") - 1];
                   while ((*p != '\n') && (*p != '\0') && (*p <= ' ')) ++p;
                   cap = p;

                   p = index(p, '\n');
                   if (p != NULL) *p = '\0';

                   if (*lastcred < maxcreds - 1)
                     {
                       ++(*lastcred);

                       if ((strcmp(role, "NULL") == 0) &&
                           (strcmp(cap , "NULL") == 0))                       
                         snprintf(&creds[*lastcred * (credlen + 1)], credlen+1,
                           "VOMS %010lu %010lu 0 /%s%s", 
                           time1_time, time2_time, vo, group);
                       else if ((strcmp(role, "NULL") != 0) &&
                                (strcmp(cap , "NULL") == 0))  
                         snprintf(&creds[*lastcred * (credlen + 1)], credlen+1,
                           "VOMS %010lu %010lu 0 /%s%s/Role=%s", 
                           time1_time, time2_time, vo, group, role);
                       else if ((strcmp(role, "NULL") == 0) &&
                                (strcmp(cap , "NULL") != 0))     
                         snprintf(&creds[*lastcred * (credlen + 1)], credlen+1,
                           "VOMS %010lu %010lu 0 /%s%s/Capability=%s", 
                           time1_time, time2_time, vo, group, cap);
                       else 
                         snprintf(&creds[*lastcred * (credlen + 1)], credlen+1,
                           "VOMS %010lu %010lu 0 /%s%s/Role=%s/Capability=%s", 
                           time1_time, time2_time, vo, group, role, cap);
                     }
                      
                   if (p == NULL) break;
                   ++p;
                 }
               else /* not something we use */
                 {
                   p = index(p, '\n');
                   if (p == NULL) break;
                   *p = '\0';
                   ++p;
                 }
             }
             
            free(charstr); 
          }
      }

   return GRST_RET_OK;
}

/// Turn a Compact Cred line into a GRSTgaclCred object
/**
 *  Returns pointer to created GRSTgaclCred or NULL or failure.
 */
 
GRSTgaclCred *GRSTx509CompactToCred(char *grst_cred)
{
   int       delegation;
   char     *p;
   time_t    now, notbefore, notafter;
   GRSTgaclCred *cred = NULL;

   time(&now);

   if (grst_cred == NULL) return NULL; /* just in case */

   if (strncmp(grst_cred, "X509USER ", 9) == 0)
     {
       if ((sscanf(grst_cred, "X509USER %lu %lu %d", 
                              &notbefore, &notafter, &delegation) == 3)
            && (now >= notbefore)
            && (now <= notafter)
            && (p = index(grst_cred, ' '))
            && (p = index(++p, ' '))
            && (p = index(++p, ' '))
            && (p = index(++p, ' ')))
         {
           cred = GRSTgaclCredNew("person");
           GRSTgaclCredSetDelegation(cred, delegation);
           GRSTgaclCredAddValue(cred, "dn", &p[1]);
         }

       return cred;
     }

   if (strncmp(grst_cred, "VOMS ", 5) == 0)
     {
       if ((sscanf(grst_cred, "VOMS %lu %lu", 
                              &notbefore, &notafter, &delegation) == 3)
            && (now >= notbefore)
            && (now <= notafter)
            && (p = index(grst_cred, ' '))
            && (p = index(++p, ' '))
            && (p = index(++p, ' '))
            && (p = index(++p, ' ')))
         {
           /* include /VO/group/subgroup/Role=role/Capability=cap */

           if (*p != '/') return NULL; /* must begin with / */

           cred = GRSTgaclCredNew("voms");
           GRSTgaclCredSetDelegation(cred, delegation);
           GRSTgaclCredAddValue(cred, "fqan", p);
         }

       return cred;
     }

   return NULL; /* dont recognise this credential type */
}

/// Get the credentials in an X509 cert/GSI proxy, including any VOMS
/**
 *  Credentials are placed in Compact Creds string array at *creds.
 * 
 *  Function returns GRST_RET_OK on success, or GRST_RET_FAILED if
 *  some inconsistency found in certificate.
 */
 
int GRSTx509CompactCreds(int *lastcred, int maxcreds, size_t credlen, 
                         char *creds, STACK_OF(X509) *certstack, char *vomsdir)
{   
   int   i, j, delegation = 0;
   char  credtemp[credlen+1];
   X509 *cert, *usercert = NULL, *gsiproxycert = NULL;

   *lastcred = -1;

   for (i = sk_X509_num(certstack) - 1; i >= 0; --i) 
      {
         cert = sk_X509_value(certstack, i);

         if (usercert != NULL) 
           {           /* found a (GSI proxy) cert after the user cert */
             gsiproxycert = cert;
             ++delegation;
           }
           
         if ((usercert == NULL) && 
             (i < sk_X509_num(certstack) - 1) &&
             (GRSTx509IsCA(cert) != GRST_RET_OK)) usercert = cert;
                                          /* found the 1st non-CA cert */
      }

   if ((usercert == NULL) /* if no usercert ("EEC"), we're not interested */
       ||
       (snprintf(credtemp, credlen+1, "X509USER %010lu %010lu %d %s",
          GRSTasn1TimeToTimeT(ASN1_STRING_data(X509_get_notBefore(usercert))), 
          GRSTasn1TimeToTimeT(ASN1_STRING_data(X509_get_notAfter(usercert))),
          delegation,
     X509_NAME_oneline(X509_get_subject_name(usercert), NULL, 0)) >= credlen+1)
       || 
       (*lastcred >= maxcreds-1))
     {
       *lastcred = -1;  /* just in case the caller looks at it */
       return GRST_RET_FAILED; /* tell caller that things didn't work out */
     }

   ++(*lastcred);
   strcpy(&creds[*lastcred * (credlen + 1)], credtemp);

   if ((gsiproxycert != NULL) 
       &&
       (snprintf(credtemp, credlen+1, "GSIPROXY %010lu %010lu %d %s",
     GRSTasn1TimeToTimeT(ASN1_STRING_data(X509_get_notBefore(gsiproxycert))), 
     GRSTasn1TimeToTimeT(ASN1_STRING_data(X509_get_notAfter(gsiproxycert))),
     delegation,
  X509_NAME_oneline(X509_get_subject_name(gsiproxycert), NULL, 0)) < credlen+1)
       &&
       (*lastcred < maxcreds-1))
     {
       ++(*lastcred);
       strcpy(&creds[*lastcred * (credlen + 1)], credtemp);
       
       GRSTx509GetVomsCreds(lastcred, maxcreds, credlen, creds, 
                            gsiproxycert, usercert, vomsdir);
     }
         
   return GRST_RET_OK;
}
