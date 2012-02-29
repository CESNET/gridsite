/*
   Copyright (c) 2002-10, Andrew McNab, University of Manchester
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

   ---------------------------------------------------------------
    For more information about GridSite: http://www.gridsite.org/
   ---------------------------------------------------------------
*/ 

#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>       
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <stdarg.h>
#include <dirent.h>
#include <string.h>
#include <pwd.h>
#include <errno.h>
#include <getopt.h>

#include <sys/types.h>
#include <sys/stat.h>

#ifndef GRST_NO_OPENSSL
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bio.h>    
#include <openssl/des.h>    
#include <openssl/rand.h>
#endif

#include "gridsite.h"

#define GRST_KEYSIZE		512
#define GRST_PROXYCACHE		"/../proxycache/"
#define GRST_MAX_CHAIN_LEN	9
#define GRST_BACKDATE_SECONDS	300

/// Compare X509 Distinguished Name strings
int GRSTx509NameCmp(char *a, char *b)
///
/// This function attempts to do with string representations what
/// would ideally be done with OIDs/values. In particular, we equate
/// "/Email=" == "/emailAddress=" to deal with this important change
/// between OpenSSL 0.9.6 and 0.9.7. 
/// Other than that, it is currently the same as ordinary strcasecmp(3)
/// (for consistency with EDG/LCG/EGEE gridmapdir case insensitivity.)
{
   int   ret;
   char *aa, *bb, *p;

   if ((a == NULL) || (b == NULL)) return 1; /* NULL never matches */

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

   ret = strcasecmp(aa, bb);

   free(aa);
   free(bb);
                                                                                
   return ret;
}


/// Check critical extensions
int GRSTx509KnownCriticalExts(X509 *cert)
///
/// Returning GRST_RET_OK if all of extensions are known to us or 
/// OpenSSL; GRST_REF_FAILED otherwise.   
///
/// Since this function relies on functionality (X509_supported_extension)
/// introduced in 0.9.7, then we do nothing and report an error 
/// (GRST_RET_FAILED) if one of the associated defines 
/// (X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION) is absent.
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

            if ((strcmp(s, GRST_PROXYCERTINFO_OID)     != 0) &&
                (strcmp(s, GRST_PROXYCERTINFO_OLD_OID) != 0))
              return GRST_RET_FAILED;
          }
      }

   return GRST_RET_OK;
#else
   return GRST_RET_FAILED;
#endif
}

/// Check if certificate can be used as a CA to sign standard X509 certs
int GRSTx509IsCA(X509 *cert)
///
/// Return GRST_RET_OK if true; GRST_RET_FAILED if not.
{
   int idret, purpose_id;

   purpose_id = X509_PURPOSE_get_by_sname("sslclient");

   /* final argument to X509_check_purpose() is whether to check for CAness */   

   if (X509_check_purpose(cert, purpose_id + X509_PURPOSE_MIN, 1))
        return GRST_RET_OK;
   else return GRST_RET_FAILED;
}   

int GRSTx509ChainFree(GRSTx509Chain *chain)
{
   GRSTx509Cert *grst_cert, *next_grst_cert;

   if (chain == NULL) return GRST_RET_OK;

   next_grst_cert = chain->firstcert; 
   
   while (next_grst_cert != NULL)
      {
        grst_cert = next_grst_cert;
        
        if (grst_cert->issuer != NULL) free(grst_cert->issuer);
        if (grst_cert->dn     != NULL) free(grst_cert->dn);
        if (grst_cert->value  != NULL) free(grst_cert->value);
        if (grst_cert->ocsp   != NULL) free(grst_cert->ocsp);
        
        next_grst_cert = grst_cert->next;
        free(grst_cert);        
      }
   
   free(chain);

   return GRST_RET_OK;
}

/// Check a specific signature against a specific (VOMS) cert
static int GRSTx509VerifySig(time_t *time1_time, time_t *time2_time,
                             unsigned char *txt, int txt_len,
                             unsigned char *sig, int sig_len, 
                             X509 *cert, EVP_MD *md_type)
///
/// Returns GRST_RET_OK if signature is ok, other values if not.
{   
   int            ret;
   EVP_PKEY      *prvkey;
   EVP_MD_CTX     ctx;
   time_t         voms_service_time1, voms_service_time2;

   prvkey = X509_extract_key(cert);
   if (prvkey == NULL) return GRST_RET_FAILED;
            
   OpenSSL_add_all_digests();
#if OPENSSL_VERSION_NUMBER >= 0x0090701fL
   EVP_MD_CTX_init(&ctx);
   EVP_VerifyInit_ex(&ctx, md_type, NULL);
#else
   EVP_VerifyInit(&ctx, md_type);
#endif
          
   EVP_VerifyUpdate(&ctx, txt, txt_len);

   ret = EVP_VerifyFinal(&ctx, sig, sig_len, prvkey);

#if OPENSSL_VERSION_NUMBER >= 0x0090701fL
   EVP_MD_CTX_cleanup(&ctx);      
#endif
   EVP_PKEY_free(prvkey);

   if (ret != 1) return GRST_RET_FAILED;

   voms_service_time1 = 
           GRSTasn1TimeToTimeT(ASN1_STRING_data(X509_get_notBefore(cert)),0);
          if (voms_service_time1 > *time1_time) 
                             *time1_time = voms_service_time1; 
           
   voms_service_time2 = 
           GRSTasn1TimeToTimeT(ASN1_STRING_data(X509_get_notAfter(cert)),0);
          if (voms_service_time2 < *time1_time) 
                             *time2_time = voms_service_time2; 
            
   return GRST_RET_OK ; /* verified */
}

/// Check the signature of the VOMS attributes
static int GRSTx509VerifyVomsSig(time_t *time1_time, time_t *time2_time,
                                 unsigned char *asn1string, 
                                 struct GRSTasn1TagList taglist[], 
                                 int lasttag,
                                 char *vomsdir, int acnumber)
///
/// Returns GRST_RET_OK if signature is ok, other values if not.
{   
#define GRST_ASN1_COORDS_VOMS_DN   "-1-1-%d-1-3-1-1-1-%%d-1-%%d"
#define GRST_ASN1_COORDS_VOMS_INFO "-1-1-%d-1"
#define GRST_ASN1_COORDS_VOMS_HASH "-1-1-%d-2-1"
#define GRST_ASN1_COORDS_VOMS_SIG  "-1-1-%d-3"
   int            ret, ihash, isig, iinfo;
   char          *certpath, *certpath2, acvomsdn[200], dn_coords[200],
                  info_coords[200], sig_coords[200], hash_coords[200],
                 *p;
   unsigned char *q;
   DIR           *vomsDIR, *vomsDIR2;
   struct dirent *vomsdirent, *vomsdirent2;
   X509          *cert;
   EVP_PKEY      *prvkey;
   FILE          *fp;
   EVP_MD_CTX     ctx;
   EVP_MD	 *md_type = NULL;
   struct stat    statbuf;
   time_t         voms_service_time1 = GRST_MAX_TIME_T, voms_service_time2 = 0,
                  tmp_time1, tmp_time2;
   ASN1_OBJECT   *hash_obj = NULL;

   if ((vomsdir == NULL) || (vomsdir[0] == '\0')) return GRST_RET_FAILED;

   snprintf(dn_coords, sizeof(dn_coords), 
            GRST_ASN1_COORDS_VOMS_DN, acnumber);
   
   if (GRSTasn1GetX509Name(acvomsdn, sizeof(acvomsdn), dn_coords,
         asn1string, taglist, lasttag) != GRST_RET_OK) return GRST_RET_FAILED;
         
   snprintf(info_coords, sizeof(info_coords), 
            GRST_ASN1_COORDS_VOMS_INFO, acnumber);
   iinfo = GRSTasn1SearchTaglist(taglist, lasttag, info_coords);

   snprintf(hash_coords, sizeof(hash_coords), 
            GRST_ASN1_COORDS_VOMS_HASH, acnumber);
   ihash  = GRSTasn1SearchTaglist(taglist, lasttag, hash_coords);

   snprintf(sig_coords, sizeof(sig_coords), 
            GRST_ASN1_COORDS_VOMS_SIG, acnumber);
   isig  = GRSTasn1SearchTaglist(taglist, lasttag, sig_coords);

   if ((iinfo < 0) || (ihash < 0) || (isig < 0)) return GRST_RET_FAILED;
   
   /* determine hash algorithm's type */

   p = &asn1string[taglist[ihash].start];
   
   d2i_ASN1_OBJECT(&hash_obj, &p, 
                   taglist[ihash].length+taglist[ihash].headerlength);

   md_type = EVP_get_digestbyname(OBJ_nid2sn(OBJ_obj2nid(hash_obj)));
   
   if (md_type == NULL) return GRST_RET_FAILED;
   
   
   vomsDIR = opendir(vomsdir);
   if (vomsDIR == NULL) return GRST_RET_FAILED;
   
   while ((vomsdirent = readdir(vomsDIR)) != NULL)
        {        
          if (vomsdirent->d_name[0] == '.') continue;
        
          asprintf(&certpath, "%s/%s", vomsdir, vomsdirent->d_name);
          stat(certpath, &statbuf);
          
          if (S_ISDIR(statbuf.st_mode))
            {
              vomsDIR2 = opendir(certpath);
              GRSTerrorLog(GRST_LOG_DEBUG, 
                           "Descend VOMS subdirectory %s", certpath);
              free(certpath);
              
              if (vomsDIR2 == NULL) continue;

              while ((vomsdirent2 = readdir(vomsDIR2)) != NULL)
                {
                  if (vomsdirent2->d_name[0] == '.') continue;
                  
                  asprintf(&certpath2, "%s/%s/%s", 
                           vomsdir, vomsdirent->d_name, vomsdirent2->d_name);
                
                  fp = fopen(certpath2, "r");
                  GRSTerrorLog(GRST_LOG_DEBUG, 
                               "Examine VOMS cert %s", certpath2);
                  free(certpath2);
                  if (fp == NULL) continue;

                  cert = PEM_read_X509(fp, NULL, NULL, NULL);
                  fclose(fp);
                  if (cert == NULL) continue;

                  tmp_time1 = 0;
                  tmp_time2 = GRST_MAX_TIME_T;

                  if (GRSTx509VerifySig(&tmp_time1, &tmp_time2,
                            &asn1string[taglist[iinfo].start], 
                            taglist[iinfo].length+taglist[iinfo].headerlength,
                            &asn1string[taglist[isig].start+
                                                taglist[isig].headerlength+1],
                            taglist[isig].length - 1,
                            cert, md_type) == GRST_RET_OK)
                    {
                      GRSTerrorLog(GRST_LOG_DEBUG, "Matched VOMS cert file %s", vomsdirent2->d_name);

                      /* Store more permissive time ranges for now */

                      if (tmp_time1 < voms_service_time1) 
                                         voms_service_time1 = tmp_time1;
                        
                      if (tmp_time2 > voms_service_time2)
                                         voms_service_time2 = tmp_time2;                        
                    }
            
                  X509_free(cert);
                }
                
              closedir(vomsDIR2);
            }
          else
            {
              fp = fopen(certpath, "r");
              GRSTerrorLog(GRST_LOG_DEBUG, "Examine VOMS cert %s", certpath);
              free(certpath);
              if (fp == NULL) continue;

              cert = PEM_read_X509(fp, NULL, NULL, NULL);
              fclose(fp);
              if (cert == NULL) continue;

              tmp_time1 = 0;
              tmp_time2 = GRST_MAX_TIME_T;

              if (GRSTx509VerifySig(&tmp_time1, &tmp_time2,
                            &asn1string[taglist[iinfo].start], 
                            taglist[iinfo].length+taglist[iinfo].headerlength,
                            &asn1string[taglist[isig].start+
                                                taglist[isig].headerlength+1],
                            taglist[isig].length - 1,
                            cert, md_type) == GRST_RET_OK)
                {
                  GRSTerrorLog(GRST_LOG_DEBUG, "Matched VOMS cert file %s", vomsdirent->d_name);

                  /* Store more permissive time ranges for now */

                  if (tmp_time1 < voms_service_time1) 
                                         voms_service_time1 = tmp_time1;
                        
                  if (tmp_time2 > voms_service_time2)
                                         voms_service_time2 = tmp_time2;
                }
            
              X509_free(cert);
            }
        }

   closedir(vomsDIR);   
   
   if ((voms_service_time1 == GRST_MAX_TIME_T) || (voms_service_time2 == 0))
     return GRST_RET_FAILED;

   /* now we tighten up the VOMS AC time range using the most permissive
      pair of VOMS certificate ranges (in case of multiple, possibly 
      overlapping, matching certificates in the VOMS certs store) */
     
   if (voms_service_time1 > *time1_time) *time1_time = voms_service_time1;
     
   if (voms_service_time2 < *time2_time) *time2_time = voms_service_time2;
     
   return GRST_RET_OK;
}

/// Check the signature of the VOMS attributes using the LSC file cert
static int GRSTx509VerifyVomsSigCert(time_t *time1_time, time_t *time2_time,
                                     unsigned char *asn1string, 
                                     struct GRSTasn1TagList taglist[], 
                                     int lasttag,
                                     char *vomsdir, int acnumber,
                                     int ivomscert,
                                     char *capath,
                                     char *acvomsdn,
                                     char *voname)
///
/// Returns GRST_RET_OK if signature is ok, other values if not.
{
#define GRST_ASN1_COORDS_VOMS_DN   "-1-1-%d-1-3-1-1-1-%%d-1-%%d"
#define GRST_ASN1_COORDS_VOMS_INFO "-1-1-%d-1"
#define GRST_ASN1_COORDS_VOMS_SIG  "-1-1-%d-3"
   int            ret, isig, iinfo, chain_errors = GRST_RET_OK,
                  cadn_len, vomsdn_len, lsc_found = 0, ihash;
   char          *lscpath, dn_coords[200],
                  info_coords[200], sig_coords[200], *p, *cacertpath,
                 *vodir, *vomscert_cadn, *vomscert_vomsdn, 
                 *lsc_cadn, *lsc_vomsdn;
   unsigned char *q;
   unsigned long  issuerhash = 0;
   DIR           *voDIR;
   struct dirent *vodirent;
   X509          *cacert = NULL, *vomscert = NULL;
   EVP_PKEY      *prvkey;
   FILE          *fp;
   EVP_MD_CTX     ctx;
   struct stat    statbuf;
   time_t         tmp_time;
   ASN1_OBJECT   *hash_obj = NULL;
   char		  coords[200];
   EVP_MD        *md_type = NULL;
   time_t	  voms_service_time1, voms_service_time2;

   if ((vomsdir == NULL) || (vomsdir[0] == '\0')) return GRST_RET_FAILED;

   q = &asn1string[taglist[ivomscert].start + 12];

   vomscert = d2i_X509(NULL, (const unsigned char **) &q, 
                       taglist[ivomscert].length - 8);

   if (vomscert == NULL) 
     {
       GRSTerrorLog(GRST_LOG_DEBUG, "Failed to read included VOMS cert in GRSTx509VerifyVomsSigCert()");
       return GRST_RET_FAILED;
     }

   GRSTerrorLog(GRST_LOG_DEBUG, "Found included VOMS cert in GRSTx509VerifyVomsSigCert()");

   snprintf(coords, sizeof(coords), GRST_ASN1_COORDS_VOMS_INFO, acnumber);
   iinfo = GRSTasn1SearchTaglist(taglist, lasttag, coords);

   snprintf(coords, sizeof(coords), GRST_ASN1_COORDS_VOMS_HASH, acnumber);
   ihash  = GRSTasn1SearchTaglist(taglist, lasttag, coords);

   snprintf(coords, sizeof(coords), GRST_ASN1_COORDS_VOMS_SIG, acnumber);
   isig  = GRSTasn1SearchTaglist(taglist, lasttag, coords);

   if ((iinfo < 0) || (ihash < 0) || (isig < 0)) return GRST_RET_FAILED;

   q = &asn1string[taglist[ihash].start];
   d2i_ASN1_OBJECT(&hash_obj, &q,
		   taglist[ihash].length+taglist[ihash].headerlength);

   md_type = EVP_get_digestbyname(OBJ_nid2sn(OBJ_obj2nid(hash_obj)));
   if (md_type == NULL) return GRST_RET_FAILED;

   /* check issuer CA certificate */

   issuerhash = X509_NAME_hash(X509_get_issuer_name(vomscert));
   asprintf(&cacertpath, "%s/%.8x.0", capath, issuerhash);

   /* check voms cert DN matches DN from AC */

   vomscert_vomsdn = X509_NAME_oneline(X509_get_subject_name(vomscert),NULL,0);

   if (GRSTx509NameCmp(vomscert_vomsdn, acvomsdn) != 0)
     {
       free(vomscert_vomsdn);
       
       GRSTerrorLog(GRST_LOG_DEBUG, "Included VOMS cert DN does not match AC issuer DN!");
       return GRST_RET_FAILED;     
     }

   free(vomscert_vomsdn);

   GRSTerrorLog(GRST_LOG_DEBUG, "Look for CA root file %s", cacertpath);

   fp = fopen(cacertpath, "r");
   free(cacertpath);

   if (fp == NULL) return GRST_RET_FAILED;
   else
     {
       cacert = PEM_read_X509(fp, NULL, NULL, NULL);
       fclose(fp);
       if (cacert != NULL) 
         {
           GRSTerrorLog(GRST_LOG_DEBUG, " Loaded CA root cert from file");
         }
       else
         {         
           GRSTerrorLog(GRST_LOG_DEBUG, " Failed to load CA root cert file");
           return GRST_RET_FAILED;
         }
     }
   
   /* check times CA cert times, and reject if necessary */

   tmp_time = GRSTasn1TimeToTimeT(
                   ASN1_STRING_data(X509_get_notBefore(cacert)), 0);
   if (tmp_time > *time1_time) chain_errors |= GRST_CERT_BAD_TIME;

   tmp_time = GRSTasn1TimeToTimeT(
                   ASN1_STRING_data(X509_get_notAfter(cacert)), 0);
   if (tmp_time < *time2_time) chain_errors |= GRST_CERT_BAD_TIME;
   
   /* check times VOMS cert times, and tighten if necessary */

   tmp_time = GRSTasn1TimeToTimeT(
                   ASN1_STRING_data(X509_get_notBefore(vomscert)), 0);
   if (tmp_time > *time1_time) chain_errors |= GRST_CERT_BAD_TIME;

   tmp_time = GRSTasn1TimeToTimeT(
                   ASN1_STRING_data(X509_get_notAfter(vomscert)), 0);
   if (tmp_time < *time2_time) chain_errors |= GRST_CERT_BAD_TIME;
   
   ret = X509_check_issued(cacert, vomscert);
   GRSTerrorLog(GRST_LOG_DEBUG, "X509_check_issued returns %d", ret);

   vomscert_cadn = X509_NAME_oneline(X509_get_issuer_name(vomscert),NULL,0);


   if (ret != X509_V_OK) return (chain_errors | GRST_CERT_BAD_SIG);

   asprintf(&vodir, "%s/%s", vomsdir, voname);
   
   voDIR = opendir(vodir);
   if (voDIR == NULL) return GRST_RET_FAILED;
   
   cadn_len   = strlen(vomscert_cadn);
   vomsdn_len = strlen(acvomsdn);
   
   lsc_cadn   = malloc(cadn_len   + 2);
   lsc_vomsdn = malloc(vomsdn_len + 2);
   
   while (((vodirent = readdir(voDIR)) != NULL) && !lsc_found)
        {        
          if (vodirent->d_name[0] == '.') continue;
          
          if (strlen(vodirent->d_name) < 5) continue;
          
          if (strcmp(&(vodirent->d_name[strlen(vodirent->d_name)-4]), ".lsc") != 0) continue;
        
          asprintf(&lscpath, "%s/%s", vodir, vodirent->d_name);
          stat(lscpath, &statbuf);

          GRSTerrorLog(GRST_LOG_DEBUG, "Check LSC file %s for %s,%s",
                       lscpath, acvomsdn, vomscert_cadn);

          if ((fp = fopen(lscpath, "r")) != NULL)
            {
              lsc_cadn[0]   = '\0';
              lsc_vomsdn[0] = '\0';
            
              if ((fgets(lsc_vomsdn, vomsdn_len + 2, fp) != NULL)
                  && (fgets(lsc_cadn, cadn_len + 2, fp) != NULL))
                {
                  if ((p = index(lsc_cadn, '\n')) != NULL) *p = '\0';

                  if ((p = index(lsc_vomsdn, '\n')) != NULL) *p = '\0';
                  
                  if ((GRSTx509NameCmp(lsc_cadn, vomscert_cadn) == 0) &&
                      (GRSTx509NameCmp(lsc_vomsdn, acvomsdn) == 0)) 
                    {
                      GRSTerrorLog(GRST_LOG_DEBUG, "Matched LSC file %s", lscpath);
                      lsc_found = 1;
                    }                      
                }
              
              fclose(fp);
            }

          free(lscpath);
        }

   closedir(voDIR);   
   free(vodir);
   free(vomscert_cadn);
   free(lsc_cadn);
   free(lsc_vomsdn);   
   
   if (!lsc_found) {
	chain_errors |= GRST_CERT_BAD_SIG;
	goto end;
   }

   ret = GRSTx509VerifySig(&voms_service_time1, &voms_service_time2,
		&asn1string[taglist[iinfo].start],
		taglist[iinfo].length+taglist[iinfo].headerlength,
		&asn1string[taglist[isig].start+
					taglist[isig].headerlength+1],
		taglist[isig].length - 1,
		vomscert, md_type);
   if (ret != GRST_RET_OK) {
	chain_errors |= GRST_CERT_BAD_SIG;
	goto end;
   }

   if (voms_service_time1 > *time1_time) *time1_time = voms_service_time1;
   if (voms_service_time2 < *time2_time) *time2_time = voms_service_time2;

end:
   if (cacert)
	X509_free(cacert);
   if (vomscert)
	X509_free(vomscert);

   return (chain_errors ? GRST_RET_FAILED : GRST_RET_OK);
}

/// Get the VOMS attributes in the given extension
static int GRSTx509ChainVomsAdd(GRSTx509Cert **grst_cert, 
                         time_t time1_time, time_t time2_time,
			 int delegation,
                         X509_EXTENSION *ex, 
                         GRSTx509Cert *user_cert, char *vomsdir, char *capath)
///
/// Add any VOMS credentials found into the chain. Always returns GRST_RET_OK
/// - even for invalid credentials, which are flagged in errors field
{
#define MAXTAG 500
#define GRST_ASN1_COORDS_FQAN          "-1-1-%d-1-7-1-2-1-2-%d"
#define GRST_ASN1_COORDS_ISSUER_DN     "-1-1-%d-1-2-1-1-1-1-%%d-1-%%d"
#define GRST_ASN1_COORDS_ISSUER_SERIAL "-1-1-%d-1-2-1-2"
#define GRST_ASN1_COORDS_VOMS_DN       "-1-1-%d-1-3-1-1-1-%%d-1-%%d"
#define GRST_ASN1_COORDS_TIME1         "-1-1-%d-1-6-1"
#define GRST_ASN1_COORDS_TIME2         "-1-1-%d-1-6-2"
#define GRST_ASN1_COORDS_VOMSCERT      "-1-1-%d-1-8-%%d-%%d"

   ASN1_OCTET_STRING *asn1data;
   char              *asn1string, acissuerdn[200], acvomsdn[200],
                      dn_coords[200], fqan_coords[200], time1_coords[200],
                      time2_coords[200], vomscert_coords[200], *voname = NULL,
                      serial_coords[200];
   long               asn1length;
   int                lasttag=-1, itag, i, j, acnumber = 1, chain_errors = 0,
                      ivomscert, tmp_chain_errors, ret;
   char              *acissuerserial = NULL;
   struct GRSTasn1TagList taglist[MAXTAG+1];
   time_t             actime1 = 0, actime2 = 0, time_now,
                      tmp_time1, tmp_time2;
   ASN1_INTEGER	      acissuerserialASN1;

   asn1data   = X509_EXTENSION_get_data(ex);
   asn1string = ASN1_STRING_data(asn1data);
   asn1length = ASN1_STRING_length(asn1data);

   GRSTasn1ParseDump(NULL, asn1string, asn1length, taglist, MAXTAG, &lasttag);

   for (acnumber = 1; ; ++acnumber) /* go through ACs one by one */
      {
        chain_errors = 0;
      
        snprintf(dn_coords, sizeof(dn_coords), GRST_ASN1_COORDS_ISSUER_DN, acnumber);
        if (GRSTasn1GetX509Name(acissuerdn, sizeof(acissuerdn), dn_coords,
                                asn1string, taglist, lasttag) != GRST_RET_OK)
                             break;

        snprintf(dn_coords, sizeof(dn_coords), GRST_ASN1_COORDS_VOMS_DN, acnumber);
        if (GRSTasn1GetX509Name(acvomsdn, sizeof(acvomsdn), dn_coords,
                                asn1string, taglist, lasttag) != GRST_RET_OK)
                             break;

        if ((GRSTx509NameCmp(user_cert->dn, acissuerdn) != 0) &&   /* old */
            (GRSTx509NameCmp(user_cert->issuer, acissuerdn) != 0)) /* new */
                             chain_errors |= GRST_CERT_BAD_CHAIN;

        /* check serial numbers */

        snprintf(serial_coords, sizeof(serial_coords), 
                 GRST_ASN1_COORDS_ISSUER_SERIAL, acnumber);

        itag = GRSTasn1SearchTaglist(taglist, lasttag, serial_coords);

        if (itag > -1) 
          {
            acissuerserialASN1.length = taglist[itag].length;
            acissuerserialASN1.type   = V_ASN1_INTEGER;
            acissuerserialASN1.data   = &asn1string[taglist[itag].start+taglist[itag].headerlength];

            acissuerserial = i2s_ASN1_INTEGER(NULL, &acissuerserialASN1);
/*
            p = &asn1string[taglist[itag].start+taglist[itag].headerlength];
          
            if (taglist[itag].length == 2)
             acissuerserial = p[1] + p[0] * 0x100;
            else if (taglist[itag].length == 3)
             acissuerserial = p[2] + p[1] * 0x100 + p[0] * 0x10000;
            else if (taglist[itag].length == 4)
             acissuerserial = p[3] + p[2] * 0x100 + p[1] * 0x10000 +
                              p[0] * 0x1000000;
*/
          }

        if (strcmp(acissuerserial, user_cert->serial) != 0)
                               chain_errors |= GRST_CERT_BAD_CHAIN;

        /* get times */

        snprintf(time1_coords, sizeof(time1_coords), GRST_ASN1_COORDS_TIME1, acnumber);
        itag = GRSTasn1SearchTaglist(taglist, lasttag, time1_coords);
        
        if (itag > -1) actime1 = GRSTasn1TimeToTimeT(
                                   &asn1string[taglist[itag].start+
                                               taglist[itag].headerlength],
                                   taglist[itag].length);
        else actime1 = 0;
        
        snprintf(time2_coords, sizeof(time2_coords), GRST_ASN1_COORDS_TIME2, acnumber);
        itag = GRSTasn1SearchTaglist(taglist, lasttag, time2_coords);
        
        if (itag > -1) actime2 = GRSTasn1TimeToTimeT(
                                   &asn1string[taglist[itag].start+
                                               taglist[itag].headerlength],
                                   taglist[itag].length);
        else actime2 = 0;
        
        if (actime1 > time1_time) time1_time = actime1;
        if (actime2 < time2_time) time2_time = actime2;

        time(&time_now);
        if ((time1_time > time_now + 300) || (time2_time < time_now))
               chain_errors |= GRST_CERT_BAD_TIME;

        /* get first FQAN and use to get VO name */

        snprintf(fqan_coords, sizeof(fqan_coords), GRST_ASN1_COORDS_FQAN, acnumber, 1);
        itag = GRSTasn1SearchTaglist(taglist, lasttag, fqan_coords);

        if ((itag > -1) && 
            (asn1string[taglist[itag].start+taglist[itag].headerlength] == '/'))
          {
            for (j=1; 
                 (asn1string[taglist[itag].start+taglist[itag].headerlength+j] != '/') && 
                 (j < taglist[itag].length);
                 ++j) ;
                               
            asprintf(&voname, "%.*s", j-1, 
                     &(asn1string[taglist[itag].start+taglist[itag].headerlength+1]));
          }

        snprintf(vomscert_coords, sizeof(vomscert_coords), 
                 GRST_ASN1_COORDS_VOMSCERT, acnumber);
	ret = GRSTasn1FindField(GRST_VOMS_PK_CERT_LIST_OID, vomscert_coords, asn1string,
				taglist, lasttag, &ivomscert);

        /* try using internal VOMS issuer cert */
        tmp_chain_errors = GRST_CERT_BAD_SIG;
        tmp_time1 = time1_time;
        tmp_time2 = time2_time;
        if ((ivomscert > -1) &&
            (voname != NULL) &&
            (GRSTx509VerifyVomsSigCert(&tmp_time1, &tmp_time2,
                      asn1string, taglist, lasttag, vomsdir, acnumber,
                      ivomscert, capath, acvomsdn, 
                      voname) == GRST_RET_OK)) 
          {          
            tmp_chain_errors = 0;
            time1_time = tmp_time1;
            time2_time = tmp_time2;
          }

        if (voname != NULL)
          {
            free(voname);
            voname = NULL;
          }

        if ((tmp_chain_errors != 0) &&
            (GRSTx509VerifyVomsSig(&time1_time, &time2_time,
                        asn1string, taglist, lasttag, vomsdir, acnumber)
                        != GRST_RET_OK))
                     chain_errors |= GRST_CERT_BAD_SIG;

        for (i=1; ; ++i) /* now go through FQANs */
           {
             snprintf(fqan_coords, sizeof(fqan_coords), GRST_ASN1_COORDS_FQAN, acnumber, i);
             itag = GRSTasn1SearchTaglist(taglist, lasttag, fqan_coords);

             if (itag > -1)
               {
                 (*grst_cert)->next = malloc(sizeof(GRSTx509Cert));
                 *grst_cert = (*grst_cert)->next;
                 bzero(*grst_cert, sizeof(GRSTx509Cert));
               
                 (*grst_cert)->notbefore = time1_time;
                 (*grst_cert)->notafter  = time2_time;
                 asprintf(&((*grst_cert)->value), "%.*s",
                          taglist[itag].length,
                          &asn1string[taglist[itag].start+
                                      taglist[itag].headerlength]);
                                      
                 (*grst_cert)->errors = chain_errors; /* ie may be invalid */
                 (*grst_cert)->type = GRST_CERT_TYPE_VOMS;
                 (*grst_cert)->issuer = strdup(acvomsdn);
                 (*grst_cert)->dn = strdup(user_cert->dn);
		 (*grst_cert)->delegation = delegation;
               }
             else break;
           }
      }
      
   return GRST_RET_OK;
}

/// Check certificate chain for GSI proxy acceptability.
int GRSTx509ChainLoadCheck(GRSTx509Chain **chain, 
                           STACK_OF(X509) *certstack, X509 *lastcert,
                           char *capath, char *vomsdir)
///
/// Returns GRST_RET_OK if valid; OpenSSL X509 errors otherwise.
///
/// The GridSite version handles old and new style Globus proxies, and
/// proxies derived from user certificates issued with "X509v3 Basic
/// Constraints: CA:FALSE" (eg UK e-Science CA)
///
/// TODO: we do not yet check ProxyCertInfo and ProxyCertPolicy extensions
///       (although via GRSTx509KnownCriticalExts() we can accept them.)
{
   X509 *cert;                  /* Points to the current cert in the loop */
   X509 *cacert = NULL;         /* The CA root cert */
   int depth = 0;               /* Depth of cert chain */
   int chain_errors = 0;	/* records previous errors */
   int first_non_ca;		/* number of the EEC issued to user by CA */
   size_t len,len2;             /* Lengths of issuer and cert DN */
   int IsCA;                    /* Holds whether cert is allowed to sign */
   int prevIsCA;                /* Holds whether previous cert in chain is 
                                   allowed to sign */
   int prevIsLimited;		/* previous cert was proxy and limited */
   int i,j,ret;                 /* Iteration/temp variables */
   char *proxy_part_DN;         /* Pointer to end part of current-cert-in-chain
                                   maybe eg "/CN=proxy" */
   char s[80], *p;
   char *cacertpath;
   unsigned long subjecthash = 0;	/* hash of the name of first cert */
   unsigned long issuerhash = 0;	/* hash of issuer name of first cert */
   FILE *fp;
   X509_EXTENSION *ex;
   time_t now;
   GRSTx509Cert *grst_cert, *new_grst_cert, *user_cert = NULL;
   
   GRSTerrorLog(GRST_LOG_DEBUG, "GRSTx509ChainLoadCheck() starts");

   time(&now);

   first_non_ca = 0; /* set to something predictable if things fail */
 
   /* Set necessary preliminary values */
   IsCA          = TRUE;           /* =prevIsCA - start from a CA */
   prevIsLimited = 0;
 
   /* Get the client cert chain */
   if (certstack != NULL) 
     depth = sk_X509_num(certstack); /* How deep is that chain? */
   
   if ((depth == 0) && (lastcert == NULL)) 
     {
       *chain = NULL;
       return GRST_RET_FAILED;
     }

   cert = sk_X509_value(certstack, depth - 1);
   subjecthash = X509_NAME_hash(X509_get_subject_name(cert));
   issuerhash = X509_NAME_hash(X509_get_issuer_name(cert));
   asprintf(&cacertpath, "%s/%.8x.0", capath, issuerhash);
   
   GRSTerrorLog(GRST_LOG_DEBUG, "Look for CA root file %s", cacertpath);

   fp = fopen(cacertpath, "r");
   free(cacertpath);

   if (fp == NULL) chain_errors |= GRST_CERT_BAD_CHAIN;
   else
     {
       cacert = PEM_read_X509(fp, NULL, NULL, NULL);
       fclose(fp);
       if (cacert != NULL) 
        GRSTerrorLog(GRST_LOG_DEBUG, " Loaded CA root cert from file");
       else
        GRSTerrorLog(GRST_LOG_DEBUG, " Failed to load CA root cert file");
     }

   *chain = malloc(sizeof(GRSTx509Chain));
   bzero(*chain, sizeof(GRSTx509Chain));
       
   /* Check the client chain */
   for (i = depth - ((subjecthash == issuerhash) ? 1 : 0);
        i >= ((lastcert == NULL) ? 0 : -1); 
        --i) 
      /* loop through client-presented chain starting at CA end */
      {
        GRSTerrorLog(GRST_LOG_DEBUG, "Process cert at depth %d in chain", i);

        prevIsCA=IsCA;

        new_grst_cert = malloc(sizeof(GRSTx509Cert));
        bzero(new_grst_cert, sizeof(GRSTx509Cert));
        new_grst_cert->errors = chain_errors;
        
        if ((*chain)->firstcert == NULL)
          {
            GRSTerrorLog(GRST_LOG_DEBUG, "Initialise chain");
            (*chain)->firstcert = new_grst_cert;
          }
        else grst_cert->next = new_grst_cert;

        grst_cert = new_grst_cert;

        /* Choose X509 certificate and point to it with 'cert' */
        if (i < 0) cert = lastcert;
        else if (i == depth)
             cert = cacert; /* the self-signed CA from the store*/
        else if ((i == depth - 1) && (subjecthash == issuerhash))
             cert = cacert; /* ie claims to be a copy of a self-signed CA */
        else cert = sk_X509_value(certstack, i);

        if (cert != NULL)
          {
            if ((i == depth - 1) && (subjecthash != issuerhash))
              {
                /* if first cert does not claim to be a self-signed copy 
                   of a CA root cert in the store, we check the signature */

                if (cacert == NULL)
                  {
                    chain_errors |= GRST_CERT_BAD_CHAIN;
                    ret = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT;
                  }
                else 
                  {
                    ret = X509_check_issued(cacert, cert);

                    GRSTerrorLog(GRST_LOG_DEBUG, 
                             "Cert sig check %d returns %d", i, ret);

                    if (ret != X509_V_OK) 
                             new_grst_cert->errors |= GRST_CERT_BAD_SIG;
                  }
              }
            else if ((i == depth - 2) && (subjecthash == issuerhash))
              {
                /* first cert claimed to be a self-signed copy of a CA root
                cert in the store, we check the signature of the second
                cert, using OUR copy of the CA cert DIRECT from the store */

                if (cacert == NULL)
                  {
                    chain_errors |= GRST_CERT_BAD_CHAIN;
                    ret = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT;
                  }
                else 
                  {
                    ret = X509_check_issued(cacert, cert);
                
                    GRSTerrorLog(GRST_LOG_DEBUG, 
                             "Cert sig check %d returns %d", i, ret);
                
                    if (ret != X509_V_OK)
                             new_grst_cert->errors |= GRST_CERT_BAD_SIG;
                  }
              }
            else if (i < depth - 1)
              {
                /* otherwise a normal part of the chain: note that if the
                   first cert claims to be a self-signed copy of a CA root
                   cert in the store, we never use it for sig checking */
              
                ret = X509_check_issued(sk_X509_value(certstack, i + 1), cert);
                
                GRSTerrorLog(GRST_LOG_DEBUG, 
                             "Cert sig check %d returns %d", i, ret);

                if ((ret != X509_V_OK) &&
                    (ret != X509_V_ERR_KEYUSAGE_NO_CERTSIGN))                
                          new_grst_cert->errors |= GRST_CERT_BAD_SIG;
                          
                /* NO_CERTSIGN can still be ok due to Proxy Certificates */
              }

            p = i2s_ASN1_INTEGER(NULL, X509_get_serialNumber(cert));
            strncpy(new_grst_cert->serial, p, GRST_X509_SERIAL_DIGITS);
            new_grst_cert->serial[GRST_X509_SERIAL_DIGITS] = '\0';
            free(p);
            
            new_grst_cert->notbefore = GRSTasn1TimeToTimeT(
                               ASN1_STRING_data(X509_get_notBefore(cert)), 0);
            new_grst_cert->notafter  = GRSTasn1TimeToTimeT(
                               ASN1_STRING_data(X509_get_notAfter(cert)), 0);
          
            /* we check times and record if invalid */
          
            if (now < new_grst_cert->notbefore)
                 new_grst_cert->errors |= GRST_CERT_BAD_TIME;

            if (now > new_grst_cert->notafter)
                 new_grst_cert->errors |= GRST_CERT_BAD_TIME;

            new_grst_cert->dn = X509_NAME_oneline(X509_get_subject_name(cert),NULL,0);
            new_grst_cert->issuer = X509_NAME_oneline(X509_get_issuer_name(cert),NULL,0);
            len       = strlen(new_grst_cert->dn);
            len2      = strlen(new_grst_cert->issuer);

            /* always treat a first cert from the CA files as a 
               CA: this is really for lousy CAs that dont create 
               proper v3 root certificates */
                
            if (i == depth) IsCA == TRUE;
            else IsCA = (GRSTx509IsCA(cert) == GRST_RET_OK);

            /* If any forebear certificate is not allowed to sign we must 
               assume all decendents are proxies and cannot sign either */
            if (prevIsCA)
              {
                if (IsCA)
                  {               
                    new_grst_cert->type = GRST_CERT_TYPE_CA;
                  }
                else 
                  {
                    new_grst_cert->type = GRST_CERT_TYPE_EEC;
                    first_non_ca = i;
                    user_cert = new_grst_cert;
                    new_grst_cert->delegation 
                       = (lastcert == NULL) ? i : i + 1;
                  }
              } 
            else 
              {
                new_grst_cert->type = GRST_CERT_TYPE_PROXY;

                IsCA = FALSE;
                /* Force proxy check next iteration. Important because I can
                   sign any CA I create! */

                new_grst_cert->delegation = (lastcert == NULL) ? i : i + 1;
              }

            if (!prevIsCA)
              {
                /* issuer didn't have CA status, so this is (at best) a proxy:
                   check for bad proxy extension*/

                if (prevIsLimited) /* we reject proxies of limited proxies! */
                  {
                    new_grst_cert->errors |= GRST_CERT_BAD_CHAIN;
                    chain_errors |= GRST_CERT_BAD_CHAIN;
                  }
              
                /* User not allowed to sign shortened DN */
                if (len2 > len) 
                  {
                    new_grst_cert->errors |= GRST_CERT_BAD_CHAIN;
                    chain_errors |= GRST_CERT_BAD_CHAIN;
                  }
                  
                /* Proxy subject must begin with issuer. */
                if (strncmp(new_grst_cert->dn, new_grst_cert->issuer, len2) != 0) 
                  {
                    new_grst_cert->errors  |= GRST_CERT_BAD_CHAIN;
                    chain_errors |= GRST_CERT_BAD_CHAIN;
                  }

                /* Set pointer to end of base DN in cert_DN */
                proxy_part_DN = &(new_grst_cert->dn[len2]);

                /* First attempt at support for Old and New style GSI
                   proxies: /CN=anything is ok for now */
                if (strncmp(proxy_part_DN, "/CN=", 4) != 0)
                  {
                    new_grst_cert->errors  |= GRST_CERT_BAD_CHAIN;
                    chain_errors |= GRST_CERT_BAD_CHAIN;
                  }

                if (strncmp(proxy_part_DN, "/CN=limited proxy", 17) == 0)
                        prevIsLimited = 1; /* ready for next cert ... */

                for (j=0; j < X509_get_ext_count(cert); ++j)
                   {
                     ex = X509_get_ext(cert, j);
                     OBJ_obj2txt(s,sizeof(s),X509_EXTENSION_get_object(ex),1);

                     if (strcmp(s, GRST_VOMS_OID) == 0) /* a VOMS extension */
                       {
                         GRSTx509ChainVomsAdd(&grst_cert, 
                                              new_grst_cert->notbefore,
                                              new_grst_cert->notafter,
					      (lastcert == NULL) ? i : i+1,
                                              ex,
                                              user_cert,
                                              vomsdir,
                                              capath);
                       }
                   }                     
              } 
          }
          

      } /* end of for loop */

   if (cacert != NULL) X509_free(cacert);
 
   return GRST_RET_OK;
}

/// Check certificate chain for GSI proxy acceptability.
int GRSTx509CheckChain(int *first_non_ca, X509_STORE_CTX *ctx)
///
/// Returns X509_V_OK/GRST_RET_OK if valid; OpenSSL X509 errors otherwise.
///
/// Inspired by GSIcheck written by Mike Jones, SVE, Manchester Computing,
/// The University of Manchester.
///
/// The GridSite version handles old and new style Globus proxies, and
/// proxies derived from user certificates issued with "X509v3 Basic
/// Constraints: CA:FALSE" (eg UK e-Science CA)
///
/// We do not check chain links between certs here: this is done by
/// GRST_check_issued/X509_check_issued in mod_ssl's ssl_engine_init.c
///
/// TODO: we do not yet check ProxyCertInfo and ProxyCertPolicy extensions
///       (although via GRSTx509KnownCriticalExts() we can accept them.)
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
           GRSTasn1TimeToTimeT(ASN1_STRING_data(X509_get_notBefore(cert)),0))
                  return X509_V_ERR_INVALID_CA;
                
            if (now > 
           GRSTasn1TimeToTimeT(ASN1_STRING_data(X509_get_notAfter(cert)),0))
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

/// Get the VOMS attributes in the given extension
int GRSTx509ParseVomsExt(int *lastcred, int maxcreds, size_t credlen, 
                         char *creds, time_t time1_time, time_t time2_time,
                         X509_EXTENSION *ex, 
                         char *ucuserdn, char *ucissuerdn, char *ucserial, 
                         char *vomsdir)
///
/// Puts any VOMS credentials found into the Compact Creds string array
/// starting at *creds. Always returns GRST_RET_OK - even for invalid
/// credentials, which are just ignored.
{
#define MAXTAG 500
#define GRST_ASN1_COORDS_FQAN    "-1-1-%d-1-7-1-2-1-2-%d"
#define GRST_ASN1_COORDS_ISSUER_DN "-1-1-%d-1-2-1-1-1-1-%%d-1-%%d"
#define GRST_ASN1_COORDS_TIME1   "-1-1-%d-1-6-1"
#define GRST_ASN1_COORDS_TIME2   "-1-1-%d-1-6-2"
   ASN1_OCTET_STRING *asn1data;
   char              *asn1string, acissuerdn[200], acvomsdn[200],
                      dn_coords[200], fqan_coords[200], time1_coords[200],
                      time2_coords[200], serial_coords[200];
   unsigned char     *p;
   long               asn1length;
   int                lasttag=-1, itag, i, acnumber = 1;
   char              *acissuerserial = NULL;
   struct GRSTasn1TagList taglist[MAXTAG+1];
   time_t             actime1, actime2, time_now;
   ASN1_INTEGER       acissuerserialASN1;

   asn1data   = X509_EXTENSION_get_data(ex);
   asn1string = ASN1_STRING_data(asn1data);
   asn1length = ASN1_STRING_length(asn1data);

   GRSTasn1ParseDump(NULL, asn1string, asn1length, taglist, MAXTAG, &lasttag);

   for (acnumber = 1; ; ++acnumber) /* go through ACs one by one */
      {
        /* check names */
      
        snprintf(dn_coords, sizeof(dn_coords), GRST_ASN1_COORDS_ISSUER_DN, acnumber);
        if (GRSTasn1GetX509Name(acissuerdn, sizeof(acissuerdn), dn_coords,
                       asn1string, taglist, lasttag) != GRST_RET_OK) break;

        if ((GRSTx509NameCmp(ucuserdn, acissuerdn) != 0) && /* old */
            (GRSTx509NameCmp(ucissuerdn, acissuerdn) != 0)) /* new */
             continue;

        /* check serial numbers */

        snprintf(serial_coords, sizeof(serial_coords), 
                 GRST_ASN1_COORDS_ISSUER_SERIAL, acnumber);

        itag = GRSTasn1SearchTaglist(taglist, lasttag, serial_coords);
        
        if (itag > -1) 
          {
            acissuerserialASN1.length = taglist[itag].length;
            acissuerserialASN1.type   = V_ASN1_INTEGER;
            acissuerserialASN1.data   = &asn1string[taglist[itag].start+taglist[itag].headerlength];

            acissuerserial = i2s_ASN1_INTEGER(NULL, &acissuerserialASN1);
/*          
            p = &asn1string[taglist[itag].start+taglist[itag].headerlength];
            
            if (taglist[itag].length == 2)
             acissuerserial = p[1] + p[0] * 0x100;
            else if (taglist[itag].length == 3)
             acissuerserial = p[2] + p[1] * 0x100 + p[0] * 0x10000;
            else if (taglist[itag].length == 4)
             acissuerserial = p[3] + p[2] * 0x100 + p[1] * 0x10000 +
                              p[0] * 0x1000000;
*/
          }
        
        if (strcmp(acissuerserial, ucserial) != 0) continue;

        if (GRSTx509VerifyVomsSig(&time1_time, &time2_time,
                             asn1string, taglist, lasttag, vomsdir, acnumber)
                             != GRST_RET_OK) continue;

        snprintf(time1_coords, sizeof(time1_coords), GRST_ASN1_COORDS_TIME1, acnumber);
        itag = GRSTasn1SearchTaglist(taglist, lasttag, time1_coords);
        actime1 = GRSTasn1TimeToTimeT(&asn1string[taglist[itag].start+
                                             taglist[itag].headerlength],
                                 taglist[itag].length);
        if (actime1 > time1_time) time1_time = actime1;

        snprintf(time2_coords, sizeof(time2_coords), GRST_ASN1_COORDS_TIME2, acnumber);
        itag = GRSTasn1SearchTaglist(taglist, lasttag, time2_coords);
        actime2 = GRSTasn1TimeToTimeT(&asn1string[taglist[itag].start+
                                             taglist[itag].headerlength],
                                             taglist[itag].length);
        if (actime2 < time2_time) time2_time = actime2;

        time(&time_now);
        if ((time1_time > time_now + 300) || (time2_time < time_now))
               continue; /* expiration isnt invalidity ...? */

        for (i=1; ; ++i)
           {
             snprintf(fqan_coords, sizeof(fqan_coords), GRST_ASN1_COORDS_FQAN, acnumber, i);
             itag = GRSTasn1SearchTaglist(taglist, lasttag, fqan_coords);

             if (itag > -1)
               {
                 if (*lastcred < maxcreds - 1)
                   {
                     ++(*lastcred);
                     snprintf(&creds[*lastcred * (credlen + 1)], credlen+1,
                           "VOMS %010lu %010lu 0 %.*s", 
                           time1_time, time2_time, 
                           taglist[itag].length,
                           &asn1string[taglist[itag].start+
                                       taglist[itag].headerlength]);
                   }            
               }
             else break;
           }
      }
      
   return GRST_RET_OK;
}

/// Get the VOMS attributes in the extensions to the given cert stack
int GRSTx509GetVomsCreds(int *lastcred, int maxcreds, size_t credlen, 
                         char *creds, X509 *usercert, STACK_OF(X509) *certstack,
                         char *vomsdir)
///
/// Puts any VOMS credentials found into the Compact Creds string array
/// starting at *creds. Always returns GRST_RET_OK.
{
   int  i, j;
   char s[80], *ucserial;
   unsigned char  *ucuser, *ucissuer;
   X509_EXTENSION *ex;
   ASN1_STRING    *asn1str;
   X509           *cert;
   time_t          time1_time = 0, time2_time = 0, uctime1_time, uctime2_time;

   uctime1_time = 
        GRSTasn1TimeToTimeT(ASN1_STRING_data(X509_get_notBefore(usercert)),0);
   uctime2_time =       
        GRSTasn1TimeToTimeT(ASN1_STRING_data(X509_get_notAfter(usercert)),0);
   ucuser =
        X509_NAME_oneline(X509_get_subject_name(usercert), NULL, 0);
   ucissuer =
        X509_NAME_oneline(X509_get_issuer_name(usercert), NULL, 0);
   ucserial = i2s_ASN1_INTEGER(NULL, X509_get_serialNumber(usercert));

   for (j=sk_X509_num(certstack)-1; j >= 0; --j)
    {
      cert = sk_X509_value(certstack, j);

      time1_time =
          GRSTasn1TimeToTimeT(ASN1_STRING_data(X509_get_notBefore(cert)),0);
      uctime1_time = (time1_time > uctime1_time) ? time1_time:uctime1_time;

      time2_time =
          GRSTasn1TimeToTimeT(ASN1_STRING_data(X509_get_notAfter(cert)),0);
      uctime2_time = (time2_time < uctime2_time) ? time2_time:uctime2_time;

      for (i=0; i < X509_get_ext_count(cert); ++i)
         {
           ex = X509_get_ext(cert, i);
           OBJ_obj2txt(s, sizeof(s), X509_EXTENSION_get_object(ex), 1);

           if (strcmp(s, GRST_VOMS_OID) == 0) /* a VOMS extension */
             {
               GRSTx509ParseVomsExt(lastcred, maxcreds, credlen, creds,
                                 uctime1_time, uctime2_time,
                                 ex, ucuser, ucissuer, ucserial,
                                 vomsdir);
             }
         }
    }

   return GRST_RET_OK;
}

/// Turn a Compact Cred line into a GRSTgaclCred object
GRSTgaclCred *GRSTx509CompactToCred(char *grst_cred)
///
/// Returns pointer to created GRSTgaclCred or NULL or failure.
{
   int       delegation;
   char     *p, *encoded;
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
           encoded = GRSThttpUrlMildencode(&p[1]);
           cred = GRSTgaclCredCreate("dn:", encoded);
           free(encoded);
           GRSTgaclCredSetDelegation(cred, delegation);
         }

       return cred;
     }

   if (strncmp(grst_cred, "VOMS ", 5) == 0)
     {
       if ((sscanf(grst_cred, "VOMS %lu %lu %d",
                              &notbefore, &notafter, &delegation) == 3)
            && (now >= notbefore)
            && (now <= notafter)
            && (p = index(grst_cred, ' '))
            && (p = index(++p, ' '))
            && (p = index(++p, ' '))
            && (p = index(++p, ' ')))
         {
           /* include /VO/group/subgroup/Role=role/Capability=cap */

           if (p[1] != '/') return NULL; /* must begin with / */

           encoded = GRSThttpUrlMildencode(&p[1]);
           cred = GRSTgaclCredCreate("fqan:", encoded);
           free(encoded);
           GRSTgaclCredSetDelegation(cred, delegation);
         }

       return cred;
     }

   return NULL; /* dont recognise this credential type */
}

/// Get the credentials in an X509 cert/GSI proxy, including any VOMS
int GRSTx509CompactCreds(int *lastcred, int maxcreds, size_t credlen, 
                         char *creds, STACK_OF(X509) *certstack, char *vomsdir, 
                         X509 *peercert)
///
/// Credentials are placed in Compact Creds string array at *creds.
///
/// Function returns GRST_RET_OK on success, or GRST_RET_FAILED if
/// some inconsistency found in certificate.
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

   if (peercert != NULL)
     {
       if (usercert != NULL) /* found a (GSI proxy) cert after user cert */
         {
           gsiproxycert = peercert;
           ++delegation;
         }

       if ((usercert == NULL) && 
           (GRSTx509IsCA(peercert) != GRST_RET_OK)) usercert = peercert;
                                          /* found the 1st non-CA cert */
     }

   if ((usercert == NULL) /* if no usercert ("EEC"), we're not interested */
       ||
       (snprintf(credtemp, credlen+1, "X509USER %010lu %010lu %d %s",
          GRSTasn1TimeToTimeT(ASN1_STRING_data(X509_get_notBefore(usercert)),0),
          GRSTasn1TimeToTimeT(ASN1_STRING_data(X509_get_notAfter(usercert)),0),
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
     GRSTasn1TimeToTimeT(ASN1_STRING_data(X509_get_notBefore(gsiproxycert)),0), 
     GRSTasn1TimeToTimeT(ASN1_STRING_data(X509_get_notAfter(gsiproxycert)),0),
     delegation,
  X509_NAME_oneline(X509_get_subject_name(gsiproxycert), NULL, 0)) < credlen+1)
       &&
       (*lastcred < maxcreds-1))
     {
       ++(*lastcred);
       strcpy(&creds[*lastcred * (credlen + 1)], credtemp);

       GRSTx509GetVomsCreds(lastcred, maxcreds, credlen, creds, 
                            usercert, certstack, vomsdir);

     }
         
   return GRST_RET_OK;
}

/// Find proxy file name of the current user
char *GRSTx509FindProxyFileName(void)
///
/// Return a string with the proxy file name or NULL if not present.
/// This function does not check if the proxy has expired.
{
  char *p;
  
  p = getenv("X509_USER_PROXY");
  
  if (p != NULL) return strdup(p);
  
  p = malloc(sizeof("/tmp/x509up_uXYYYXXXYYY"));
  
  sprintf(p, "/tmp/x509up_u%d", getuid());  

  return p;
}

static void mpcerror(FILE *debugfp, char *msg)
{
  if (debugfp != NULL)
    {
      fputs(msg, debugfp);
      ERR_print_errors_fp(debugfp);
    }
}

/// Make a GSI Proxy chain from a request, certificate and private key
int GRSTx509MakeProxyCert(char **proxychain, FILE *debugfp, 
                          char *reqtxt, char *cert, char *key, int minutes)
///
/// The proxy chain is returned in *proxychain. If debugfp is non-NULL,
/// errors are output to that file pointer. The proxy will expired in
/// the given number of minutes starting from the current time.
{
  char *ptr, *certchain, s[41];
  static unsigned char pci_str[] = { 0x30, 0x0c, 0x30, 0x0a, 0x06, 0x08,
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x15, 0x01, 0 },
    kyu_str[] = { 0x03, 0x02, 0x03, 
                  X509v3_KU_DIGITAL_SIGNATURE | 
                  X509v3_KU_KEY_ENCIPHERMENT  | 
                  X509v3_KU_KEY_AGREEMENT, 
                  0 };
  int i, ncerts, any_rfc_proxies = 0;
  long serial = 1234, ptrlen;
  EVP_PKEY *pkey, *CApkey;
  const EVP_MD *digest;
  X509 *certs[GRST_MAX_CHAIN_LEN];
  X509_REQ *req;
  X509_NAME *name, *CAsubject, *newsubject;
  X509_NAME_ENTRY *ent;
  ASN1_OBJECT *pci_obj = NULL, *kyu_obj;
  ASN1_OCTET_STRING *pci_oct, *kyu_oct;
  X509_EXTENSION *pci_ex, *kyu_ex;
  FILE *fp;
  BIO *reqmem, *certmem;
  time_t notAfter;

  /* read in the request */
  reqmem = BIO_new(BIO_s_mem());
  BIO_puts(reqmem, reqtxt);
    
  if (!(req = PEM_read_bio_X509_REQ(reqmem, NULL, NULL, NULL)))
    {
      mpcerror(debugfp,
              "GRSTx509MakeProxyCert(): error reading request from BIO memory\n");
      BIO_free(reqmem);
      return GRST_RET_FAILED;
    }
    
  BIO_free(reqmem);

  /* verify signature on the request */
  if (!(pkey = X509_REQ_get_pubkey(req)))
    {
      mpcerror(debugfp,
              "GRSTx509MakeProxyCert(): error getting public key from request\n");
      
      X509_REQ_free(req);
      return GRST_RET_FAILED;
    }

  if (X509_REQ_verify(req, pkey) != 1)
    {
      mpcerror(debugfp,
            "GRSTx509MakeProxyCert(): error verifying signature on certificate\n");

      X509_REQ_free(req);
      return GRST_RET_FAILED;
    }
    
  /* read in the signing certificate */
  if (!(fp = fopen(cert, "r")))
    {
      mpcerror(debugfp,
            "GRSTx509MakeProxyCert(): error opening signing certificate file\n");

      X509_REQ_free(req);
      return GRST_RET_FAILED;
    }    

  for (ncerts = 1; ncerts < GRST_MAX_CHAIN_LEN; ++ncerts)
   if ((certs[ncerts] = PEM_read_X509(fp, NULL, NULL, NULL)) == NULL) break;

  if (ncerts == 1) /* zeroth cert with be new proxy cert */
    {
      mpcerror(debugfp,
            "GRSTx509MakeProxyCert(): error reading signing certificate file\n");

      X509_REQ_free(req);
      return GRST_RET_FAILED;
    }    

  fclose(fp);
  
  CAsubject = X509_get_subject_name(certs[1]);

  /* read in the CA private key */
  if (!(fp = fopen(key, "r")))
    {
      mpcerror(debugfp,
            "GRSTx509MakeProxyCert(): error reading signing private key file\n");

      X509_REQ_free(req);
      return GRST_RET_FAILED;
    }    

  if (!(CApkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL)))
    {
      mpcerror(debugfp,
            "GRSTx509MakeProxyCert(): error reading signing private key in file\n");

      X509_REQ_free(req);
      return GRST_RET_FAILED;
    }    

  fclose(fp);
  
  /* get subject name */
  if (!(name = X509_REQ_get_subject_name(req)))
    {
      mpcerror(debugfp,
            "GRSTx509MakeProxyCert(): error getting subject name from request\n");

      X509_REQ_free(req);
      return GRST_RET_FAILED;
    }    

  /* create new certificate */
  if (!(certs[0] = X509_new()))
    {
      mpcerror(debugfp,
            "GRSTx509MakeProxyCert(): error creating X509 object\n");

      X509_REQ_free(req);
      return GRST_RET_FAILED;
    }    

  /* set version number for the certificate (X509v3) and the serial number   
     
     We now use 2 = v3 for the GSI proxy, rather than the old Globus 
     behaviour of 3 = v4. See Savannah Bug #53721 */
     
  if (X509_set_version(certs[0], 2L) != 1)
    {
      mpcerror(debugfp,
            "GRSTx509MakeProxyCert(): error setting certificate version\n");

      X509_REQ_free(req);
      return GRST_RET_FAILED;
    }    

  ASN1_INTEGER_set(X509_get_serialNumber(certs[0]), (long) time(NULL));

  if (!(name = X509_get_subject_name(certs[1])))
    {
      mpcerror(debugfp,
      "GRSTx509MakeProxyCert(): error getting subject name from CA certificate\n");

      X509_REQ_free(req);
      return GRST_RET_FAILED;
    }    

  if (X509_set_issuer_name(certs[0], name) != 1)
    {
      mpcerror(debugfp,
      "GRSTx509MakeProxyCert(): error setting issuer name of certificate\n");

      X509_REQ_free(req);
      return GRST_RET_FAILED;
    }    

  /* set public key in the certificate */
  if (X509_set_pubkey(certs[0], pkey) != 1)
    {
      mpcerror(debugfp,
      "GRSTx509MakeProxyCert(): error setting public key of the certificate\n");

      X509_REQ_free(req);
      return GRST_RET_FAILED;
    }    

  /* set duration for the certificate */
  if (!(X509_gmtime_adj(X509_get_notBefore(certs[0]), -GRST_BACKDATE_SECONDS)))
    {
      mpcerror(debugfp,
      "GRSTx509MakeProxyCert(): error setting beginning time of the certificate\n");

      X509_REQ_free(req);
      return GRST_RET_FAILED;
    }    

  if (!(X509_gmtime_adj(X509_get_notAfter(certs[0]), 60 * minutes)))
    {
      mpcerror(debugfp,
      "GRSTx509MakeProxyCert(): error setting ending time of the certificate\n");

      X509_REQ_free(req);
      return GRST_RET_FAILED;
    }
    
  /* go through chain making sure this proxy is not longer lived */

  pci_obj = OBJ_txt2obj(GRST_PROXYCERTINFO_OID, 0);

  notAfter = 
     GRSTasn1TimeToTimeT(ASN1_STRING_data(X509_get_notAfter(certs[0])), 0);
     
  for (i=1; i < ncerts; ++i)
     {
       if (notAfter > 
           GRSTasn1TimeToTimeT(ASN1_STRING_data(X509_get_notAfter(certs[i])),
                               0))
         {
           notAfter = 
            GRSTasn1TimeToTimeT(ASN1_STRING_data(X509_get_notAfter(certs[i])),
                                0);
            
           ASN1_UTCTIME_set(X509_get_notAfter(certs[0]), notAfter);
         }
         
       if (X509_get_ext_by_OBJ(certs[i], pci_obj, -1) > 0) 
         any_rfc_proxies = 1;
     }

   /* if any earlier proxies are RFC 3820, then new proxy must be 
      an RFC 3820 proxy too with the required extensions */ 
   if (any_rfc_proxies)
    {
      /* key usage */
      kyu_obj = OBJ_txt2obj(GRST_KEYUSAGE_OID, 0);
      kyu_ex = X509_EXTENSION_new();
      
      X509_EXTENSION_set_object(kyu_ex, kyu_obj);
      ASN1_OBJECT_free(kyu_obj);
      X509_EXTENSION_set_critical(kyu_ex, 1);

      kyu_oct = ASN1_OCTET_STRING_new();
      ASN1_OCTET_STRING_set(kyu_oct, kyu_str, strlen(kyu_str));
      X509_EXTENSION_set_data(kyu_ex, kyu_oct);
      ASN1_OCTET_STRING_free(kyu_oct);
      
      X509_add_ext(certs[0], kyu_ex, -1);
      X509_EXTENSION_free(kyu_ex);

      /* proxy certificate info */
      pci_ex = X509_EXTENSION_new();
      
      X509_EXTENSION_set_object(pci_ex, pci_obj);
      X509_EXTENSION_set_critical(pci_ex, 1);

      pci_oct = ASN1_OCTET_STRING_new();
      ASN1_OCTET_STRING_set(pci_oct, pci_str, strlen(pci_str));
      X509_EXTENSION_set_data(pci_ex, pci_oct);
      ASN1_OCTET_STRING_free(pci_oct);
      
      X509_add_ext(certs[0], pci_ex, -1);
      X509_EXTENSION_free(pci_ex);
    }
  ASN1_OBJECT_free(pci_obj);

  /* set issuer and subject name of the cert from the req and the CA */

  if (any_rfc_proxies) /* user CN=number rather than CN=proxy */
    {
       snprintf(s, sizeof(s), "%ld", (long) time(NULL));
       ent = X509_NAME_ENTRY_create_by_NID(NULL, OBJ_txt2nid("commonName"), 
                                      MBSTRING_ASC, s, -1);
    }    
  else ent = X509_NAME_ENTRY_create_by_NID(NULL, OBJ_txt2nid("commonName"), 
                                      MBSTRING_ASC, "proxy", -1);

  newsubject = X509_NAME_dup(CAsubject);

  X509_NAME_add_entry(newsubject, ent, -1, 0);

  if (X509_set_subject_name(certs[0], newsubject) != 1)
    {
      mpcerror(debugfp,
      "GRSTx509MakeProxyCert(): error setting subject name of certificate\n");

      X509_REQ_free(req);
      return GRST_RET_FAILED;
    }    
    
  X509_NAME_free(newsubject);
  X509_NAME_ENTRY_free(ent);

  /* sign the certificate with the signing private key */
  if (EVP_PKEY_type(CApkey->type) == EVP_PKEY_RSA)
    digest = EVP_md5();
  else
    {
      mpcerror(debugfp,
      "GRSTx509MakeProxyCert(): error checking signing private key for a valid digest\n");

      X509_REQ_free(req);
      return GRST_RET_FAILED;
    }    

  if (!(X509_sign(certs[0], CApkey, digest)))
    {
      mpcerror(debugfp,
      "GRSTx509MakeProxyCert(): error signing certificate\n");

      X509_REQ_free(req);
      return GRST_RET_FAILED;
    }    

  /* store the completed certificate chain */

  certchain = strdup("");

  for (i=0; i < ncerts; ++i)
     {
       certmem = BIO_new(BIO_s_mem());

       if (PEM_write_bio_X509(certmem, certs[i]) != 1)
         {
           mpcerror(debugfp,
            "GRSTx509MakeProxyCert(): error writing certificate to memory BIO\n");            

           X509_REQ_free(req);
           return GRST_RET_FAILED;
         }

       ptrlen = BIO_get_mem_data(certmem, &ptr);
  
       certchain = realloc(certchain, strlen(certchain) + ptrlen + 1);
       
       strncat(certchain, ptr, ptrlen);
    
       BIO_free(certmem);
       X509_free(certs[i]);
     }
  
  EVP_PKEY_free(pkey);
  EVP_PKEY_free(CApkey);
  X509_REQ_free(req);
      
  *proxychain = certchain;  
  return GRST_RET_OK;
}

/// Find a proxy file in the proxy cache
char *GRSTx509CachedProxyFind(char *proxydir, char *delegation_id, 
                              char *user_dn)
///
/// Returns the full path and file name of proxy file associated
/// with given delegation ID and user DN.
///
/// Return a pointer to a malloc'd string with the full path of the 
/// proxy file corresponding to the given delegation_id, or NULL
/// if not found.
{
  char *user_dn_enc, *proxyfile;
  struct stat statbuf;

  user_dn_enc = GRSThttpUrlEncode(user_dn);

  asprintf(&proxyfile, "%s/%s/%s/userproxy.pem",
           proxydir, user_dn_enc, delegation_id);
           
  free(user_dn_enc);

  if ((stat(proxyfile, &statbuf) != 0) || !S_ISREG(statbuf.st_mode))
    {
      free(proxyfile);
      return NULL;
    }
    
  return proxyfile;
}

/// Find a temporary proxy private key file in the proxy cache
char *GRSTx509CachedProxyKeyFind(char *proxydir, char *delegation_id, 
                                 char *user_dn)
///
/// Returns the full path and file name of the private key file associated
/// with given delegation ID and user DN.
///
/// Return a pointer to a malloc'd string with the full path of the 
/// private proxy key corresponding to the given delegation_id, or NULL
/// if not found.
{
  char *user_dn_enc, *prvkeyfile;
  struct stat statbuf;

  user_dn_enc = GRSThttpUrlEncode(user_dn);

  asprintf(&prvkeyfile, "%s/cache/%s/%s/userkey.pem",
           proxydir, user_dn_enc, delegation_id);
           
  free(user_dn_enc);

  if ((stat(prvkeyfile, &statbuf) != 0) || !S_ISREG(statbuf.st_mode))
    {
      free(prvkeyfile);
      return NULL;
    }
    
  return prvkeyfile;
}

static void mkdir_printf(mode_t mode, char *fmt, ...)
{
  int   ret;
  char *path;
  va_list ap;
  
  va_start(ap, fmt);
  vasprintf(&path, fmt, ap);
  va_end(ap);

  ret = mkdir(path, mode);

  free(path);
}

/// Create a X.509 request for a GSI proxy and its private key
int GRSTx509CreateProxyRequest(char **reqtxt, char **keytxt, char *ocspurl)
///
/// Returns GRST_RET_OK on success, non-zero otherwise. Request string
/// and private key are PEM encoded strings
{
  int              i;
  char            *ptr;
  size_t           ptrlen;
  RSA             *keypair;
  X509_NAME       *subject;
  X509_NAME_ENTRY *ent;
  EVP_PKEY        *pkey;
  X509_REQ        *certreq;
  BIO             *reqmem, *keymem;
  const EVP_MD    *digest;
  struct stat      statbuf;

  /* create key pair and put it in a PEM string */

  if ((keypair = RSA_generate_key(GRST_KEYSIZE, 65537, NULL, NULL)) == NULL)
                                                               return 1;

  keymem = BIO_new(BIO_s_mem());
  if (!PEM_write_bio_RSAPrivateKey(keymem, keypair, NULL, NULL, 0, NULL, NULL))
    {
      BIO_free(keymem);
      return 3;
    }

  ptrlen = BIO_get_mem_data(keymem, &ptr);
  
  *keytxt = malloc(ptrlen + 1);
  memcpy(*keytxt, ptr, ptrlen);
  (*keytxt)[ptrlen] = '\0';

  BIO_free(keymem);
  
  /* now create the certificate request */

  certreq = X509_REQ_new();

  OpenSSL_add_all_algorithms();

  pkey = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(pkey, keypair);

  X509_REQ_set_pubkey(certreq, pkey);
  
  subject = X509_NAME_new();
  ent = X509_NAME_ENTRY_create_by_NID(NULL, OBJ_txt2nid("organizationName"), 
                                      MBSTRING_ASC, "Dummy", -1);
  X509_NAME_add_entry (subject, ent, -1, 0);
  X509_REQ_set_subject_name (certreq, subject);
  
  digest = EVP_md5();
  X509_REQ_sign(certreq, pkey, digest);

  reqmem = BIO_new(BIO_s_mem());
  PEM_write_bio_X509_REQ(reqmem, certreq);
  ptrlen = BIO_get_mem_data(reqmem, &ptr);
  
  *reqtxt = malloc(ptrlen + 1);
  memcpy(*reqtxt, ptr, ptrlen);
  (*reqtxt)[ptrlen] = '\0';

  BIO_free(reqmem);

  X509_REQ_free(certreq);
  
  return 0;
}

/// Make and store a X.509 request for a GSI proxy
int GRSTx509MakeProxyRequest(char **reqtxt, char *proxydir, 
                             char *delegation_id, char *user_dn)
///
/// Returns GRST_RET_OK on success, non-zero otherwise. Request string
/// is PEM encoded, and the key is stored in the temporary cache under
/// proxydir
{
  int              i;
  char            *docroot, *prvkeyfile, *ptr, *user_dn_enc;
  size_t           ptrlen;
  FILE            *fp;
  RSA             *keypair;
  X509_NAME       *subject;
  X509_NAME_ENTRY *ent;
  EVP_PKEY        *pkey;
  X509_REQ        *certreq;
  BIO             *reqmem;
  const EVP_MD    *digest;
  struct stat      statbuf;

  if (strcmp(user_dn, "cache") == 0) return GRST_RET_FAILED;
    
  user_dn_enc = GRSThttpUrlEncode(user_dn);

  /* create directories if necessary */

  mkdir_printf(S_IRUSR | S_IWUSR | S_IXUSR, 
               "%s/cache",       proxydir);
  mkdir_printf(S_IRUSR | S_IWUSR | S_IXUSR, 
               "%s/cache/%s",    proxydir, user_dn_enc);
  mkdir_printf(S_IRUSR | S_IWUSR | S_IXUSR, 
               "%s/cache/%s/%s", proxydir, user_dn_enc, delegation_id);

  /* make the new proxy private key */

  asprintf(&prvkeyfile, "%s/cache/%s/%s/userkey.pem",
           proxydir, user_dn_enc, delegation_id);

  if (prvkeyfile == NULL)  
    {
      free(user_dn_enc);
      return GRST_RET_FAILED;
    }
        
  if ((keypair = RSA_generate_key(GRST_KEYSIZE, 65537, NULL, NULL)) == NULL)
    {
      free(prvkeyfile);
      return 1;
    }
          
  if ((fp = fopen(prvkeyfile, "w")) == NULL) 
    {
      free(prvkeyfile);
      return 2;
    }
  
  chmod(prvkeyfile, S_IRUSR | S_IWUSR);
  free(prvkeyfile);
  free(user_dn_enc);

  if (!PEM_write_RSAPrivateKey(fp, keypair, NULL, NULL, 0, NULL, NULL))
                               return 3;
  
  if (fclose(fp) != 0) return 4;
  
  /* now create the certificate request */

  certreq = X509_REQ_new();
  if (certreq == NULL) return 5;

  OpenSSL_add_all_algorithms();

  pkey = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(pkey, keypair);

  X509_REQ_set_pubkey(certreq, pkey);
  
  subject = X509_NAME_new();
  ent = X509_NAME_ENTRY_create_by_NID(NULL, OBJ_txt2nid("organizationName"), 
                                      MBSTRING_ASC, "Dummy", -1);
  X509_NAME_add_entry (subject, ent, -1, 0);
  X509_REQ_set_subject_name (certreq, subject);
  
  digest = EVP_md5();
  X509_REQ_sign(certreq, pkey, digest);

  reqmem = BIO_new(BIO_s_mem());
  PEM_write_bio_X509_REQ(reqmem, certreq);
  ptrlen = BIO_get_mem_data(reqmem, &ptr);
  
  *reqtxt = malloc(ptrlen + 1);
  memcpy(*reqtxt, ptr, ptrlen);
  (*reqtxt)[ptrlen] = '\0';

  BIO_free(reqmem);

  X509_REQ_free(certreq);
  
  return 0;
}

/// Destroy stored GSI proxy files
int GRSTx509ProxyDestroy(char *proxydir, char *delegation_id, char *user_dn)
///
/// Returns GRST_RET_OK on success, non-zero otherwise.
/// (Including GRST_RET_NO_SUCH_FILE if the private key or cert chain
///  were not found.)
{
  int              ret = GRST_RET_OK;
  char            *docroot, *filename, *user_dn_enc;

  if (strcmp(user_dn, "cache") == 0) return GRST_RET_FAILED;
    
  user_dn_enc = GRSThttpUrlEncode(user_dn);

  /* proxy file */
  
  asprintf(&filename, "%s/%s/%s/userproxy.pem",
           proxydir, user_dn_enc, delegation_id);

  if (filename == NULL)  
    {
      free(user_dn_enc);
      return GRST_RET_FAILED;
    }

  if (unlink(filename) != 0) ret = GRST_RET_NO_SUCH_FILE;  
  free(filename);

  /* voms file */
  
  asprintf(&filename, "%s/%s/%s/voms.attributes",
           proxydir, user_dn_enc, delegation_id);

  if (filename == NULL)  
    {
      free(user_dn_enc);
      return GRST_RET_FAILED;
    }

  unlink(filename);
  free(filename);
  
  return ret;
}

/// Get start and finish validity times of stored GSI proxy file
int GRSTx509ProxyGetTimes(char *proxydir, char *delegation_id, char *user_dn, 
                          time_t *start, time_t *finish)
///
/// Returns GRST_RET_OK on success, non-zero otherwise.
/// (Including GRST_RET_NO_SUCH_FILE if the cert chain was not found.)
{
  char  *docroot, *filename, *user_dn_enc;
  FILE  *fp;
  X509  *cert;

  if (strcmp(user_dn, "cache") == 0) return GRST_RET_FAILED;
    
  user_dn_enc = GRSThttpUrlEncode(user_dn);
  
  asprintf(&filename, "%s/%s/%s/userproxy.pem",
           proxydir, user_dn_enc, delegation_id);
           
  free(user_dn_enc);

  if (filename == NULL) return GRST_RET_FAILED;

  fp = fopen(filename, "r");
  free(filename);
  
  if (fp == NULL) return GRST_RET_NO_SUCH_FILE;

  cert = PEM_read_X509(fp, NULL, NULL, NULL); /* first cert is X.509 PC */

  fclose(fp);
  
  *start  = GRSTasn1TimeToTimeT(ASN1_STRING_data(X509_get_notBefore(cert)),0);
  *finish = GRSTasn1TimeToTimeT(ASN1_STRING_data(X509_get_notAfter(cert)),0);

  X509_free(cert);
  
  return GRST_RET_OK;
}

/// Create a stack of X509 certificate from a PEM-encoded string
int GRSTx509StringToChain(STACK_OF(X509) **certstack, char *certstring)
///
/// Creates a dynamically allocated stack of X509 certificate objects
/// by walking through the PEM-encoded X509 certificates.
///
/// Returns GRST_RET_OK on success, non-zero otherwise.
{   
  STACK_OF(X509_INFO) *sk=NULL;
  BIO *certbio;
  X509_INFO *xi;

  *certstack = sk_X509_new_null();
  if (*certstack == NULL) return GRST_RET_FAILED;

  certbio = BIO_new_mem_buf(certstring, -1);
  
  if (!(sk=PEM_X509_INFO_read_bio(certbio, NULL, NULL, NULL)))
    {
      BIO_free(certbio);
      sk_X509_INFO_free(sk);
      sk_X509_free(*certstack);
      return GRST_RET_FAILED;
    }
      
  while (sk_X509_INFO_num(sk))
       {
         xi=sk_X509_INFO_shift(sk);
         if (xi->x509 != NULL)
           {
             sk_X509_push(*certstack, xi->x509);
             xi->x509=NULL;
           }
         X509_INFO_free(xi);
       }
       
   if (!sk_X509_num(*certstack))
     {
       BIO_free(certbio);
       sk_X509_INFO_free(sk);
       sk_X509_free(*certstack);
       return GRST_RET_FAILED;
     }

   BIO_free(certbio);
   sk_X509_INFO_free(sk);
   
   return GRST_RET_OK;
}

/// Returns a Delegation ID based on hash of GRST_CRED_0, ...
char *GRSTx509MakeDelegationID(void)
///
/// Returns a malloc'd string with Delegation ID made by SHA1-hashing the
/// values of the compact credentials exported by mod_gridsite
{ 
  unsigned char hash_delegation_id[EVP_MAX_MD_SIZE];        
  int  size_needed = 0, i, delegation_id_len;
  char cred_name[14], *cred_value, *delegation_id;
  const EVP_MD *m;
  EVP_MD_CTX ctx;

  OpenSSL_add_all_digests();

  m = EVP_sha1();
  if (m == NULL) return NULL;

  EVP_DigestInit(&ctx, m);

  for (i=0; i <= 999; ++i)
     {
       snprintf(cred_name, sizeof(cred_name), "GRST_CRED_%d", i);       
       if ((cred_value = getenv(cred_name)) == NULL) break;
       
       EVP_DigestUpdate(&ctx, cred_value, strlen(cred_value));
     }
     
  EVP_DigestFinal(&ctx, hash_delegation_id, &delegation_id_len);

  delegation_id = malloc(17);

  for (i=0; i <=7; ++i)
   sprintf(&delegation_id[i*2], "%02x", hash_delegation_id[i]);

  delegation_id[16] = '\0';

  return delegation_id;
}

#if 0
/// Return the short file name for the given delegation_id and user_dn
char *GRSTx509MakeProxyFileName(char *delegation_id,
                                STACK_OF(X509) *certstack)
///
/// Returns a malloc'd string with the short file name (no paths) that
/// derived from the hashed delegation_id and user_dn
///
/// File name is SHA1_HASH(DelegationID)+"-"+SHA1_HASH(DN) where DN
/// is DER encoded version of user_dn with any trailing CN=proxy removed
/// Hashes are the most significant 8 bytes, in lowercase hexadecimal.
{ 
  int        i, depth, prevIsCA = 1, IsCA, hash_name_len, delegation_id_len,
                 der_name_len;
  unsigned char *der_name, *buf, hash_name[EVP_MAX_MD_SIZE],
                 hash_delegation_id[EVP_MAX_MD_SIZE],
                 filename[34];
  X509_NAME *subject_name;
  X509      *cert;
  const EVP_MD *m;
  EVP_MD_CTX ctx;

  depth = sk_X509_num(certstack);  
  
  for (i=depth-1; i >= 0; --i)
        /* loop through the proxy chain starting at CA end */
     {
       if (cert = sk_X509_value(certstack, i))
         {
           IsCA = (GRSTx509IsCA(cert) == GRST_RET_OK);

           if (prevIsCA && !IsCA) /* the full certificate of the user */
             {
               break;
             }
         }
     }

  if (i < 0) return NULL; /* not found: something wrong with the chain */

  if ((subject_name = X509_get_subject_name(cert)) == NULL) return NULL;
  
  der_name_len = i2d_X509_NAME(X509_get_subject_name(cert), NULL);
  if (der_name_len == 0) return NULL;
  
  buf = OPENSSL_malloc(der_name_len);
  der_name = buf;


  if (!i2d_X509_NAME(X509_get_subject_name(cert), &der_name))
    {
      OPENSSL_free(der_name);
      return NULL;
    }

  OpenSSL_add_all_digests();

  m = EVP_sha1();
  if (m == NULL)
    {
      OPENSSL_free(der_name);
      return NULL;
    }


  EVP_DigestInit(&ctx, m);
  EVP_DigestUpdate(&ctx, delegation_id, strlen(delegation_id));
  EVP_DigestFinal(&ctx, hash_delegation_id, &delegation_id_len);

  /* lots of nasty hard coded numbers: 
     "8bytes/16chars delegation ID" + "-" + "8bytes/16chars DN" */

  for (i=0; i <=7; ++i)
   sprintf(&filename[i*2], "%02x", hash_delegation_id[i]);

  filename[16] = '-';

  EVP_DigestInit(&ctx, m);
  EVP_DigestUpdate(&ctx, buf, der_name_len);
  EVP_DigestFinal(&ctx, hash_name, &hash_name_len);

  for (i=0; i <=7; ++i)
   sprintf(&filename[17 + i*2], "%02x", hash_name[i]);

  return strdup(filename);
}
#endif

/// Store a GSI proxy chain in the proxy cache, along with the private key
int GRSTx509CacheProxy(char *proxydir, char *delegation_id, 
                                       char *user_dn, char *proxychain)
///
/// Returns GRST_RET_OK on success, non-zero otherwise. The existing
/// private key with the same delegation ID and user DN is moved out of
/// the temporary cache.
{
  int   c, len = 0, i, ret;
  char *user_dn_enc, *p, *ptr, *prvkeyfile, *proxyfile;
  STACK_OF(X509) *certstack;
  BIO  *certmem;
  X509 *cert;
  long  ptrlen;        
  FILE *ifp, *ofp;

  if (strcmp(user_dn, "cache") == 0) return GRST_RET_FAILED;
    
  /* find the existing private key file */

  prvkeyfile = GRSTx509CachedProxyKeyFind(proxydir, delegation_id, user_dn);

  if (prvkeyfile == NULL)
    {
      return GRST_RET_FAILED;
    }

  /* open it ready for later */

  if ((ifp = fopen(prvkeyfile, "r")) == NULL)
    {
      free(prvkeyfile);
      return GRST_RET_FAILED;
    }

  /* get the X509 stack */

  if (GRSTx509StringToChain(&certstack, proxychain) != GRST_RET_OK)
    {
      fclose(ifp);
      free(prvkeyfile);
      return GRST_RET_FAILED;
    }

  /* create directories if necessary, and set proxy filename */

  user_dn_enc = GRSThttpUrlEncode(user_dn);

  mkdir_printf(S_IRUSR | S_IWUSR | S_IXUSR, 
               "%s/%s",    proxydir, user_dn_enc);
  mkdir_printf(S_IRUSR | S_IWUSR | S_IXUSR, 
               "%s/%s/%s", proxydir, user_dn_enc, delegation_id);

  asprintf(&proxyfile, "%s/%s/%s/userproxy.pem",
           proxydir, user_dn_enc, delegation_id);
           
  free(user_dn_enc);

  /* set up to write proxy file */

  ofp = fopen(proxyfile, "w");
  chmod(proxyfile, S_IRUSR | S_IWUSR);
  free(proxyfile);

  if (ofp == NULL)
    {
      fclose(ifp);
      free(prvkeyfile);
      return GRST_RET_FAILED;
    }

  /* write out the most recent proxy by itself */

  if (cert = sk_X509_value(certstack, 0))
    {
      certmem = BIO_new(BIO_s_mem());
      if (PEM_write_bio_X509(certmem, cert) == 1)
        {
          ptrlen = BIO_get_mem_data(certmem, &ptr);
          fwrite(ptr, 1, ptrlen, ofp);
        }

      BIO_free(certmem);
    }

  /* insert proxy private key, read from private key file */

  while ((c = fgetc(ifp)) != EOF) fputc(c, ofp);
  unlink(prvkeyfile);
  free(prvkeyfile);

  for (i=1; i <= sk_X509_num(certstack) - 1; ++i)
        /* loop through the proxy chain starting at 2nd most recent proxy */
     {
       if (cert = sk_X509_value(certstack, i))
         {
           certmem = BIO_new(BIO_s_mem());
           if (PEM_write_bio_X509(certmem, cert) == 1)
             {
               ptrlen = BIO_get_mem_data(certmem, &ptr);
               fwrite(ptr, 1, ptrlen, ofp);
             }

           BIO_free(certmem);
         }
     }

  sk_X509_free(certstack);

  if (fclose(ifp) != 0) return GRST_RET_FAILED;
  if (fclose(ofp) != 0) return GRST_RET_FAILED;

  return GRST_RET_OK;
}
