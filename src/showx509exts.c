
#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include <openssl/buffer.h>
#include <openssl/objects.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/bio.h>

#include "gridsite.h"

#define MAXTAG 500
                                 
main()
{
   X509   *cert, *tmpcert;
   STACK_OF(X509) *certstack = sk_X509_new_null();
   FILE   *fp;
   struct vomsdata *vd;
   int    i, j, vomserror, i1, i2, j1, j2, lastobject;
   X509_EXTENSION *ex;
   ASN1_OBJECT *asnobject;
   char s[80], *t;
   ASN1_OCTET_STRING *asndata;
   BIO *out;
   unsigned char *p, *op, *tot, *p1, *p2, *q, *oq;
   long len1, length1, len2, length2;
   int tag,xclass,ret=0;
   struct GRSTasn1TagList taglist[MAXTAG+1];
   int lasttag=-1, itag;
   
 
   OpenSSL_add_all_algorithms();
   ERR_load_crypto_strings();
//   seed_prng();
   
//   fp = fopen("proxy-with-voms", "r");
   fp = fopen("/tmp/x509up_u300", "r");
   
   cert = PEM_read_X509(fp, NULL, NULL, NULL);
      
   fclose(fp);

   out=BIO_new(BIO_s_file());                                                                                        
   BIO_set_fp(out,stdout,BIO_NOCLOSE|BIO_FP_TEXT);
        
   for (i = 0; i < X509_get_ext_count(cert); ++i)
      {
        lasttag=-1;
      
        ex = X509_get_ext(cert, i);

        OBJ_obj2txt(s, sizeof(s), X509_EXTENSION_get_object(ex), 1);        
        printf("%d OID=%s\n", i, s);
        
        asnobject = X509_EXTENSION_get_object(ex);
        asndata = X509_EXTENSION_get_data(ex);

        p1 = ASN1_STRING_data(asndata);
        p = p1;
        length1 = ASN1_STRING_length(asndata);
              
        GRSTasn1ParseDump(out, p1, length1, taglist, MAXTAG, &lasttag);

{
        int n, tag, xclass;
        unsigned char *q, buf[100];
        const unsigned char *dn, hash[EVP_MAX_MD_SIZE];
        ASN1_OBJECT *obj = NULL;
        const EVP_MD *m;
        EVP_MD_CTX ctx;
        char creds[501][101];
        int lastcred = -1;
   
        itag = GRSTasn1SearchTaglist(taglist, lasttag, 
               "-1-1-1-1-2-1-1-1-1-1-1-1");
               
        X509_NAME *xname;
        
        q = &p[taglist[itag].start];
        
        d2i_ASN1_OBJECT(&obj, &q, taglist[itag].length + 
                                  taglist[itag].headerlength);

        n  = OBJ_obj2nid(obj);
        dn = OBJ_nid2sn(n);
                         
//        dn = X509_NAME_oneline(xname,NULL,0);
        
        if (obj != NULL) printf("n=%d dn=%s obj2txt=%s\n", n, dn, OBJ_obj2txt(NULL,0,obj,1));
        else  printf("n=%d dn=%s obj2txt=NULL\n", n, dn);

        GRSTasn1GetX509Name(buf, 99, "-1-1-1-1-2-1-1-1-1-%d-1-%d", 
                            p1, taglist, lasttag);
        printf("%s\n", buf);
        GRSTasn1GetX509Name(buf, 99, "-1-1-1-1-3-1-1-1-%d-1-%d", 
                            p1, taglist, lasttag);
        printf("%s\n", buf);

        lastcred = -1;        
        ret = GRSTx509ParseVomsExt(&lastcred, 500, 100, creds, 0, 2000040861,
                             ex, 
                  "/C=UK/O=eScience/OU=Manchester/L=HEP/CN=Andrew McNab",
                  "/etc/grid-security/vomsdir");
                  
                  
        printf("GRSTx509ParseVomsExt() returns %d, %d\n", ret, lastcred);
                  
        for (j=0; j <= lastcred;  ++j)
         printf("cred=%d %s\n", j, creds[j]);
        
/*        
        m = EVP_md5();
        EVP_DigestInit(&ctx, m); 
        EVP_DigestUpdate(&ctx, delegation_id, strlen(delegation_id));
        EVP_DigestFinal(&ctx, hash, &delegation_id_len);
 */      
}              

/*       
        itag = GRSTasn1SearchTaglist(taglist, &lasttag,
                                     "1-1-1-1-1-7-1-2-1-2-1");
                                    
        printf("tag=%d %s %d %.*s\n",
               itag, taglist[itag].treecoords, taglist[itag].tag,
               taglist[itag].length, 
               &p[taglist[itag].start+taglist[itag].headerlength]);
*/
      }
}
