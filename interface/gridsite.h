/*
   Copyright (c) 2002-5, Andrew McNab, University of Manchester
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

/*---------------------------------------------------------------*
 * For more about GridSite: http://www.gridsite.org/             *
 *---------------------------------------------------------------*/

#ifndef HEADER_SSL_H
#include <openssl/ssl.h>
#endif

#ifndef HEADER_CRYPTO_H
#include <openssl/crypto.h>
#endif

#ifndef FALSE
#define FALSE (0)
#endif
#ifndef TRUE
#define TRUE (!FALSE)
#endif

/// Everything ok (= OpenSSL X509_V_OK)
#define GRST_RET_OK		0

/// Failed for unspecified reason
#define GRST_RET_FAILED		1000

/// Failed to find certificate in some cert store / directory
#define GRST_RET_CERT_NOT_FOUND	1001

/// Bad signature
#define GRST_RET_BAD_SIGNATURE	1002

/// No such file or directory
#define GRST_RET_NO_SUCH_FILE	1003

typedef struct { char                      *name;
                 char                      *value;
                 void                      *next;  } GRSTgaclNamevalue;

typedef struct { char                      *type;
                 int                        delegation;
                 GRSTgaclNamevalue         *firstname;
                 void                      *next;      } GRSTgaclCred;
 
typedef int                GRSTgaclAction;
typedef unsigned int       GRSTgaclPerm;
 
typedef struct { GRSTgaclCred   *firstcred;
                 GRSTgaclPerm    allowed;
                 GRSTgaclPerm    denied;
                 void           *next;    } GRSTgaclEntry;
 
typedef struct { GRSTgaclEntry *firstentry; } GRSTgaclAcl;
 
typedef struct { GRSTgaclCred *firstcred; 
                 char         *dnlists;   } GRSTgaclUser;

#define GRST_PERM_NONE   0
#define GRST_PERM_READ   1
#define GRST_PERM_EXEC   2
#define GRST_PERM_LIST   4
#define GRST_PERM_WRITE  8
#define GRST_PERM_ADMIN 16
#define GRST_PERM_ALL   31

/* DO NOT USE PermIsNone!! */
#define GRSTgaclPermIsNone(perm)    (perm == 0)

#define GRSTgaclPermHasNone(perm)    (perm == 0)
#define GRSTgaclPermHasRead(perm)  ((perm & GRST_PERM_READ ) != 0)
#define GRSTgaclPermHasExec(perm)  ((perm & GRST_PERM_EXEC ) != 0)
#define GRSTgaclPermHasList(perm)  ((perm & GRST_PERM_LIST ) != 0)
#define GRSTgaclPermHasWrite(perm) ((perm & GRST_PERM_WRITE) != 0)
#define GRSTgaclPermHasAdmin(perm) ((perm & GRST_PERM_ADMIN) != 0)

#define GRST_ACTION_ALLOW 0
#define GRST_ACTION_DENY  1

#define GRST_HIST_PREFIX  ".grsthist"
#define GRST_ACL_FILE     ".gacl"
#define GRST_DN_LISTS     "/etc/grid-security/dn-lists"
#define GRST_RECURS_LIMIT 9

#define GRST_PROXYCERTINFO_OID	"1.3.6.1.4.1.3536.1.222"
#define GRST_VOMS_OID		"1.3.6.1.4.1.8005.100.100.5"
#define GRST_VOMS_DIR		"/etc/grid-security/vomsdir"

#define GRST_ASN1_MAXCOORDLEN	50
#define GRST_ASN1_MAXTAGS	500

struct GRSTasn1TagList { char treecoords[GRST_ASN1_MAXCOORDLEN+1];
                         int  start;
                         int  headerlength;
                         int  length;
                         int  tag; } ;

#define GRST_HTTP_PORT		777
#define GRST_HTTPS_PORT		488
#define GRST_HTCP_PORT		777
                         
#define GRSThtcpNOPop 0
#define GRSThtcpTSTop 1

typedef struct { unsigned char length_msb;
                 unsigned char length_lsb;
                 char text[1]; } GRSThtcpCountstr;

#define GRSThtcpCountstrLen(string) (256*((string)->length_msb) + (string)->length_lsb)

typedef struct { unsigned char total_length_msb;
                 unsigned char total_length_lsb;
                 unsigned char version_msb;
                 unsigned char version_lsb;
                 unsigned char data_length_msb;
                 unsigned char data_length_lsb;
                 unsigned int  response : 4;
                 unsigned int  opcode   : 4;
                 unsigned int  rr       : 1;                 
                 unsigned int  f1       : 1;
                 unsigned int  reserved : 6;
                 unsigned int  trans_id;	/* must be 4 bytes */
                 GRSThtcpCountstr *method;
                 GRSThtcpCountstr *uri;
                 GRSThtcpCountstr *version;
                 GRSThtcpCountstr *req_hdrs;
                 GRSThtcpCountstr *resp_hdrs;
                 GRSThtcpCountstr *entity_hdrs;
                 GRSThtcpCountstr *cache_hdrs;   } GRSThtcpMessage;

int GRSTgaclInit(void);

/* #define GACLnewCred(x)		GRSTgaclCredNew((x)) */
GRSTgaclCred  *GRSTgaclCredNew(char *);

/* #define GACLaddToCred(x,y,z)	GRSTgaclCredAddValue((x),(y),(z)) */
int        GRSTgaclCredAddValue(GRSTgaclCred *, char *, char *);

#define GRSTgaclCredSetDelegation(cred, level) ((cred)->delegation = (level))
#define GRSTgaclCredGetDelegation(cred) ((cred)->delegation)

/* #define GACLfreeCred(x)		GRSTgaclCredFree((x)) */
int        GRSTgaclCredFree(GRSTgaclCred *);

/*  #define GACLaddCred(x,y)	GRSTgaclEntryAddCred((x),(y)) */
int        GRSTgaclEntryAddCred(GRSTgaclEntry *, GRSTgaclCred *);

/*  #define GACLdelCred(x,y)	GRSTgaclEntryDelCred((x),(y)) */
int        GRSTgaclEntryDelCred(GRSTgaclEntry *, GRSTgaclCred *);

/*  #define GACLprintCred(x,y)	GRSTgaclCredPrint((x),(y)) */
int        GRSTgaclCredCredPrint(GRSTgaclCred *, FILE *);


/*  #define GACLnewEntry(x)		GRSTgaclEntryNew((x)) */
GRSTgaclEntry *GRSTgaclEntryNew(void);

/*  #define GACLfreeEntry(x)	GRSTgaclEntryFree((x)) */
int        GRSTgaclEntryFree(GRSTgaclEntry *);

/*  #define GACLaddEntry(x,y)	GRSTgaclAclAddEntry((x),(y)) */
int        GRSTgaclAclAddEntry(GRSTgaclAcl *, GRSTgaclEntry *);

/*  #define GACLprintEntry(x,y)	GRSTgaclEntryPrint((x),(y)) */
int        GRSTgaclEntryPrint(GRSTgaclEntry *, FILE *);


/*  #define GACLprintPerm(x,y)	GRSTgaclPermPrint((x),(y)) */
int        GRSTgaclPermPrint(GRSTgaclPerm, FILE *);

/*  #define GACLallowPerm(x,y)	GRSTgaclEntryAllowPerm((x),(y)) */
int        GRSTgaclEntryAllowPerm(GRSTgaclEntry *, GRSTgaclPerm);

/*  #define GACLunallowPerm(x,y)	GRSTgaclEntryUnallowPerm((x),(y)) */
int        GRSTgaclEntryUnallowPerm(GRSTgaclEntry *, GRSTgaclPerm);

/*  #define GACLdenyPerm(x,y)	GRSTgaclEntryDenyPerm((x),(y)) */
int        GRSTgaclEntryDenyPerm(GRSTgaclEntry *, GRSTgaclPerm);

/*  #define GACLundenyPerm(x,y)	GRSTgaclEntryUndenyPerm((x),(y)) */
int        GRSTgaclEntryUndenyPerm(GRSTgaclEntry *, GRSTgaclPerm);

/*  #define GACLpermToChar(x)	GRSTgaclPermToChar((x)) */
char      *GRSTgaclPermToChar(GRSTgaclPerm);

/*  #define GACLcharToPerm(x)	GRSTgaclPermFromChar((x)) */
GRSTgaclPerm   GRSTgaclPermFromChar(char *);

/*  #define GACLnewAcl(x)		GRSTgaclAclNew((x)) */
GRSTgaclAcl   *GRSTgaclAclNew(void);

/*  #define GACLfreeAcl(x)		GRSTgaclAclFree((x)) */
int        GRSTgaclAclFree(GRSTgaclAcl *);

/*  #define GACLprintAcl(x,y)	GRSTgaclAclPrint((x),(y)) */
int        GRSTgaclAclPrint(GRSTgaclAcl *, FILE *);

/*  #define GACLsaveAcl(x,y)	GRSTgaclAclSave((y),(x)) */
int        GRSTgaclAclSave(GRSTgaclAcl *, char *);

/*  #define GACLloadAcl(x)		GRSTgaclFileLoadAcl((x)) */
GRSTgaclAcl   *GRSTgaclAclLoadFile(char *);

/*  #define GACLfindAclForFile(x)	GRSTgaclFileFindAclname((x)) */
char      *GRSTgaclFileFindAclname(char *);

/*  #define GACLloadAclForFile(x)	GRSTgaclFileLoadAcl((x)) */
GRSTgaclAcl   *GRSTgaclAclLoadforFile(char *);

/*  #define GACLisAclFile(x)	GRSTgaclFileIsAcl((x)) */
int        GRSTgaclFileIsAcl(char *);


/*  #define GACLnewUser(x)		GRSTgaclUserNew((x)) */
GRSTgaclUser *GRSTgaclUserNew(GRSTgaclCred *);

/*  #define GACLfreeUser(x)		GRSTgaclUserFree((x)) */
int       GRSTgaclUserFree(GRSTgaclUser *);

/*  #define GACLuserAddCred(x,y)	GRSTgaclUserAddCred((x),(y)) */
int       GRSTgaclUserAddCred(GRSTgaclUser *, GRSTgaclCred *);

/*  #define GACLuserHasCred(x,y)	GRSTgaclUserHasCred((x),(y)) */
int       GRSTgaclUserHasCred(GRSTgaclUser *, GRSTgaclCred *);

int       GRSTgaclUserSetDNlists(GRSTgaclUser *, char *);

/*  #define GACLuserFindCredType(x,y) GRSTgaclUserFindCredtype((x),(y)) */
GRSTgaclCred *GRSTgaclUserFindCredtype(GRSTgaclUser *, char *);

/*  #define GACLtestDnList(x,y)	GRSTgaclDNlistHasUser((x),(y)) */
int GRSTgaclDNlistHasUser(char *, GRSTgaclUser *);

/*  #define GACLtestUserAcl(x,y)	GRSTgaclAclTestUser((x),(y)) */
GRSTgaclPerm   GRSTgaclAclTestUser(GRSTgaclAcl *, GRSTgaclUser *);

/*  #define GACLtestExclAcl(x,y)	GRSTgaclAclTestexclUser((x),(y)) */
GRSTgaclPerm   GRSTgaclAclTestexclUser(GRSTgaclAcl *, GRSTgaclUser *);

char      *GRSThttpUrlDecode(char *);

/*  #define GACLurlEncode(x)	GRSThttpUrlEncode((x)) */
char      *GRSThttpUrlEncode(char *);

/*  #define GACLmildUrlEncode(x)	GRSThttpMildUrlEncode((x)) */
char      *GRSThttpUrlMildencode(char *);

int GRSTx509NameCmp(char *, char *);

int GRSTx509KnownCriticalExts(X509 *);

int GRSTx509IsCA(X509 *);
int GRSTx509CheckChain(int *, X509_STORE_CTX *);
int GRSTx509VerifyCallback(int, X509_STORE_CTX *);

int GRSTx509GetVomsCreds(int *, int, size_t, char *, X509 *, STACK_OF(X509) *, char *);
GRSTgaclCred *GRSTx509CompactToCred(char *);
int GRSTx509CompactCreds(int *, int, size_t, char *, STACK_OF(X509) *, char *, X509 *);
char *GRSTx509CachedProxyFind(char *, char *, char *);
char *GRSTx509FindProxyFileName(void);
int GRSTx509MakeProxyCert(char **, FILE *, char *, char *, char *, int);
char *GRSTx509CachedProxyKeyFind(char *, char *, char *);
int GRSTx509MakeProxyRequest(char **, char *, char *, char *);
int GRSTx509StringToChain(STACK_OF(X509) **, char *);
char *GRSTx509MakeProxyFileName(char *, STACK_OF(X509) *);
int GRSTx509CacheProxy(char *, char *, char *, char *);

#define GRST_HEADFILE   "gridsitehead.txt"
#define GRST_FOOTFILE   "gridsitefoot.txt"
#define GRST_ADMIN_FILE "gridsite-admin.cgi"

typedef struct { char *text;
                 void *next; } GRSThttpCharsList;

typedef struct { size_t             size;
                 GRSThttpCharsList *first;
                 GRSThttpCharsList *last;  } GRSThttpBody;

void  GRSThttpBodyInit(GRSThttpBody *); 
void  GRSThttpPrintf(GRSThttpBody *, char *, ...);
int   GRSThttpCopy(GRSThttpBody *, char *);
void  GRSThttpWriteOut(GRSThttpBody *);
int   GRSThttpPrintHeaderFooter(GRSThttpBody *, char *, char *);
char *GRSThttpGetCGI(char *);

time_t GRSTasn1TimeToTimeT(char *, size_t);
int    GRSTasn1SearchTaglist(struct GRSTasn1TagList taglist[], int, char *);
int    GRSTasn1ParseDump(BIO *, unsigned char *, long,
                         struct GRSTasn1TagList taglist[], int, int *);
int    GRSTasn1GetX509Name(char *, int, char *, char *,
                           struct GRSTasn1TagList taglist[], int);

int    GRSThtcpNOPrequestMake(char **, int *, unsigned int);
int    GRSThtcpNOPresponseMake(char **, int *, unsigned int);
int    GRSThtcpTSTrequestMake(char **, int *, unsigned int, char *, char *, char *);
int    GRSThtcpTSTresponseMake(char **, int *, unsigned int, char *, char *, char *);
int    GRSThtcpMessageParse(GRSThtcpMessage *, char *, int);
