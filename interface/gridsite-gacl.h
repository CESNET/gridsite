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

/*---------------------------------------------------------------*
 * For more about GridSite: http://www.gridsite.org/             *
 *---------------------------------------------------------------*/

#ifndef HEADER_GACL_H
#define HEADER_GACL_H
#endif

#ifndef GACL_LIB_VERSION
#define GACL_LIB_VERSION "x.x.x"
#endif

typedef GRSTgaclCred GACLcred;

typedef int                GACLaction;
typedef unsigned int       GACLperm;

typedef GRSTgaclEntry  GACLentry;

typedef GRSTgaclAcl    GACLacl;  

typedef GRSTgaclUser   GACLuser;

extern char      *gacl_perm_syms[];
extern GACLperm   gacl_perm_vals[];

#define GACL_PERM_NONE  GRST_PERM_NONE
#define GACL_PERM_READ  GRST_PERM_READ
#define GACL_PERM_LIST  GRST_PERM_LIST
#define GACL_PERM_WRITE GRST_PERM_WRITE
#define GACL_PERM_ADMIN GRST_PERM_ADMIN

#define GACLhasNone(perm)  (perm == 0)
#define GACLhasRead(perm)  ((perm & GRST_PERM_READ) != 0)
#define GACLhasList(perm)  ((perm & GRST_PERM_LIST) != 0)
#define GACLhasWrite(perm) ((perm & GRST_PERM_WRITE) != 0)
#define GACLhasAdmin(perm) ((perm & GRST_PERM_ADMIN) != 0)

#define GACL_ACTION_ALLOW GRST_ACTION_ALLOW
#define GACL_ACTION_DENY  GRST_ACTION_DENY

#define GACL_ACL_FILE GRST_ACL_FILE
#define GACL_DN_LISTS GRST_DN_LISTS

#define GACLinit() GRSTgaclInit()

#define GACLnewCred(x)		GRSTgaclCredNew((x))
/* GACLcred  *GACLnewCred(char *); */

#define GACLaddToCred(x,y,z)	GRSTgaclCredAddValue((x),(y),(z))
/* int        GACLaddToCred(GACLcred *, char *, char *); */

#define GACLfreeCred(x)		GRSTgaclCredFree((x))
/* int        GACLfreeCred(GACLcred *); */

#define GACLaddCred(x,y)	GRSTgaclEntryAddCred((x),(y))
/* int        GACLaddCred(GACLentry *, GACLcred *); */

#define GACLdelCred(x,y)	GRSTgaclEntryDelCred((x),(y))
/* int        GACLdelCred(GACLentry *, GACLcred *); */

#define GACLprintCred(x,y)	GRSTgaclCredPrint((x),(y))
/*  int        GACLprintCred(GACLcred *, FILE *); */


#define GACLnewEntry()		GRSTgaclEntryNew()
/*  GACLentry *GACLnewEntry(void); */

#define GACLfreeEntry(x)	GRSTgaclEntryFree((x))
/*  int        GACLfreeEntry(GACLentry *); */

#define GACLaddEntry(x,y)	GRSTgaclAclAddEntry((x),(y))
/*  int        GACLaddEntry(GACLacl *, GACLentry *); */

#define GACLprintEntry(x,y)	GRSTgaclEntryPrint((x),(y))
/*  int        GACLprintEntry(GACLentry *, FILE *); */


#define GACLprintPerm(x,y)	GRSTgaclPermPrint((x),(y))
/* int        GACLprintPerm(GACLperm, FILE *); */

#define GACLallowPerm(x,y)	GRSTgaclEntryAllowPerm((x),(y))
/*  int        GACLallowPerm(GACLentry *, GACLperm); */

#define GACLunallowPerm(x,y)	GRSTgaclEntryUnallowPerm((x),(y))
/* int        GACLunallowPerm(GACLentry *, GACLperm); */

#define GACLdenyPerm(x,y)	GRSTgaclEntryDenyPerm((x),(y))
/*  int        GACLdenyPerm(GACLentry *, GACLperm); */

#define GACLundenyPerm(x,y)	GRSTgaclEntryUndenyPerm((x),(y))
/*  int        GACLundenyPerm(GACLentry *, GACLperm); */

#define GACLpermToChar(x)	GRSTgaclPermToChar((x))
/*  char      *GACLpermToChar(GACLperm); */

#define GACLcharToPerm(x)	GRSTgaclPermFromChar((x))
/*  GACLperm   GACLcharToPerm(char *); */

#define GACLnewAcl()		GRSTgaclAclNew()
/*  GACLacl   *GACLnewAcl(void); */

#define GACLfreeAcl(x)		GRSTgaclAclFree((x))
/*  int        GACLfreeAcl(GACLacl *); */

#define GACLprintAcl(x,y)	GRSTgaclAclPrint((x),(y))
/*  int        GACLprintAcl(GACLacl *, FILE *); */

#define GACLsaveAcl(x,y)	GRSTgaclAclSave((y),(x))
/*  int        GACLsaveAcl(char *, GACLacl *); */

#define GACLloadAcl(x)		GRSTgaclAclLoadFile((x))
/*  GACLacl   *GACLloadAcl(char *); */

#define GACLfindAclForFile(x)	GRSTgaclFileFindAclname((x))
/*  char      *GACLfindAclForFile(char *); */

#define GACLloadAclForFile(x)	GRSTgaclAclLoadforFile((x))
/*  GACLacl   *GACLloadAclForFile(char *); */

#define GACLisAclFile(x)	GRSTgaclFileIsAcl((x))
/*  int        GACLisAclFile(char *); */


#define GACLnewUser(x)		GRSTgaclUserNew((x))
/*  GACLuser *GACLnewUser(GACLcred *); */

#define GACLfreeUser(x)		GRSTgaclUserFree((x))
/*  int       GACLfreeUser(GACLuser *); */

#define GACLuserAddCred(x,y)	GRSTgaclUserAddCred((x),(y))
/*  int       GACLuserAddCred(GACLuser *, GACLcred *); */

#define GACLuserHasCred(x,y)	GRSTgaclUserHasCred((x),(y))
/*  int       GACLuserHasCred(GACLuser *, GACLcred *); */

#define GACLuserFindCredType(x,y) GRSTgaclUserFindCredtype((x),(y))
/*  GACLcred *GACLuserFindCredType(GACLuser *, char *); */

#define GACLtestDnList(x,y)	GRSTgaclDNlistHasUser((x),(y))
/*  int        GACLtestDnList(char *, GACLuser *); */

#define GACLtestUserAcl(x,y)	GRSTgaclAclTestUser((x),(y))
/*  GACLperm   GACLtestUserAcl(GACLacl *, GACLuser *); */

#define GACLtestExclAcl(x,y)	GRSTgaclAclTestexclUser((x),(y))
/*  GACLperm   GACLtestExclAcl(GACLacl *, GACLuser *); */


#define GACLurlEncode(x)	GRSThttpUrlEncode((x))
/*  char      *GACLurlEncode(char *); */

#define GACLmildUrlEncode(x)	GRSThttpUrlMildencode((x))
/*  char      *GACLmildUrlEncode(char *); */

//GACLentry *GRSTgaclEntryParse(xmlNodePtr cur);
/*  special function for legacy EDG LB service */
