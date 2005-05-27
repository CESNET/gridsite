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
*/
/*---------------------------------------------------------------*
 * For more information about GridSite: http://www.gridsite.org/ *
 *---------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>              
#include <string.h>
#include <dirent.h>
#include <ctype.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fnmatch.h>

#include <libxml/xmlmemory.h>
#include <libxml/tree.h>
#include <libxml/parser.h>

#include "gridsite.h"

/*                                                                      *
 * Global variables, shared by all GACL functions by private to libgacl *
 *                                                                      */
 
char     *grst_perm_syms[] =  { "none",
                                "read",
                                "exec",
                                "list",
                                "write",
                                "admin",
                                NULL              };

GRSTgaclPerm grst_perm_vals[] =  {   GRST_PERM_NONE,
                                     GRST_PERM_READ,
                                     GRST_PERM_EXEC,
                                     GRST_PERM_LIST,
                                     GRST_PERM_WRITE,
                                     GRST_PERM_ADMIN,
                                     -1                };
                                 
int GRSTgaclInit(void)
{
  xmlInitParser();

  LIBXML_TEST_VERSION

  xmlKeepBlanksDefault(0);

  return 1;
}                             

/* declare these two private functions at the start */

GRSTgaclAcl *GRSTgaclAclParse(xmlDocPtr, xmlNodePtr, GRSTgaclAcl *);
GRSTgaclAcl *GRSTxacmlAclParse(xmlDocPtr, xmlNodePtr, GRSTgaclAcl *);

/*                                             *
 * Functions to manipulate GRSTgaclCred structures *
 *                                             */

GRSTgaclCred *GRSTgaclCredNew(char *type)
/*
    GRSTgaclCredNew - allocate a new GRSTgaclCred structure, and return
                      it's pointer or NULL on (malloc) error.
*/
{
  GRSTgaclCred *newcred; 

  if (type == NULL) return NULL;

  newcred = malloc(sizeof(GRSTgaclCred));
  if (newcred == NULL) return NULL;
  
  newcred->type       = strdup(type);
  newcred->delegation = 0;
  newcred->firstname  = NULL;
  newcred->next       = NULL;

  return newcred;
}

int GRSTgaclCredAddValue(GRSTgaclCred *cred, char *rawname, char *rawvalue)
/*
    GRSTgaclCredAddValue - add a name/value pair to a GRSTgaclCred
*/
{
  int                i;
  char              *name, *value;
  GRSTgaclNamevalue *p;

  name  = strdup(rawname);

  /* no leading or trailing space in value */

  value = rawvalue; 
  while ((*value != '\0') && isspace(*value)) ++value;

  value = strdup(value);

  for (i=strlen(value) - 1; (i >= 0) && isspace(value[i]); --i) value[i]='\0';
  
  if (cred->firstname == NULL) 
    {
      cred->firstname = malloc(sizeof (GRSTgaclNamevalue));
      (cred->firstname)->name  = name;
      (cred->firstname)->value = value;
      (cred->firstname)->next  = NULL;
    }
  else
    {
      p = cred->firstname; 
  
      while (p->next != NULL) p = (GRSTgaclNamevalue *) p->next;
  
      p->next = malloc(sizeof(GRSTgaclNamevalue));
      ((GRSTgaclNamevalue *) p->next)->name  = name;
      ((GRSTgaclNamevalue *) p->next)->value = value;
      ((GRSTgaclNamevalue *) p->next)->next  = NULL;
    } 
  
  return 1;
}

static int GRSTgaclNamevalueFree(GRSTgaclNamevalue *p)
{
  if (p == NULL) return 1;
  
  if (p->next  != NULL) 
        GRSTgaclNamevalueFree((GRSTgaclNamevalue *) p->next);
  if (p->name  != NULL) free(p->name);
  if (p->value != NULL) free(p->value);
  free(p);
  
  return 1;
}

int GRSTgaclCredFree(GRSTgaclCred *cred)
/*
    GRSTgaclCredFree - free memory structures of a GRSTgaclCred, 
    returning 1 always!
*/
{
  if (cred == NULL) return 1;

  GRSTgaclNamevalueFree(cred->firstname);  
  if (cred->type != NULL) free(cred->type);
  free(cred);
  
  return 1;
}

static int GRSTgaclCredsFree(GRSTgaclCred *firstcred)
/*
    GRSTgaclCredsFree - free a cred and all the creds in its *next chain
*/
{
  if (firstcred == NULL) return 0;
  
  if (firstcred->next != NULL) GRSTgaclCredsFree(firstcred->next);
  
  return GRSTgaclCredFree(firstcred);
}

static int GRSTgaclCredInsert(GRSTgaclCred *firstcred, GRSTgaclCred *newcred)
/* 
    GRSTgaclCredInsert - insert a cred in the *next chain of firstcred

    FOR THE MOMENT THIS JUST APPENDS!
*/
{
  if (firstcred == NULL) return 0;
  
  if (firstcred->next == NULL)
    {
      firstcred->next = newcred;
      return 1;
    }

  return GRSTgaclCredInsert(firstcred->next, newcred);     
}

int GRSTgaclEntryAddCred(GRSTgaclEntry *entry, GRSTgaclCred *cred)
/*  
    GRSTaddCred - add a new credential to an existing entry, returning 1
    on success or 0 on error 
*/ 
{
  if (entry == NULL) return 0;
 
  if (entry->firstcred == NULL) 
    {
      entry->firstcred = cred;
      return 1;
    }
  else return GRSTgaclCredInsert(entry->firstcred, cred);
}

static int GRSTgaclCredRemoveCred(GRSTgaclCred *firstcred, GRSTgaclCred *oldcred)
/* 
    (Private)

    GRSTgaclCredRemoveCred - remove a cred in the *next chain of firstcred
                     and relink the chain
*/
{
  if (firstcred == NULL) return 0;

// yeah, I know
}

int GRSTgaclEntryDelCred(GRSTgaclEntry *entry, GRSTgaclCred *cred)
/*  
    GRSTgaclEntryDelCred - remove a new cred from an entry, returning 1
    on success (or absense) or 0 on error.
*/ 
{
  if (entry == NULL) return 0;

  return GRSTgaclCredRemoveCred(entry->firstcred, cred);
}

int GRSTgaclCredPrint(GRSTgaclCred *cred, FILE *fp)
/* 
   GRSTgaclCredPrint - print a credential and any name-value pairs is contains
*/
{
  char              *q;
  GRSTgaclNamevalue *p;

  if (cred->firstname != NULL)
    {
      fprintf(fp, "<%s>\n", cred->type);
    
      p = cred->firstname;
      
      do { 
           fprintf(fp, "<%s>", p->name);

            for (q=p->value; *q != '\0'; ++q)
              if      (*q == '<')  fputs("&lt;",   fp);
              else if (*q == '>')  fputs("&gt;",   fp);
              else if (*q == '&')  fputs("&amp;" , fp);
              else if (*q == '\'') fputs("&apos;", fp);
              else if (*q == '"')  fputs("&quot;", fp);
              else                 fputc(*q, fp);

           fprintf(fp, "</%s>\n", p->name);

           p = (GRSTgaclNamevalue *) p->next;
         
         } while (p != NULL);

      fprintf(fp, "</%s>\n", cred->type);
    }
  else fprintf(fp, "<%s/>\n", cred->type);
  
  return 1;  
}

/*                                              *
 * Functions to manipulate GRSTgaclEntry structures *
 *                                              */

GRSTgaclEntry *GRSTgaclEntryNew(void)
/*
    GRSTgaclEntryNew - allocate space for a new entry, returning its pointer
                   or NULL on failure.
*/
{
  GRSTgaclEntry *newentry;
  
  newentry = (GRSTgaclEntry *) malloc(sizeof(GRSTgaclEntry));
  if (newentry == NULL) return NULL;

  newentry->firstcred    = NULL;
  newentry->allowed      = 0;
  newentry->denied       = 0;
  newentry->next         = NULL;

  return newentry;
}

int GRSTgaclEntryFree(GRSTgaclEntry *entry)
/* 
    GRSTgaclEntryFree - free up space used by an entry (always returns 1)
*/
{
  int i;
  
  if (entry == NULL) return 1;

  GRSTgaclCredsFree(entry->firstcred);  

  free(entry);
  
  return 1;
}

static int GRSTgaclEntriesFree(GRSTgaclEntry *entry)
/*
    GRSTgaclEntriesFree - free up entry and all entries linked to in its *next 
                      chain
*/
{
  if (entry == NULL) return 0;
  
  if (entry->next != NULL) GRSTgaclEntriesFree(entry->next);
  
  return GRSTgaclEntryFree(entry);  
}

static int GRSTgaclEntryInsert(GRSTgaclEntry *firstentry, GRSTgaclEntry *newentry)
/* 
    GRSTgaclEntryInsert - insert an entry in the *next chain of firstentry

    FOR THE MOMENT THIS JUST APPENDS
*/
{
  if (firstentry == NULL) return 0;
  
  if (firstentry->next == NULL)
    {
      firstentry->next = newentry;
      return 1;
    }

  return GRSTgaclEntryInsert(firstentry->next, newentry);     
}

int GRSTgaclAclAddEntry(GRSTgaclAcl *acl, GRSTgaclEntry *entry)
/*  
    GRSTgaclAclAddEntry - add a new entry to an existing acl, returning 1
    on success or 0 on error 
*/ 
{
  if (acl == NULL) return 0;

  if (acl->firstentry == NULL) 
    { 
      acl->firstentry = entry;
      return 1;
    }
  else return GRSTgaclEntryInsert(acl->firstentry, entry);
}

int GRSTgaclEntryPrint(GRSTgaclEntry *entry, FILE *fp)
{
  GRSTgaclCred  *cred;
  GRSTgaclPerm  i;

  fputs("<entry>\n", fp);
  
  for (cred = entry->firstcred; cred != NULL; cred = cred->next)
                                            GRSTgaclCredPrint(cred, fp);

  if (entry->allowed)
    {
      fputs("<allow>", fp);

      for (i=GRST_PERM_READ; i <= GRST_PERM_ADMIN; ++i)
       if ((entry->allowed) & i) GRSTgaclPermPrint(i, fp);

      fputs("</allow>\n", fp);
    }
    

  if (entry->denied)
    {
      fputs("<deny>", fp);

      for (i=GRST_PERM_READ; i <= GRST_PERM_ADMIN; ++i)
       if (entry->denied & i) GRSTgaclPermPrint(i, fp);

      fputs("</deny>\n", fp);
    }
    
  fputs("</entry>\n", fp);

  return 1;
}

/*                                         *
 * Functions to manipulate GRSTgaclPerm items *
 *                                         */

int GRSTgaclPermPrint(GRSTgaclPerm perm, FILE *fp)
{
  GRSTgaclPerm i;
  
  for (i=GRST_PERM_READ; grst_perm_syms[i] != NULL; ++i)
       if (perm == grst_perm_vals[i]) 
         {
           fprintf(fp, "<%s/>", grst_perm_syms[i]);
           return 1;
         }
         
  return 0;
}

int GRSTgaclEntryAllowPerm(GRSTgaclEntry *entry, GRSTgaclPerm perm)
{
  entry->allowed = entry->allowed | perm;

  return 1;
}

int GRSTgaclEntryUnallowPerm(GRSTgaclEntry *entry, GRSTgaclPerm perm)
{
  entry->allowed = entry->allowed & ~perm;

  return 1;
}

int GRSTgaclEntryDenyPerm(GRSTgaclEntry *entry, GRSTgaclPerm perm)
{
  entry->denied = entry->denied | perm;

  return 1;
}

int GRSTgaclEntryUndenyPerm(GRSTgaclEntry *entry, GRSTgaclPerm perm)
{
  entry->denied = entry->denied & ~perm;

  return 1;
}

char *GRSTgaclPermToChar(GRSTgaclPerm perm)
/*
   GRSTgaclPermToChar - return char * or NULL corresponding to most significant
                     set bit of perm.
*/
{
  char      *p = NULL;
  GRSTgaclPerm  i;
  
  for (i=0; grst_perm_syms[i] != NULL; ++i)
       if (perm & grst_perm_vals[i]) p = grst_perm_syms[i];

  return p;
}

GRSTgaclPerm GRSTgaclPermFromChar(char *s)
/*
   GRSTgaclPermToChar - return access perm corresponding to symbol s[]
*/
{
  GRSTgaclPerm i;

  for (i=0; grst_perm_syms[i] != NULL; ++i)
       if (strcasecmp(grst_perm_syms[i], s) == 0) return grst_perm_vals[i];

  return -1; 
}

/*                                            *
 * Functions to manipulate GRSTgaclAcl structures *
 *                                            */

GRSTgaclAcl *GRSTgaclAclNew(void)
/*  
    GRSTgaclAclNew - allocate a new acl and return its pointer (or NULL 
                 on failure.)
*/
{
  GRSTgaclAcl *newacl;
  
  newacl = (GRSTgaclAcl *) malloc(sizeof(GRSTgaclAcl));
  if (newacl == NULL) return NULL;
  
  newacl->firstentry = NULL;

  return newacl;
}

int GRSTgaclAclFree(GRSTgaclAcl *acl)
/*
    GRSTgaclAclFree - free up space used by *acl. Always returns 1.
*/
{
  if (acl == NULL) return 1;

  GRSTgaclEntriesFree(acl->firstentry);  

  return 1;
}

int GRSTgaclAclPrint(GRSTgaclAcl *acl, FILE *fp)
{
  GRSTgaclEntry *entry;
  
  fputs("<gacl version=\"0.0.1\">\n", fp);
  
  for (entry = acl->firstentry; entry != NULL; entry = entry->next)
                                            GRSTgaclEntryPrint(entry, fp);

  fputs("</gacl>\n", fp);

  return 1;
}

int GRSTgaclAclSave(GRSTgaclAcl *acl, char *filename)
{
  int   ret;
  FILE *fp;
  
  fp = fopen(filename, "w");
  if (fp == NULL) return 0;
  
  fputs("<?xml version=\"1.0\"?>\n", fp);
  
  ret = GRSTgaclAclPrint(acl, fp);
  
  fclose(fp);
  
  return ret;
}

/*                                                    *
 * Functions for loading and parsing XML using libxml *
 *                                                    */
 
// need to check these for libxml memory leaks? - what needs to be freed?

static GRSTgaclCred *GRSTgaclCredParse(xmlNodePtr cur)
/*
    GRSTgaclCredParse - parse a credential stored in the libxml structure cur, 
                    returning it as a pointer or NULL on error.
*/
{
  xmlNodePtr  cur2;
  GRSTgaclCred   *cred;
  
  cred = GRSTgaclCredNew((char *) cur->name);
  
  cred->firstname = NULL;
  cred->next      = NULL;
  
  for (cur2 = cur->xmlChildrenNode; cur2 != NULL; cur2=cur2->next)
     {
       GRSTgaclCredAddValue(cred, (char *) cur2->name, 
                           (char *) xmlNodeGetContent(cur2));     
     }

  return cred;
}

static GRSTgaclEntry *GRSTgaclEntryParse(xmlNodePtr cur)
/*
    GRSTgaclEntryParse - parse an entry stored in the libxml structure cur,
                     returning it as a pointer or NULL on error.
*/
{
  int        i;
  xmlNodePtr cur2;
  GRSTgaclEntry *entry;
  GRSTgaclCred  *cred;
  GRSTgaclPerm  perm;

  if (xmlStrcmp(cur->name, (const xmlChar *) "entry") != 0) return NULL;
  
  cur = cur->xmlChildrenNode;

  entry = GRSTgaclEntryNew();
  
  while (cur != NULL)
       {
         if (xmlStrcmp(cur->name, (const xmlChar *) "allow") == 0)
           {
             for (cur2 = cur->xmlChildrenNode; cur2 != NULL; cur2=cur2->next)
              for (i=0; grst_perm_syms[i] != NULL; ++i)
               if (xmlStrcmp(cur2->name, 
                             (const xmlChar *) grst_perm_syms[i]) == 0)
                     GRSTgaclEntryAllowPerm(entry, grst_perm_vals[i]);
           }
         else if (xmlStrcmp(cur->name, (const xmlChar *) "deny") == 0)
           {
             for (cur2 = cur->xmlChildrenNode; cur2 != NULL; cur2=cur2->next)
              for (i=0; grst_perm_syms[i] != NULL; ++i)
               if (xmlStrcmp(cur2->name, 
                             (const xmlChar *) grst_perm_syms[i]) == 0)
                     GRSTgaclEntryDenyPerm(entry, grst_perm_vals[i]);
           }
         else if ((cred = GRSTgaclCredParse(cur)) != NULL) 
           {
             if (!GRSTgaclEntryAddCred(entry, cred))
               { 
                 GRSTgaclCredFree(cred);                
                 GRSTgaclEntryFree(entry);
                 return NULL;
               }
           }
         else /* I cannot parse this - give up rather than get it wrong */
           {
             GRSTgaclEntryFree(entry);
             return NULL;
           }
           
         cur=cur->next;
       } 
       
  return entry;
}

GRSTgaclAcl *GRSTgaclAclLoadFile(char *filename)
{
  xmlDocPtr   doc;
  xmlNodePtr  cur;
  GRSTgaclAcl    *acl;

  doc = xmlParseFile(filename);
  if (doc == NULL) return NULL;

  cur = xmlDocGetRootElement(doc);
  if (cur == NULL) return NULL;

  if (!xmlStrcmp(cur->name, (const xmlChar *) "Policy")) { acl=GRSTxacmlAclParse(doc, cur, acl);}
  else if (!xmlStrcmp(cur->name, (const xmlChar *) "gacl")) {acl=GRSTgaclAclParse(doc, cur, acl);}
  else /* ACL format not recognised */
    {
      free(doc);
      free(cur);
      return NULL;
    }

    
  xmlFreeDoc(doc);
  return acl;
}

GRSTgaclAcl *GRSTgaclAclParse(xmlDocPtr doc, xmlNodePtr cur, GRSTgaclAcl *acl)
{
  GRSTgaclEntry  *entry;

  cur = cur->xmlChildrenNode;

  acl = GRSTgaclAclNew();

  while (cur != NULL)
       {
         entry = GRSTgaclEntryParse(cur);
         if (entry == NULL)
           {
             GRSTgaclAclFree(acl);
             xmlFreeDoc(doc);
             return NULL;
           }

         GRSTgaclAclAddEntry(acl, entry);

         cur=cur->next;
       }

  return acl;
}
int GRSTgaclFileIsAcl(char *pathandfile)
/* Return 1 if filename in *pathandfile starts GRST_ACL_FILE
   Return 0 otherwise. */
{
  char *filename;

  filename = rindex(pathandfile, '/');
  if (filename == NULL) filename = pathandfile;
  else                  filename++;

  return (strncmp(filename, GRST_ACL_FILE, sizeof(GRST_ACL_FILE) - 1) == 0);
}

char *GRSTgaclFileFindAclname(char *pathandfile)
/* Return malloc()ed ACL filename that governs the given file or directory 
   (for directories, the ACL file is in the directory itself), or NULL if none
   can be found. */
{
  int          len;
  char        *path, *file, *p;
  struct stat  statbuf;

  len = strlen(pathandfile);
  if (len == 0) return NULL;
  
  path = malloc(len + sizeof(GRST_ACL_FILE) + 2);
  strcpy(path, pathandfile);

  if ((stat(path, &statbuf) == 0)	&&
       S_ISDIR(statbuf.st_mode)		&&
      (path[len-1] != '/'))
    {
      strcat(path, "/");
      ++len;
    }
    
  if (path[len-1] != '/')
    {
      p = rindex(pathandfile, '/');
      if (p != NULL)
        {
          file = &p[1];          
          p = rindex(path, '/');          
          sprintf(p, "/%s:%s", GRST_ACL_FILE, file);

          if (stat(path, &statbuf) == 0) return path;

          *p = '\0'; /* otherwise strip off any filename */
        }
    }

  while (path[0] != '\0')
       {
         strcat(path, "/");
         strcat(path, GRST_ACL_FILE);
         
         if (stat(path, &statbuf) == 0) return path;
           
         p = rindex(path, '/');
         *p = '\0';     /* strip off the / we added for ACL */

         p = rindex(path, '/');
         if (p == NULL) break; /* must start without / and we there now ??? */

         *p = '\0';     /* strip off another layer of / */                 
       }
       
  free(path);
  return NULL;
}

GRSTgaclAcl *GRSTgaclAclLoadforFile(char *pathandfile)
/* Return ACL that governs the given file or directory (for directories,
   the ACL file is in the directory itself.) */
{
  char        *path;
  GRSTgaclAcl     *acl;

  path = GRSTgaclFileFindAclname(pathandfile);
  
  if (path != NULL)
    {
      acl = GRSTgaclAclLoadFile(path);
      free(path);
      return acl;
    }
    
  return NULL;
}

/*                                        *
 * Functions to create and query GACLuser *
 *                                        */

GRSTgaclUser *GRSTgaclUserNew(GRSTgaclCred *cred)
{
  GRSTgaclUser *user;
  
  if (cred == NULL) return NULL;
  
  user = malloc(sizeof(GRSTgaclUser));
  
  if (user != NULL) user->firstcred = cred;
  
  user->dnlists = NULL;
  
  return user;
}

int GRSTgaclUserFree(GRSTgaclUser *user)
{
  if (user == NULL) return 1;
  
  if (user->firstcred != NULL) GRSTgaclCredsFree(user->firstcred);

  if (user->dnlists != NULL) free(user->dnlists);
  
  free(user);
  
  return 1;
}

int GRSTgaclUserAddCred(GRSTgaclUser *user, GRSTgaclCred *cred)
{
  GRSTgaclCred *crediter;

  if ((user == NULL) || (cred == NULL)) return 0;

  if (user->firstcred == NULL) 
    {
      user->firstcred = cred;
      cred->next = NULL; /* so cannot be used to add whole lists */
      return 1;
    }
  
  crediter = user->firstcred;  

  while (crediter->next != NULL) crediter = crediter->next;

  crediter->next = cred;
  cred->next = NULL; /* so cannot be used to add whole lists */
       
  return 1;
}

int GRSTgaclUserHasCred(GRSTgaclUser *user, GRSTgaclCred *cred)
/* test if the user has the given credential */
{
  GRSTgaclCred      *crediter;
  GRSTgaclNamevalue *usernamevalue, *crednamevalue;
  int i;
  char buf[12];

  if (cred == NULL) return 0;

  if (strcmp(cred->type, "any-user") == 0) return 1;
  
  if (user == NULL) return 0;
  
  if (strcmp(cred->type, "dn-list") == 0) 
    {
      if ((cred->firstname == NULL) ||
          (strcmp((cred->firstname)->name, "url") != 0) ||
          ((cred->firstname)->next != NULL))                 return 0;
      
      return GRSTgaclDNlistHasUser((cred->firstname)->value, user);
    }
  /* Check for voms attributes*/
  
  if  (strcmp(cred->type, "voms")==0)
    {
      if ( (user->firstcred==NULL) ||
           ((user->firstcred)->firstname == NULL) ||
           (cred->firstname == NULL) ||
           (strcmp((cred->firstname)->name, "fqan") != 0) ||
           ((cred->firstname)->next != NULL)) return 0;
          
      /*assuimng only one name/value pair per cred*/
      for(i=1; ; i++)
      {
	      sprintf (buf, "GRST_CRED_%d", i);
	      if (getenv(buf)==NULL) break;

	      if (strcmp ( 
		           index(getenv(buf),'/'), 
			   (cred->firstname)->value
			 )  
		   == 0) return 1;
      }
      /* no match found */
      return 0;
    }

  if (strcmp(cred->type, "dns") == 0) 
    {
      if ((user->firstcred == NULL) ||
          ((user->firstcred)->firstname == NULL) ||
          (cred->firstname == NULL) ||
          (strcmp((cred->firstname)->name, "hostname") != 0) ||
          ((cred->firstname)->next != NULL)) return 0;
      
      for (crediter=user->firstcred; 
           crediter != NULL; 
           crediter = crediter->next)
        if (strcmp(crediter->type, "dns") == 0) 
          {            
            if ((crediter->firstname == NULL) ||
              (strcmp((crediter->firstname)->name, "hostname") != 0)) return 0;
               
            return (fnmatch((cred->firstname)->value, 
                            (crediter->firstname)->value, FNM_CASEFOLD) == 0);
          }
          
           
      return 0;    
    }
    
  if (strcmp(cred->type, "auth-user") == 0)
    {
      if ((user->firstcred == NULL) ||
          ((user->firstcred)->firstname == NULL)) return 0;
      
      for (crediter=user->firstcred; 
           crediter != NULL; 
           crediter = crediter->next)
        if (strcmp(crediter->type, "person") == 0) return 1;
                
      return 0;    
    }
  
  for (crediter=user->firstcred; crediter != NULL; crediter = crediter->next)
       {
         if (strcmp(crediter->type, cred->type) != 0) continue;
         
         if ((crediter->firstname == NULL) && 
             (cred->firstname     == NULL)) return 1;
         
         if ((crediter->firstname == NULL) || 
             (cred->firstname     == NULL)) continue;
             
         usernamevalue = crediter->firstname;
         crednamevalue = cred->firstname;
         
         for (;;)
            {
              if (strcmp(usernamevalue->name,crednamevalue->name) != 0) break;

              if (strcmp(cred->type, "person") == 0)
                {
                  if (GRSTx509NameCmp(usernamevalue->value, 
                                      crednamevalue->value) != 0) break;
                }
              else if (strcmp(usernamevalue->value,
                              crednamevalue->value) != 0) break;
              
              /* ok if cred list runs out before user's cred list */
              if (crednamevalue->next == NULL) return 1;

              /* but not ok if more names to match which user doesn't have */
              if (usernamevalue->next == NULL) break;
             
              crednamevalue = (GRSTgaclNamevalue *) crednamevalue->next;
              usernamevalue = (GRSTgaclNamevalue *) usernamevalue->next;
            }
       }
         
  return 0;
}

GRSTgaclCred *GRSTgaclUserFindCredtype(GRSTgaclUser *user, char *type)
/* find the first credential of a given type for this user */
{
  GRSTgaclCred *cred;

  if (user == NULL) return NULL;
  
  cred = user->firstcred;  

  while (cred != NULL)
       {
         if (strcmp(cred->type, type) == 0) return cred;
         
         cred = cred->next;       
       }
       
  return NULL;
}

int GRSTgaclUserSetDNlists(GRSTgaclUser *user, char *dnlists)
{
  if ((user == NULL) || (dnlists == NULL)) return 0;

  if (user->dnlists != NULL) free(user->dnlists);

  user->dnlists = strdup(dnlists);

  return 1;
}

/*                                                     *
 * Functions to test for access perm of an individual  *
 *                                                     */

static char *recurse4file(char *dir, char *file, int recurse_level)
/* try to find file[] in dir[]. try subdirs if not found. 
   return full path to first found version or NULL on failure */
{
  char          *fullfilename, *fulldirname;
  struct stat    statbuf;
  DIR           *dirDIR;
  struct dirent *file_ent;

  /* try to find in current directory */

  asprintf(&fullfilename, "%s/%s", dir, file);  
  if (stat(fullfilename, &statbuf) == 0) return fullfilename;
  free(fullfilename);

  /* maybe search in subdirectories */
  
  if (recurse_level >= GRST_RECURS_LIMIT) return NULL;

  dirDIR = opendir(dir);
  
  if (dirDIR == NULL) return NULL;
  
  while ((file_ent = readdir(dirDIR)) != NULL)
       {
         if (file_ent->d_name[0] == '.') continue;
       
         asprintf(&fulldirname, "%s/%s", dir, file_ent->d_name);

         if ((stat(fulldirname, &statbuf) == 0) &&
             S_ISDIR(statbuf.st_mode) &&
             ((fullfilename = recurse4file(fulldirname, file, 
                                             recurse_level + 1)) != NULL))
           {
             closedir(dirDIR);             
             return fullfilename;
           }
           
         free(fulldirname);
       }
  
  closedir(dirDIR);  

  return NULL;
}

int GRSTgaclDNlistHasUser(char *listurl, GRSTgaclUser *user)
{
  char *dn_lists_dirs, *dn_list_ptr, *enclisturl, *filename, *dirname,
        line[512], *p;
  FILE *fp;
  GRSTgaclCred  *cred;
    
  if ((listurl == NULL) || (user == NULL)) return 0;

  enclisturl = GRSThttpUrlEncode(listurl);

  if (user->dnlists != NULL) p = user->dnlists;
  else p = getenv("GRST_DN_LISTS");

  if (p == NULL) p = GRST_DN_LISTS;
  dn_lists_dirs = strdup(p);     /* we need to keep this for free() later! */
  dn_list_ptr   = dn_lists_dirs; /* copy, for naughty function strsep()    */

  while ((dirname = strsep(&dn_list_ptr, ":")) != NULL)
       {    
         filename = recurse4file(dirname, enclisturl, 0);
         if (filename == NULL) continue;
  
         fp = fopen(filename, "r");
         free(filename);
  
         if (fp == NULL) continue;

         while (fgets(line, sizeof(line), fp) != NULL)
              {
                p = index(line, '\n');
                if (p != NULL) *p = '\0';

                cred = user->firstcred;
         
                while (cred != NULL)                  
                     {
                       if ((strcmp(cred->type, "person") == 0)          && 
                           (cred->firstname != NULL)                    &&
                           (strcmp("dn", (cred->firstname)->name) == 0) &&
                 (GRSTx509NameCmp(line, (cred->firstname)->value) == 0))
                         {
                           fclose(fp);
                           free(dn_lists_dirs);
                           free(enclisturl);
                           return 1;
                         }
                  
                       cred = cred->next;
                     }
              }
       
         fclose(fp);
       }

  free(dn_lists_dirs);
  free(enclisturl);

  return 0;
}

GRSTgaclPerm GRSTgaclAclTestUser(GRSTgaclAcl *acl, GRSTgaclUser *user)
/*
    GACLgaclAclTestUser - return bit fields depending on access perms user has
                      for given acl. All zero for no access. If *user is
                      NULL, matching to "any-user" will still work.
*/
{
  int        flag, onlyanyuser;
  GRSTgaclPerm   allowperms = 0, denyperms = 0, allowed;
  GRSTgaclEntry *entry;
  GRSTgaclCred  *cred, *usercred;
  
  if (acl == NULL) return 0;
  
  for (entry = acl->firstentry; entry != NULL; entry = entry->next)
     {
       flag = 1;        /* begin by assuming this entry applies to us */
       onlyanyuser = 1; /* begin by assuming just <any-user/> */
       
       /* now go through creds, checking they all do apply to us */
     
       for (cred = entry->firstcred; cred != NULL; cred = cred->next)
             if (!GRSTgaclUserHasCred(user, cred)) flag = 0;
             else if (strcmp(cred->type, "any-user") != 0) onlyanyuser = 0;

       if (!flag) continue; /* flag false if a subtest failed */

       /* does apply to us, so we remember this entry's perms */
       
       /* we dont allow Write or Admin on the basis of any-user alone */

       allowed = entry->allowed;

       if (onlyanyuser)
            allowed = entry->allowed & ~GRST_PERM_WRITE & ~GRST_PERM_ADMIN;
       else allowed = entry->allowed;

       allowperms = allowperms | allowed;
       denyperms  = denyperms  | entry->denied;
     }

  return (allowperms & (~ denyperms)); 
  /* for each perm type, any deny we saw kills any allow */
}

GRSTgaclPerm GRSTgaclAclTestexclUser(GRSTgaclAcl *acl, GRSTgaclUser *user)
/*
    GRSTgaclAclTestexclUser - 
                      return bit fields depending on ALLOW perms OTHER users 
                      have for given acl. All zero if they have no access.
                      (used for testing if a user has exclusive access)
*/
{
  int        flag;
  GRSTgaclPerm  perm = 0;
  GRSTgaclEntry *entry;
  GRSTgaclCred  *cred;
  
  if (acl == NULL) return 0;
  
  for (entry = acl->firstentry; entry != NULL; entry = entry->next)
     {
       flag = 0; /* flag will be set if cred implies other users */
     
       for (cred = entry->firstcred; cred != NULL; cred = cred->next)
          {
            if (strcmp(cred->type, "person") != 0)
             /* if we ever add support for other person-specific credentials,
                they must also be recognised here */
              {
                flag = 1;
                break; 
              }

            if (!GRSTgaclUserHasCred(user, cred))
                 /* if user doesnt have this person credential, assume
                    it refers to a different individual */
              {
                flag = 1;
                break;
              }
          }

       if (flag) perm = perm | entry->allowed;
     }

  return perm;     
}

/* 
    Wrapper functions for gridsite-gacl.h support of legacy API
*/

GRSTgaclEntry *GACLparseEntry(xmlNodePtr cur)
{
  return GRSTgaclEntryParse(cur);
}
