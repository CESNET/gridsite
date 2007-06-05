/*
  Copyright (c) 2003-7, Shiv Kaushal and Andrew McNab, 
  University of Manchester. All rights reserved.

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

/*-----------------------------------------------------------*
* This program is part of GridSite: http://www.gridsite.org/ *
*------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <gridsite.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

extern char *grst_perm_syms[];
extern int grst_perm_vals[];

                                  

#include "grst_admin.h"

// CGI GACL Editor interface functions
void show_acl(int admin, GRSTgaclUser *user, char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file);
void new_entry_form(GRSTgaclUser *user, char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file);
void new_entry(GRSTgaclUser *user, char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file);
void del_entry(GRSTgaclUser *user, char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file);
void edit_entry_form(GRSTgaclUser *user, char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file);
void edit_entry(GRSTgaclUser *user, char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file);
void add_cred_form(GRSTgaclUser *user, char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file);
void add_cred(GRSTgaclUser *user, char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file);
void del_cred(GRSTgaclUser *user, char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file);
void del_entry_sure(GRSTgaclUser *user, char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file);
void del_cred_sure(GRSTgaclUser *user, char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file);
void admin_continue(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file, GRSThttpBody *bp);

// Functions for producing HTML output
void StartHTML(GRSThttpBody *bp, char *dir_uri, char* dir_path);
void StartForm(GRSThttpBody *bp, char* dir_uri, char* dir_path, char* admin_file, int timestamp, char* target_function);
void EndForm(GRSThttpBody *bp);
void GRSTgaclCredTableStart(GRSThttpBody *bp);
void GRSTgaclCredTableAdd(GRSTgaclUser *user, GRSTgaclEntry *entry, GRSTgaclCred *cred, int cred_no, int entry_no, int admin, int timestamp, GRSThttpBody *bp, char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file);
void GRSTgaclCredTableEnd(GRSTgaclEntry* entry, int entry_no, int admin, int timestamp, GRSThttpBody *bp, char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file);

// ACL Manipulation functions
int GACLentriesInAcl(GRSTgaclAcl *acl);
int GRSTgaclCredsInEntry(GRSTgaclEntry *entry);
void check_acl_save(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file, GRSTgaclUser* user, GRSTgaclAcl *acl, GRSThttpBody *bp);
void GACLeditGetPerms(GRSTgaclEntry *entry);
GRSTgaclEntry *GACLreturnEntry(GRSTgaclAcl *acl, int entry_no);
GRSTgaclCred *GACLreturnCred(GRSTgaclEntry *entry, int cred_no);

void StringHTMLEncode (char* string, GRSThttpBody *bp);

void revert_acl(GRSTgaclUser *user, char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file);

/*****************************************/
/********** FUNCTIONS FOLLOW *************/
/*****************************************/

void show_acl(int admin, GRSTgaclUser *user, char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file){
  // Shows the contents of the ACL. Gives edit 'buttons' if (int admin) == 1
  GRSTgaclAcl *acl;
  GRSTgaclEntry *entry;
  GRSTgaclCred *cred;
  int entry_no, cred_no, allow, deny,timestamp;
  GRSThttpBody bp;
  char* AclFilename;
  struct stat file_info;
  int history_mode=0;

  if (admin==2){
    history_mode=1;
    admin=0;
  }

  /*double-check access permision*/
  if (!GRSTgaclPermHasAdmin(perm)) admin=0;

  StartHTML(&bp, dir_uri, dir_path);

  /* Load ACL from file and get timestamp*/
  if (history_mode==1) {
    AclFilename=malloc(strlen(dir_path)+strlen(file)+2);
    strcpy(AclFilename, dir_path);
    strcat(AclFilename, "/");
    strcat(AclFilename, file);
  }
  else  AclFilename=GRSTgaclFileFindAclname(dir_path);
  
  if (AclFilename==NULL){
    GRSThttpPrintf ( &bp,"The ACL was not found !!!<br>\n");
    admin_continue(dn, perm, help_uri, dir_path, file, dir_uri, admin_file, &bp);
    return;
  }

  stat(GRSTgaclFileFindAclname(dir_path), &file_info);
  timestamp=file_info.st_mtime;
  acl = GRSTgaclAclLoadFile(AclFilename);

  if (acl==NULL){
    GRSThttpPrintf ( &bp,"The ACL was found but could not be loaded - it could be incorrectly formatted<br>\n");
    adminfooter(&bp, dn, help_uri, dir_uri, NULL);
    GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_FOOTFILE); 
    GRSThttpWriteOut(&bp);
    return;
  }

  if (admin) GRSThttpPrintf (&bp,"<a href=\"%s%s?cmd=new_entry_form&diruri=%s&timestamp=%d\">New&nbsp;Entry</a><br>\n", dir_uri, admin_file, dir_uri, timestamp );

  // Start with the first entry in the list and work through
  entry=acl->firstentry;
  entry_no=1;
  while (entry!=NULL){

    GRSThttpPrintf (&bp,"<br>Entry %d:\n", entry_no);
    if (admin){
      GRSThttpPrintf (&bp,"<a href=\"%s%s?cmd=edit_entry_form&entry_no=%d&diruri=%s&timestamp=%d\">Edit&nbsp;Entry</a> ", dir_uri, admin_file, entry_no, dir_uri, timestamp );
      GRSThttpPrintf (&bp,"<a href=\"%s%s?cmd=del_entry_sure&entry_no=%d&diruri=%s&timestamp=%d\">Delete&nbsp;Entry</a> ",dir_uri, admin_file, entry_no, dir_uri, timestamp );
      GRSThttpPrintf (&bp,"<p>\n");
    }

    GRSTgaclCredTableStart(&bp);

    // Start with the first credential in the entry and work through
    cred=entry->firstcred;
    cred_no=1;
    while (cred!=NULL){
      GRSTgaclCredTableAdd(user, entry, cred, cred_no, entry_no, admin, timestamp, &bp, dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
      // Change to next credential
      cred=cred->next;
      cred_no++;
    }

    GRSTgaclCredTableEnd (entry, entry_no, admin, timestamp, &bp, dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
    // Change to next entry
    entry=entry->next;
    entry_no++;
  }

  if (!admin && GRSTgaclPermHasAdmin(perm) && !history_mode) //Print a link for admin mode, if not in admin mode but the user has admin permissions
    GRSThttpPrintf (&bp,"<a href=\"%s%s?cmd=admin_acl&diruri=%s&timestamp=%d\">Admin&nbsp;Mode</a>",  dir_uri, admin_file, dir_uri, timestamp );
  if (history_mode==1 && GRSTgaclUserHasAURI(user, getenv("REDIRECT_GRST_ADMIN_LIST"))){
    StartForm(&bp, dir_uri, dir_path, admin_file, timestamp, "revert_acl");
//GRSThttpPrintf (&bp,"<a href=\"%s%s?cmd=revert_acl&diruri=%s&timestamp=%d&file=%s\">Revert to this Version</a>",  dir_uri, admin_file, dir_uri, timestamp, file );
    GRSThttpPrintf (&bp, "<input type=\"hidden\" name=\"file\" value=\"%s\">\n", file);
    // Revert Button
    GRSThttpPrintf (&bp, "<p align=center><input type=\"submit\" value=\"Revert to this ACL\" name=\"B1\"></p>\n</form>\n");
  }

  adminfooter(&bp, dn, help_uri, dir_uri, NULL);
  GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_FOOTFILE); GRSThttpWriteOut(&bp); return;
}


void new_entry_form(GRSTgaclUser *user, char *dn, GRSTgaclPerm perm,char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file){
  // Presents the user with a form asking for details required to create a new entry
  GRSThttpBody bp;
  int timestamp=atol(GRSThttpGetCGI("timestamp"));
  GRSTgaclCred* cred;
  GRSTgaclEntry *entry;

  if (!GRSTgaclPermHasAdmin(perm)) GRSThttpError ("403 Forbidden");
  entry = GRSTgaclEntryNew(); 
  StartHTML(&bp, dir_uri, dir_path);
  StartForm(&bp, dir_uri, dir_path, admin_file, timestamp, "new_entry");
  GRSThttpPrintf (&bp, "<font size=\"4\"><b>NEW ENTRY IN ACL FOR %s </b></font></p>\n", dir_uri);

  GRSTgaclCredTableStart(&bp);
  GRSTgaclCredTableAdd(user, entry,cred, 0, 0, 0, timestamp, &bp, dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
  GRSTgaclCredTableEnd (entry, 0, 0, timestamp, &bp, dn, perm, help_uri, dir_path, file, dir_uri, admin_file);

  /*Submit and reset buttons -  submit button sends the data in the form back to the script & new_entry() to be called*/
  EndForm(&bp);
  admin_continue(dn, perm, help_uri, dir_path, file, dir_uri, admin_file, &bp);
  return;
}

void new_entry(GRSTgaclUser *user, char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file){
  // Processes the information entered into the form from new_entry_form() and adds a new entry to the ACL
  GRSTgaclAcl *acl;
  GRSTgaclEntry *entry;
  GRSTgaclCred *cred;
  char *cred_auri_1, *p;
  GRSThttpBody bp;
  if (!GRSTgaclPermHasAdmin(perm)) GRSThttpError ("403 Forbidden");

  // Get new credential info and perform checks
  cred_auri_1=GRSThttpGetCGI("cred_auri_1");

  /* check AURI for scheme:path form */

  for (p=cred_auri_1; *p != '\0'; ++p) if (!isalnum(*p) && (*p != '-') && (*p != '_')) break;

  if ((p == cred_auri_1) || (*p != ':'))
    {
        StartHTML(&bp, dir_uri, dir_path);
        GRSThttpPrintf (&bp, "ERROR: CANNOT SAVE CHANGES\n\n<p>Attribute URIs must take the form scheme:path"
        "<p>For example dn:/DC=com/DC=example/CN=name or "
        "fqan:/voname/groupname or https://host.name/listname or dns:host.name.pattern or ip:ip.number.pattern\n<p>\n");
        admin_continue(dn, perm, help_uri, dir_path, file, dir_uri, admin_file, &bp);
        return;
    }

  // Create the credential
  cred=GRSTgaclCredCreate(cred_auri_1, NULL);

  // Create and empty entry, add the credential and get permissions
  entry = GRSTgaclEntryNew();
  GRSTgaclEntryAddCred(entry, cred);
  GACLeditGetPerms(entry);

  // Load the ACL, add the entry and save
  acl = GRSTgaclAclLoadFile(GRSTgaclFileFindAclname(dir_path));
  GRSTgaclAclAddEntry(acl, entry);
  check_acl_save(dn, perm, help_uri, dir_path, file, dir_uri, admin_file, user, acl, &bp);
  return;
}

void del_entry(GRSTgaclUser *user, char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file){
  // Deletes the entry denoted by the GCI variable "entry_no"*/
  int entry_no;
  GRSTgaclAcl *acl;
  GRSTgaclEntry *previous, *entry;
  GRSThttpBody bp;

  if (!GRSTgaclPermHasAdmin(perm)) GRSThttpError ("403 Forbidden");

  // Load the ACL
  acl = GRSTgaclAclLoadFile(GRSTgaclFileFindAclname(dir_path));

  // Get the number of the entry to be deleted and check okay to delete
  entry_no=atol(GRSThttpGetCGI("entry_no"));
  if(GACLentriesInAcl(acl)<=1){
    StartHTML(&bp, dir_uri, dir_path);
    GRSThttpPrintf (&bp, "ERROR: Cannot delete all entries from the ACL<br>\n");
    admin_continue(dn, perm, help_uri, dir_path, file, dir_uri, admin_file, &bp);
    return;
  }

  // Get pointer to entry and previous entry
  entry = GACLreturnEntry(acl, entry_no);
  if (entry_no!=1) previous = GACLreturnEntry(acl, entry_no-1);

  if(entry==NULL || entry_no<1 || entry_no>GACLentriesInAcl(acl) ){
    GRSThttpError ("500 Unable to read entry from ACL file");
    return;
  }

  // Perform deletion from the list by changing pointers
  if (entry_no==1) acl->firstentry=entry->next;
  else if (entry_no==GACLentriesInAcl(acl)) previous->next=NULL;
  else previous->next=entry->next;

  // Save ACL and exit
  check_acl_save(dn, perm, help_uri, dir_path, file, dir_uri, admin_file, user, acl, &bp);

  return;
}


void edit_entry_form(GRSTgaclUser *user, char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file){
  // Presents the user with an editable form containing details of entry denoted by CGI variable entry_no*/
  int entry_no, cred_no, i, admin=0, timestamp=atol(GRSThttpGetCGI("timestamp"));
  GRSTgaclAcl *acl;
  GRSTgaclEntry *entry;
  GRSTgaclCred *cred;
  GRSThttpBody bp;

  if (!GRSTgaclPermHasAdmin(perm)) GRSThttpError ("403 Forbidden");

  // Load ACL from file
  acl = GRSTgaclAclLoadFile(GRSTgaclFileFindAclname(dir_path));

  // Get pointer to the entry and check okay
  entry_no=atol(GRSThttpGetCGI("entry_no"));
  entry = GACLreturnEntry(acl, entry_no);
  if(entry==NULL || entry_no<1 || entry_no>GACLentriesInAcl(acl) ){
    GRSThttpError ("500 Unable to read from ACL file");
    return;
  }

  StartHTML(&bp, dir_uri, dir_path);
  GRSThttpPrintf (&bp, "<b><font size=\"4\">EDITING ENTRY %d IN ACL FOR %s </font></b></p>\n", entry_no, dir_uri);

  // Start with first credential in the entry and display them in order*/
  cred=entry->firstcred;
  cred_no=1;
  StartForm(&bp, dir_uri, dir_path, admin_file, timestamp, "edit_entry");
  GRSThttpPrintf (&bp, "<input type=\"hidden\" name=\"entry_no\" value=\"%d\">\n", entry_no);

  GRSTgaclCredTableStart(&bp);

  while (cred!=NULL){
    // Start with the first namevalue in the credential
    GRSTgaclCredTableAdd(user, entry, cred, cred_no, entry_no, admin, timestamp, &bp, dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
    // Change to next credential
    cred=cred->next;
    cred_no++;
  }
  GRSTgaclCredTableEnd (entry, entry_no, admin, timestamp, &bp, dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
  GRSThttpPrintf (&bp, "<input type=\"hidden\" name=\"last_cred_no\" value=\"%d\">\n", cred_no-1);
  EndForm(&bp);

  admin_continue(dn, perm, help_uri, dir_path, file, dir_uri, admin_file, &bp);
  return;
}


void edit_entry(GRSTgaclUser *user, char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file){
  //Processes the information entered into the form from edit_entry_form() and updates the entry corresponding to entry_no*/
  int entry_no, cred_no, i, last_cred_no;
  GRSTgaclAcl *acl;
  GRSTgaclEntry *entry;
  GRSTgaclCred *cred;
  char variable[30], *cred_auri_i, *p;
  GRSThttpBody bp;

  if (!GRSTgaclPermHasAdmin(perm)) GRSThttpError ("403 Forbidden");

  // Load the ACL
  acl = GRSTgaclAclLoadFile(GRSTgaclFileFindAclname(dir_path));

  // Get pointer to the entry and perform checks
  entry_no     = atol(GRSThttpGetCGI("entry_no"));
  entry        = GACLreturnEntry(acl, entry_no);
  last_cred_no = atol(GRSThttpGetCGI("entry_no"));

  if(entry==NULL || entry_no<1 || entry_no>GACLentriesInAcl(acl) ){
    GRSThttpError ("500 Unable to read from ACL file");
    return;
  }

  // Reset the first credential and add in each one as they are found
  entry->firstcred = NULL;
  cred_no = 1;

  for (cred_no = 1; cred_no <= last_cred_no; ++cred_no)
       {
         sprintf(variable, "cred_auri_%d", cred_no);
         cred_auri_i = GRSThttpGetCGI(variable);
         
         if (cred_auri_i[0] != '\0')
           {
             /* check AURI for scheme:path form */

             for (p=cred_auri_i; *p != '\0'; ++p) if (!isalnum(*p) && (*p != '-') && (*p != '_')) break;

             if ((p == cred_auri_i) || (*p != ':'))
               {
                 StartHTML(&bp, dir_uri, dir_path);
                 GRSThttpPrintf (&bp, "ERROR: CANNOT SAVE CHANGES\n\n<p>Attribute URIs must take the form scheme:path"
                 "<p>For example dn:/DC=com/DC=example/CN=name or "
                 "fqan:/voname/groupname or https://host.name/listname or dns:host.name.pattern or ip:ip.number.pattern\n<p>\n");
                 admin_continue(dn, perm, help_uri, dir_path, file, dir_uri, admin_file, &bp);
                 return;
               }

             if (entry->firstcred == NULL)
               {
                 entry->firstcred = GRSTgaclCredCreate(cred_auri_i, NULL);
                 cred = entry->firstcred;
               }
             else
               {
                 cred->next = GRSTgaclCredCreate(cred_auri_i, NULL);
                 cred = cred->next;
               }
           }
       }

  if (entry->firstcred == NULL)
    {
      StartHTML(&bp, dir_uri, dir_path);
      GRSThttpPrintf (&bp, "ERROR: CANNOT SAVE CHANGES\n\n<p>Each entry must include at least one valid credential (Attribute URI)\n<p>\n");
     admin_continue(dn, perm, help_uri, dir_path, file, dir_uri, admin_file, &bp);
     return;    
    }
    
  
  // Update permissions
  GACLeditGetPerms(entry);
  check_acl_save(dn, perm, help_uri, dir_path, file, dir_uri, admin_file, user, acl, &bp);
  return;
}


void add_cred_form(GRSTgaclUser *user, char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file){
  // Presents the user with a form asking for details required to create a new credential in the entry denoted by entry_no
  GRSThttpBody bp;
  int timestamp=atol(GRSThttpGetCGI("timestamp")), entry_no=atol(GRSThttpGetCGI("entry_no"));
  GRSTgaclAcl *acl;
  GRSTgaclEntry* entry;
  GRSTgaclCred* cred;
  
  if (!GRSTgaclPermHasAdmin(perm)) GRSThttpError ("403 Forbidden");

  acl = GRSTgaclAclLoadFile(GRSTgaclFileFindAclname(dir_path)); // Load the ACL

  //Get pointer to the entry  and perform checks
  entry = GACLreturnEntry(acl, entry_no);
  if(entry==NULL || entry_no<1 || entry_no>GACLentriesInAcl(acl) ){
    GRSThttpError ("500 Unable to read from ACL file");
    return;
  }


  if (strcmp(GRSThttpGetCGI("cmd"), "add_cred_form")==0){ //if not a new entry check to see if <any-user> cred exists
    cred=entry->firstcred;
    while (cred!=NULL) {
      if (strcmp (cred->auri, "gacl:any-user")==0) {
        StartHTML(&bp, dir_uri, dir_path);
        GRSThttpPrintf (&bp, "ERROR: AND-ing \"any-user\" credential with other credential does not make sense <br>\n");
        admin_continue(dn, perm, help_uri, dir_path, file, dir_uri, admin_file, &bp);
	return;
      }
     cred=cred->next;
    }
  }

  StartHTML(&bp, dir_uri, dir_path);
  GRSThttpPrintf (&bp, " <font size=\"4\"><b>NEW CREDENTIAL IN ENTRY %d OF ACL FOR %s</b></font></p>\n", entry_no, dir_uri);
  StartForm(&bp, dir_uri, dir_path, admin_file, timestamp, "add_cred");

  GRSThttpPrintf (&bp, " <input type=\"hidden\" name=\"entry_no\" value=\"%d\">\n", entry_no);

  GRSTgaclCredTableStart(&bp);
  GRSTgaclCredTableAdd(user, entry, cred, 0, 0, 0, timestamp, &bp, dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
  GRSTgaclCredTableEnd (entry, 0, 0, timestamp, &bp, dn, perm, help_uri, dir_path, file, dir_uri, admin_file);

  EndForm(&bp);
  admin_continue(dn, perm, help_uri, dir_path, file, dir_uri, admin_file, &bp);
  return;
}


void add_cred(GRSTgaclUser *user, char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file){
  // Processes the information entered into the form [add_cred_form()]and adds a new credential to the entry corresponding to entry_no
  int entry_no;
  GRSTgaclAcl *acl;
  GRSTgaclEntry *entry;
  GRSTgaclCred *cred;
  GRSThttpBody bp;
  char *cred_auri_1, *p;

  if (!GRSTgaclPermHasAdmin(perm)) GRSThttpError ("403 Forbidden");

  acl = GRSTgaclAclLoadFile(GRSTgaclFileFindAclname(dir_path));// Load the ACL

  // Get pointer to the entry  and perform checks
  entry_no=atol(GRSThttpGetCGI("entry_no"));
  entry = GACLreturnEntry(acl, entry_no);
  if(entry==NULL || entry_no<1 || entry_no>GACLentriesInAcl(acl)){
    GRSThttpError ("500 Unable to read from ACL file");
    return;
  }

  // Create new credential and add it to entry
  cred_auri_1=GRSThttpGetCGI("cred_auri_1");

  /* check AURI for scheme:path form */

  for (p=cred_auri_1; *p != '\0'; ++p) if (!isalnum(*p) && (*p != '-') && (*p != '_')) break;

  if ((p == cred_auri_1) || (*p != ':'))
    {
      StartHTML(&bp, dir_uri, dir_path);
      GRSThttpPrintf (&bp, "ERROR: CANNOT SAVE CHANGES\n\n<p>Attribute URIs must take the form scheme:path"
                 "<p>For example dn:/DC=com/DC=example/CN=name or "
                 "fqan:/voname/groupname or https://host.name/listname or dns:host.name.pattern or ip:ip.number.pattern\n<p>\n");
                 admin_continue(dn, perm, help_uri, dir_path, file, dir_uri, admin_file, &bp);
      return;
    }

  cred=GRSTgaclCredCreate(cred_auri_1, NULL);
  GRSTgaclEntryAddCred(entry, cred);

  check_acl_save(dn, perm, help_uri, dir_path, file, dir_uri, admin_file, user, acl, &bp);
  return;
}


void del_cred(GRSTgaclUser *user, char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file){
  // Deletes the credential denoted by the GCI variable "cred_no", in the entry denoted by "entry_no"
  int entry_no, cred_no;
  GRSTgaclAcl *acl;
  GRSTgaclEntry *entry;
  GRSTgaclCred *previous, *cred;
  GRSThttpBody bp;

  if (!GRSTgaclPermHasAdmin(perm)) GRSThttpError ("403 Forbidden");

  acl = GRSTgaclAclLoadFile(GRSTgaclFileFindAclname(dir_path));

  // Get pointer to the entry and perform checks
  entry_no=atol(GRSThttpGetCGI("entry_no"));
  entry = GACLreturnEntry(acl, entry_no);
  if(entry==NULL || entry_no<1 || entry_no>GACLentriesInAcl(acl) ){
    GRSThttpError ("500 Unable to read from ACL file");
    return;
  }
  // Get pointer the the credential and perform checks
  cred_no=atol(GRSThttpGetCGI("cred_no"));
  cred=GACLreturnCred(entry, cred_no);
  if(entry==NULL || entry_no<1 || cred_no>GRSTgaclCredsInEntry(entry)){
    GRSThttpError ("500 Unable to read from ACL file");
    return;
  }
  // Get pointer to previous credential - if needed
  if (cred_no!=1) previous = GACLreturnCred(entry, cred_no-1);

  // Perform deletion from the list by changing pointers
  if (cred_no==1) entry->firstcred=cred->next;
  else if (cred_no==GRSTgaclCredsInEntry(entry)) previous->next=NULL;
  else previous->next=cred->next;

  check_acl_save(dn, perm, help_uri, dir_path, file, dir_uri, admin_file, user, acl, &bp);
  return;
}

void admin_continue(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file, GRSThttpBody *bp){
  // Single line printed out to forward users back to show_acl in admin mode
  // Should ALWAYS called from another function so no HTML header required
  // Should ALWAYS be the end of a page
  GRSThttpPrintf (bp, "\n<br><a href=\"%s%s?diruri=%s&cmd=admin_acl&timestamp=%d\">Click&nbsp;Here</a> to return to the editor", dir_uri,admin_file,dir_uri, time(NULL));
  adminfooter(bp, dn, help_uri, dir_uri, NULL);
  GRSThttpPrintHeaderFooter(bp, dir_path, GRST_FOOTFILE);
  GRSThttpWriteOut(bp);
  return;
}


void del_entry_sure(GRSTgaclUser *user, char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file){
  // Prints out entry denoted by entry_no and asks if the user really wants to delete it
  GRSTgaclAcl *acl;
  GRSTgaclEntry *entry;
  GRSTgaclCred *cred;
  int entry_no, cred_no, allow, deny, i, timestamp;
  GRSThttpBody bp;

  if (!GRSTgaclPermHasAdmin(perm)) GRSThttpError ("403 Forbidden");

  acl = GRSTgaclAclLoadFile(GRSTgaclFileFindAclname(dir_path));// Load ACL from file

  if (acl==NULL){
    GRSThttpError ("500 Unable to read from ACL file");
    return;
  }

  // Get pointer to the entry and check okay
  entry_no=atol(GRSThttpGetCGI("entry_no"));
  entry = GACLreturnEntry(acl, entry_no);
  if(entry==NULL || entry_no<1 || entry_no>GACLentriesInAcl(acl) ){
    GRSThttpError ("500 Unable to read from ACL file");
    return;
  }

  StartHTML(&bp, dir_uri, dir_path);
  GRSThttpPrintf (&bp, "<h1 align=center>Do you really want to delete the following entry?</h1><br><br>\n");
  GRSThttpPrintf (&bp,"<br>Entry %d:<br>\n", entry_no);

  // Print the entry out
  // Start with the first credential in the entry and work through
  cred=entry->firstcred;
  cred_no=1;

  GRSTgaclCredTableStart(&bp);
  while (cred!=NULL){
    // Start with the first namevalue in the credential
    GRSTgaclCredTableAdd(user, entry, cred, cred_no, entry_no, 0, 0, &bp, dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
    // Change to next credential
    cred=cred->next;
    cred_no++;
  }

  GRSTgaclCredTableEnd (entry, entry_no, 0, 0, &bp, dn, perm, help_uri, dir_path, file, dir_uri, admin_file);

  StartForm(&bp, dir_uri, dir_path, admin_file, atol(GRSThttpGetCGI("timestamp")), "del_entry");
  GRSThttpPrintf (&bp, "<input type=\"hidden\" name=\"entry_no\" value=\"%d\">\n", entry_no);
  GRSThttpPrintf (&bp, " <p align=center><input type=\"submit\" value=\"Yes\" name=\"B1\"></p>\n</form>\n");

  admin_continue(dn, perm, help_uri, dir_path, file, dir_uri, admin_file, &bp);
  return;
}

void del_cred_sure(GRSTgaclUser *user, char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file){
  // Prints out credential denoted by entry_no/cred_no and asks if the user really wants to delete it
  GRSTgaclAcl *acl;
  GRSTgaclEntry *entry;
  GRSTgaclCred *cred;
  int entry_no, cred_no, allow, deny, timestamp, i;
  GRSThttpBody bp;

  if (!GRSTgaclPermHasAdmin(perm)) GRSThttpError ("403 Forbidden");

  acl = GRSTgaclAclLoadFile(GRSTgaclFileFindAclname(dir_path));// Load ACL from file

  if (acl==NULL){
    GRSThttpError ("500 Unable to read from ACL file");
    return;
  }

  // Get pointer to the entry and check okay
  entry_no=atol(GRSThttpGetCGI("entry_no"));
  entry = GACLreturnEntry(acl, entry_no);
  if(entry==NULL || entry_no<1 || entry_no>GACLentriesInAcl(acl) ){
    GRSThttpError ("500 Unable to read from ACL file");
    return;
  }

  // Get pointer to the credential and check okay
  cred_no=atol(GRSThttpGetCGI("cred_no"));
  cred=GACLreturnCred(entry, cred_no);
  if(entry==NULL || entry_no<1 || cred_no>GRSTgaclCredsInEntry(entry)){
    GRSThttpError ("500 Unable to read from ACL file");
    return;
  }

  if(GRSTgaclCredsInEntry(entry)<=1){
    del_entry_sure(user, dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
    return;
  }

  StartHTML(&bp, dir_uri, dir_path);
  GRSThttpPrintf (&bp, "<h1 align=center>Do you really want to delete the following credential from entry %d?</h1><br><br>", entry_no);

  // Print the credential out
  GRSTgaclCredTableStart(&bp);
  GRSTgaclCredTableAdd(user, entry, cred, cred_no, entry_no, 0, 0, &bp, dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
  GRSTgaclCredTableEnd (entry, entry_no, 0, 0, &bp, dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
  GRSThttpPrintf (&bp,"<br>\n");

  // Yes Button
  StartForm(&bp, dir_uri, dir_path, admin_file, atol(GRSThttpGetCGI("timestamp")), "del_cred");
  GRSThttpPrintf (&bp, "<input type=\"hidden\" name=\"entry_no\" value=\"%d\">\n", entry_no);
  GRSThttpPrintf (&bp, "<input type=\"hidden\" name=\"cred_no\" value=\"%d\">\n", cred_no);
  GRSThttpPrintf (&bp, " <p align=center><input type=\"submit\" value=\"Yes\" name=\"B1\"></p>\n</form>\n");

  admin_continue(dn, perm, help_uri, dir_path, file, dir_uri, admin_file, &bp);
  return;
}


int GACLentriesInAcl(GRSTgaclAcl *acl){
  // Returns the number of entries in acl
  GRSTgaclEntry *entry;
  int number;

  entry=acl->firstentry;
  number=0;

  while (entry!=NULL)
  {
    number++;
    entry=entry->next;
  }

  return number;
}

int GRSTgaclCredsInEntry(GRSTgaclEntry *entry){
  // Returns the number of credentials in entry
  int number;
  GRSTgaclCred *cred;

  cred=entry->firstcred;
  number=0;

  while (cred!=NULL)
  {
    number++;
    cred=cred->next;
  }

  return number;
}


void GACLeditGetPerms(GRSTgaclEntry *entry){
  // Updates the permissions entry using permissions from a form produced using GRSTgaclCredTableEnd
  int i;
  char buf[30];


  for (i=0; grst_perm_syms[i]!=NULL; i++)  /* Print the list of allowed permissions*/
  {
    sprintf (buf, "allow_%s", grst_perm_syms[i]); // Update allowed
    if (strcmp (GRSThttpGetCGI(buf), "ON") == 0 )  GRSTgaclEntryAllowPerm(entry, grst_perm_vals[i]);  else GRSTgaclEntryUnallowPerm(entry, grst_perm_vals[i]);

    sprintf (buf, "deny_%s", grst_perm_syms[i]); // Update denied
    if (strcmp (GRSThttpGetCGI(buf), "ON") == 0 )  GRSTgaclEntryDenyPerm(entry, grst_perm_vals[i]);  else GRSTgaclEntryUndenyPerm(entry, grst_perm_vals[i]);

  }

  return;
}

GRSTgaclEntry *GACLreturnEntry(GRSTgaclAcl *acl, int entry_no){
  // Returns a pointer to entry in ACL denoted by entry_no, returns NULL if not found
  int number;
  GRSTgaclEntry *entry;

  if (acl==NULL) return NULL;

  entry=acl->firstentry;
  number=1;

  while (entry!=NULL)
  {
    if (number==entry_no) return entry;
    number++;
    entry=entry->next;
  }

  return NULL;
}


GRSTgaclCred *GACLreturnCred(GRSTgaclEntry *entry, int cred_no){
  // Returns a pointer to credential denoted by cred_no in entry, returns NULL if not found
  int number;
  GRSTgaclCred *cred;

  if (entry==NULL) return NULL;

  cred=entry->firstcred;
  number=1;

  while (cred!=NULL)
  {
    if (number==cred_no) return cred;
    number++;
    cred=cred->next;
  }

  return NULL;
}
void StartHTML(GRSThttpBody *bp, char *dir_uri, char* dir_path){
  //Start HTML output and insert page title
  printf("Status: 200 OK\nContent-Type: text/html\n");
  GRSThttpBodyInit(bp);
  GRSThttpPrintf(bp, "<title>Access Control List for %s</title>\n", dir_uri);
  GRSThttpPrintHeaderFooter(bp, dir_path, GRST_HEADFILE);
  return;
}
void StartForm(GRSThttpBody *bp, char* dir_uri, char* dir_path, char* admin_file, int timestamp, char* target_function){
  // Starts an HTML form with gridsite admin as the target and target_function as the value of cmd.
  // Also inputs the dir_uri and the timestamp
  GRSThttpPrintf (bp, "<form method=\"POST\" action=\"%s%s?diruri=%s\">\n", dir_uri, admin_file, dir_uri);
  GRSThttpPrintf (bp, " <input type=\"hidden\" name=\"cmd\" value=\"%s\">\n", target_function);
  GRSThttpPrintf (bp, " <input type=\"hidden\" name=\"timestamp\" value=\"%d\">\n", timestamp);
  return;
}

void EndForm(GRSThttpBody *bp){
  GRSThttpPrintf (bp, " <br><input type=\"submit\" value=\"Submit\" name=\"B1\"><input type=\"reset\" value=\"Reset\" name=\"B2\"></p>\n");
  GRSThttpPrintf (bp, "</form>\n");
  return;
}

void GRSTgaclCredTableStart(GRSThttpBody *bp){
  //Starts an HTML table of credentials by setting the column widths and inputting the headings
  GRSThttpPrintf (bp,"<table border=\"1\" cellpadding=\"2\" cellspacing=\"0\" style=\"border-collapse: collapse\" bordercolor=\"#111111\" width=\"100%\" id=\"CredentialTable\">");
  GRSThttpPrintf (bp,"<tr><td align=center width=\"15%\"><b>Credential No.</td><td align=left width=\"85%\"><b>Attribute URI</b></td></tr>");
  return;
}

void GRSTgaclCredTableAdd(GRSTgaclUser *user, GRSTgaclEntry *entry, GRSTgaclCred *cred, int cred_no, int entry_no, int admin, int timestamp, GRSThttpBody *bp, char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file)
{
  // Adds the credential "cred" to a table started byGRSTgaclCredTableStart allowing the user to edit if appropriate
  char* cmd = GRSThttpGetCGI("cmd");
  int edit_values=0, new_cred=0, allow_new_person=1;
  int site_admin=GRSTgaclUserHasAURI(user, getenv("REDIRECT_GRST_ADMIN_LIST"));

  if (strcmp(cmd, "new_entry_form")==0 || strcmp(cmd, "add_cred_form")==0) new_cred=1;
  if (new_cred || (strcmp(cmd, "edit_entry_form") == 0)) edit_values=1;

  if (new_cred) 
    {
     //create dummy credential for the user to edit
     cred=GRSTgaclCredCreate("", "");
     //Drop down list of types
     GRSThttpPrintf(bp,"<tr><td align=center >New</td>");
     cred_no = 1;
    }
  else 
    { //Print out type and descriptor for existing cred

     GRSThttpPrintf(bp,"<tr><td align=center >%d", cred_no);
     if (admin) GRSThttpPrintf (bp,"<a href=\"%s%s?diruri=%s&cmd=del_cred_sure&entry_no=%d&cred_no=%d&timestamp=%d\">(Delete)</a>", dir_uri,admin_file,dir_uri, entry_no, cred_no, timestamp);
     GRSThttpPrintf(bp, "</td>");
    }

  if (strcmp(cred->auri, "gacl:any-user")==0) GRSThttpPrintf (bp, "<td>%s", cred->auri); 
  else
   {
    if (edit_values)
      { // Place AURI in an editable box if appropriate
      GRSThttpPrintf (bp, "<td align=left><input type=\"text\" name=\"cred_auri_%d\"\n", cred_no);
      GRSThttpPrintf (bp, "size=\"50\" value=\"");
      StringHTMLEncode(cred->auri, bp);
      GRSThttpPrintf (bp, "\">");
      }
    else if ((strncmp(cred->auri, "http://", 7) == 0) ||
             (strncmp(cred->auri, "https://", 8) == 0))
      {
         GRSThttpPrintf(bp, "<td align=left ><a href=\"");
	 StringHTMLEncode(cred->auri, bp);
	 GRSThttpPrintf(bp, " \">");
	 StringHTMLEncode(cred->auri, bp);
	 GRSThttpPrintf(bp, "</a>");
      }
    else 
      {
        GRSThttpPrintf(bp, "<td align=left> "); 
        StringHTMLEncode(cred->auri, bp);
      }
   }
  //Print out warning symbol if cred being printed relates to current user - but NOT for users in site admin list
  if (GRSTgaclUserHasCred(user, cred) && !site_admin)  GRSThttpPrintf(bp, "<font color=red><b>&nbsp;&lt;--</b></font>");
  GRSThttpPrintf(bp, "</td></tr>");
}

void GRSTgaclCredTableEnd(GRSTgaclEntry* entry, int entry_no, int admin, int timestamp, GRSThttpBody *bp, char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file){
  // Finishes off a table of credentials by inputting "Add Credential" link and a list of premissions in the final row
  int i, blank_perms, edit_perms, show_perms;
  char* cmd = GRSThttpGetCGI("cmd");

  if (strcmp(cmd, "add_cred_form")==0 ||strcmp(cmd, "del_cred_sure")==0) show_perms=0; else show_perms=1;
  if (strcmp(cmd, "edit_entry_form")==0 || strcmp(cmd, "new_entry_form")==0) edit_perms=1; else edit_perms=0;
  if (strcmp(cmd, "new_entry_form")==0)  blank_perms=1; else blank_perms=0;

  // If showing the last row is not required then exit
  if (show_perms==0){GRSThttpPrintf (bp,"</table><br>\n"); return;}

  GRSThttpPrintf (bp,"<tr><td align=center>");

  if (admin) GRSThttpPrintf (bp,"<a href=\"%s%s?diruri=%s&cmd=add_cred_form&entry_no=%d&timestamp=%d\">Add&nbsp;Credential</a>", dir_uri,admin_file,dir_uri, entry_no, timestamp);

  GRSThttpPrintf (bp, "</td>\n<td align=left>");

  if (blank_perms==1)entry->allowed=entry->denied=GRST_PERM_NONE;

  // Show Permissions - will produce a list or a list of check boxes depending on whether the permissions are to be edited or not
  GRSThttpPrintf (bp, "<b>Allowed:</b>  ");
  for (i=0; grst_perm_syms[i]!=NULL; i++)  /* Print the list of allowed permissions*/
  {
    if ( entry->allowed & grst_perm_vals[i]){
      if (edit_perms) GRSThttpPrintf (bp, "%s<input type=\"checkbox\" name=\"allow_%s\" value=\"ON\" checked>&nbsp;&nbsp;&nbsp;\n", grst_perm_syms[i],grst_perm_syms[i]);
      else GRSThttpPrintf(bp,"%s ", grst_perm_syms[i]); if (strcmp(grst_perm_syms[i], "none")==0) break;
    }
    else if (strcmp(grst_perm_syms[i], "none")!=0 && edit_perms) GRSThttpPrintf (bp, "%s<input type=\"checkbox\" name=\"allow_%s\" value=\"ON\" unchecked>&nbsp;&nbsp;&nbsp;\n", grst_perm_syms[i],grst_perm_syms[i]);
  }

  if (edit_perms) GRSThttpPrintf (bp, "<p>");
  GRSThttpPrintf (bp, "<b>Denied:&nbsp;</b>");
  for (i=0; grst_perm_syms[i]!=NULL; i++)  /* Print the list of denied permissions*/
  {
   if  ( entry->denied & grst_perm_vals[i])
   {
     if (edit_perms) GRSThttpPrintf (bp, "%s<input type=\"checkbox\" name=\"deny_%s\" value=\"ON\" checked>&nbsp;&nbsp;&nbsp;\n", grst_perm_syms[i],grst_perm_syms[i]);
     else GRSThttpPrintf(bp,"%s ", grst_perm_syms[i]);
     if (strcmp(grst_perm_syms[i], "none")==0) break;
   }
   else if (strcmp(grst_perm_syms[i], "none")!=0 && edit_perms) GRSThttpPrintf (bp, "%s<input type=\"checkbox\" name=\"deny_%s\" value=\"ON\" unchecked>&nbsp;&nbsp;&nbsp;\n", grst_perm_syms[i],grst_perm_syms[i]);
  }

  GRSThttpPrintf (bp, "</td></tr>");
  GRSThttpPrintf (bp,"</table><br>\n");
  GRSThttpPrintf (bp,"\n");
}

void check_acl_save(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file, GRSTgaclUser* user, GRSTgaclAcl *acl, GRSThttpBody *bp){
  // Checks if the acl for the current directory has been changed, check the current user's permissions.
  // If all is okay the ACl is saved -> returns 1 else returns 0
  struct stat file_info;
  GRSTgaclPerm new_perm;
  char *vfile, *dir_path_vfile, *dir_path_file;
  FILE *fp;


  /*Check ACL has not been modified*/
  stat(GRSTgaclFileFindAclname(dir_path), &file_info);
  if (atol(GRSThttpGetCGI("timestamp"))!=file_info.st_mtime){
    StartHTML(bp, dir_uri, dir_path);
    GRSThttpPrintf (bp, "ERROR: CANNOT SAVE CHANGES<p><p> The ACL has been modified since it was last viewed\n<p>");
    admin_continue(dn, perm, help_uri, dir_path, file, dir_uri, admin_file, bp);
    return;
  }

  // check users permissions in the new ACL

  if (!GRSTgaclUserHasAURI(user, getenv("REDIRECT_GRST_ADMIN_LIST")))
  {
    new_perm = GRSTgaclAclTestUser(acl, user);
    if (new_perm != perm){
      StartHTML(bp, dir_uri, dir_path);
      if (!GRSTgaclPermHasAdmin(new_perm)){//Check that user still has Admin permissions - if not then exit without saving the new ACL
        GRSThttpPrintf (bp, "ERROR: CANNOT SAVE CHANGES\n\n<p><p> You cannot deny yourself admin access from within the editor\n");
        admin_continue(dn, perm, help_uri, dir_path, file, dir_uri, admin_file, bp);
        return;
      }
      //Functions to inform of other permission changes come next
      GRSThttpPrintf (bp, "WARNING: OPERATION CHANGED YOUR PERMISSIONS!\n\n<p><p> You still have Admin permissions<p>\n");
      admin_continue(dn, perm, help_uri, dir_path, file, dir_uri, admin_file, bp);
      return;
    }
  }
  // ACL not modified, notified of permission changes - can now save

  dir_path_file=GRSTgaclFileFindAclname(dir_path);
  vfile=makevfilename(".gacl", file_info.st_size, dn); // Make temporary file name
  dir_path_vfile = malloc(strlen(dir_path) + strlen(vfile) + 2);
  strcpy(dir_path_vfile, dir_path);
  strcat(dir_path_vfile, "/");
  strcat(dir_path_vfile, vfile);


  // save the new ACL to the temporary file in the correct format using the GridsiteACLFormat directive

  if (strcasecmp(getenv("REDIRECT_GRST_ACL_FORMAT"), "XACML") ==0) GRSTxacmlAclSave(acl, dir_path_vfile);
  else if (strcasecmp(getenv("REDIRECT_GRST_ACL_FORMAT"), "GACL") ==0) GRSTgaclAclSave(acl, dir_path_vfile);
  else
  {
    GRSThttpPrintf (bp, "ERROR: ACL type not correctly specified");
    admin_continue(dn, perm, help_uri, dir_path, file, dir_uri, admin_file, bp);
    return;
  }


  unlink(dir_path_file);
  if (link (dir_path_vfile,dir_path_file)!=0) GRSThttpError("403 Forbidden");

  printf ("Status: 302 Moved Temporarily\n Content Length: 0\nLocation: %s%s?cmd=admin_acl\n\n", dir_uri, admin_file);
  return;
}

void StringHTMLEncode (char* string, GRSThttpBody *bp){

  char* current_char;
  char* tmp;
  int n;
  tmp=malloc(2);

  *(tmp+1)='\0';
  current_char=string;
  while(*current_char != '\0'){

    if  (*current_char  == '<')     GRSThttpPrintf (bp,"&lt;");
    else if (*current_char == '>')  GRSThttpPrintf (bp,"&gt;");
    else if (*current_char == '&')  GRSThttpPrintf (bp,"&amp;");
    else if (*current_char == '\'') GRSThttpPrintf (bp,"&apos;");
    else if (*current_char == '"')  GRSThttpPrintf (bp,"&quot;");
    else{
       *tmp=*current_char;
       GRSThttpPrintf(bp, "%s", tmp);

    }
    current_char++;
  }
  return;
}

void revert_acl(GRSTgaclUser *user, char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file){
  char *AclFilename;
  GRSTgaclAcl *acl;
  GRSThttpBody bp;
  // Load the old ACL, add the entry and save
  AclFilename=malloc(strlen(dir_path)+strlen(file)+2);
  strcpy(AclFilename, dir_path);
  strcat(AclFilename, "/");
  strcat(AclFilename, file);

  acl = GRSTgaclAclLoadFile(AclFilename);
  check_acl_save(dn, perm, help_uri, dir_path, file, dir_uri, admin_file, user, acl, &bp);
  return;
}
