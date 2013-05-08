/*
   Copyright (c) 2002-3, Andrew McNab and Shiv Kaushal, 
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

/*------------------------------------------------------------------*
 * This program is part of GridSite: http://www.gridsite.org/       *
 *------------------------------------------------------------------*/

void  GRSThttpError(char *);
void  adminfooter(GRSThttpBody *, char *, char *, char *, char *);
int   GRSTstrCmpShort(char *, char *);
char *makevfilename(char *, size_t, char *);

/*CGI GACL - Edit interface functions*/
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
void revert_acl(GRSTgaclUser *user, char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file);

/*Functions producing messages*/
//void error(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file);
void admin_continue(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file, GRSThttpBody *bp);

//functions for cgi program
int verifypasscode();
void outputformactionerror(char *dn, GRSTgaclPerm perm, char *help_uri,
                      char *dir_path, char *dir_uri, char *admin_file);
char *storeuploadfile(char *boundary, int *bufferused);
void uploadfile(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path,
                char *dir_uri, char *admin_file);
void deletefileaction(char *dn, GRSTgaclPerm perm, char *help_uri,
                      char *dir_path, char *file, char *dir_uri,
                      char *admin_file);
void deletefileform(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path,
                    char *file, char *dir_uri, char *admin_file);
void renameform(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path,
	    char *file, char *dir_uri, char *admin_file);
void editfileaction(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path,
                    char *file, char *dir_uri, char *admin_file);
void create_acl(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path,
                    char *file, char *dir_uri, char *admin_file);
void renameaction(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path,
                  char *file, char *dir_uri, char *admin_file);
void newdirectory(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path,
                    char *file, char *dir_uri, char *admin_file);
void editdnlistaction(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path,
                      char *file, char *dir_uri, char *admin_file);
void printfile(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path,
                  char *file, char *dir_uri, char *admin_file);
void filehistory(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path,
                 char *file, char *dir_uri, char *admin_file);
void ziplist(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path,
             char *file, char *dir_uri, char *admin_file);
void unzipfile(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path,
               char *file, char *dir_uri, char *admin_file);
void editfileform(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path,
                  char *file, char *dir_uri, char *admin_file);
void editdnlistform(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path,
                    char *file, char *dir_uri, char *admin_file);
void managedir(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path,
               char *dir_uri, char *admin_file);
int userisgroupadmin(GRSTgaclUser *user, char *adminrole, char *uri);
void managednlists(GRSTgaclUser *user, char *dn, GRSTgaclPerm perm,
                   char *help_uri, char *dir_path,
                   char *dir_uri, char *admin_file);

/* XACML */
int GRSTxacmlAclSave(GRSTgaclAcl *acl, char *filename, char* dir_uri);
