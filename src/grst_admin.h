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

/*---------------------------------------------------------------------------*
 * This program is part of GridSite: http://www.gridpp.ac.uk/gridsite/       *
 *---------------------------------------------------------------------------*/

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

/*Functions producing messages*/
//void error(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file);
void admin_continue(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, char *file, char *dir_uri, char *admin_file, GRSThttpBody *bp);

