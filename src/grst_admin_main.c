/*
   Andrew McNab and Shiv Kaushal, University of Manchester. 
   Copyright (c) 2002-5. All rights reserved.

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

#ifndef VERSION
#define VERSION "x.x.x"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>

// when porting: remember that sendfile() is very OS-specific!
#if defined(FREEBSD) || defined(__FreeBSD__) 
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#else
#include <sys/sendfile.h>
#endif

#include <gridsite.h>

#include "grst_admin.h"

/*

   GridSite human/interactive management interface. This should produce
   a CGI executable, usually ./sbin/real-gridsite-admin.cgi, which is
   called from HTML forms either by GET or POST methods or both (ie input 
   present in both QUERY_STRING and the stdin of the CGI process.)

   The CGI name/value pairs used are: 
    
    cmd  = edit, managedir, print, history
    file = short name of file, without path

   If real-gridsite-admin.cgi is run by an internal redirection inside 
   mod_gridsite (as should ALWAYS be the case) then the environment 
   variable  REDIRECT_GRST_DIR_PATH  will be set to the full path of
   the directory holding the file in question. This respects any complex
   URI -> file path mapping done by Apache.

*/

void GRSThttpError(char *status)
{
  printf("Status: %s\n", status);
  printf("Server-CGI: GridSite Admin %s\n", VERSION);
  printf("Content-Length: %zd\n", 2 * strlen(status) + 58);
  puts("Content-Type: text/html\n");

  printf("<head><title>%s</title></head>\n", status);
  printf("<body><h1   >%s</h1   ></body>\n", status);
   
  exit(0);
}

void adminfooter(GRSThttpBody *bp, char *dn, char *help_uri, char *dir_uri,
                 char *admin_file)
{
  GRSThttpPrintf(bp, "<p><small>\n");  

  if (dn != NULL) GRSThttpPrintf(bp, "<hr>You are %s<br>\n", dn);
  else            GRSThttpPrintf(bp, "<hr>\n");

  if (admin_file != NULL)
       GRSThttpPrintf(bp, "<a href=\"%s%s?cmd=managedir\">"
                      "Manage&nbsp;directory</a> .\n", 
                      dir_uri, admin_file);
  else GRSThttpPrintf(bp, "<a href=\"%s\">"
                      "Back&nbsp;to&nbsp;directory</a> .\n", dir_uri);

  if (help_uri != NULL) 
    GRSThttpPrintf(bp, "<a href=\"%s\">Website&nbsp;Help</a> .\n", help_uri);

  if ((getenv("GRST_NO_LINK") == NULL) &&
      (getenv("REDIRECT_GRST_NO_LINK") == NULL))
    GRSThttpPrintf(bp, "Built with "
     "<a href=\"http://www.gridsite.org/\">GridSite</a> %s\n",
     VERSION);
   
  GRSThttpPrintf(bp, "</small>\n");
}

int GRSTstrCmpShort(char *long_s, char *short_s)
{
  while (*short_s != '\0')
       {
         if (*long_s > *short_s) return +1;
         if (*long_s < *short_s) return -1;
         
         ++long_s;
         ++short_s;
       }

  return 0;
}

char *makevfilename(char *publicname, size_t size, char *dn)
{
  int             i;
  char           *ext, *vfilename, *encpublicname, *encdn, *p;
  struct timeval  tv_now;
  
  gettimeofday(&tv_now, NULL);

  ext = rindex(publicname, '.');
  if (ext == NULL) ext = "";
  
  encpublicname = GRSThttpUrlEncode(publicname);  
  for (p=encpublicname; *p != '\0'; ++p) if (*p == '%') *p = '=';
  
  encdn = GRSThttpUrlEncode(dn);  
  for (p=encdn; *p != '\0'; ++p) if (*p == '%') *p = '=';

  /* we used zero-padding for times so 
     alphanumeric sorting will sort chronologically too */

  asprintf(&vfilename, "%s:%s:%08lX:%05lX:%zX:%s:%s", GRST_HIST_PREFIX,
           encpublicname, tv_now.tv_sec, tv_now.tv_usec, size, encdn, ext);
   
  return vfilename;
}

void justheader(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path,
                char *dir_uri, char *admin_file)
{
  GRSThttpBody bp;
 
  puts("Status: 200 OK\nContent-Type: text/html");
   
  GRSThttpBodyInit(&bp);
 
  GRSThttpPrintHeader(&bp, dir_path);

  GRSThttpWriteOut(&bp);
}

void justfooter(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path,
                char *dir_uri, char *admin_file)
{
  GRSThttpBody bp;

  puts("Status: 200 OK\nContent-Type: text/html");
   
  GRSThttpBodyInit(&bp);
 
  if (GRSTgaclPermHasList(perm) || GRSTgaclPermHasWrite(perm) 
                                || GRSTgaclPermHasAdmin(perm))
               adminfooter(&bp, dn, help_uri, dir_uri, admin_file);

  GRSThttpPrintFooter(&bp, dir_path);
                                                                                
  GRSThttpWriteOut(&bp);
}

int main()
{
  int           i, gsiproxylimit_i = 1, delegation = 0;
  char         *cmd, *dir_uri, *file, *dir_path, *admin_file, *dn = NULL,
               *help_uri, *p, *content_type, *request_uri, *button, 
               *grst_auri_i, *grst_valid_i, *gsiproxylimit, buf[12];
  GRSTgaclCred *cred;
  GRSTgaclUser *user = NULL;
  GRSTgaclAcl  *acl;
  GRSTgaclPerm  perm = GRST_PERM_NONE;

  help_uri      = getenv("REDIRECT_GRST_HELP_URI"); /* can be NULL */
  admin_file    = getenv("REDIRECT_GRST_ADMIN_FILE");
  dir_path      = getenv("REDIRECT_GRST_DIR_PATH");
  request_uri   = getenv("REQUEST_URI");
  
  if ((dir_path == NULL) || (admin_file == NULL) || (request_uri == NULL))
    {
      puts("Status: 500 Internal Server Error\nContent-type: text/plain\n\n"
           "REDIRECT_GRST_DIR_PATH or REDIRECT_GRST_ADMIN_FILE "
           "or REQUEST_URI missing");
      return -1;
    }

  GRSTgaclInit();

  gsiproxylimit = getenv("REDIRECT_GRST_GSIPROXY_LIMIT");
  if (gsiproxylimit != NULL) sscanf(gsiproxylimit, "%d", &gsiproxylimit_i);

  grst_auri_i  = getenv("GRST_CRED_AURI_0");
  grst_valid_i = getenv("GRST_CRED_VALID_0");
  
  if ((grst_auri_i != NULL) && (strncmp(grst_auri_i, "dn:", 3) == 0))  
    {
      dn = &grst_auri_i[3];
    
      sscanf(grst_valid_i, 
         "notbefore=%*d notafter=%*d delegation=%d nist-loa=%*d",
         &delegation);
      
      if (delegation <= gsiproxylimit_i)
        {    
          cred = GRSTgaclCredCreate(grst_auri_i, NULL);
          user = GRSTgaclUserNew(cred);

          /* User has a cert so check for VOMS attributes etc */
          for (i=1; ; i++)
             {
               sprintf (buf, "GRST_CRED_%d", i);

  	       grst_auri_i = getenv(buf);
	       if (grst_auri_i == NULL) break;
 	       
               cred = GRSTgaclCredCreate(grst_auri_i, NULL);
               GRSTgaclUserAddCred(user, cred);
             }

          /* no more VOMS attributes etc found */
        }
    }
  else if ((dn = getenv("SSL_CLIENT_S_DN")) != NULL)
    {
      cred = GRSTgaclCredCreate("dn:", GRSThttpUrlMildencode(dn));
      user = GRSTgaclUserNew(cred);
    }

  if (GRSTgaclUserHasAURI(user, getenv("REDIRECT_GRST_ADMIN_LIST")))
    perm = GRST_PERM_ALL;
  else
    {
      p = getenv("REMOTE_HOST");
      if (p != NULL)
        {
          cred = GRSTgaclCredCreate("dns:", p);
  
          if (user == NULL) user = GRSTgaclUserNew(cred);
          else              GRSTgaclUserAddCred(user, cred);
        }

      acl = GRSTgaclAclLoadforFile(dir_path);
      if (acl != NULL) perm = GRSTgaclAclTestUser(acl, user);
    }
    
  /* we're relying on being a CGI with all this un-free()ed strdup()ing */

  dir_uri  = strdup(request_uri);
  p = rindex(dir_uri, '?');
  if (p != NULL) *p = '\0';
  p = rindex(dir_uri, '/');
  if (p != NULL) p[1] = '\0';

  content_type = getenv("CONTENT_TYPE");

  if ((content_type != NULL) &&
      (GRSTstrCmpShort(content_type, "multipart/form-data; boundary=") == 0))
    {
      uploadfile(dn, perm, help_uri, dir_path, dir_uri, admin_file);
      return 0;
    }
  
  cmd    = GRSThttpGetCGI("cmd");
  button = GRSThttpGetCGI("button");

  file   = GRSThttpGetCGI("file");
  
  if ((index(file, '/') != NULL) ||
      (index(file, '<') != NULL) ||
      (index(file, '>') != NULL) ||
      (index(file, '&') != NULL) ||
      (index(file, '"') != NULL)) file[0] = '\0';

  /* file and directory functions in grst_admin_file.c */

  if (strcmp(cmd, "header") == 0) 
      justheader(dn, perm, help_uri, dir_path, dir_uri, admin_file);
  else if (strcmp(cmd, "footer") == 0) 
      justfooter(dn, perm, help_uri, dir_path, dir_uri, admin_file);
  else if (strcmp(cmd, "managedir") == 0) 
      managedir(dn, perm, help_uri, dir_path, dir_uri, admin_file);
  else if (strcmp(cmd, "print") == 0) 
      printfile(dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
  else if (strcmp(cmd, "history") == 0) 
      filehistory(dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
  else if (strcmp(cmd, "managednlists") == 0) 
      managednlists(user, dn, perm, help_uri, dir_path, dir_uri, admin_file);
  else if (strcmp(cmd, "editdnlist") == 0) 
      editdnlistform(dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
  else if (strcmp(cmd, "edit") == 0)
    { 
      if ((strcasecmp(button, "new directory") == 0) ||
          (strcasecmp(button, "Create") == 0))
       newdirectory(dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
      else
       editfileform(dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
    }
  else if (strcmp(cmd, "editaction") == 0) 
      editfileaction(dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
  else if (strcmp(cmd, "editdnlistaction") == 0) 
      editdnlistaction(dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
  else if (strcmp(cmd, "delete") == 0) 
      deletefileform(dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
  else if (strcmp(cmd, "deleteaction") == 0) 
     deletefileaction(dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
  else if (strcmp(cmd, "rename") == 0) 
     renameform(dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
  else if (strcmp(cmd, "renameaction") == 0) 
     renameaction(dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
  else if (strcmp(cmd, "ziplist") == 0) 
     ziplist(dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
  else if (strcmp(cmd, "unzipfile") == 0) 
     unzipfile(dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
  else if (strcmp(cmd, "create_acl") == 0) 
     create_acl(dn, perm, help_uri, dir_path, file, dir_uri, admin_file);

  /* GACL functions in grst_admin_gacl.c */

  else if (strcmp(cmd, "show_acl") == 0)
     show_acl(0, user, dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
  else if (strcmp(cmd, "admin_acl") == 0)
     show_acl(1, user, dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
  else if (strcmp(cmd, "acl_history") == 0)
     show_acl(2, user, dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
  else if (strcmp(cmd, "revert_acl") == 0)
    revert_acl(user, dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
    //show_acl(2, user, dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
  else if (strcmp(cmd,"new_entry_form")==0)
     new_entry_form(user, dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
  else if (strcmp(cmd,"new_entry")==0)
     new_entry(user, dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
  else if (strcmp(cmd,"del_entry_sure")==0)
     del_entry_sure(user, dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
  else if (strcmp(cmd,"del_entry")==0)
     del_entry(user, dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
  else if (strcmp(cmd,"edit_entry_form")==0)
     edit_entry_form(user, dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
  else if (strcmp(cmd,"edit_entry")==0)
     edit_entry(user, dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
  else if (strcmp(cmd,"add_cred_form")==0)
     add_cred_form(user, dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
  else if (strcmp(cmd,"add_cred")==0)
     add_cred(user, dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
  else if (strcmp(cmd,"del_cred_sure")==0)
     del_cred_sure(user, dn, perm, help_uri, dir_path, file, dir_uri, admin_file);
  else if (strcmp(cmd,"del_cred")==0)
     del_cred(user, dn, perm, help_uri, dir_path, file, dir_uri, admin_file);

  /* you what? */

  else GRSThttpError("500 Internal Server Error");
}
