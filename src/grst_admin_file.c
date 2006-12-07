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

/*------------------------------------------------------------------*
 * This program is part of GridSite: http://www.gridsite.org/       *
 *------------------------------------------------------------------*/

#ifndef VERSION
#define VERSION "x.x.x"
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
#include <sys/sendfile.h>

#include <gridsite.h>

#include "grst_admin.h"

char *storeuploadfile(char *boundary, int *bufferused)
{
// rewrite this to copy whole POSTed stdin HTTP body to disk then 
// mmap() and pick apart? How to deal with 100MB uploaded files, say?

  char *filebuffer = NULL;
  int   bufferlen = 0, c, boundarylen;

  *bufferused = 0;
  boundarylen = strlen(boundary);

  while ((c = getchar()) != EOF)
       {
         if (*bufferused > 1024*1024*100) return NULL;
       
         ++(*bufferused);
   
         if (*bufferused > bufferlen)
           {
             bufferlen = bufferlen + 1000;
             filebuffer = realloc(filebuffer, (size_t) bufferlen);
           }

         filebuffer[*bufferused - 1] = c;         

         if ( (*bufferused >= boundarylen + 4)    &&
              (boundary[boundarylen-1] == c) && 
              (boundary[boundarylen-2] == filebuffer[*bufferused - 2]) &&
              (strncmp(boundary, &filebuffer[*bufferused - boundarylen],
                                                       boundarylen) == 0))
             {
               *bufferused = *bufferused - boundarylen - 4;

               if (filebuffer == NULL) return strdup("");
               else return filebuffer;
             }
       }

  return NULL;
}

void uploadfile(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, 
                char *dir_uri, char *admin_file)
{
  char  *boundary, *p, oneline[200], *filename = NULL, 
         tmpfilename[256], *filebuffer = NULL, *filepath,
        *vfile, *dir_path_vfile;         
  int    mimestate, bufferused = 0, itworked = 0;
  FILE   *fp;
  GRSThttpBody bp;

#define MIMESTUNKNOWN  1
#define MIMESTUPLOAD   2
#define MIMESTFILENM   3

  if (!GRSTgaclPermHasWrite(perm)) GRSThttpError("403 Forbidden");

  p = getenv("CONTENT_TYPE");
  boundary = &p[30];
    
  mimestate = MIMESTUNKNOWN;
  
  while (fgets(oneline, sizeof(oneline), stdin) != NULL)
     {
       if (*oneline == 13) // MIME has CR/LF line breaks, CR=13
         {
           if      (mimestate == MIMESTUPLOAD)
             {
               filebuffer = storeuploadfile(boundary, &bufferused);
               mimestate = MIMESTUNKNOWN;
             }
           else if (mimestate == MIMESTFILENM)
             {
               fgets(tmpfilename, sizeof(tmpfilename), stdin);
               if (*tmpfilename != 13)
                 {
                   p = index(tmpfilename, 13);
                   *p = '\0';
                   filename = strdup(tmpfilename);
                 }
               mimestate = MIMESTUNKNOWN;
             }
         }
       else if (GRSTstrCmpShort(oneline,             
            "Content-Disposition: form-data; name=\"uploadfile\"; filename=\"") 
                == 0)
         {
           mimestate = MIMESTUPLOAD;
           if (filename == NULL) 
             {
               filename = strdup(&oneline[61]);

               p = rindex(&oneline[61], '\\');
               if (p != NULL) { ++p ; filename = p; }

               p = rindex(&oneline[61], '/');
               if (p != NULL) { ++p ; filename = p; }
                                  
               p = index(filename, '"');
               if (p != NULL) *p = '\0'; 
             }
         }
       else if (GRSTstrCmpShort(oneline,
                 "Content-Disposition: form-data; name=\"file\"") == 0)
         {
           mimestate = MIMESTFILENM;           
         }      
     }

  if ((filebuffer != NULL) && (bufferused >= 0))
    {
      if (filename == NULL) GRSThttpError("403 Forbidden");
      else if ((index(filename, '/') != NULL) ||
               (strcmp(filename, GRST_ACL_FILE) == 0))
        {
          puts("Status: 403 Forbidden filename\nContent-Type: text/html");
                                                                                
          GRSThttpBodyInit(&bp);
                                                                   
          GRSThttpPrintf(&bp,"<title>Forbidden filename %s</title>\n", filename);
          GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_HEADFILE);
                                 
          GRSThttpPrintf(&bp, "<h1 align=center>Forbidden filename %s</h1>\n",
                         filename);
                                                                                
          GRSThttpPrintf(&bp,
                      "<p align=center>New file names cannot include slashes "
                      "or use the reserved ACL name, %s\n", GRST_ACL_FILE);
                                                                                
          GRSThttpPrintf(&bp,"<p align=center>"
                     "<a href=\"%s%s?cmd=managedir\">Return to "
                     "directory listing</a>\n", dir_uri, admin_file);
                                                                                
          adminfooter(&bp, dn, help_uri, dir_uri, admin_file);
          GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_FOOTFILE);
                                                                                
          GRSThttpWriteOut(&bp);
          return;
        }
      else
        {
          vfile = makevfilename(filename, bufferused, dn);
          asprintf(&dir_path_vfile, "%s/%s", dir_path, vfile);

          fp = fopen(dir_path_vfile, "w");
          if (fp != NULL)
            {              
              if ((fwrite(filebuffer, 
                          sizeof(char), bufferused, fp) == bufferused) &&
                  (fclose(fp) == 0)) 
                {                  
                  asprintf(&filepath, "%s/%s", dir_path, filename);
          
                  unlink(filepath); /* this can fail ok */
          
                  itworked = (link(dir_path_vfile, filepath) == 0);
                }
            }
        }
                 
      free((void *) filebuffer);
    }
    
  if (itworked) 
    {
      printf("Status: 302 Moved Temporarily\nContent-Length: 0\n"
                  "Location: %s%s?cmd=managedir\n\n", dir_uri, admin_file);
      return;
    }

  puts("Status: 500 Failed trying to upload\nContent-Type: text/html");
  
  GRSThttpBodyInit(&bp);

  GRSThttpPrintf(&bp, "<title>Failed to upload</title>\n");

  GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_HEADFILE);

  GRSThttpPrintf(&bp, "<h1 align=center>Failed to upload</h1>\n");
  
  GRSThttpPrintf(&bp, "<p align=center>GridSite considers you are authorized "
                      "to upload the file, but the upload failed. This is "
                      "probably a web server or operating system level "
                      "misconfiguration. Consult the site administrator.");

  GRSThttpPrintf(&bp,"<p align=center>"
                     "<a href=\"%s%s?cmd=managedir\">Return to "
                     "directory listing</a>\n", dir_uri, admin_file);
  
  adminfooter(&bp, dn, help_uri, dir_uri, admin_file);
  GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_FOOTFILE);

  GRSThttpWriteOut(&bp);
}

void deletefileaction(char *dn, GRSTgaclPerm perm, char *help_uri, 
                      char *dir_path, char *file, char *dir_uri, 
                      char *admin_file)
{
  int            fd, numfiles;
  char          *dir_path_file, *dir_path_vfile, *p, *vfile, *dnlistsuri, 
                *fulluri, *server_name, *realfile;
  struct stat    statbuf;
  GRSThttpBody   bp; 
  struct dirent *subdirfile_ent;
  DIR           *subDIR;

  if (((strcmp(file, GRST_ACL_FILE) != 0) && !GRSTgaclPermHasWrite(perm)) ||
      ((strcmp(file, GRST_ACL_FILE) == 0) && !GRSTgaclPermHasAdmin(perm)))
                                               GRSThttpError("403 Forbidden");

  dnlistsuri = getenv("GRST_DN_LISTS_URI");
  if (dnlistsuri == NULL) dnlistsuri = getenv("REDIRECT_GRST_DN_LISTS_URI");

  if ((dnlistsuri != NULL) && 
      (strncmp(dnlistsuri, dir_uri, strlen(dnlistsuri)) == 0))
       realfile = GRSThttpUrlEncode(file);
  else if (index(file, '/') != NULL) GRSThttpError("403 Forbidden");
  else realfile = file;

  dir_path_file = malloc(strlen(dir_path) + strlen(realfile) + 2);
  
  strcpy(dir_path_file, dir_path);
  strcat(dir_path_file, "/");
  strcat(dir_path_file, realfile);

  if ((stat(dir_path_file, &statbuf) == 0) && S_ISDIR(statbuf.st_mode))
    {
      subDIR = opendir(dir_path_file);
      if (subDIR == NULL) numfiles = 99; /* stop deletion */
      else
        {
          numfiles = 0; 
          while ((subdirfile_ent = readdir(subDIR)) != NULL) 
             if (subdirfile_ent->d_name[0] != '.') ++numfiles;
             else if (strncmp(subdirfile_ent->d_name, 
                              GRST_ACL_FILE,
                              sizeof(GRST_ACL_FILE)) == 0) ++numfiles;
          closedir(subDIR);
        }
                     
      if (numfiles == 0)
        {
          vfile = makevfilename(file, 0, dn);
          dir_path_vfile = malloc(strlen(dir_path) + strlen(vfile) + 2);  
          strcpy(dir_path_vfile, dir_path);
          strcat(dir_path_vfile, "/");
          strcat(dir_path_vfile, vfile);
          
          if (rename(dir_path_file, dir_path_vfile) == 0)
            {
              printf("Status: 302 Moved Temporarily\nContent-Length: 0\n"
                     "Location: %s%s?cmd=managedir\n\n", dir_uri, admin_file);
              return; 
            }
        }
    }
  else if (unlink(dir_path_file) == 0)
    {
      if (strcmp(file, GRST_ACL_FILE) != 0)
        {
          vfile = makevfilename(file, 0, dn);
          dir_path_file = malloc(strlen(dir_path) + strlen(vfile) + 2);  
          strcpy(dir_path_file, dir_path);
          strcat(dir_path_file, "/");
          strcat(dir_path_file, vfile);

          fd = open(dir_path_file, O_WRONLY | O_CREAT);
          if (fd != -1) close(fd);           
        }

      printf("Status: 302 Moved Temporarily\nContent-Length: 0\n"
             "Location: %s%s?cmd=managedir\n\n", dir_uri, admin_file);
          
      return;
    }

  puts("Status: 500 Failed trying to delete\nContent-Type: text/html");
  
  GRSThttpBodyInit(&bp);

  GRSThttpPrintf(&bp, "<title>Error deleting %s%s</title>\n", dir_uri, file);

  GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_HEADFILE);

  GRSThttpPrintf(&bp, "<h1 align=center>Error deleting %s%s</h1>\n", 
                      dir_uri, file);
  
  GRSThttpPrintf(&bp, "<p align=center>GridSite considers you are authorized "
                      "to delete %s, but the delete failed. This is "
                      "probably a web server or operating system level "
                      "misconfiguration. Consult the site administrator.",
                      file);

  GRSThttpPrintf(&bp,"<p align=center>"
                     "<a href=\"%s%s?cmd=managedir\">Return to "
                     "directory listing</a>\n", dir_uri, admin_file);
  
  adminfooter(&bp, dn, help_uri, dir_uri, admin_file);
  GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_FOOTFILE);

  GRSThttpWriteOut(&bp);
}                    

void deletefileform(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path,
                    char *file, char *dir_uri, char *admin_file)
{
  GRSThttpBody bp; 

  if (!GRSTgaclPermHasWrite(perm)) GRSThttpError("403 Forbidden");

  puts("Status: 200 OK\nContent-Type: text/html");
  
  GRSThttpBodyInit(&bp);

  GRSThttpPrintf(&bp, "<title>Delete %s</title>\n", file);

  GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_HEADFILE);

  GRSThttpPrintf(&bp, "<h1 align=center>Delete %s</h1>\n", file);
  
  GRSThttpPrintf(&bp,"<form action=\"%s%s\" method=post>\n",dir_uri,admin_file);
  GRSThttpPrintf(&bp,"<h2 align=center>Do you really want to delete %s?", file);
  GRSThttpPrintf(&bp,"<p align=center><input type=submit value=\"Yes, delete %s\"></h2>\n", file);
  GRSThttpPrintf(&bp,"<input type=hidden name=file value=\"%s\">\n", file);
  GRSThttpPrintf(&bp,"<input type=hidden name=cmd value=deleteaction>\n");
  GRSThttpPrintf(&bp,"</form>\n");

  GRSThttpPrintf(&bp,"<p align=center>Or "
                     "<a href=\"%s%s?cmd=managedir\">return to "
                     "directory listing</a>\n", dir_uri, admin_file);
  
  adminfooter(&bp, dn, help_uri, dir_uri, admin_file);
  GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_FOOTFILE);

  GRSThttpWriteOut(&bp);
}                    

void renameform(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path,
                    char *file, char *dir_uri, char *admin_file)
{
  GRSThttpBody bp; 

  if (!GRSTgaclPermHasWrite(perm)) GRSThttpError("403 Forbidden");

  puts("Status: 200 OK\nContent-Type: text/html");
  
  GRSThttpBodyInit(&bp);

  GRSThttpPrintf(&bp, "<title>Rename %s</title>\n", file);

  GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_HEADFILE);

  GRSThttpPrintf(&bp, "<h1 align=center>Rename %s%s</h1>\n", dir_uri, file);
  
  GRSThttpPrintf(&bp,"<form action=\"%s%s\" method=post>\n",dir_uri,admin_file);
  GRSThttpPrintf(&bp,"<h2 align=center>What do you want to rename %s to?</h2>", file);
  GRSThttpPrintf(&bp,"<input type=hidden name=file value=\"%s\">\n", file);
  GRSThttpPrintf(&bp,"<p align=center>New name: <input type=text name=newfile value=\"%s\">\n", file);
  GRSThttpPrintf(&bp,"<input type=submit value=\"Rename\">\n");
  GRSThttpPrintf(&bp,"<input type=hidden name=cmd value=renameaction>\n");
  GRSThttpPrintf(&bp,"</form>\n");

  GRSThttpPrintf(&bp,"<p align=center>Or "
                     "<a href=\"%s%s?cmd=managedir&diruri=%s\">return to "
                     "directory listing</a>\n", dir_uri, admin_file, dir_uri);
  
  adminfooter(&bp, dn, help_uri, dir_uri, admin_file);
  GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_FOOTFILE);

  GRSThttpWriteOut(&bp);
}                    

void editfileaction(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path,
                    char *file, char *dir_uri, char *admin_file)
{
  char         *pagetext, *dir_path_file, *vfile, *dir_path_vfile,
               *dnlistsuri, *server_name, *fulluri, *realfile;
  FILE         *fp;
  GRSThttpBody  bp;
  
  if (!GRSTgaclPermHasWrite(perm) || (strcmp(file, GRST_ACL_FILE) == 0))
                                               GRSThttpError("403 Forbidden");
                                                 
  dnlistsuri = getenv("GRST_DN_LISTS_URI");
  if (dnlistsuri == NULL) dnlistsuri = getenv("REDIRECT_GRST_DN_LISTS_URI");

  if ((dnlistsuri != NULL) && 
      (strncmp(dnlistsuri, dir_uri, strlen(dnlistsuri)) == 0))
    {
      realfile = GRSThttpUrlEncode(file);
      
      if (realfile[0] == '.') GRSThttpError("403 Forbidden");
    }
  else if (index(file, '/') != NULL) GRSThttpError("403 Forbidden");
  else realfile = file;

  asprintf(&dir_path_file, "%s/%s", dir_path, realfile);

  pagetext = GRSThttpGetCGI("pagetext");
  vfile = makevfilename(file, strlen(pagetext), dn);
  asprintf(&dir_path_vfile, "%s/%s", dir_path, vfile);
      
  fp = fopen(dir_path_vfile, "w");
  if (fp == NULL)
    {
      puts("Status: 500 Failed trying to write\nContent-Type: text/html");
  
      GRSThttpBodyInit(&bp);

      GRSThttpPrintf(&bp,"<title>Error writing %s%s</title>\n", dir_uri, file);
      GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_HEADFILE);

      GRSThttpPrintf(&bp, "<h1 align=center>Error writing %s%s</h1>\n", 
                      dir_uri, file);
  
      GRSThttpPrintf(&bp, 
                      "<p align=center>GridSite considers you are authorized "
                      "to write the file, but the write failed. This is "
                      "probably a web server or operating system level "
                      "misconfiguration. Consult the site administrator.");

      GRSThttpPrintf(&bp,"<p align=center>"
                     "<a href=\"%s%s?cmd=managedir\">Return to "
                     "directory listing</a>\n", dir_uri, admin_file);
  
      adminfooter(&bp, dn, help_uri, dir_uri, admin_file);
      GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_FOOTFILE);

      GRSThttpWriteOut(&bp);
      return;
    }

  fwrite(pagetext, strlen(pagetext), sizeof(char), fp);
  
  fclose(fp);
  
  unlink(dir_path_file);
  
  if (link(dir_path_vfile,dir_path_file) != 0) GRSThttpError("403 Forbidden");

  if ((strlen(file) > 7) && (strcmp(&file[strlen(file) - 5], ".html") == 0))
       printf("Status: 302 Moved Temporarily\nContent-Length: 0\n"
              "Location: %s%s\n\n", dir_uri, file);      
  else printf("Status: 302 Moved Temporarily\nContent-Length: 0\n"
              "Location: %s%s?cmd=managedir\n\n", dir_uri, admin_file);
}

void create_acl(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path,
                    char *file, char *dir_uri, char *admin_file)
{
  int           fd;
  char         *tmpgacl, *newgacl;
  GRSTgaclAcl  *acl;
  FILE         *fp;
  GRSThttpBody  bp;
  
  if (!GRSTgaclPermHasAdmin(perm)) GRSThttpError("403 Forbidden");

  asprintf(&tmpgacl, "%s/.tmp.XXXXXX", dir_path);
  asprintf(&newgacl, "%s/%s", dir_path, GRST_ACL_FILE);
  
  if (((acl = GRSTgaclAclLoadforFile(dir_path)) != NULL) &&
      ((fd = mkstemp(tmpgacl)) != -1) && 
      ((fp = fdopen(fd, "w+")) != NULL) &&
      GRSTgaclAclPrint(acl, fp) &&
      (fclose(fp) == 0) &&
      (rename(tmpgacl, newgacl) == 0))
    {
      printf("Status: 302 Moved Temporarily\nContent-Length: 0\n"
         "Location: %s%s?cmd=managedir\n\n", dir_uri, admin_file);

      free(tmpgacl);
      free(newgacl);
      return;
    }

  puts("Status: 500 Failed trying to create\nContent-Type: text/html");
  
  GRSThttpBodyInit(&bp);

  GRSThttpPrintf(&bp,"<title>Error creating %s%s</title>\n", dir_uri, 
                                                             GRST_ACL_FILE);
  GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_HEADFILE);

  GRSThttpPrintf(&bp, "<h1 align=center>Error creating %s%s</h1>\n", 
                      dir_uri, GRST_ACL_FILE);
  
  GRSThttpPrintf(&bp, "<p align=center>GridSite considers you are authorized "
                      "to create it, but the create failed. This is "
                      "probably a web server or operating system level "
                      "misconfiguration. Consult the site administrator.");

  GRSThttpPrintf(&bp,"<p align=center>"
                     "<a href=\"%s%s?cmd=managedir\">Return to "
                     "directory listing</a>\n", dir_uri, admin_file);
  
  adminfooter(&bp, dn, help_uri, dir_uri, admin_file);
  GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_FOOTFILE);

  GRSThttpWriteOut(&bp);

  free(tmpgacl);
  free(newgacl);
}

void renameaction(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path,
                  char *file, char *dir_uri, char *admin_file)
{
  int           len;
  char         *dir_path_file, *vfile, *dir_path_vfile,
               *dnlistsuri, *newfile, *dir_path_newfile;
  struct stat   statbuf;
  FILE         *fp;
  GRSThttpBody  bp;
  
  if (!GRSTgaclPermHasWrite(perm) || (strcmp(file, GRST_ACL_FILE) == 0)) 
                                              GRSThttpError("403 Forbidden");
                                              
  if (index(file, '/') != NULL) GRSThttpError("403 Forbidden");

  dir_path_file = malloc(strlen(dir_path) + strlen(file) + 2);  
  strcpy(dir_path_file, dir_path);
  strcat(dir_path_file, "/");
  strcat(dir_path_file, file);
  
  if (stat(dir_path_file, &statbuf) != 0) GRSThttpError("404 Not Found");

  newfile = GRSThttpGetCGI("newfile");

  if ((strcmp(newfile, GRST_ACL_FILE) == 0) ||
      (strcmp(newfile, file) == 0)) GRSThttpError("403 Forbidden");

  dir_path_newfile = malloc(strlen(dir_path) + strlen(newfile) + 2);  
  strcpy(dir_path_newfile, dir_path);
  strcat(dir_path_newfile, "/");
  strcat(dir_path_newfile, newfile);

  vfile = makevfilename(newfile, statbuf.st_size, dn);
  dir_path_vfile = malloc(strlen(dir_path) + strlen(vfile) + 2);  
  strcpy(dir_path_vfile, dir_path);
  strcat(dir_path_vfile, "/");
  strcat(dir_path_vfile, vfile);

  unlink(dir_path_newfile); /* just in case */

  if ((link(dir_path_file, dir_path_vfile  ) == 0) &&
      (link(dir_path_file, dir_path_newfile) == 0) &&
      (unlink(dir_path_file) == 0))
    {
      printf("Status: 302 Moved Temporarily\nContent-Length: 0\n"
             "Location: %s\n\n", dir_uri);
      return;
    }

  puts("Status: 500 Failed trying to rename\nContent-Type: text/html");
  
  GRSThttpBodyInit(&bp);

  GRSThttpPrintf(&bp,"<title>Error renaming %s%s</title>\n", dir_uri, file);
  GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_HEADFILE);

  GRSThttpPrintf(&bp, "<h1 align=center>Error renaming %s%s</h1>\n", 
                      dir_uri, file);
  
  GRSThttpPrintf(&bp, "<p align=center>GridSite considers you are authorized "
                      "to rename it, but the rename failed. This is "
                      "probably a web server or operating system level "
                      "misconfiguration. Consult the site administrator.");

  GRSThttpPrintf(&bp,"<p align=center>"
                     "<a href=\"%s%s?cmd=managedir\">Return to "
                     "directory listing</a>\n", dir_uri, admin_file);
  
  adminfooter(&bp, dn, help_uri, dir_uri, admin_file);
  GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_FOOTFILE);

  GRSThttpWriteOut(&bp);
}

void newdirectory(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path,
                    char *file, char *dir_uri, char *admin_file)
{
  int           len;
  char         *dir_path_file, *vfile, *dir_path_vfile, *filedup;
  FILE         *fp;
  GRSThttpBody  bp;
  
  if ((file[0] == '\0') || 
      !GRSTgaclPermHasWrite(perm) || (strcmp(file, GRST_ACL_FILE) == 0))
                                                GRSThttpError("403 Forbidden");

  filedup = strdup(file);
  if (filedup[strlen(filedup)-1] == '/') filedup[strlen(filedup)-1] = '\0';
  if (index(filedup, '/') != NULL) GRSThttpError("403 Forbidden");
  
  dir_path_file = malloc(strlen(dir_path) + strlen(file) + 2);  
  strcpy(dir_path_file, dir_path);
  strcat(dir_path_file, "/");
  strcat(dir_path_file, file);

  if (mkdir(dir_path_file, 0751) == 0)
    {
      printf("Status: 302 Moved Temporarily\nContent-Length: 0\n"
             "Location: %s%s?cmd=managedir\n\n", dir_uri, admin_file);
      return;    
    }
      
  puts("Status: 500 Failed trying to create\nContent-Type: text/html");
  
  GRSThttpBodyInit(&bp);

  GRSThttpPrintf(&bp,"<title>Error create %s%s</title>\n", dir_uri, file);
  GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_HEADFILE);

  GRSThttpPrintf(&bp, "<h1 align=center>Error creating directory %s%s</h1>\n",
                      dir_uri, file);
  
  GRSThttpPrintf(&bp, 
                      "<p align=center>GridSite considers you are authorized "
                      "to create the directory, but the creation failed. This "
                      "is probably a web server or operating system level "
                      "misconfiguration. Consult the site administrator.");

  GRSThttpPrintf(&bp,"<p align=center>"
                     "<a href=\"%s%s?cmd=managedir\">Return to "
                     "parent directory listing</a>\n", dir_uri, admin_file);
  
  adminfooter(&bp, dn, help_uri, dir_uri, admin_file);
  GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_FOOTFILE);

  GRSThttpWriteOut(&bp);
}

void editdnlistaction(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path,
                      char *file, char *dir_uri, char *admin_file)
{
  int           numdn = 0, ifd, ofd, numdnlines = 0, i, found;
  char         *dir_path_file, *dir_path_tmpfile, *realfile,
               *dnlistsuri, *server_name, *fulldiruri, *p, oneline[513],
              **dnlines, name[81], *add;
  FILE         *ofp;
  struct stat   statbuf;
  GRSThttpBody  bp;
  
  if (!GRSTgaclPermHasWrite(perm)) GRSThttpError("403 Forbidden");
  
  dnlistsuri = getenv("GRST_DN_LISTS_URI");
  if (dnlistsuri == NULL) dnlistsuri = getenv("REDIRECT_GRST_DN_LISTS_URI");

  server_name = getenv("SERVER_NAME");

  if ((server_name == NULL) ||
      (dnlistsuri == NULL) || 
      (strncmp(dnlistsuri, dir_uri, strlen(dnlistsuri)) != 0))      
                                         GRSThttpError("403 Forbidden");
                                         
  asprintf(&fulldiruri, "https://%s%s", server_name, dir_uri);
  
  if ((strncmp(fulldiruri, file, strlen(fulldiruri)) != 0) && 
      ((strncmp(fulldiruri, file, strlen(fulldiruri) - 1) != 0) ||
       (strlen(fulldiruri) - 1 != strlen(file))))
    {
      puts("Status: 403 Forbidden\nContent-Type: text/html");
  
      GRSThttpBodyInit(&bp);

      GRSThttpPrintf(&bp,"<title>Error writing %s</title>\n", file);
      GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_HEADFILE);

      GRSThttpPrintf(&bp, "<h1 align=center>Error writing %s to %s</h1>\n", 
                     file, dir_uri);
  
      GRSThttpPrintf(&bp, "<p align=center>You cannot create a DN List "
                     "with that prefix in this directory. Please see the "
                     "the GridSite User's Guide for an explanation."); 

      GRSThttpPrintf(&bp,"<p align=center>"
                     "<a href=\"%s%s?cmd=managedir\">Return to "
                     "directory listing</a>\n", dir_uri, admin_file);
  
      adminfooter(&bp, dn, help_uri, dir_uri, admin_file);
      GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_FOOTFILE);

      GRSThttpWriteOut(&bp);
      return;    
    }

  p = GRSThttpGetCGI("numdn");
  if ((p == NULL) || (sscanf(p, "%d", &numdn) != 1))
                                         GRSThttpError("500 No number of DNs");

  if (numdn > 0) 
    {
      dnlines = malloc(sizeof(char *) * numdn);
      
      for (i=1; i <= numdn; ++i)
         {
           sprintf(name, "dn%d", i);
           p = GRSThttpGetCGI(name);
           
           if (*p != '\0') 
             {
               dnlines[numdnlines] = p;
               ++numdnlines;
             }           
         } 
    }
    
  add = GRSThttpGetCGI("add");

  realfile = GRSThttpUrlEncode(file);

  dir_path_file = malloc(strlen(dir_path) + strlen(realfile) + 2);  
  strcpy(dir_path_file, dir_path);
  strcat(dir_path_file, "/");
  strcat(dir_path_file, realfile);
      
  dir_path_tmpfile = malloc(strlen(dir_path) + 13);  
  strcpy(dir_path_tmpfile, dir_path);
  strcat(dir_path_tmpfile, "/.tmp.XXXXXX");

  if (((ofd = mkstemp(dir_path_tmpfile)) != -1) && 
      ((ofp = fdopen(ofd, "w")) != NULL))
    {
      if (*add != '\0') 
        {
          fputs(add, ofp);
          fputc('\n', ofp);
        }

      for (i=0; i < numdnlines; ++i)
         {
           fputs(dnlines[i], ofp);
           fputc('\n', ofp);
         }
 
      if ((fclose(ofp) == 0) &&
          ((stat(dir_path_file, &statbuf) != 0) || 
           (unlink(dir_path_file) == 0)) &&
          (rename(dir_path_tmpfile, dir_path_file) == 0))
        {
          printf("Status: 302 Moved Temporarily\nContent-Length: 0\n"
                 "Location: %s%s?cmd=managedir\n\n", dir_uri, admin_file);
          return;
        }
    }

  puts("Status: 500 Failed trying to write\nContent-Type: text/html");
  
  GRSThttpBodyInit(&bp);

  GRSThttpPrintf(&bp,"<title>Error writing %s%s</title>\n", dir_uri, file);
  GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_HEADFILE);

  GRSThttpPrintf(&bp, "<h1 align=center>Error writing %s%s</h1>\n", 
                      dir_uri, file);
  
  GRSThttpPrintf(&bp, "<p align=center>GridSite considers you are authorized "
                      "to write the file, but the write failed. This is "
                      "probably a web server or operating system level "
                      "misconfiguration. Consult the site administrator.");

  GRSThttpPrintf(&bp,"<p align=center>"
                     "<a href=\"%s%s?cmd=managedir\">Return to "
                     "directory listing</a>\n", dir_uri, admin_file);
  
  adminfooter(&bp, dn, help_uri, dir_uri, admin_file);
  GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_FOOTFILE);

  GRSThttpWriteOut(&bp);

  /* try to clean up */
  if (stat(dir_path_tmpfile, &statbuf) == 0) unlink(dir_path_tmpfile);    
}

void printfile(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, 
                  char *file, char *dir_uri, char *admin_file)
{
  int   c;
  char *dir_path_file;
  FILE *fp;
  struct stat statbuf;
  
  if (!GRSTgaclPermHasRead(perm)) GRSThttpError("403 Forbidden");

  if (index(file, '/') != NULL) GRSThttpError("403 Forbidden");
  
  dir_path_file = malloc(strlen(dir_path) + strlen(file) + 2);
  
  strcpy(dir_path_file, dir_path);
  strcat(dir_path_file, "/");
  strcat(dir_path_file, file);
 
  if ((stat(dir_path_file, &statbuf) != 0) ||
        !S_ISREG(statbuf.st_mode)) GRSThttpError("403 Forbidden");
       
  fp = fopen(dir_path_file, "r");
  if (fp == NULL) GRSThttpError("500 Internal server error");
 
  printf("Status: 200 OK\nContent-Type: text/html\nContent-Length: %d\n\n",
         statbuf.st_size);

  while ((c = fgetc(fp)) != EOF) putchar(c);

  fflush(stdout);
  fclose(fp);
}

void filehistory(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path,
                 char *file, char *dir_uri, char *admin_file)
{
  int             fd, n, i, j, enclen, num = 0;
  char           *encodedfile, *p, *dndecoded, modified[99], *vfile, *q,
                 *encdn;
  time_t          file_time;
  size_t          file_size;
  struct stat     statbuf;
  struct dirent **namelist;
  struct tm       file_tm;
  GRSThttpBody    bp;
  
  if (!GRSTgaclPermHasRead(perm)) GRSThttpError("403 Forbidden");

  if (index(file, '/') != NULL) GRSThttpError("403 Forbidden");
  
  puts("Status: 200 OK\nContent-Type: text/html");
                                                                                
  GRSThttpBodyInit(&bp);
  GRSThttpPrintf(&bp, "<title>History of %s%s</title>\n", dir_uri, file);
  GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_HEADFILE);
  GRSThttpPrintf(&bp,
   "<h1 align=center>History of <a href=\"%s%s\">%s%s</a></h1>\n",
   dir_uri, file, dir_uri, file);

  asprintf(&vfile, "%s/%s", dir_path, file);
  if (stat(vfile, &statbuf) == 0)
    {
      localtime_r((const time_t *) &(statbuf.st_mtime), &file_tm);
      strftime(modified, sizeof(modified), 
               "%a&nbsp;%e&nbsp;%b&nbsp;%Y&nbsp;%k:%M", &file_tm);

      GRSThttpPrintf(&bp, "<p align=center>Last modified: %s\n", modified);
    }
  free(vfile);
  
  encodedfile = GRSThttpUrlEncode(file);
  for (p=encodedfile; *p != '\0'; ++p) if (*p == '%') *p = '=';
  enclen = strlen(encodedfile);  
  
  n = scandir(dir_path, &namelist, 0, alphasort);
  
  if (n > 0)
    {
      for (i = n - 1; i >= 0; --i)
         {
           if ((strncmp(namelist[i]->d_name, GRST_HIST_PREFIX,
                                        sizeof(GRST_HIST_PREFIX) - 1) == 0) &&
               ((namelist[i]->d_name)[sizeof(GRST_HIST_PREFIX) - 1] == ':') &&
               (strncmp(&((namelist[i]->d_name)[sizeof(GRST_HIST_PREFIX)]),
                                                 encodedfile, enclen) == 0) &&
               ((namelist[i]->d_name)[sizeof(GRST_HIST_PREFIX)+enclen] == ':'))
             {
               if (num == 0) GRSThttpPrintf(&bp, 
                       "<p align=center><table border=1 cellpadding=5>\n"
                       "<tr><td>Date</td><td>Size after</td>"
                       "<td colspan=2>Changed by</td></tr>\n");
                       
               ++num;

               p = index(namelist[i]->d_name, ':');
               p = index(&p[1], ':');
               sscanf(&p[1], "%X:", &file_time);
               p = index(&p[1], ':'); /* skip over microseconds time */
               p = index(&p[1], ':');
               sscanf(&p[1], "%X:", &file_size);
               p = index(&p[1], ':');

               encdn = strdup(&p[1]);
               q = index(encdn, ':');
               if (q != NULL) *q = '\0';
               
               for (q=encdn; *q != '\0'; ++q) if (*q == '=') *q = '%';
               dndecoded = GRSThttpUrlDecode(encdn);

               localtime_r((const time_t *) &file_time, &file_tm);
               strftime(modified, sizeof(modified), 
                 "%a&nbsp;%e&nbsp;%b&nbsp;%Y&nbsp;%k:%M", &file_tm);

               GRSThttpPrintf(&bp, 
                 "<tr><td>%s</td><td align=right>%d</td><td>%s</td>\n",
                 modified, file_size, dndecoded);

               free(dndecoded);

               asprintf(&vfile, "%s/%s", dir_path, namelist[i]->d_name);
               if ((stat(vfile, &statbuf) == 0) && (statbuf.st_size > 0))
               {
	            GRSThttpPrintf(&bp, "<td><a href=\"");
                    if (strcmp (file, GRST_ACL_FILE)==0)
                        GRSThttpPrintf(&bp, "%s%s?cmd=acl_history&amp;dir_uri=%s&amp;file=%s\">View</a></td></tr>\n",
                           dir_uri, admin_file, dir_uri, namelist[i]->d_name);
                    else GRSThttpPrintf(&bp, "%s%s\">View</a></td></tr>\n",
                       dir_uri, namelist[i]->d_name);
               }
               else GRSThttpPrintf(&bp, "<td>&nbsp;</td></tr>");
                 
               free(vfile);
             }
         }      
    }
  
  if (num > 0) GRSThttpPrintf(&bp, "</table>\n");
  else GRSThttpPrintf(&bp, "<p align=center>No history for this file\n");
  
  if (GRSTgaclPermHasList(perm))
       adminfooter(&bp, dn, help_uri, dir_uri, admin_file);
  else adminfooter(&bp, dn, help_uri, dir_uri, NULL);
                                                                                
  GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_FOOTFILE);
  GRSThttpWriteOut(&bp);
}

void ziplist(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path,
             char *file, char *dir_uri, char *admin_file)
{
  char           *shellcmd, *unzip, oneline[129];
  FILE           *fp;
  GRSThttpBody    bp;
    
  if (!GRSTgaclPermHasRead(perm)) GRSThttpError("403 Forbidden");

  if (index(file, '/') != NULL) GRSThttpError("403 Forbidden");
  
  puts("Status: 200 OK\nContent-Type: text/html");
                                                                                
  GRSThttpBodyInit(&bp);
  GRSThttpPrintf(&bp, "<title>Contents of %s%s</title>\n", dir_uri, file);
  GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_HEADFILE);
  GRSThttpPrintf(&bp,
   "<h1 align=center>Contents of ZIP file <a href=\"%s%s\">%s%s</a></h1>\n",
   dir_uri, file, dir_uri, file);

  unzip = getenv("GRST_UNZIP");
  if (unzip == NULL) unzip = getenv("REDIRECT_GRST_UNZIP");

  if (unzip != NULL)
    {  
      GRSThttpPrintf(&bp, "<center><table><tr><td><pre>\n");
      asprintf(&shellcmd, "cd %s ; %s -Z %s", dir_path, unzip, file);
      fp = popen(shellcmd, "r");
  
      while (fgets(oneline, sizeof(oneline), fp) != NULL)           
                          GRSThttpPrintf(&bp, "%s", oneline);         
      pclose(fp);
      GRSThttpPrintf(&bp, "</pre></td></tr></table></center>\n");

      if (GRSTgaclPermHasWrite(perm))
           GRSThttpPrintf(&bp, 
            "<p><center><form action=\"%s%s\" method=post>"
            "<input type=submit value=\"Unzip this file\"> in %s"
            "<input type=hidden name=cmd value=unzipfile>"
            "<input type=hidden name=file value=\"%s\"></form>"
            "<p>(All files are placed in the same directory and files "
            "beginning with &quot;.&quot; are ignored.)</center>\n",
            dir_uri, admin_file, dir_uri, file);
    }
  else GRSThttpPrintf(&bp, "<p align=center>unzip path not defined!\n");
  
  if (GRSTgaclPermHasList(perm))
       adminfooter(&bp, dn, help_uri, dir_uri, admin_file);
  else adminfooter(&bp, dn, help_uri, dir_uri, NULL);
                                                                                
  GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_FOOTFILE);
  GRSThttpWriteOut(&bp);
}

void unzipfile(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, 
               char *file, char *dir_uri, char *admin_file)
{
  char           *shellcmd, *unzip, oneline[129];
  FILE           *fp;
  GRSThttpBody    bp;
    
  if (!GRSTgaclPermHasWrite(perm)) GRSThttpError("403 Forbidden");
  
  if (index(file, '/') != NULL) GRSThttpError("403 Forbidden");
  
  puts("Status: 200 OK\nContent-Type: text/html");
                                                                                
  GRSThttpBodyInit(&bp);
  GRSThttpPrintf(&bp, "<title>Unzipping %s%s</title>\n", dir_uri, file);
  GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_HEADFILE);
  GRSThttpPrintf(&bp,
   "<h1 align=center>Unzipping <a href=\"%s%s\">%s%s</a></h1>\n",
   dir_uri, file, dir_uri, file);

  unzip = getenv("GRST_UNZIP");
  if (unzip == NULL) unzip = getenv("REDIRECT_GRST_UNZIP");

  if (unzip != NULL)
    {  
      GRSThttpPrintf(&bp, "<center><table><tr><td><pre>\n");
      asprintf(&shellcmd, "cd %s ; %s -jo %s -x '.*'", dir_path, unzip, file);
      fp = popen(shellcmd, "r");
  
      while (fgets(oneline, sizeof(oneline), fp) != NULL)           
                          GRSThttpPrintf(&bp, "%s", oneline);         
      pclose(fp);
      GRSThttpPrintf(&bp, "</pre></td></tr></table></center>\n");      

      if (GRSTgaclPermHasList(perm))
                GRSThttpPrintf(&bp, "<p align=center>"
                                    "<b><a href=\"%s%s?cmd=managedir\">Back to "
                                    "directory</a></b>", dir_uri, admin_file);
    }
  else GRSThttpPrintf(&bp, "<p align=center>unzip path not defined!\n");
  
  if (GRSTgaclPermHasList(perm))
       adminfooter(&bp, dn, help_uri, dir_uri, admin_file);
  else adminfooter(&bp, dn, help_uri, dir_uri, NULL);
                                                                                
  GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_FOOTFILE);
  GRSThttpWriteOut(&bp);
}

void editfileform(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path, 
                  char *file, char *dir_uri, char *admin_file)
{
  int   fd, rawpagesize, i, c;
  char *dir_path_file, *rawpage, *p;
  FILE *fp = NULL;
  struct stat statbuf;
  GRSThttpBody    bp; 
  
  if (!GRSTgaclPermHasWrite(perm)) GRSThttpError("403 Forbidden");
  
  if (index(file, '/') != NULL) GRSThttpError("403 Forbidden");
  
  dir_path_file = malloc(strlen(dir_path) + strlen(file) + 2);
  
  strcpy(dir_path_file, dir_path);
  strcat(dir_path_file, "/");
  strcat(dir_path_file, file);
  
  fd = open(dir_path_file, O_RDONLY);      
  if (fd != -1)
    {
      fp = fdopen(fd, "r");
      if (fp == NULL) GRSThttpError("500 File open failed!");

      if ((fstat(fd, &statbuf) != 0) ||
        !S_ISREG(statbuf.st_mode)) GRSThttpError("500 Not a regular file!");
    }
       
  puts("Status: 200 OK\nContent-Type: text/html");
  
  GRSThttpBodyInit(&bp);

  GRSThttpPrintf(&bp, "<title>Edit file %s</title>\n", file);

  GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_HEADFILE);

  GRSThttpPrintf(&bp, "<h1>Edit file %s</h1>\n", file);
  
  GRSThttpPrintf(&bp,"<form action=\"%s%s\" method=post>\n",dir_uri,admin_file);
  GRSThttpPrintf(&bp,"<p><input type=submit value=\"Save changes\">\n");
  GRSThttpPrintf(&bp,"<p>File name: <input type=text name=file value=\"%s\">\n", file);
  GRSThttpPrintf(&bp,"<input type=hidden name=cmd value=editaction>\n");
  GRSThttpPrintf(&bp,"<p><textarea name=pagetext cols=80 rows=22>");

  if (fp != NULL)
    {  
      rawpagesize = statbuf.st_size + 1000;
      rawpage = malloc(rawpagesize);
  
      i = 0;
  
      while ((c = fgetc(fp)) != EOF)
           {
             if (c == '<')      { strcpy(&rawpage[i], "&lt;");
                                  i += 4; }
             else if (c == '>') { strcpy(&rawpage[i], "&gt;");
                                  i += 4; }
             else if (c == '&') { strcpy(&rawpage[i], "&amp;");
                                  i += 5; }
             else if (c == '"') { strcpy(&rawpage[i], "&quot;");
                                  i += 6; }
             else               { rawpage[i] = c;
                                  i += 1; }
           
             if (i >= rawpagesize - 7)
               {
                 rawpagesize += 1000;
                 rawpage = realloc(rawpage, rawpagesize);           
               }
           }

      rawpage[i] = '\0';
  
      GRSThttpPrintf(&bp, "%s", rawpage);
    }
    
  GRSThttpPrintf(&bp, "</textarea>\n");  
  GRSThttpPrintf(&bp, "<p><input type=submit value=\"Save changes\">\n");
  GRSThttpPrintf(&bp, "</form>\n");

  if (fp != NULL) fclose(fp);

  adminfooter(&bp, dn, help_uri, dir_uri, admin_file);
  
  GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_FOOTFILE);
  GRSThttpWriteOut(&bp);
}

void editdnlistform(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path,
                    char *file, char *dir_uri, char *admin_file)
{
  int   fd, i, c, numdn = 0;
  char *dir_path_file, *rawpage, *p, *dnlistsuri, *server_name, *fulluri,
       *realfile, oneline[513];
  FILE *fp = NULL;
  struct stat statbuf;
  GRSThttpBody    bp; 
  
  dnlistsuri = getenv("GRST_DN_LISTS_URI");
  if (dnlistsuri == NULL) dnlistsuri = getenv("REDIRECT_GRST_DN_LISTS_URI");

  if (!GRSTgaclPermHasWrite(perm) ||
      (dnlistsuri == NULL) ||
      (strncmp(dnlistsuri, dir_uri, strlen(dnlistsuri)) != 0)) 
                                             GRSThttpError("403 Forbidden");
  
  realfile = GRSThttpUrlEncode(file);

  dir_path_file = malloc(strlen(dir_path) + strlen(realfile) + 2);
  
  strcpy(dir_path_file, dir_path);
  strcat(dir_path_file, "/");
  strcat(dir_path_file, realfile);
  
  fd = open(dir_path_file, O_RDONLY);      
  if (fd != -1) /* we dont mind open failing, but it must work if it doesnt */
    {
      fp = fdopen(fd, "r");
      if (fp == NULL) GRSThttpError("500 File open failed!");

      if ((fstat(fd, &statbuf) != 0) ||
        !S_ISREG(statbuf.st_mode)) GRSThttpError("500 Not a regular file!");
    }
       
  puts("Status: 200 OK\nContent-Type: text/html");
  
  GRSThttpBodyInit(&bp);

  GRSThttpPrintf(&bp, "<title>Edit DN List %s</title>\n", file);

  GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_HEADFILE);

  GRSThttpPrintf(&bp, "<h1>Edit DN List</h1>\n");
  
  GRSThttpPrintf(&bp,"<form action=\"%s%s\" method=post>\n",dir_uri,admin_file);
  GRSThttpPrintf(&bp,"<p><input type=submit value=\"Update\">\n");
  GRSThttpPrintf(&bp,"<p>List URL: <input type=text name=file value=\"%s\" "
                     "size=%d>\n", file, strlen(file));
  GRSThttpPrintf(&bp,"<input type=hidden name=cmd value=editdnlistaction>\n");

  if (fp != NULL)
    {
      GRSThttpPrintf(&bp, "<p><table>\n<tr><th>Keep?</th>"
                          "<th>Name</th></tr>\n");

      while (fgets(oneline, sizeof(oneline), fp) != NULL)
           {
             ++numdn;
         
             p = rindex(oneline, '\n');
             if (p != NULL) *p = '\0';
         
             GRSThttpPrintf(&bp, "<tr><td align=center><input type=checkbox "
                             "name=\"dn%d\" value=\"%s\" checked></td>"
                             "<td>%s</td></tr>\n", numdn, oneline, oneline);
           }

      GRSThttpPrintf(&bp,"</table>\n");
    }
    
  GRSThttpPrintf(&bp,"<input type=hidden name=numdn value=\"%d\">\n", numdn);

  GRSThttpPrintf(&bp, "<p>Add new DN: <input type=text name=add "
                      "size=60 maxlength=512>\n");

  GRSThttpPrintf(&bp,"<p><input type=submit value=\"Update\">\n");
  GRSThttpPrintf(&bp, "</form>\n");

  if (fp != NULL) fclose(fp);

  adminfooter(&bp, dn, help_uri, dir_uri, admin_file);
  
  GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_FOOTFILE);
  GRSThttpWriteOut(&bp);
}

void managedir(char *dn, GRSTgaclPerm perm, char *help_uri, char *dir_path,
               char *dir_uri, char *admin_file)
{
  int         n, is_dnlists_dir = 0, enclen, numfiles, encprefixlen;
  char       *d_namepath, modified[99], *absaclpath, *editable, *p, *unzip,
             *dnlistsuri, *d_name, *server_name, *fulluri, *encfulluri,
             *encprefix, *dnlistsprefix;
  GRSThttpBody    bp;
  struct tm       mtime_tm;
  struct stat     statbuf;
  struct dirent **namelist, *subdirfile_ent;
  DIR            *subDIR;

  if (((!GRSTgaclPermHasWrite(perm)) &&
       (!GRSTgaclPermHasList(perm))) ||
      (stat(dir_path, &statbuf) != 0) || !S_ISDIR(statbuf.st_mode))
                   GRSThttpError("403 Forbidden");

  editable = getenv("GRST_EDITABLE");
  if (editable == NULL) editable = getenv("REDIRECT_GRST_EDITABLE");
  
  unzip = getenv("GRST_UNZIP");
  if (unzip == NULL) unzip = getenv("REDIRECT_GRST_UNZIP");
  
  dnlistsuri = getenv("GRST_DN_LISTS_URI");
  if (dnlistsuri == NULL) dnlistsuri = getenv("REDIRECT_GRST_DN_LISTS_URI");

  if (dnlistsuri && (strncmp(dnlistsuri, dir_uri, strlen(dnlistsuri)) == 0))
    {
      is_dnlists_dir = 1;
      server_name = getenv("SERVER_NAME");

      asprintf(&fulluri, "https://%s%s", server_name, dir_uri);
      encfulluri = GRSThttpUrlEncode(fulluri);
      enclen = strlen(encfulluri);

      asprintf(&dnlistsprefix, "https://%s%s", server_name, dnlistsuri);
      encprefix = GRSThttpUrlEncode(dnlistsprefix);
      encprefixlen = strlen(encprefix);
    }
  
  printf("Status: 200 OK\nContent-Type: text/html\n");

  GRSThttpBodyInit(&bp);

  GRSThttpPrintf(&bp,"<title>Manage directory %s</title>\n", dir_uri);

  GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_HEADFILE);
    
  GRSThttpPrintf(&bp, "<h1>Manage directory %s</h1>\n<table>\n", dir_uri);
  
  if (dir_uri[1] != '\0')
     GRSThttpPrintf(&bp, 
      "<tr><td colspan=3>[<a href=\"../%s?cmd=managedir\">Parent "
       "directory</a>]</td></tr>\n", admin_file);

  if (GRSTgaclPermHasList(perm) || GRSTgaclPermHasAdmin(perm))
    {
      absaclpath = malloc(strlen(dir_path) + sizeof(GRST_ACL_FILE) + 1);
      strcpy(absaclpath, dir_path);
      strcat(absaclpath, "/");
      strcat(absaclpath, GRST_ACL_FILE);

      if (stat(absaclpath, &statbuf) == 0) /* ACL exists in THIS directory */
        {
          localtime_r(&(statbuf.st_mtime), &mtime_tm);
          strftime(modified, sizeof(modified), 
           "<td align=right>%R</td><td align=right>%e&nbsp;%b&nbsp;%y</td>",
                        &mtime_tm);    

          if (!is_dnlists_dir)
            {
              GRSThttpPrintf(&bp,
                      "<tr><td><a href=\"%s\">%s</a></td>"
                      "<td align=right>%ld</td>%s\n",
                      GRST_ACL_FILE,
                      GRST_ACL_FILE,
                      statbuf.st_size, modified);

              GRSThttpPrintf(&bp,
                   "<td><a href=\"%s%s?cmd=history&amp;file=%s\">"
                      "History</a></td>",
                      dir_uri, admin_file, GRST_ACL_FILE);
            }
          else GRSThttpPrintf(&bp,
                      "<tr><td>%s</td>"
                      "<td align=right>%ld</td>%s\n",
                      GRST_ACL_FILE,
                      statbuf.st_size, modified);

          if (GRSTgaclPermHasAdmin(perm)) 
               GRSThttpPrintf(&bp,
                   "<td><a href=\"%s%s?cmd=admin_acl\">Edit</a></td>"
                   "<td><a href=\"%s%s?cmd=delete&amp;file=%s\">Delete</a></td>",
                   dir_uri, admin_file,
                   dir_uri, admin_file, GRST_ACL_FILE);
          else if (GRSTgaclPermHasRead(perm))
               GRSThttpPrintf(&bp,
                   "<td><a href=\"%s%s?cmd=show_acl\">View</a></td>"
                   "<td>&nbsp;</td>", dir_uri, admin_file);
          else GRSThttpPrintf(&bp, "<td>&nbsp;</td><td>&nbsp;</td>\n");

          GRSThttpPrintf(&bp, "<td>&nbsp;</td></tr>\n");
        }
      else if (GRSTgaclPermHasAdmin(perm))
          GRSThttpPrintf(&bp, "<form method=post action=\"%s%s\">\n"
        "<tr><td colspan=8><input type=submit value=\"Create .gacl\"></td>\n"
        "<input type=hidden name=cmd value=\"create_acl\"></tr></form>\n",
        dir_uri, admin_file);
    }

  if (GRSTgaclPermHasList(perm))
    {
      n = scandir(dir_path, &namelist, 0, alphasort);
      while (n--)
       {
         if (namelist[n]->d_name[0] != '.')
           {
               d_namepath = malloc(strlen(dir_path) + 
                                   strlen(namelist[n]->d_name) + 2);
               strcpy(d_namepath, dir_path);
               strcat(d_namepath, "/");
               strcat(d_namepath, namelist[n]->d_name);
               stat(d_namepath, &statbuf);
               
               if (S_ISDIR(statbuf.st_mode))
                 { 
                   subDIR = opendir(d_namepath);
                   
                   if (subDIR == NULL) numfiles = 99; /* stop deletion */
                   else
                     {
                       numfiles = 0; 
                       while ((subdirfile_ent = readdir(subDIR)) != NULL) 
                         if (subdirfile_ent->d_name[0] != '.') ++numfiles;
                         else if (strncmp(subdirfile_ent->d_name, 
                                     GRST_ACL_FILE,
                                    sizeof(GRST_ACL_FILE)) == 0) ++numfiles;

                       closedir(subDIR);
                     }                     
                 }
                              
               free(d_namepath);
               
               localtime_r(&(statbuf.st_mtime), &mtime_tm);
               strftime(modified, sizeof(modified), 
               "<td align=right>%R</td><td align=right>%e&nbsp;%b&nbsp;%y</td>",
                        &mtime_tm);    
                              
               if (S_ISDIR(statbuf.st_mode)) 
                 {
                   GRSThttpPrintf(&bp,
                      "<tr><td><a href=\"%s%s/%s?cmd=managedir\">"
                      "%s/</a></td>"
                      "<td align=right>%ld</td>%s\n<td colspan=2>&nbsp;</td>",
                      dir_uri, namelist[n]->d_name, admin_file,
                      namelist[n]->d_name,
                      statbuf.st_size, modified);

                   if (numfiles == 0)
                        GRSThttpPrintf(&bp,
                        "<td><a href=\"%s%s?cmd=delete&amp;file=%s\">"
                        "Delete</a></td>\n", 
                        dir_uri, admin_file, namelist[n]->d_name);
                   else GRSThttpPrintf(&bp, "<td>&nbsp;</td>\n");
                      
                   GRSThttpPrintf(&bp, "<td>&nbsp;</td></tr>\n");
                 }
               else if (is_dnlists_dir) 
                 {        
                   if ((strlen(namelist[n]->d_name) <= encprefixlen) ||
                       (strncmp(namelist[n]->d_name, encprefix, 
                                              encprefixlen) != 0)) continue;

                   d_name = GRSThttpUrlDecode(namelist[n]->d_name);

                   GRSThttpPrintf(&bp, "<tr><td><a href=\"%s\">%s</a></td>"
                                       "<td align=right>%ld</td>%s"
                                       "<td>&nbsp;</td>",
                                       d_name, d_name,
                                       statbuf.st_size, modified);

                   if (GRSTgaclPermHasWrite(perm))
                     GRSThttpPrintf(&bp, "<form action=\"%s%s\" method=post>"
                        "<td><input type=submit value=Edit></td>"
                        "<input type=hidden name=cmd value=editdnlist>"
                        "<input type=hidden name=file value=\"%s\">"
                        "</form>\n",
                        dir_uri, admin_file, d_name);
                   else GRSThttpPrintf(&bp, "<td>&nbsp;</td>\n");
                   
                   if (GRSTgaclPermHasWrite(perm))
                     GRSThttpPrintf(&bp, "<form action=\"%s%s\" method=post>"
                        "<td><input type=submit value=Delete></td>"
                        "<input type=hidden name=cmd value=delete>"
                        "<input type=hidden name=file value=\"%s\">"
                        "</form>\n",
                        dir_uri, admin_file, d_name);
                   else GRSThttpPrintf(&bp, "<td>&nbsp;</td>\n");

                   GRSThttpPrintf(&bp, "<td>&nbsp;</td></tr>");
                 }
               else /* regular directory, not DN Lists */
                 {        
                   d_name = namelist[n]->d_name;

                   GRSThttpPrintf(&bp,
                          "<tr><td><a href=\"%s%s\">%s</a></td>"
                          "<td align=right>%ld</td>%s",
                          dir_uri, d_name, 
                          d_name, 
                          statbuf.st_size, modified);                                        

                   GRSThttpPrintf(&bp,
                     "<td><a href=\"%s%s?cmd=history&amp;file=%s\">"
                      "History</a></td>",
                      dir_uri, admin_file, GRSThttpUrlEncode(d_name));

                   p = rindex(namelist[n]->d_name, '.');

                   if      ((unzip != NULL) &&
                            (p != NULL) && 
                            (strcasecmp(&p[1], "zip") == 0) &&
                            GRSTgaclPermHasRead(perm))
                             GRSThttpPrintf(&bp,
                               "<td><a href=\"%s%s?cmd=ziplist&amp;file=%s\">"
                               "List</a></td>\n",
                               dir_uri, admin_file, GRSThttpUrlEncode(d_name));                   
                   else if ((p != NULL) && 
                       (strstr(editable, &p[1]) != NULL) &&
                       GRSTgaclPermHasWrite(perm))
                         GRSThttpPrintf(&bp,
                               "<td><a href=\"%s%s?cmd=edit&amp;file=%s\">"
                               "Edit</a></td>\n",
                               dir_uri, admin_file, GRSThttpUrlEncode(d_name));
                   else  GRSThttpPrintf(&bp, "<td>&nbsp;</td>");

                   if (GRSTgaclPermHasWrite(perm))
                    GRSThttpPrintf(&bp,
                     "<td><a href=\"%s%s?cmd=delete&amp;file=%s\">"
                     "Delete</a></td>\n", dir_uri, admin_file, GRSThttpUrlEncode(d_name));
                   else
                    GRSThttpPrintf(&bp, "<td>&nbsp;</td>\n");

                   if (GRSTgaclPermHasWrite(perm))
                    GRSThttpPrintf(&bp,
                     "<td><a href=\"%s%s?cmd=rename&amp;file=%s\">"
                     "Rename</a></td></tr>\n", dir_uri, admin_file, GRSThttpUrlEncode(d_name));
                   else
                    GRSThttpPrintf(&bp, "<td>&nbsp;</td></tr>");
                 }
           }

         free(namelist[n]);
       }
                    
      free(namelist);
    }

  if (GRSTgaclPermHasWrite(perm))
    {
      if (is_dnlists_dir)
        {
          GRSThttpPrintf(&bp, "<form method=post action=\"%s%s\">\n"
        "<tr><td colspan=4>New list name: "
        "<input type=text name=file value=\"%sNEW_LIST\" size=%d>\n"
        "<input type=hidden name=cmd value=editdnlist></td>"
        "<td colspan=2 align=center><input type=submit value=Create></td>\n"
        "</tr></form>\n",
        dir_uri, admin_file, fulluri, strlen(fulluri)+8);

          GRSThttpPrintf(&bp, "<form method=post action=\"%s%s\">\n"
        "<tr><td colspan=4>New directory: "
        "<input type=text name=file>\n"
        "<td colspan=2 align=center><input type=submit name=button value=\"Create\"></td>\n"
        "<input type=hidden name=cmd value=edit></td></tr></form>\n",
        dir_uri, admin_file);      
        }
      else
        {
          GRSThttpPrintf(&bp, "<form method=post action=\"%s%s\">\n"
        "<tr><td colspan=8><hr width=\"75%\"></td></tr>\n"
        "<tr><td>New name:</td>"
        "<td colspan=3><input type=text name=file size=25>\n"
        "<td colspan=2 align=center><input type=submit name=button value=\"New file\"></td>\n"
        "<td colspan=2 align=center><input type=submit name=button value=\"New directory\"></td>\n"
        "<input type=hidden name=cmd value=edit></td></tr></form>\n",
        dir_uri, admin_file);
      
          GRSThttpPrintf(&bp,
        "<form method=post action=\"%s%s\" enctype=\"multipart/form-data\">\n"
        "<tr><td colspan=8><hr width=\"75%\"></td></tr>\n"
        "<tr><td rowspan=2>Upload file:</td>"
        "<td colspan=2>New name:</td>"
        "<td colspan=6><input type=text name=file size=25> "
        "<input type=submit value=Upload></td></tr>\n"
        "<tr><td colspan=2>Local name:</td>"
        "<td colspan=6><input type=file name=uploadfile size=25></td></tr>\n"
        "</form>\n", dir_uri, admin_file);
        }
    }

  GRSThttpPrintf(&bp, "</table>\n");

  if (!is_dnlists_dir) adminfooter(&bp, dn, help_uri, dir_uri, NULL);

  GRSThttpPrintHeaderFooter(&bp, dir_path, GRST_FOOTFILE);
  GRSThttpWriteOut(&bp);
}

