/*
   Copyright (c) 2003-7, Andrew McNab, Shiv Kaushal, Joseph Dada,
   and Yibiao Li, University of Manchester. All rights reserved.

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


   This program includes code from dav_parse_range() from Apache mod_dav.c,
   and associated code contributed by  David O Callaghan
   
   Copyright 2000-2005 The Apache Software Foundation or its licensors, as
   applicable.
   
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0
   
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
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

#include <apr_strings.h>
#include <apr_tables.h>
#include <apr_network_io.h>

#include <ap_config.h>
#include <httpd.h>
#include <http_config.h>
#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_request.h>
#include <unixd.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>              
#include <netdb.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <time.h>

#include <sys/select.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 

#include <libxml/parser.h>
#include <libxml/tree.h>

#include "mod_ssl-private.h"

#include "gridsite.h"

#ifndef UNSET
#define UNSET -1
#endif

#define GRST_SESSIONS_DIR "/var/www/sessions"

module AP_MODULE_DECLARE_DATA gridsite_module;

#define GRST_SITECAST_GROUPS 32

struct sitecast_group
   { int socket; int quad1; int quad2; int quad3; int quad4; int port; };

#define GRST_SITECAST_ALIASES 32
   
struct sitecast_alias
   { const char *sitecast_url; const char *scheme; int port; 
     const char *local_path; const char *local_hostname; };

/* Globals, defined by main server directives in httpd.conf  
   These are assigned default values in create_gridsite_srv_config() */

int gridhttpport = 0; /* set by create_gridsite_srv_config, used as flag */
char                    *sessionsdir = NULL;
char			*sitecastdnlists = NULL;
char 			*ocspmodes = NULL;
struct sitecast_group	sitecastgroups[GRST_SITECAST_GROUPS+1];
struct sitecast_alias	sitecastaliases[GRST_SITECAST_ALIASES];

typedef struct
{
   int			auth;
   int			envs;
   int			format;
   int			indexes;
   char			*indexheader;
   int			gridsitelink;
   char			*adminfile;
   char			*adminuri;
   char			*helpuri;
   char			*dnlists;
   char			*dnlistsuri;
   char			*adminlist;
   int			gsiproxylimit;
   char			*unzip;
   char			*methods;
   char			*editable;
   char			*headfile;
   char			*footfile;
   int			gridhttp;
   char			*aclformat;
   char			*aclpath;
   char			*execmethod;
   char			*delegationuri;
   ap_unix_identity_t	execugid;
   apr_fileperms_t	diskmode;
}  mod_gridsite_dir_cfg; /* per-directory config choices */


/*
 *   parse_content_range() is loosely 
 *   based on modules/dav/main/mod_dav.c from Apache
 */

int parse_content_range(request_rec *r, apr_off_t *range_start, 
                        apr_off_t *range_end, apr_off_t *range_length)
{
// this all needs verifying to be ok for large (>2GB, >4GB) files 

    const char *range_c;
    char *range;
    char *dash;
    char *slash;

    range_c = apr_table_get(r->headers_in, "content-range");
    if (range_c == NULL) return 0;
    
    range = apr_pstrdup(r->pool, range_c);

    if ((strncasecmp(range, "bytes ", 6) != 0) ||
        ((dash = ap_strchr(range, '-')) == NULL) ||
        ((slash = ap_strchr(range, '/')) == NULL)) 
      {        
        return 0; /* malformed header. ignore it (per S14.16 of RFC2616) */
      }

    *dash = *slash = '\0';
    
    // Check for GridSite-specific Content-Range: bytes *-*/LENGTH form
    
    if ((range[6] == '*') && (dash[1] == '*'))
      {
        if (slash[1] == '*') return 0; /* invalid truncation length */
        
        *range_length = apr_atoi64(&slash[1]);
        *range_start  = 0;
        *range_end    = 0;
        
        return 1; /* a valid (truncation) length */
      }          
    
    *range_length = 0;
    *range_start  = apr_atoi64(&range[6]);
    *range_end    = apr_atoi64(&dash[1]);

    if ((*range_end < *range_start) || 
        ((slash[1] != '*') && (apr_atoi64(&slash[1]) <= *range_end)))
            return 0; /* ignore invalid ranges */

    /* we now have a valid range */
    return 1;
}

char *html_escape(apr_pool_t *pool, char *s)
{
    int    htmlspecials, i;
    char  *escaped, *p;

    for (htmlspecials=0,p=s; *p != '\0'; ++p) 
      if ((*p == '<') || (*p == '>') || (*p == '&') || (*p == '"')) 
          ++htmlspecials;

    escaped = apr_palloc(pool, strlen(s) + htmlspecials * 6);
        
    for (i=0,p=s; *p != '\0'; ++p)
       {
             if      (*p == '<') 
                { 
                  strcpy(&escaped[i], "&lt;");
                  i += 4;
                }
            else if (*p == '>') 
                {
                  strcpy(&escaped[i], "&gt;");
                  i += 4;
                }
            else if (*p == '&') 
                {
                  strcpy(&escaped[i], "&amp;");
                  i += 5;
                }
            else if (*p == '"') 
                {
                  strcpy(&escaped[i], "&quot;");
                  i += 6;
                }
            else 
                {
                  escaped[i] = *p;
                  ++i;
                }                  
       }

    escaped[i] = '\0';
   
    return escaped;
}

char *make_admin_footer(request_rec *r, mod_gridsite_dir_cfg *conf,
                        int isdirectory)
/*
    make string holding last modified text and admin links
*/
{
    char     *out, *https, *p, *dn = NULL, *file = NULL, *permstr = NULL, 
             *temp, modified[99], *dir_uri, *grst_cred_auri_0 = NULL;
    GRSTgaclPerm  perm = GRST_PERM_NONE;
    struct tm mtime_tm;
    time_t    mtime_time;

    https = (char *) apr_table_get(r->subprocess_env, "HTTPS");

    dir_uri = apr_pstrdup(r->pool, r->uri);
    p = rindex(dir_uri, '/');

    if (p == NULL) return "";
    
    file = apr_pstrdup(r->pool, &p[1]);
    p[1] = '\0';
    /* dir_uri always gets both a leading and a trailing slash */
       
    out = apr_pstrdup(r->pool, "<p>\n");

    if (!isdirectory)
      {
        mtime_time = apr_time_sec(r->finfo.mtime);

        localtime_r(&mtime_time, &mtime_tm);
        strftime(modified, sizeof(modified), 
                 "%a&nbsp;%e&nbsp;%B&nbsp;%Y", &mtime_tm);    
        temp = apr_psprintf(r->pool,"<hr><small>Last modified %s\n", modified);
        out = apr_pstrcat(r->pool, out, temp, NULL);

        if ((conf->adminuri != NULL) &&
            (conf->adminuri[0] != '\0') &&
            (conf->adminfile != NULL) &&
            (conf->adminfile[0] != '\0') &&
            (strncmp(file, GRST_HIST_PREFIX, sizeof(GRST_HIST_PREFIX)-1) != 0))
          {
            temp = apr_psprintf(r->pool, 
                            ". <a href=\"%s?cmd=history&amp;file=%s\">"
                            "View&nbsp;page&nbsp;history</a>\n",
                            conf->adminfile, file);
            out = apr_pstrcat(r->pool, out, temp, NULL);
          }
          
        out = apr_pstrcat(r->pool, out, "</small>", NULL);
      }

    out = apr_pstrcat(r->pool, out, "<hr><small>", NULL);

    if (r->connection->notes != NULL)
      {
        grst_cred_auri_0 = (char *) 
                  apr_table_get(r->connection->notes, "GRST_CRED_AURI_0");
      }                       

    if ((grst_cred_auri_0 != NULL) && 
        (strncmp(grst_cred_auri_0, "dn:", 3) == 0))
      {
         dn = &grst_cred_auri_0[3];
         if (dn[0] == '\0') dn = NULL;         
      }
  
    if (dn != NULL) 
      {
        temp = apr_psprintf(r->pool, 
                            "You are %s<br>\n", html_escape(r->pool,dn));
        out = apr_pstrcat(r->pool, out, temp, NULL);
               
        if (r->notes != NULL)
                permstr = (char *) apr_table_get(r->notes, "GRST_PERM");

        if ((permstr != NULL) &&
            (conf->adminuri != NULL) &&
            (conf->adminuri[0] != '\0') &&
            (conf->adminfile != NULL) &&
            (conf->adminfile[0] != '\0'))
          {
            sscanf(permstr, "%d", &perm);
            
            if (!isdirectory &&
                GRSTgaclPermHasWrite(perm) &&
                (strncmp(file, GRST_HIST_PREFIX,
                         sizeof(GRST_HIST_PREFIX) - 1) != 0))
              {
                temp = apr_psprintf(r->pool, 
                     "<a href=\"%s?cmd=edit&amp;file=%s\">"
                     "Edit&nbsp;page</a> .\n", conf->adminfile, file);
                out = apr_pstrcat(r->pool, out, temp, NULL);
              }
                 
            if (GRSTgaclPermHasList(perm) || GRSTgaclPermHasWrite(perm))
              {
                temp = apr_psprintf(r->pool, 
                 "<a href=\"%s%s?cmd=managedir\">Manage&nbsp;directory</a> .\n",
                 dir_uri, conf->adminfile);

                out = apr_pstrcat(r->pool, out, temp, NULL);
              }                 
          }
      }
    
    if ((https != NULL) && (strcasecmp(https, "on") == 0))
         temp = apr_psprintf(r->pool,
                   "<a href=\"http://%s%s\">Switch&nbsp;to&nbsp;HTTP</a> \n", 
                   r->server->server_hostname, r->unparsed_uri);
    else temp = apr_psprintf(r->pool,
                   "<a href=\"https://%s%s\">Switch&nbsp;to&nbsp;HTTPS</a> \n",
                   r->server->server_hostname, r->unparsed_uri);
    
    out = apr_pstrcat(r->pool, out, temp, NULL);

    if ((conf->helpuri != NULL) && (conf->helpuri[0] != '\0'))
      {
        temp = apr_psprintf(r->pool,
                   ". <a href=\"%s\">Website&nbsp;Help</a>\n", conf->helpuri);
        out = apr_pstrcat(r->pool, out, temp, NULL);
      }

    if ((!isdirectory) &&
        (conf->adminuri != NULL) &&
        (conf->adminuri[0] != '\0') &&
        (conf->adminfile != NULL) &&
        (conf->adminfile[0] != '\0'))
      {
        temp = apr_psprintf(r->pool, ". <a href=\"%s?cmd=print&amp;file=%s\">"
               "Print&nbsp;View</a>\n", conf->adminfile, file);
        out = apr_pstrcat(r->pool, out, temp, NULL);
      }

    if (conf->gridsitelink)
      {
        temp = apr_psprintf(r->pool,
           ". Built with <a href=\"http://www.gridsite.org/\">"
           "GridSite</a>&nbsp;%s\n", VERSION);
        out = apr_pstrcat(r->pool, out, temp, NULL);
      }

    out = apr_pstrcat(r->pool, out, "\n</small>\n", NULL);

    return out;
}

void delegation_header(request_rec *r, mod_gridsite_dir_cfg *conf)
{
  apr_table_add(r->headers_out,
                apr_pstrdup(r->pool, "Proxy-Delegation-Service"),
                apr_psprintf(r->pool,"https://%s%s", r->hostname, conf->delegationuri));
  return;

}

int html_format(request_rec *r, mod_gridsite_dir_cfg *conf)
/*
    try to do GridSite formatting of .html files (NOT .shtml etc)
*/
{
    int    i, fd, errstatus;
    char  *buf, *p, *file, *s, *head_formatted, *header_formatted,
          *body_formatted, *admin_formatted, *footer_formatted;
    size_t length;
    struct stat statbuf;
    apr_file_t *fp;

    if (r->finfo.filetype == APR_NOFILE) return HTTP_NOT_FOUND;

    if (apr_file_open(&fp, r->filename, APR_READ, 0, r->pool) != 0)
                                     return HTTP_INTERNAL_SERVER_ERROR;


    /* Put in Delegation service header if required */
    if (conf->delegationuri) delegation_header(r, conf);

    file = rindex(r->uri, '/');
    if (file != NULL) ++file; /* file points to name without path */

    buf = apr_palloc(r->pool, (size_t)(r->finfo.size + 1));
    length = r->finfo.size;
    apr_file_read(fp, buf, &length);
    buf[r->finfo.size] = '\0';
    apr_file_close(fp);

    /* **** try to find a header file in this or parent directories **** */

    /* first make a buffer big enough to hold path names we want to try */
    fd = -1;
    s = apr_palloc(r->pool, 
                       strlen(r->filename) + strlen(conf->headfile) + 1);
    strcpy(s, r->filename);

    for (;;)
       {
         p = rindex(s, '/');
         if (p == NULL) break; /* failed to find one */
         p[1] = '\0';
         strcat(p, conf->headfile);

         fd = open(s, O_RDONLY);
         if (fd != -1) break; /* found one */

         *p = '\0';
       }

    if (fd == -1) /* not found, so set up not to output one */
      {
        head_formatted   = apr_pstrdup(r->pool, "");
        header_formatted = apr_pstrdup(r->pool, "");
        body_formatted   = buf;
      }
    else /* found a header file, so set up head and body to surround it */
      {
        fstat(fd, &statbuf);
        header_formatted = apr_palloc(r->pool, statbuf.st_size + 1);
        read(fd, header_formatted, statbuf.st_size);
        header_formatted[statbuf.st_size] = '\0';
        close(fd);

        p = strstr(buf, "<body");
        if (p == NULL) p = strstr(buf, "<BODY");
        if (p == NULL) p = strstr(buf, "<Body");

        if (p == NULL)
          {
            head_formatted = apr_pstrdup(r->pool, "");
            body_formatted = buf;
          }
        else
          {
            *p = '\0';
            head_formatted = buf;
            ++p;

            while ((*p != '>') && (*p != '\0')) ++p;

            if (*p == '\0')
              {
                body_formatted = p;
              }
            else
              {
                *p = '\0';
                ++p;
                body_formatted = p;
              }
          }
      }

    /* **** remove closing </body> tag from body **** */

    p = strstr(body_formatted, "</body");
    if (p == NULL) p = strstr(body_formatted, "</BODY");
    if (p == NULL) p = strstr(body_formatted, "</Body");

    if (p != NULL) *p = '\0';

    /* **** set up dynamic part of footer to go at end of body **** */

    admin_formatted = make_admin_footer(r, conf, FALSE);

    /* **** try to find a footer file in this or parent directories **** */

    /* first make a buffer big enough to hold path names we want to try */
    fd = -1;
    s = apr_palloc(r->pool, 
                       strlen(r->filename) + strlen(conf->footfile) + 1);
    strcpy(s, r->filename);

    for (;;)
       {
         p = rindex(s, '/');
         if (p == NULL) break; /* failed to find one */

         p[1] = '\0';
         strcat(p, conf->footfile);

         fd = open(s, O_RDONLY);
         if (fd != -1) break; /* found one */

         *p = '\0';
       }

    if (fd == -1) /* failed to find a footer, so set up empty default */
      {
        footer_formatted = apr_pstrdup(r->pool, "");
      }
    else /* found a footer, so set up to use it */
      {
        fstat(fd, &statbuf);
        footer_formatted = apr_palloc(r->pool, statbuf.st_size + 1);
        read(fd, footer_formatted, statbuf.st_size);
        footer_formatted[statbuf.st_size] = '\0';
        close(fd);
      }

    /* **** can now calculate the Content-Length and output headers **** */

    length = strlen(head_formatted) + strlen(header_formatted) +
             strlen(body_formatted) + strlen(admin_formatted)  +
             strlen(footer_formatted);

    ap_set_content_length(r, length);
    ap_set_content_type(r, "text/html");

    /* ** output the HTTP body (HTML Head+Body) ** */

    ap_rputs(head_formatted,   r);
    ap_rputs(header_formatted, r);
    ap_rputs(body_formatted,   r);
    ap_rputs(admin_formatted,  r);
    ap_rputs(footer_formatted, r);

    return OK;
}

int html_dir_list(request_rec *r, mod_gridsite_dir_cfg *conf)
/* 
    output HTML directory listing, with level of formatting controlled
    by GridSiteHtmlFormat/conf->format
*/
{
    int    i, fd, n, nn;
    char  *buf, *p, *s, *head_formatted, *header_formatted,
          *body_formatted, *admin_formatted, *footer_formatted, *temp,
           modified[99], *d_namepath, *indexheaderpath, *indexheadertext,
           *encoded, *escaped;
    size_t length;
    struct stat statbuf;
    struct tm   mtime_tm;
    struct dirent **namelist;
    
    if (r->finfo.filetype == APR_NOFILE) return HTTP_NOT_FOUND;

    /* Put in Delegation service header if required */
    if (conf->delegationuri) delegation_header(r, conf);

    head_formatted = apr_psprintf(r->pool,
      "<head><title>Directory listing %s</title></head>\n", r->uri);

    if (conf->format)
      {
        /* **** try to find a header file in this or parent directories **** */

        /* first make a buffer big enough to hold path names we want to try */
        fd = -1;
        s = apr_palloc(r->pool, 
                       strlen(r->filename) + strlen(conf->headfile) + 1);
        strcpy(s, r->filename);

        for (;;)
           {
             p = rindex(s, '/');
             if (p == NULL) break; /* failed to find one */
             p[1] = '\0';
             strcat(p, conf->headfile);
    
             fd = open(s, O_RDONLY);
             if (fd != -1) break; /* found one */

             *p = '\0';
           }
            
        if (fd == -1) /* not found, so set up to output sensible default */
          {
            header_formatted = apr_pstrdup(r->pool, "<body bgcolor=white>");
          }
        else /* found a header file, so set up head and body to surround it */
          {
            fstat(fd, &statbuf);
            header_formatted = apr_palloc(r->pool, statbuf.st_size + 1);
            read(fd, header_formatted, statbuf.st_size);
            header_formatted[statbuf.st_size] = '\0';
            close(fd);
          }
      }
    else header_formatted = apr_pstrdup(r->pool, "<body bgcolor=white>");
            
    body_formatted = apr_psprintf(r->pool, 
      "<h1>Directory listing %s</h1>\n", r->uri);
      
    if (conf->indexheader != NULL)
      {
        indexheaderpath = apr_psprintf(r->pool, "%s/%s", r->filename, 
                                                         conf->indexheader);
        fd = open(indexheaderpath, O_RDONLY);
        if (fd != -1)
          {
            fstat(fd, &statbuf);
            indexheadertext = apr_palloc(r->pool, statbuf.st_size + 1);
            read(fd, indexheadertext, statbuf.st_size);
            indexheadertext[statbuf.st_size] = '\0';
            close(fd);
            
            body_formatted = apr_pstrcat(r->pool, body_formatted,
                                         indexheadertext, NULL);
          }
      }

    body_formatted = apr_pstrcat(r->pool, body_formatted, "<p><table>\n", NULL);

    if (r->unparsed_uri[1] != '\0')
     body_formatted = apr_pstrcat(r->pool, body_formatted, 
        "<tr><td colspan=3>[<a href=\"../\">Parent directory</a>]</td></tr>\n", 
         NULL);
      
    nn = scandir(r->filename, &namelist, 0, versionsort);
    for (n=0; n < nn; ++n)
         {
           if ((namelist[n]->d_name[0] != '.') && 
               ((conf->indexheader == NULL) || 
                (strcmp(conf->indexheader, namelist[n]->d_name) != 0)))
             {
               d_namepath = apr_psprintf(r->pool, "%s/%s", r->filename,
                                                  namelist[n]->d_name);
               stat(d_namepath, &statbuf);
               
               localtime_r(&(statbuf.st_mtime), &mtime_tm);
               strftime(modified, sizeof(modified), 
              "<td align=right>%R</td><td align=right>%e&nbsp;%b&nbsp;%y</td>",
                        &mtime_tm);    

               encoded = GRSThttpUrlMildencode(namelist[n]->d_name);
               escaped = html_escape(r->pool, namelist[n]->d_name);

               if (S_ISDIR(statbuf.st_mode))
                    temp = apr_psprintf(r->pool, 
                      "<tr><td><a href=\"%s/\" content-length=\"%ld\" "
                      "last-modified=\"%ld\">"
                      "%s/</a></td>"
                      "<td align=right>%ld</td>%s</tr>\n", 
                      encoded, statbuf.st_size, statbuf.st_mtime,
                      escaped, 
                      statbuf.st_size, modified);
               else temp = apr_psprintf(r->pool, 
                      "<tr><td><a href=\"%s\" content-length=\"%ld\" "
                      "last-modified=\"%ld\">"
                      "%s</a></td>"
                      "<td align=right>%ld</td>%s</tr>\n", 
                      encoded, statbuf.st_size, statbuf.st_mtime,
                      escaped, 
                      statbuf.st_size, modified);
                      
               free(encoded);
               /* escaped done with pool so no free() */

               body_formatted = apr_pstrcat(r->pool,body_formatted,temp,NULL);
             }

           free(namelist[n]);
         }
                 
    free(namelist);
    
    body_formatted = apr_pstrcat(r->pool, body_formatted, "</table>\n", NULL);

    if (conf->format)
      {
        /* **** set up dynamic part of footer to go at end of body **** */

        admin_formatted = make_admin_footer(r, conf, TRUE);
    
        /* **** try to find a footer file in this or parent directories **** */

        /* first make a buffer big enough to hold path names we want to try */
        fd = -1;
        s = apr_palloc(r->pool, 
                       strlen(r->filename) + strlen(conf->footfile) + 1);
        strcpy(s, r->filename);
    
        for (;;)
           {
             p = rindex(s, '/');
             if (p == NULL) break; /* failed to find one */
    
             p[1] = '\0';
             strcat(p, conf->footfile);
    
             fd = open(s, O_RDONLY);
             if (fd != -1) break; /* found one */

             *p = '\0';
           }
            
        if (fd == -1) /* failed to find a footer, so use standard default */
          {
            footer_formatted = apr_pstrdup(r->pool, "</body>");
          }
        else /* found a footer, so set up to use it */
          {
            fstat(fd, &statbuf);
            footer_formatted = apr_palloc(r->pool, statbuf.st_size + 1);
            read(fd, footer_formatted, statbuf.st_size);
            footer_formatted[statbuf.st_size] = '\0';
            close(fd);
          }
      }
    else
      {
        admin_formatted = apr_pstrdup(r->pool, "");
        footer_formatted = apr_pstrdup(r->pool, "</body>");
      }

    /* **** can now calculate the Content-Length and output headers **** */
      
    length = strlen(head_formatted) + strlen(header_formatted) + 
             strlen(body_formatted) + strlen(admin_formatted)  +
             strlen(footer_formatted);

    ap_set_content_length(r, length);
    ap_set_content_type(r, "text/html");

    /* ** output the HTTP body (HTML Head+Body) ** */

    ap_rputs(head_formatted,   r);
    ap_rputs(header_formatted, r);
    ap_rputs(body_formatted,   r);
    ap_rputs(admin_formatted,  r);
    ap_rputs(footer_formatted, r);

    return OK;
}

int http_gridhttp(request_rec *r, mod_gridsite_dir_cfg *conf)
{ 
    int          i;
    char        *httpurl, *filetemplate, *cookievalue, *envname_i, 
                *grst_cred_i, expires_str[APR_RFC822_DATE_LEN];
    apr_uint64_t gridauthcookie;
    apr_table_t *env;
    apr_time_t   expires_time;
    apr_file_t  *fp;

    /* create random cookie and gridauthcookie file */

    if (apr_generate_random_bytes((char *) &gridauthcookie, 
                                  sizeof(gridauthcookie))
         != APR_SUCCESS) return HTTP_INTERNAL_SERVER_ERROR;
    
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
               "Generated GridHTTP passcode %016llx", gridauthcookie);

    filetemplate = apr_psprintf(r->pool, "%s/passcode-%016llxXXXXXX", 
     ap_server_root_relative(r->pool,
     sessionsdir),
     gridauthcookie);

    if (apr_file_mktemp(&fp, 
                        filetemplate, 
                        APR_CREATE | APR_WRITE | APR_EXCL,
                        r->pool)
                      != APR_SUCCESS) return HTTP_INTERNAL_SERVER_ERROR;
                      
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
               "Created passcode file %s", filetemplate);

    expires_time = apr_time_now() + apr_time_from_sec(300);
    /* passcode cookies are valid for only 5 mins! */

    apr_file_printf(fp,
              "expires=%lu\ndomain=%s\npath=%s\nonetime=yes\nmethod=%s\n",
              (time_t) apr_time_sec(expires_time),
              r->hostname, r->uri, r->method);
    /* above variables are evaluated in order and method= MUST be last! */

    for (i=0; ; ++i)
       {
         envname_i = apr_psprintf(r->pool, "GRST_CRED_AURI_%d", i);
         if (grst_cred_i = (char *)
                           apr_table_get(r->connection->notes, envname_i))
           {
             apr_file_printf(fp, "%s=%s\n", envname_i, grst_cred_i);
           }
         else break; /* GRST_CRED_AURI_i are numbered consecutively */

         envname_i = apr_psprintf(r->pool, "GRST_CRED_VALID_%d", i);
         if (grst_cred_i = (char *)
                           apr_table_get(r->connection->notes, envname_i))
           {
             apr_file_printf(fp, "%s=%s\n", envname_i, grst_cred_i);
           }
         else break; /* GRST_CRED_VALID_i are numbered consecutively */
       }

    if (apr_file_close(fp) != APR_SUCCESS) 
      {
        apr_file_remove(filetemplate, r->pool); /* try to clean up */
        return HTTP_INTERNAL_SERVER_ERROR;
      }
    
    /* send redirection header back to client */
       
    cookievalue = rindex(filetemplate, '-');
    if (cookievalue != NULL) ++cookievalue;
    else cookievalue = filetemplate;
       
    apr_rfc822_date(expires_str, expires_time);

    apr_table_add(r->headers_out, 
                  apr_pstrdup(r->pool, "Set-Cookie"), 
                  apr_psprintf(r->pool, 
                  "GRIDHTTP_PASSCODE=%s; "
                  "expires=%s; "
                  "domain=%s; "
                  "path=%s",
                  cookievalue, expires_str, r->hostname, r->uri));

    if (gridhttpport != DEFAULT_HTTP_PORT)
         httpurl = apr_psprintf(r->pool, "http://%s:%d%s", r->hostname,
                                gridhttpport, ap_escape_uri(r->pool, r->uri));
    else httpurl = apr_pstrcat(r->pool, "http://", r->hostname,
                                ap_escape_uri(r->pool, r->uri), NULL);

    apr_table_setn(r->headers_out, apr_pstrdup(r->pool, "Location"), httpurl);

    r->status = HTTP_MOVED_TEMPORARILY;  
    return OK;
}

int http_put_method(request_rec *r, mod_gridsite_dir_cfg *conf)
{
  char        buf[2048], *filename, *dirname, *basename;
  const char  *p;
  size_t      block_length, length_sent;
  int         retcode, stat_ret;
  apr_file_t *fp;
  struct stat statbuf;
  int       has_range = 0, is_done = 0;
  apr_off_t range_start, range_end, range_length, length_to_send, length = 0;
  
  /* ***  check if directory creation: PUT /.../  *** */

  if ((r->unparsed_uri    != NULL) && 
      (r->unparsed_uri[0] != '\0') &&
      (r->unparsed_uri[strlen(r->unparsed_uri) - 1] == '/'))
    {
      if (apr_dir_make(r->filename, 
                       conf->diskmode 
                       | APR_UEXECUTE | APR_GEXECUTE | APR_WEXECUTE, 
                       r->pool) != 0) return HTTP_INTERNAL_SERVER_ERROR;

      /* we force the permissions, rather than accept any existing ones */

      apr_file_perms_set(r->filename, conf->diskmode
                             | APR_UEXECUTE | APR_GEXECUTE | APR_WEXECUTE);
                             
      ap_set_content_length(r, 0);
      ap_set_content_type(r, "text/html");
      return OK;
    }

  /* ***  otherwise assume trying to create a regular file *** */

  stat_ret = stat(r->filename, &statbuf);

  /* find if a range is specified */

  has_range = parse_content_range(r, &range_start, &range_end, &range_length);

  if (has_range)
    {
       if ((range_start == 0) && (range_end == 0)) /* truncate? */
         {
           if (stat_ret != 0) return HTTP_NOT_FOUND;
          
           if (truncate(r->filename, range_length) != 0)
                return HTTP_INTERNAL_SERVER_ERROR;
           else return OK;
         }
    
       filename = r->filename;

       if (apr_file_open(&fp, filename, APR_WRITE | APR_CREATE | APR_BUFFERED,
            conf->diskmode, r->pool) != 0) return HTTP_INTERNAL_SERVER_ERROR;
    }
  else /* use temporary file if not a partial transfer */ 
    {
      dirname = apr_pstrdup(r->pool, r->filename);
      basename = rindex(dirname, '/');
      if (basename == NULL) return HTTP_INTERNAL_SERVER_ERROR;
        
      *basename = '\0';
      ++basename;

      filename = apr_psprintf(r->pool,
                             "%s/.grsttmp-%s-XXXXXX", dirname, basename);

      if (apr_file_mktemp(&fp, filename,
                    APR_CREATE | APR_WRITE | APR_BUFFERED | APR_EXCL, r->pool)
                    != APR_SUCCESS) return HTTP_INTERNAL_SERVER_ERROR;
/*
      p = apr_table_get(r->headers_in, "Content-Length");
      if (p != NULL) 
        {
          length = (apr_off_t) atol(p);
          if (length > 16384)
            {
              if (apr_file_seek(fp, APR_SET, &length) == 0)
                {
                  block_length = 1;
                  apr_file_write(fp, "0", &block_length);
                }

              apr_file_seek(fp, APR_SET, 0);
            }
        }
*/
    }

  /* we force the permissions, rather than accept any existing ones */

  apr_file_perms_set(filename, conf->diskmode);

  if (has_range)
    {
      if (apr_file_seek(fp, APR_SET, &range_start) != 0) 
        {
          retcode = HTTP_INTERNAL_SERVER_ERROR;
          return retcode;
        }

      length_to_send = range_end - range_start + 1;
    }

  retcode = ap_setup_client_block(r, REQUEST_CHUNKED_DECHUNK);
  if (retcode == OK)
    {
      if (has_range) length_sent = 0;

      if (ap_should_client_block(r))
          while ((block_length = ap_get_client_block(r, buf, sizeof(buf))) > 0)
            {
              if (has_range && (length_sent + block_length > length_to_send))
                {
                  block_length = length_to_send - length_sent;
                  is_done = 1;
                }

              if (apr_file_write(fp, buf, &block_length) != 0) 
                {
                  retcode = HTTP_INTERNAL_SERVER_ERROR;
                  break;
                }

              if (has_range)
                {
                  if (is_done) break;
                  else length_sent += block_length;
                }
            }
      ap_set_content_length(r, 0);
      ap_set_content_type(r, "text/html");
    }

  if ((apr_file_close(fp) != 0) || (retcode == HTTP_INTERNAL_SERVER_ERROR))
    {
      if (strcmp(filename, r->filename) != 0) remove(filename);
      return HTTP_INTERNAL_SERVER_ERROR;
    }

  if ((strcmp(filename, r->filename) != 0) &&
      (apr_file_rename(filename, r->filename, r->pool) != 0))
      return HTTP_FORBIDDEN; /* best guess as to the problem ... */

  if ((retcode == OK) && (stat_ret != 0))
    {
      retcode = HTTP_CREATED;
      ap_custom_response(r, HTTP_CREATED, "");
    }

  return retcode;
}

int http_delete_method(request_rec *r, mod_gridsite_dir_cfg *conf)
{
  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
               "Try remove(%s)", r->filename);

  if (remove(r->filename) != 0) return HTTP_FORBIDDEN;
       
  ap_set_content_length(r, 0);
  ap_set_content_type(r, "text/html");

  return OK;
}

int http_move_method(request_rec *r, mod_gridsite_dir_cfg *conf)
{
  char *destination_translated = NULL;
  
  if (r->notes != NULL) destination_translated = 
            (char *) apr_table_get(r->notes, "GRST_DESTINATION_TRANSLATED");

  if (destination_translated == NULL) return HTTP_BAD_REQUEST;
  
  if (strcmp(r->filename, destination_translated) == 0)
                                      return HTTP_FORBIDDEN;
  
  if (apr_file_rename(r->filename, destination_translated, r->pool) != 0)
                                                       return HTTP_FORBIDDEN;

  ap_set_content_length(r, 0);
  ap_set_content_type(r, "text/html");

  return OK;
}

static int mod_gridsite_dir_handler(request_rec *r, mod_gridsite_dir_cfg *conf)
/*
   handler switch for directories
*/
{
    /* *** is this a write method? only possible if  GridSiteAuth on *** */

    if (conf->auth)
      {
        if ((r->method_number == M_PUT) && 
            (conf->methods != NULL) &&
            (strstr(conf->methods, " PUT "   ) != NULL))
                                           return http_put_method(r, conf);

        if ((r->method_number == M_DELETE) &&
            (conf->methods != NULL) &&
            (strstr(conf->methods, " DELETE ") != NULL)) 
                                           return http_delete_method(r, conf);
      }
      
    /* *** directory listing? *** */
    if ((r->method_number == M_GET) && (conf->indexes))       
                       return html_dir_list(r, conf); /* directory listing */
    
    return DECLINED; /* *** nothing to see here, move along *** */
}

static int mod_gridsite_nondir_handler(request_rec *r, mod_gridsite_dir_cfg *conf)
/*
   one big handler switch for everything other than directories, since we 
   might be responding to MIME * / * for local PUT, MOVE, COPY and DELETE, 
   and GET inside ghost directories.
*/
{
    char *upgradeheader, *upgradespaced, *p;
    const char *https_env;

    /* *** is this a write method or GridHTTP HTTPS->HTTP redirection? 
           only possible if  GridSiteAuth on *** */
    
    if (conf->auth)
      {
        if ((conf->gridhttp) &&
            ((r->method_number == M_GET) || 
             ((r->method_number == M_PUT) && 
              (strstr(conf->methods, " PUT ") != NULL))) &&
            ((upgradeheader = (char *) apr_table_get(r->headers_in,
                                                     "Upgrade")) != NULL) &&
            ((https_env=apr_table_get(r->subprocess_env,"HTTPS")) != NULL) &&
            (strcasecmp(https_env, "on") == 0))
          {
            upgradespaced = apr_psprintf(r->pool, " %s ", upgradeheader);

            for (p=upgradespaced; *p != '\0'; ++p)
             if ((*p == ',') || (*p == '\t')) *p = ' ';

// TODO: what if we're pointing at a CGI or some dynamic content???
 
            if (strstr(upgradespaced, " GridHTTP/1.0 ") != NULL)
                                            return http_gridhttp(r, conf);
          }

        if ((r->method_number == M_PUT) && 
            (conf->methods != NULL) &&
            (strstr(conf->methods, " PUT "   ) != NULL))
                                           return http_put_method(r, conf);

        if ((r->method_number == M_DELETE) &&
            (conf->methods != NULL) &&
            (strstr(conf->methods, " DELETE ") != NULL)) 
                                           return http_delete_method(r, conf);

        if ((r->method_number == M_MOVE) &&
            (conf->methods != NULL) &&
            (strstr(conf->methods, " MOVE ") != NULL)) 
                                           return http_move_method(r, conf);
      }

    /* *** check if a special ghost admin CGI *** */
      
    if (conf->adminfile && conf->adminuri &&
        (strlen(r->filename) > strlen(conf->adminfile) + 1) &&
        (strcmp(&(r->filename[strlen(r->filename) - strlen(conf->adminfile)]),
                                                    conf->adminfile) == 0) &&
        (r->filename[strlen(r->filename)-strlen(conf->adminfile)-1] == '/') &&
        ((r->method_number == M_POST) ||
         (r->method_number == M_GET))) 
      {
        ap_internal_redirect(conf->adminuri, r);
        return OK;
      }
      
    /* *** finally look for .html files that we should format *** */

    if ((conf->format) &&  /* conf->format set by  GridSiteHtmlFormat on */ 
        (strlen(r->filename) > 5) &&
        (strcmp(&(r->filename[strlen(r->filename)-5]), ".html") == 0) &&
        (r->method_number == M_GET)) return html_format(r, conf);
     
    return DECLINED; /* *** nothing to see here, move along *** */
}

static void recurse4dirlist(char *dirname, time_t *dirs_time,
                             char *fulluri, int fullurilen,
                             char *encfulluri, int enclen,
                             apr_pool_t *pool, char **body,
                             int recurse_level)
/* try to find DN Lists in dir[] and its subdirs that match the fulluri[]
   prefix. add blobs of HTML to body as they are found. */
{
   char          *unencname, modified[99], *oneline, *d_namepath,
                 *mildencoded;
   DIR           *oneDIR;
   struct dirent *onedirent;
   struct tm      mtime_tm;
   size_t         length;
   struct stat    statbuf;

   if ((stat(dirname, &statbuf) != 0) ||
       (!S_ISDIR(statbuf.st_mode)) ||
       ((oneDIR = opendir(dirname)) == NULL)) return;

   if (statbuf.st_mtime > *dirs_time) *dirs_time = statbuf.st_mtime;

   while ((onedirent = readdir(oneDIR)) != NULL)
        {
          if (onedirent->d_name[0] == '.') continue;
        
          d_namepath = apr_psprintf(pool, "%s/%s", dirname, onedirent->d_name);
          if (stat(d_namepath, &statbuf) != 0) continue;

          if (S_ISDIR(statbuf.st_mode) && (recurse_level < GRST_RECURS_LIMIT)) 
                 recurse4dirlist(d_namepath, dirs_time, fulluri,
                                 fullurilen, encfulluri, enclen, 
                                 pool, body, recurse_level + 1);
          else if ((strncmp(onedirent->d_name, encfulluri, enclen) == 0) &&
                   (onedirent->d_name[strlen(onedirent->d_name) - 1] != '~'))
            {
              unencname = GRSThttpUrlDecode(onedirent->d_name);
                    
              if (strncmp(unencname, fulluri, fullurilen) == 0)
                {

                  if (statbuf.st_mtime > *dirs_time) 
                                                *dirs_time = statbuf.st_mtime;

                  localtime_r(&(statbuf.st_mtime), &mtime_tm);
                  strftime(modified, sizeof(modified), 
              "<td align=right>%R</td><td align=right>%e&nbsp;%b&nbsp;%y</td>",
                       &mtime_tm);
                  
                  mildencoded = GRSThttpUrlMildencode(&unencname[fullurilen]);
                 
                  oneline = apr_psprintf(pool,
                                     "<tr><td><a href=\"%s\" "
                                     "content-length=\"%ld\" "
                                     "last-modified=\"%ld\">"
                                     "%s</a></td>"
                                     "<td align=right>%ld</td>%s</tr>\n", 
                                     mildencoded, statbuf.st_size, 
                                     statbuf.st_mtime, 
                                     html_escape(pool, unencname), 
                                     statbuf.st_size, modified);

                  free(mildencoded);

                  *body = apr_pstrcat(pool, *body, oneline, NULL);
                }      
                      
              free(unencname); /* libgridsite doesnt use pools */    
            }
        }
        
   closedir(oneDIR);
}

static int mod_gridsite_dnlistsuri_dir_handler(request_rec *r, 
                                               mod_gridsite_dir_cfg *conf)
/*
    virtual DN-list file lister: make all DN lists on the dn-lists
    path of this server appear to be in the dn-lists directory itself
    (ie where they appear in the DN lists path doesnt matter, as long
    as their name matches)
*/
{
    int            enclen, fullurilen, fd;
    char          *fulluri, *encfulluri, *dn_list_ptr, *dirname, *unencname,
                  *body, *oneline, *p, *s,
                  *head_formatted, *header_formatted, *footer_formatted,
                  *permstr = NULL;
    struct stat    statbuf;
    size_t         length;
    time_t         dirs_time = 0;
    GRSTgaclPerm   perm = GRST_PERM_NONE;
        
    if (r->notes != NULL)
           permstr = (char *) apr_table_get(r->notes, "GRST_PERM");

    if (permstr != NULL) sscanf(permstr, "%d", &perm);

    fulluri = apr_psprintf(r->pool, "https://%s%s",
                                    ap_get_server_name(r), conf->dnlistsuri);
    fullurilen = strlen(fulluri);

    encfulluri = GRSThttpUrlEncode(fulluri);
    enclen     = strlen(encfulluri);

    if (conf->dnlists != NULL) p = conf->dnlists;
    else p = getenv("GRST_DN_LISTS");

    if (p == NULL) p = GRST_DN_LISTS;
    dn_list_ptr = apr_pstrdup(r->pool, p);

    head_formatted = apr_psprintf(r->pool, 
      "<head><title>Directory listing %s</title></head>\n", r->uri);

    if (conf->format)
      {
        /* **** try to find a header file in this or parent directories **** */

        /* first make a buffer big enough to hold path names we want to try */
        fd = -1;
        s = malloc(strlen(r->filename) + strlen(conf->headfile) + 1);
        strcpy(s, r->filename);
    
        for (;;)
           {
             p = rindex(s, '/');
             if (p == NULL) break; /* failed to find one */
             p[1] = '\0';
             strcat(p, conf->headfile);
    
             fd = open(s, O_RDONLY);
             if (fd != -1) break; /* found one */

             *p = '\0';
           }
            
        free(s);

        if (fd == -1) /* not found, so set up to output sensible default */
          {
            header_formatted = apr_pstrdup(r->pool, "<body bgcolor=white>");
          }
        else /* found a header file, so set up head and body to surround it */
          {
            fstat(fd, &statbuf);
            header_formatted = apr_palloc(r->pool, statbuf.st_size + 1);
            read(fd, header_formatted, statbuf.st_size);
            header_formatted[statbuf.st_size] = '\0';
            close(fd);
          }
      }
    else header_formatted = apr_pstrdup(r->pool, "<body bgcolor=white>");
            
    body = apr_psprintf(r->pool, 
      "<h1>Directory listing %s</h1>\n<table>", r->uri);

    if ((r->uri)[1] != '\0')
     body = apr_pstrcat(r->pool, body, 
       "<tr><td>[<a href=\"../\">Parent directory</a>]</td></tr>\n",
       NULL);

    while ((dirname = strsep(&dn_list_ptr, ":")) != NULL)
        recurse4dirlist(dirname, &dirs_time, fulluri, fullurilen,
                                 encfulluri, enclen, r->pool, &body, 0);

    if ((stat(r->filename, &statbuf) == 0) &&
        S_ISDIR(statbuf.st_mode) && 
        GRSTgaclPermHasWrite(perm))
      {
        oneline = apr_psprintf(r->pool,
           "<form action=\"%s%s\" method=post>\n"
           "<input type=hidden name=cmd value=managedir>"
           "<tr><td colspan=4 align=center><small><input type=submit "
           "value=\"Manage directory\"></small></td></tr></form>\n",
           r->uri, conf->adminfile);
          
        body = apr_pstrcat(r->pool, body, oneline, NULL);
      } 

    body = apr_pstrcat(r->pool, body, "</table>\n", NULL);

    free(encfulluri); /* libgridsite doesnt use pools */

    if (conf->format)
      {
        /* **** try to find a footer file in this or parent directories **** */

        /* first make a buffer big enough to hold path names we want to try */
        fd = -1;
        s  = malloc(strlen(r->filename) + strlen(conf->footfile));
        strcpy(s, r->filename);
    
        for (;;)
           {
             p = rindex(s, '/');
             if (p == NULL) break; /* failed to find one */
    
             p[1] = '\0';
             strcat(p, conf->footfile);
    
             fd = open(s, O_RDONLY);
             if (fd != -1) break; /* found one */

             *p = '\0';
           }
            
        free(s);

        if (fd == -1) /* failed to find a footer, so use standard default */
          {
            footer_formatted = apr_pstrdup(r->pool, "</body>");
          }
        else /* found a footer, so set up to use it */
          {
            fstat(fd, &statbuf);
            footer_formatted = apr_palloc(r->pool, statbuf.st_size + 1);
            read(fd, footer_formatted, statbuf.st_size);
            footer_formatted[statbuf.st_size] = '\0';
            close(fd);
          }
      }
    else footer_formatted = apr_pstrdup(r->pool, "</body>");

    /* **** can now calculate the Content-Length and output headers **** */
      
    length = strlen(head_formatted) + strlen(header_formatted) + 
             strlen(body) + strlen(footer_formatted);

    ap_set_content_length(r, length);
    r->mtime = apr_time_from_sec(dirs_time);
    ap_set_last_modified(r);
    ap_set_content_type(r, "text/html");

    /* ** output the HTTP body (HTML Head+Body) ** */
    ap_rputs(head_formatted,   r);
    ap_rputs(header_formatted, r);
    ap_rputs(body,		   r);
    ap_rputs(footer_formatted, r);

    return OK;
}

static char *recurse4file(char *dir, char *file, apr_pool_t *pool, 
                          int recurse_level)
/* try to find file[] in dir[]. try subdirs if not found.
   return full path to first found version or NULL on failure */
{
    char          *fullfilename, *fulldirname;
    struct stat    statbuf;
    DIR           *dirDIR;
    struct dirent *file_ent;

    /* try to find in current directory */

    fullfilename = apr_psprintf(pool, "%s/%s", dir, file);

    if (stat(fullfilename, &statbuf) == 0) return fullfilename;

    /* maybe search in subdirectories */

    if (recurse_level >= GRST_RECURS_LIMIT) return NULL;

    dirDIR = opendir(dir);

    if (dirDIR == NULL) return NULL;

    while ((file_ent = readdir(dirDIR)) != NULL)
       {
         if (file_ent->d_name[0] == '.') continue;

         fulldirname = apr_psprintf(pool, "%s/%s", dir, file_ent->d_name);
         if ((stat(fulldirname, &statbuf) == 0) &&
             S_ISDIR(statbuf.st_mode) &&
             ((fullfilename = recurse4file(fulldirname, file,
                                           pool, recurse_level + 1)) != NULL))
           {
             closedir(dirDIR);
             return fullfilename;
           }
       }

    closedir(dirDIR);

    return NULL;
}

static int mod_gridsite_dnlistsuri_handler(request_rec *r, 
                                           mod_gridsite_dir_cfg *conf)
/*
    virtual DN-list file generator
*/
{
    int          fd;
    char        *fulluri, *encfulluri, *dn_list_ptr, *filename, *dirname, *p,
                *buf;
    struct stat  statbuf;
    
    /* *** check if a special ghost admin CGI *** */
      
    if (conf->adminfile && conf->adminuri &&
        (strlen(r->filename) > strlen(conf->adminfile) + 1) &&
        (strcmp(&(r->filename[strlen(r->filename) - strlen(conf->adminfile)]),
                                                    conf->adminfile) == 0) &&
        (r->filename[strlen(r->filename)-strlen(conf->adminfile)-1] == '/') &&
        ((r->method_number == M_POST) ||
         (r->method_number == M_GET))) 
      {
        ap_internal_redirect(conf->adminuri, r);
        return OK;
      }

    fulluri = apr_psprintf(r->pool, "https://%s%s", 
                                    ap_get_server_name(r), r->uri);

    encfulluri = GRSThttpUrlEncode(fulluri);
    
    if (conf->dnlists != NULL) p = conf->dnlists;
    else p = getenv("GRST_DN_LISTS");
 
    if (p == NULL) p = GRST_DN_LISTS;
    dn_list_ptr = apr_pstrdup(r->pool, p);

    while ((dirname = strsep(&dn_list_ptr, ":")) != NULL)
       {
         filename = recurse4file(dirname, encfulluri, r->pool, 0);

         if (filename == NULL) continue;
    
         fd = open(filename, O_RDONLY);

         if (fd == -1) continue;

         fstat(fd, &statbuf);         
         ap_set_content_length(r, (apr_off_t) statbuf.st_size);
         r->mtime = apr_time_from_sec(statbuf.st_mtime);
         ap_set_content_type(r, "text/plain");
         ap_set_last_modified(r);

         buf = apr_palloc(r->pool, statbuf.st_size + 1);
         read(fd, buf, statbuf.st_size);
         buf[statbuf.st_size] = '\0';
            
         ap_rputs(buf, r);

         close(fd);

         return OK;
       }

    return HTTP_NOT_FOUND;
}

static void *create_gridsite_srv_config(apr_pool_t *p, server_rec *s)
{
    int i;

    /* only run once (in base server) */
    if (!(s->is_virtual) && (gridhttpport == 0))
      {
        gridhttpport = GRST_HTTP_PORT;
      
        sessionsdir = apr_pstrdup(p, GRST_SESSIONS_DIR);
                                      /* GridSiteSessionsDir dir-path   */

        sitecastdnlists = NULL;

        sitecastgroups[0].quad1 = 0;
        sitecastgroups[0].quad2 = 0;
        sitecastgroups[0].quad3 = 0;
        sitecastgroups[0].quad4 = 0;
        sitecastgroups[0].port  = GRST_HTCP_PORT;
                                      /* GridSiteCastUniPort udp-port */

        for (i=1; i <= GRST_SITECAST_GROUPS; ++i)
           {
             sitecastgroups[i].port = 0; /* GridSiteCastGroup mcast-list */
           }

        for (i=1; i <= GRST_SITECAST_ALIASES; ++i)
           {
             sitecastaliases[i].sitecast_url   = NULL;
             sitecastaliases[i].port           = 0;
             sitecastaliases[i].scheme         = NULL;
             sitecastaliases[i].local_path     = NULL;
             sitecastaliases[i].local_hostname = NULL;
           }                              /* GridSiteCastAlias url path */
      }

    return NULL;
}

static void *create_gridsite_dir_config(apr_pool_t *p, char *path)
{
    mod_gridsite_dir_cfg *conf = apr_palloc(p, sizeof(*conf));

    if (path == NULL) /* set up document root defaults */
      {
        conf->auth          = 0;     /* GridSiteAuth          on/off       */
        conf->envs          = 1;     /* GridSiteEnvs          on/off       */
        conf->format        = 0;     /* GridSiteHtmlFormat    on/off       */
        conf->indexes       = 0;     /* GridSiteIndexes       on/off       */
        conf->indexheader   = NULL;  /* GridSiteIndexHeader   File-value   */
        conf->gridsitelink  = 1;     /* GridSiteLink          on/off       */
        conf->adminfile     = apr_pstrdup(p, GRST_ADMIN_FILE);
                                /* GridSiteAdminFile      File-value   */
        conf->adminuri      = NULL;  /* GridSiteAdminURI      URI-value    */
        conf->helpuri       = NULL;  /* GridSiteHelpURI       URI-value    */
        conf->dnlists       = NULL;  /* GridSiteDNlists       Search-path  */
        conf->dnlistsuri    = NULL;  /* GridSiteDNlistsURI    URI-value    */
        conf->adminlist     = NULL;  /* GridSiteAdminList     URI-value    */
        conf->gsiproxylimit = 1;     /* GridSiteGSIProxyLimit number       */
        conf->unzip         = NULL;  /* GridSiteUnzip         file-path    */

        conf->methods    = apr_pstrdup(p, " GET ");
                                        /* GridSiteMethods      methods    */

        conf->editable = apr_pstrdup(p, " txt shtml html htm css js php jsp ");
                                        /* GridSiteEditable     types   */

        conf->headfile = apr_pstrdup(p, GRST_HEADFILE);
        conf->footfile = apr_pstrdup(p, GRST_FOOTFILE);
               /* GridSiteHeadFile and GridSiteFootFile  file name */

        conf->gridhttp      = 0;     /* GridSiteGridHTTP      on/off       */
	conf->aclformat     = apr_pstrdup(p, "GACL");
                                     /* GridSiteACLFormat     gacl/xacml   */
	conf->aclpath       = NULL;  /* GridSiteACLPath       acl-path     */
	conf->delegationuri = NULL;  /* GridSiteDelegationURI URI-value    */
	conf->execmethod    = NULL;
               /* GridSiteExecMethod  nosetuid/suexec/X509DN/directory */
               
        conf->execugid.uid     = 0;	/* GridSiteUserGroup User Group */
        conf->execugid.gid     = 0;	/* ditto */
        conf->execugid.userdir = 0;	/* ditto */
        
        conf->diskmode	= APR_UREAD | APR_UWRITE; 
              /* GridSiteDiskMode group-mode world-mode
                 GroupNone | GroupRead | GroupWrite   WorldNone | WorldRead */
      }
    else
      {
        conf->auth          = UNSET; /* GridSiteAuth          on/off       */
        conf->envs          = UNSET; /* GridSiteEnvs          on/off       */
        conf->format        = UNSET; /* GridSiteHtmlFormat    on/off       */
        conf->indexes       = UNSET; /* GridSiteIndexes       on/off       */
        conf->indexheader   = NULL;  /* GridSiteIndexHeader   File-value   */
        conf->gridsitelink  = UNSET; /* GridSiteLink          on/off       */
        conf->adminfile     = NULL;  /* GridSiteAdminFile     File-value   */
        conf->adminuri      = NULL;  /* GridSiteAdminURI      URI-value    */
        conf->helpuri       = NULL;  /* GridSiteHelpURI       URI-value    */
        conf->dnlists       = NULL;  /* GridSiteDNlists       Search-path  */
        conf->dnlistsuri    = NULL;  /* GridSiteDNlistsURI    URI-value    */
        conf->adminlist     = NULL;  /* GridSiteAdminList     URI-value    */
        conf->gsiproxylimit = UNSET; /* GridSiteGSIProxyLimit number       */
        conf->unzip         = NULL;  /* GridSiteUnzip         file-path    */
        conf->methods       = NULL;  /* GridSiteMethods       methods      */
        conf->editable      = NULL;  /* GridSiteEditable      types        */
        conf->headfile      = NULL;  /* GridSiteHeadFile      file name    */
        conf->footfile      = NULL;  /* GridSiteFootFile      file name    */
        conf->gridhttp      = UNSET; /* GridSiteGridHTTP      on/off       */
	conf->aclformat     = NULL;  /* GridSiteACLFormat     gacl/xacml   */
	conf->aclpath       = NULL;  /* GridSiteACLPath       acl-path     */
	conf->delegationuri = NULL;  /* GridSiteDelegationURI URI-value    */
	conf->execmethod    = NULL;  /* GridSiteExecMethod */
        conf->execugid.uid     = UNSET;	/* GridSiteUserGroup User Group */
        conf->execugid.gid     = UNSET; /* ditto */
        conf->execugid.userdir = UNSET; /* ditto */
        conf->diskmode	    = UNSET; /* GridSiteDiskMode group world */
      }

    return conf;
}

static void *merge_gridsite_dir_config(apr_pool_t *p, void *vserver,
                                                      void *vdirect)
/* merge directory with server-wide directory configs */
{
    mod_gridsite_dir_cfg *conf, *server, *direct;

    server = (mod_gridsite_dir_cfg *) vserver;
    direct = (mod_gridsite_dir_cfg *) vdirect;
    conf = apr_palloc(p, sizeof(*conf));

    if (direct->auth != UNSET) conf->auth = direct->auth;
    else                       conf->auth = server->auth;

    if (direct->envs != UNSET) conf->envs = direct->envs;
    else                       conf->envs = server->envs;
        
    if (direct->format != UNSET) conf->format = direct->format;
    else                         conf->format = server->format;
        
    if (direct->indexes != UNSET) conf->indexes = direct->indexes;
    else                          conf->indexes = server->indexes;
        
    if (direct->gridsitelink != UNSET) conf->gridsitelink=direct->gridsitelink;
    else                               conf->gridsitelink=server->gridsitelink;

    if (direct->indexheader != NULL) conf->indexheader = direct->indexheader;
    else                             conf->indexheader = server->indexheader;
        
    if (direct->adminfile != NULL) conf->adminfile = direct->adminfile;
    else                           conf->adminfile = server->adminfile;
        
    if (direct->adminuri != NULL) conf->adminuri = direct->adminuri;
    else                          conf->adminuri = server->adminuri;
        
    if (direct->helpuri != NULL) conf->helpuri = direct->helpuri;
    else                         conf->helpuri = server->helpuri;
        
    if (direct->dnlists != NULL) conf->dnlists = direct->dnlists;
    else                         conf->dnlists = server->dnlists;
        
    if (direct->dnlistsuri != NULL) conf->dnlistsuri = direct->dnlistsuri;
    else                            conf->dnlistsuri = server->dnlistsuri;

    if (direct->adminlist != NULL) conf->adminlist = direct->adminlist;
    else                           conf->adminlist = server->adminlist;

    if (direct->gsiproxylimit != UNSET)
                         conf->gsiproxylimit = direct->gsiproxylimit;
    else                 conf->gsiproxylimit = server->gsiproxylimit;

    if (direct->unzip != NULL) conf->unzip = direct->unzip;
    else                       conf->unzip = server->unzip;

    if (direct->methods != NULL) conf->methods = direct->methods;
    else                         conf->methods = server->methods;

    if (direct->editable != NULL) conf->editable = direct->editable;
    else                          conf->editable = server->editable;

    if (direct->headfile != NULL) conf->headfile = direct->headfile;
    else                          conf->headfile = server->headfile;

    if (direct->footfile != NULL) conf->footfile = direct->footfile;
    else                          conf->footfile = server->footfile;

    if (direct->gridhttp != UNSET) conf->gridhttp = direct->gridhttp;
    else                           conf->gridhttp = server->gridhttp;
        
    if (direct->aclformat != NULL) conf->aclformat = direct->aclformat;
    else                           conf->aclformat = server->aclformat;

    if (direct->aclpath != NULL)   conf->aclpath = direct->aclpath;
    else                           conf->aclpath = server->aclpath;

    if (direct->delegationuri != NULL) conf->delegationuri = direct->delegationuri;
    else                               conf->delegationuri = server->delegationuri;

    if (direct->execmethod != NULL) conf->execmethod = direct->execmethod;
    else                            conf->execmethod = server->execmethod;

    if (direct->execugid.uid != UNSET)
      { conf->execugid.uid = direct->execugid.uid;
        conf->execugid.gid = direct->execugid.gid;
        conf->execugid.userdir = direct->execugid.userdir; }
    else
      { conf->execugid.uid = server->execugid.uid;
        conf->execugid.gid = server->execugid.gid;
        conf->execugid.userdir = server->execugid.userdir; }

    if (direct->diskmode != UNSET) conf->diskmode = direct->diskmode;
    else                            conf->diskmode = server->diskmode;
        
    return conf;
}

static const char *mod_gridsite_take1_cmds(cmd_parms *a, void *cfg,
                                           const char *parm)
{
    int   n, i;
    char *p;
  
    if (strcasecmp(a->cmd->name, "GridSiteSessionsDir") == 0)
    {
      if (a->server->is_virtual)
       return "GridSiteSessionsDir cannot be used inside a virtual server";
    
      sessionsdir = apr_pstrdup(a->pool, parm);
    }
/* GridSiteOnetimesDir is deprecated in favour of GridSiteSessionsDir */
    else if (strcasecmp(a->cmd->name, "GridSiteOnetimesDir") == 0)
    {
      if (a->server->is_virtual)
       return "GridSiteOnetimesDir cannot be used inside a virtual server";
    
      sessionsdir = apr_pstrdup(a->pool, parm);
    }
    else if (strcasecmp(a->cmd->name, "GridSiteGridHTTPport") == 0)
    {
      gridhttpport = atoi(parm);
    }
    else if (strcasecmp(a->cmd->name, "GridSiteCastDNlists") == 0)
    {
      if (a->server->is_virtual)
       return "GridSiteDNlists cannot be used inside a virtual server";
    
      sitecastdnlists = apr_pstrdup(a->pool, parm);
    }
    else if (strcasecmp(a->cmd->name, "GridSiteCastUniPort") == 0)
    {
      if (a->server->is_virtual)
       return "GridSiteCastUniPort cannot be used inside a virtual server";

      if (sscanf(parm, "%d", &(sitecastgroups[0].port)) != 1)
        return "Failed parsing GridSiteCastUniPort numeric value";
    }
    else if (strcasecmp(a->cmd->name, "GridSiteCastGroup") == 0)
    {
      if (a->server->is_virtual)
       return "GridSiteCastGroup cannot be used inside a virtual server";

      for (i=1; i <= GRST_SITECAST_GROUPS; ++i)
         {
           if (sitecastgroups[i].port == 0) /* a free slot */
             {
               sitecastgroups[i].port = GRST_HTCP_PORT;
             
               if (sscanf(parm, "%d.%d.%d.%d:%d",
                          &(sitecastgroups[i].quad1), 
                          &(sitecastgroups[i].quad2), 
                          &(sitecastgroups[i].quad3), 
                          &(sitecastgroups[i].quad4), 
                          &(sitecastgroups[i].port)) < 4)
                 return "Failed parsing GridSiteCastGroup nnn.nnn.nnn.nnn[:port]";
                 
               break;
             }
         }
         
      if (i > GRST_SITECAST_GROUPS)
                     return "Maximum GridSiteCastGroup groups reached";
    }
    else if (strcasecmp(a->cmd->name, "GridSiteAdminFile") == 0)
    {
      if (index(parm, '/') != NULL) 
           return "/ not permitted in GridSiteAdminFile";
     
      ((mod_gridsite_dir_cfg *) cfg)->adminfile =
        apr_pstrdup(a->pool, parm);
    }
    else if (strcasecmp(a->cmd->name, "GridSiteAdminURI") == 0)
    {
      if (*parm != '/') return "GridSiteAdminURI must begin with /";
     
      ((mod_gridsite_dir_cfg *) cfg)->adminuri =
        apr_pstrdup(a->pool, parm);
    }
    else if (strcasecmp(a->cmd->name, "GridSiteHelpURI") == 0)
    {
      if (*parm != '/') return "GridSiteHelpURI must begin with /";

      ((mod_gridsite_dir_cfg *) cfg)->helpuri =
        apr_pstrdup(a->pool, parm);
    }
    else if (strcasecmp(a->cmd->name, "GridSiteDNlists") == 0)
    {
      ((mod_gridsite_dir_cfg *) cfg)->dnlists =
        apr_pstrdup(a->pool, parm);
    }
    else if (strcasecmp(a->cmd->name, "GridSiteDNlistsURI") == 0)
    {
      if (*parm != '/') return "GridSiteDNlistsURI must begin with /";

      if ((*parm != '\0') && (parm[strlen(parm) - 1] == '/'))
       ((mod_gridsite_dir_cfg *) cfg)->dnlistsuri =
        apr_pstrdup(a->pool, parm);
      else
       ((mod_gridsite_dir_cfg *) cfg)->dnlistsuri =
        apr_pstrcat(a->pool, parm, "/", NULL);
    }
    else if (strcasecmp(a->cmd->name, "GridSiteAdminList") == 0)
    {
      ((mod_gridsite_dir_cfg *) cfg)->adminlist =
        apr_pstrdup(a->pool, parm);
    }
    else if (strcasecmp(a->cmd->name, "GridSiteGSIProxyLimit") == 0)
    {
      n = -1;
    
      if ((sscanf(parm, "%d", &n) == 1) && (n >= 0))
                  ((mod_gridsite_dir_cfg *) cfg)->gsiproxylimit = n;
      else return "GridSiteGSIProxyLimit must be a number >= 0";     
    }
    else if (strcasecmp(a->cmd->name, "GridSiteUnzip") == 0)
    {
      if (*parm != '/') return "GridSiteUnzip must begin with /";
     
      ((mod_gridsite_dir_cfg *) cfg)->unzip =
        apr_pstrdup(a->pool, parm);
    }
    else if (strcasecmp(a->cmd->name, "GridSiteMethods") == 0)
    {
      ((mod_gridsite_dir_cfg *) cfg)->methods =
        apr_psprintf(a->pool, " %s ", parm);
       
      for (p = ((mod_gridsite_dir_cfg *) cfg)->methods;
           *p != '\0';
           ++p) if (*p == '\t') *p = ' ';
    }
    else if (strcasecmp(a->cmd->name, "GridSiteOCSP") == 0)
    {
      ocspmodes = apr_psprintf(a->pool, " %s ", parm);
       
      for (p = ocspmodes; *p != '\0'; ++p)
               if (*p == '\t') *p = ' ';
               else *p = tolower(*p);
    }
    else if (strcasecmp(a->cmd->name, "GridSiteEditable") == 0)
    {
      ((mod_gridsite_dir_cfg *) cfg)->editable =
        apr_psprintf(a->pool, " %s ", parm);
     
      for (p = ((mod_gridsite_dir_cfg *) cfg)->editable;
           *p != '\0';
           ++p) if (*p == '\t') *p = ' ';
    }
    else if (strcasecmp(a->cmd->name, "GridSiteHeadFile") == 0)
    {
      ((mod_gridsite_dir_cfg *) cfg)->headfile =
        apr_pstrdup(a->pool, parm);
    }
    else if (strcasecmp(a->cmd->name, "GridSiteFootFile") == 0)
    {
      ((mod_gridsite_dir_cfg *) cfg)->footfile =
        apr_pstrdup(a->pool, parm);
    }  
    else if (strcasecmp(a->cmd->name, "GridSiteIndexHeader") == 0)
    {
      if (index(parm, '/') != NULL) 
           return "/ not permitted in GridSiteIndexHeader";

      ((mod_gridsite_dir_cfg *) cfg)->indexheader =
        apr_pstrdup(a->pool, parm);
    }
    else if (strcasecmp(a->cmd->name, "GridSiteACLFormat") == 0)
    {
      if ((strcasecmp(parm,"GACL") != 0) &&
          (strcasecmp(parm,"XACML") != 0))
          return "GridsiteACLFormat must be either GACL or XACML";
      
      ((mod_gridsite_dir_cfg *) cfg)->aclformat = apr_pstrdup(a->pool, parm);
    }
    else if (strcasecmp(a->cmd->name, "GridSiteACLPath") == 0)
    {
      ((mod_gridsite_dir_cfg *) cfg)->aclpath = apr_pstrdup(a->pool, parm);
    }
    else if (strcasecmp(a->cmd->name, "GridSiteDelegationURI") == 0)
    {
      if (*parm != '/') return "GridSiteDelegationURI must begin with /";

      if (*parm != '\0')
       ((mod_gridsite_dir_cfg *) cfg)->delegationuri =
        apr_pstrdup(a->pool, parm);

    }
    else if (strcasecmp(a->cmd->name, "GridSiteExecMethod") == 0)
    {
      if (strcasecmp(parm, "nosetuid") == 0)
        {
          ((mod_gridsite_dir_cfg *) cfg)->execmethod = NULL;
          return NULL;
        }

      if ((strcasecmp(parm, "suexec")    != 0) &&
          (strcasecmp(parm, "X509DN")    != 0) &&
          (strcasecmp(parm, "directory") != 0))
          return "GridsiteExecMethod must be nosetuid, suexec, X509DN or directory";

      ((mod_gridsite_dir_cfg *) cfg)->execmethod = apr_pstrdup(a->pool, parm);
    }

    return NULL;
}

static const char *mod_gridsite_take2_cmds(cmd_parms *a, void *cfg,
                                       const char *parm1, const char *parm2)
{
    int   i;
    char *p, *q, buf[APRMAXHOSTLEN + 1] = "localhost";
    
    if (strcasecmp(a->cmd->name, "GridSiteUserGroup") == 0)
    {
      if (!(unixd_config.suexec_enabled))
          return "Using GridSiteUserGroup will "
                 "require rebuilding Apache with suexec support!";
    
      /* NB ap_uname2id/ap_gname2id are NOT thread safe - but OK
         as long as not used in .htaccess, just at server start time */

      ((mod_gridsite_dir_cfg *) cfg)->execugid.uid = ap_uname2id(parm1);
      ((mod_gridsite_dir_cfg *) cfg)->execugid.gid = ap_gname2id(parm2);
      ((mod_gridsite_dir_cfg *) cfg)->execugid.userdir = 0;
    }
    else if (strcasecmp(a->cmd->name, "GridSiteDiskMode") == 0)
    {
      if ((strcasecmp(parm1, "GroupNone" ) != 0) &&
          (strcasecmp(parm1, "GroupRead" ) != 0) &&
          (strcasecmp(parm1, "GroupWrite") != 0))
        return "First parameter of GridSiteDiskMode must be "
               "GroupNone, GroupRead or GroupWrite!";
          
      if ((strcasecmp(parm2, "WorldNone" ) != 0) &&
          (strcasecmp(parm2, "WorldRead" ) != 0))
        return "Second parameter of GridSiteDiskMode must be "
               "WorldNone or WorldRead!";
          
      ((mod_gridsite_dir_cfg *) cfg)->diskmode = 
       APR_UREAD | APR_UWRITE 
       | ( APR_GREAD               * (strcasecmp(parm1, "GroupRead") == 0))
       | ((APR_GREAD | APR_GWRITE) * (strcasecmp(parm1, "GroupWrite") == 0))
       | ((APR_GREAD | APR_WREAD)  * (strcasecmp(parm2, "WorldRead") == 0));
    }
    else if (strcasecmp(a->cmd->name, "GridSiteCastAlias") == 0)
    {
      if ((parm1[strlen(parm1)-1] != '/') || (parm2[strlen(parm2)-1] != '/'))
        return "GridSiteCastAlias URL and path must end with /";
    
      for (i=0; i < GRST_SITECAST_ALIASES; ++i) /* look for free slot */
         {
           if (sitecastaliases[i].sitecast_url == NULL)
             {
               sitecastaliases[i].scheme = apr_pstrdup(a->pool, parm1);

               if (((p = index(sitecastaliases[i].scheme, ':')) == NULL)
                   || (p[1] != '/') || (p[2] != '/'))
                 return "GridSiteCastAlias URL must begin with scheme (http/https/gsiftp/...) and ://";

               *p = '\0';
               ++p;
               while (*p == '/') ++p;
             
               if ((q = index(p, '/')) == NULL)
                return "GridSiteCastAlias URL must be of form scheme://domain:port/dirs";

               *q = '\0';

               p = index(p, ':');
               if (p == NULL)
                 {
                   return "GridSiteCastAlias URL must include the port number";
                 }

               if (sscanf(p, ":%d", &(sitecastaliases[i].port)) != 1)
                 return "Unable to parse numeric port number in GridSiteCastAlias";

               sitecastaliases[i].sitecast_url   = apr_pstrdup(a->pool, parm1);
               sitecastaliases[i].local_path     = apr_pstrdup(a->pool, parm2);
               
               if (a->server->server_hostname == NULL)
                 {
                   apr_gethostname(buf, APRMAXHOSTLEN + 1, a->pool);
                   sitecastaliases[i].local_hostname = apr_pstrdup(a->pool, buf);
                 }
               else sitecastaliases[i].local_hostname = apr_pstrdup(a->pool, 
                                                   a->server->server_hostname);

               break;
             }
         }
    }
    
    return NULL;
}

static const char *mod_gridsite_flag_cmds(cmd_parms *a, void *cfg,
                                      int flag)
{
    if      (strcasecmp(a->cmd->name, "GridSiteAuth") == 0)
    {
      ((mod_gridsite_dir_cfg *) cfg)->auth = flag;
    }
    else if (strcasecmp(a->cmd->name, "GridSiteEnvs") == 0)
    {
      ((mod_gridsite_dir_cfg *) cfg)->envs = flag;
    }
    else if (strcasecmp(a->cmd->name, "GridSiteHtmlFormat") == 0)
    {
      ((mod_gridsite_dir_cfg *) cfg)->format = flag;
    }
    else if (strcasecmp(a->cmd->name, "GridSiteIndexes") == 0)
    {
      ((mod_gridsite_dir_cfg *) cfg)->indexes = flag;
    }
    else if (strcasecmp(a->cmd->name, "GridSiteLink") == 0)
    {
      ((mod_gridsite_dir_cfg *) cfg)->gridsitelink = flag;
    }
    else if (strcasecmp(a->cmd->name, "GridSiteGridHTTP") == 0)
    {
// TODO: return error if try this on non-HTTPS virtual server

      ((mod_gridsite_dir_cfg *) cfg)->gridhttp = flag;
    }

    return NULL;
}

static const command_rec mod_gridsite_cmds[] =
{
// TODO: need to check and document valid contexts for each command!

    AP_INIT_FLAG("GridSiteAuth", mod_gridsite_flag_cmds, 
                 NULL, OR_FILEINFO, "on or off"),
    AP_INIT_FLAG("GridSiteEnvs", mod_gridsite_flag_cmds, 
                 NULL, OR_FILEINFO, "on or off"),
    AP_INIT_FLAG("GridSiteHtmlFormat", mod_gridsite_flag_cmds, 
                 NULL, OR_FILEINFO, "on or off"),
    AP_INIT_FLAG("GridSiteIndexes", mod_gridsite_flag_cmds, 
                 NULL, OR_FILEINFO, "on or off"),
    AP_INIT_FLAG("GridSiteLink", mod_gridsite_flag_cmds, 
                 NULL, OR_FILEINFO, "on or off"),
                 
    AP_INIT_TAKE1("GridSiteAdminFile", mod_gridsite_take1_cmds,
                   NULL, OR_FILEINFO, "Ghost per-directory admin CGI"),
    AP_INIT_TAKE1("GridSiteAdminURI", mod_gridsite_take1_cmds,
                   NULL, OR_FILEINFO, "URI of real gridsite-admin.cgi"),
    AP_INIT_TAKE1("GridSiteHelpURI", mod_gridsite_take1_cmds,
                   NULL, OR_FILEINFO, "URI of Website Help pages"),
    AP_INIT_TAKE1("GridSiteDNlists", mod_gridsite_take1_cmds,
                   NULL, OR_FILEINFO, "DN Lists directories search path"),
    AP_INIT_TAKE1("GridSiteDNlistsURI", mod_gridsite_take1_cmds,
                   NULL, OR_FILEINFO, "URI of published DN lists"),
    AP_INIT_TAKE1("GridSiteAdminList", mod_gridsite_take1_cmds,
                   NULL, OR_FILEINFO, "URI of admin DN List"),
    AP_INIT_TAKE1("GridSiteGSIProxyLimit", mod_gridsite_take1_cmds,
                   NULL, OR_FILEINFO, "Max level of GSI proxy validity"),
    AP_INIT_TAKE1("GridSiteUnzip", mod_gridsite_take1_cmds,
                   NULL, OR_FILEINFO, "Absolute path to unzip command"),

    AP_INIT_RAW_ARGS("GridSiteMethods", mod_gridsite_take1_cmds,
                   NULL, OR_FILEINFO, "permitted HTTP methods"),
    AP_INIT_RAW_ARGS("GridSiteOCSP", mod_gridsite_take1_cmds,
                 NULL, RSRC_CONF, "Set OCSP lookups"),
    AP_INIT_RAW_ARGS("GridSiteEditable", mod_gridsite_take1_cmds,
                   NULL, OR_FILEINFO, "editable file extensions"),
    AP_INIT_TAKE1("GridSiteHeadFile", mod_gridsite_take1_cmds,
                   NULL, OR_FILEINFO, "filename of HTML header"),
    AP_INIT_TAKE1("GridSiteFootFile", mod_gridsite_take1_cmds,
                   NULL, OR_FILEINFO, "filename of HTML footer"),
    AP_INIT_TAKE1("GridSiteIndexHeader", mod_gridsite_take1_cmds,
                   NULL, OR_FILEINFO, "filename of directory header"),
    
    AP_INIT_FLAG("GridSiteGridHTTP", mod_gridsite_flag_cmds,
                 NULL, OR_FILEINFO, "on or off"),
    AP_INIT_TAKE1("GridSiteGridHTTPport", mod_gridsite_take1_cmds,
                   NULL, RSRC_CONF, "GridHTTP port"),
    AP_INIT_TAKE1("GridSiteSessionsDir", mod_gridsite_take1_cmds,
                 NULL, RSRC_CONF, "directory with GridHTTP passcodes and SSL session creds"),
/* GridSiteOnetimesDir is deprecated in favour of GridSiteSessionsDir */
    AP_INIT_TAKE1("GridSiteOnetimesDir", mod_gridsite_take1_cmds,
                 NULL, RSRC_CONF, "directory with GridHTTP passcodes"),

    AP_INIT_TAKE1("GridSiteCastDNlists", mod_gridsite_take1_cmds,
                 NULL, RSRC_CONF, "DN Lists directories search path for SiteCast"),
    AP_INIT_TAKE1("GridSiteCastUniPort", mod_gridsite_take1_cmds,
                 NULL, RSRC_CONF, "UDP port for unicast/replies"),
    AP_INIT_TAKE1("GridSiteCastGroup", mod_gridsite_take1_cmds,
                 NULL, RSRC_CONF, "multicast group[:port] to listen for HTCP on"),
    AP_INIT_TAKE2("GridSiteCastAlias", mod_gridsite_take2_cmds,
                 NULL, RSRC_CONF, "URL and local path mapping"),

    AP_INIT_TAKE1("GridSiteACLFormat", mod_gridsite_take1_cmds,
                 NULL, OR_FILEINFO, "format to save access control lists in"),
    AP_INIT_TAKE1("GridSiteACLPath", mod_gridsite_take1_cmds,
                 NULL, OR_FILEINFO, "explicit location of access control file"),

    AP_INIT_TAKE1("GridSiteDelegationURI", mod_gridsite_take1_cmds,
                 NULL, OR_FILEINFO, "URI of the delegation service CGI"),

    AP_INIT_TAKE1("GridSiteExecMethod", mod_gridsite_take1_cmds,
                 NULL, OR_FILEINFO, "execution strategy used by gsexec"),
                 
    AP_INIT_TAKE2("GridSiteUserGroup", mod_gridsite_take2_cmds, 
                  NULL, OR_FILEINFO,
                  "user and group of gsexec processes in suexec mode"),
          
    AP_INIT_TAKE2("GridSiteDiskMode", mod_gridsite_take2_cmds, 
                  NULL, OR_FILEINFO,
                  "group and world file modes for new files/directories"),
          
    {NULL}
};

/*  Blank unset these HTTP headers, to prevent injection attacks.
    This is run before mod_shib's check_user_id hook, which may
    legitimately create such headers.                           */

static int mod_gridsite_check_user_id(request_rec *r)
{
    apr_table_unset(r->headers_in, "User-Distinguished-Name");
#if 0
    apr_table_unset(r->headers_in, "User-Distinguished-Name-2");
#endif
    apr_table_unset(r->headers_in, "Nist-LoA");
    apr_table_unset(r->headers_in, "LoA");
    apr_table_unset(r->headers_in, "VOMS-Attribute");

    return DECLINED; /* ie carry on processing request */
}

static int mod_gridsite_first_fixups(request_rec *r)
{
    mod_gridsite_dir_cfg *conf;

    if (r->finfo.filetype != APR_DIR) return DECLINED;

    conf = (mod_gridsite_dir_cfg *)
                    ap_get_module_config(r->per_dir_config, &gridsite_module);

    /* we handle DN Lists as regular files, even if they also match
       directory names  */

    if ((conf != NULL) &&
        (conf->dnlistsuri != NULL) &&
        (strncmp(r->uri, conf->dnlistsuri, strlen(conf->dnlistsuri)) == 0) &&
        (strcmp(r->uri, conf->dnlistsuri) != 0))
      {
        r->finfo.filetype = APR_REG; 
      }

    return DECLINED;
}  


int GRST_get_session_id(SSL *ssl, char *session_id, size_t len)
{
   int          i;
   SSL_SESSION *session;

   if (((session = SSL_get_session(ssl)) == NULL) ||
       (session->session_id_length == 0)) return GRST_RET_FAILED;
   
   if (2 * session->session_id_length + 1 > len) return GRST_RET_FAILED;

   for (i=0; i < (int) session->session_id_length; ++i)
    sprintf(&(session_id[i*2]), "%02X", (unsigned char) session->session_id[i]);

   session_id[i*2] = '\0';
   
   return GRST_RET_OK;
}

int GRST_load_ssl_creds(SSL *ssl, conn_rec *conn)
{
   char session_id[(SSL_MAX_SSL_SESSION_ID_LENGTH+1)*2], *sessionfile = NULL,
        line[512], *p;
   apr_file_t  *fp = NULL;
   int i;
      
   if (GRST_get_session_id(ssl, session_id, sizeof(session_id)) != GRST_RET_OK)
     return GRST_RET_FAILED;
   
   sessionfile = apr_psprintf(conn->pool, "%s/sslcreds-%s",
                         ap_server_root_relative(conn->pool, sessionsdir),
                         session_id);

   if (apr_file_open(&fp, sessionfile, APR_READ, 0, conn->pool) != APR_SUCCESS)
       return GRST_RET_FAILED;
   
   while (apr_file_gets(line, sizeof(line), fp) == APR_SUCCESS)
        {
          if (sscanf(line, "GRST_CRED_AURI_%d=", &i) == 1)
            {
              if ((p = index(line, '\n')) != NULL) *p = '\0';              
              p = index(line, '=');

              apr_table_setn(conn->notes,
                         apr_psprintf(conn->pool, "GRST_CRED_AURI_%d", i),
                         apr_pstrdup(conn->pool, &p[1]));
            }
          else if (sscanf(line, "GRST_CRED_VALID_%d=", &i) == 1)
            {
              if ((p = index(line, '\n')) != NULL) *p = '\0';              
              p = index(line, '=');

              apr_table_setn(conn->notes,
                         apr_psprintf(conn->pool, "GRST_CRED_VALID_%d", i),
                         apr_pstrdup(conn->pool, &p[1]));
            }
          else if (sscanf(line, "GRST_OCSP_URL_%d=", &i) == 1)
            {
              if ((p = index(line, '\n')) != NULL) *p = '\0';              
              p = index(line, '=');

              apr_table_setn(conn->notes,
                         apr_psprintf(conn->pool, "GRST_OCSP_URL_%d", i),
                         apr_pstrdup(conn->pool, &p[1]));
            }
        }
        
   apr_file_close(fp);

   /* connection notes created by GRST_save_ssl_creds() are now reloaded */
   apr_table_set(conn->notes, "GRST_save_ssl_creds", "yes");

   return GRST_RET_OK;
}

/*
    Save result of AURIs and validity info from chain into connection notes,
    and write out in an SSL session creds file.
*/

void GRST_save_ssl_creds(conn_rec *conn, GRSTx509Chain *grst_chain)
{
   int          i, lastcred, lowest_voms_delegation = 65535;
   char         envname[14], *tempfile = NULL,
               *sessionfile, session_id[(SSL_MAX_SSL_SESSION_ID_LENGTH+1)*2];
   apr_file_t  *fp = NULL;
   SSL         *ssl;
   SSLConnRec  *sslconn;
   GRSTx509Cert  *grst_cert = NULL;

   /* check if already done */

   if ((grst_chain != NULL) && (conn->notes != NULL) &&
       (apr_table_get(conn->notes, "GRST_save_ssl_creds") != NULL)) return;

   /* we at least need to say we've been run */

   apr_table_set(conn->notes, "GRST_save_ssl_creds", "yes");
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, conn->base_server,
                                            "set GRST_save_ssl_creds");

   sslconn = (SSLConnRec *)ap_get_module_config(conn->conn_config,&ssl_module);

   if ((sslconn != NULL) && 
       ((ssl = sslconn->ssl) != NULL) &&
       (GRST_get_session_id(ssl,session_id,sizeof(session_id)) == GRST_RET_OK))
     {
       sessionfile = apr_psprintf(conn->pool, "%s/sslcreds-%s",
                         ap_server_root_relative(conn->pool, sessionsdir),
                         session_id);

       tempfile = apr_pstrcat(conn->pool, 
                          ap_server_root_relative(conn->pool, sessionsdir), 
                          "/tmp-XXXXXX", NULL);
   
       if ((tempfile != NULL) && (tempfile[0] != '\0'))
               apr_file_mktemp(&fp, tempfile, 
                               APR_CREATE | APR_WRITE | APR_EXCL, conn->pool);
     }

   i=0;
   
   for (grst_cert = grst_chain->firstcert;
        grst_cert != NULL; grst_cert = grst_cert->next)
      {
        if (grst_cert->type == GRST_CERT_TYPE_VOMS)
          {
            /* want to record the delegation level 
               of the last proxy with VOMS attributes */
          
            lowest_voms_delegation = grst_cert->delegation;
          }
        else if ((grst_cert->type == GRST_CERT_TYPE_EEC) ||
                 (grst_cert->type == GRST_CERT_TYPE_PROXY))
          {
            apr_table_setn(conn->notes,
                   apr_psprintf(conn->pool, "GRST_CRED_AURI_%d", i),
                   apr_pstrcat(conn->pool, "dn:", grst_cert->dn, NULL));

            if (fp != NULL) apr_file_printf(fp, "GRST_CRED_AURI_%d=dn:%s\n",
                                                i, grst_cert->dn);

            apr_table_setn(conn->notes,
                   apr_psprintf(conn->pool, "GRST_CRED_VALID_%d", i),
                   apr_psprintf(conn->pool, 
                      "notbefore=%ld notafter=%ld delegation=%d nist-loa=%d", 
                      grst_cert->notbefore,
                      grst_cert->notafter,
                      grst_cert->delegation, 0));

            if (fp != NULL) apr_file_printf(fp, 
  "GRST_CRED_VALID_%d=notbefore=%ld notafter=%ld delegation=%d nist-loa=%d\n",
                                            i, grst_cert->notbefore,
                                               grst_cert->notafter, 
                                               grst_cert->delegation, 0);

            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, conn->base_server,
                      "store GRST_CRED_AURI_%d=dn:%s", i, grst_cert->dn);

            ++i;
          }
      }

   for (grst_cert = grst_chain->firstcert; 
        grst_cert != NULL; grst_cert = grst_cert->next)
      {
        if ((grst_cert->type == GRST_CERT_TYPE_VOMS) &&
            (grst_cert->delegation == lowest_voms_delegation))
          {
            /* only export attributes from the last proxy to contain them */
          
            apr_table_setn(conn->notes,
                   apr_psprintf(conn->pool, "GRST_CRED_AURI_%d", i),
                   apr_pstrcat(conn->pool, "fqan:", grst_cert->value, NULL));

            if (fp != NULL) apr_file_printf(fp, "GRST_CRED_AURI_%d=fqan:%s\n",
                                                i, grst_cert->value);

            apr_table_setn(conn->notes,
                   apr_psprintf(conn->pool, "GRST_CRED_VALID_%d", i),
                   apr_psprintf(conn->pool, 
                      "notbefore=%ld notafter=%ld delegation=%d nist-loa=%d", 
                      grst_cert->notbefore,
                      grst_cert->notafter, 
                      grst_cert->delegation, 0));

            if (fp != NULL) apr_file_printf(fp, 
  "GRST_CRED_VALID_%d=notbefore=%ld notafter=%ld delegation=%d nist-loa=%d\n",
                                            i, grst_cert->notbefore,
                                               grst_cert->notafter,
                                               grst_cert->delegation, 0);

            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, conn->base_server,
                      "store GRST_CRED_AURI_%d=fqan:%s", i, grst_cert->value);

            ++i;
          }
      }

   /* this needs to be merged into grst_x509? */
#if 0
   if (ocspmodes != NULL)
   {
     int   j;
     const char *ex_sn;
     char s[80];
     X509 *cert;     
     X509_EXTENSION *ex;
     
     for (j=sk_X509_num(certstack)-1; j >= 0; --j)
        {
          cert = sk_X509_value(certstack, j);
          
          for (i=0; i < X509_get_ext_count(cert); ++i)
             {
               ex = X509_get_ext(cert, i);

               OBJ_obj2txt(s, sizeof(s), X509_EXTENSION_get_object(ex), 0);

               if (strcmp(s, "authorityInfoAccess") == 0) /* OCSP */
                 {
                   apr_table_setn(conn->notes, "GRST_OCSP_URL",
                                  (const char *) X509_EXTENSION_get_data(ex));

                   /* strategy is to remove what has been checked, 
                      for this connnection */
                   apr_table_set(conn->notes, "GRST_OCSP_UNCHECKED",
                                 ocspmodes);

                   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, conn->base_server,
                "store GRST_OCSP_URL_%d=%s", i, X509_EXTENSION_get_data(ex));

                   if (fp != NULL) apr_file_printf(fp, "GRST_OCSP_URL_%d=%s\n",
                                             i, X509_EXTENSION_get_data(ex));
                 }
             }
        }   
   }
#endif
   /* end of bit that needs to go into grst_x509 */
     
   if (fp != NULL)
     {
       apr_file_close(fp);
       apr_file_rename(tempfile, sessionfile, conn->pool);
     }
}

static char *get_aclpath_component(request_rec *r, int n)
/*
    Get the nth component of REQUEST_URI, or component 0
    which is the server name.

*/
{
    int ii, i, nn;

    if (n == 0) return r->server->server_hostname;

    if (r->uri == NULL) return NULL; /* some kind of internal error? */

    i  = 1; /* start of first component */
    nn = 1;
    
    for (ii=1; r->uri[ii] != '\0'; ++ii) /* look for this component */
       {
         if (r->uri[ii] == '/') /* end of a component */
           {
             if (nn == n) break;
             
             ++nn;
             i = ii + 1;
           }
         else if ((r->uri[ii] == '.') && (r->uri[ii+1] == '.'))
           {
             return NULL; /* can this happen? dont allow anyway */
           }         
       }
       
    if (nn != n) return NULL; /* no component for this number */
    
    return apr_psprintf(r->pool, "%.*s", ii - i, &(r->uri[i]));
}

static char *make_aclpath(request_rec *r, char *format)
{
    int i, n;
    char *formatted, *p;
    
    formatted = apr_pstrdup(r->pool, format);

    while (1)
         {
           for (i=0; (formatted[i] != '\0') && (formatted[i] != '%'); ++i) ;
    
           if (formatted[i] == '\0') break;
           
           if ((formatted[i] == '%') && (formatted[i+1] == '%')) 
             {
               ++i;
               continue;
             }
            
           if (sscanf(&formatted[i+1], "%d", &n) != 1)
             {
               return NULL; /* not %% or %0,%1,... */
             }
           
           formatted[i] = '\0';
           
           for (i++; isdigit(formatted[i]); ++i) ;
           
           if ((p = get_aclpath_component(r, n)) == NULL) return NULL;
           
           formatted = apr_pstrcat(r->pool, formatted, p, &formatted[i],NULL);                                   
           i += strlen(p);
         }
            
    return ap_server_root_relative(r->pool, formatted);
}

static int mod_gridsite_perm_handler(request_rec *r)
/*
    Do authentication/authorization here rather than in the normal module
    auth functions since the results of mod_ssl are available.

    We also publish environment variables here if requested by GridSiteEnv.
*/
{
    int          retcode = DECLINED, i, n, file_is_acl = 0, cc_delegation,
                 destination_is_acl = 0, ishttps = 0, nist_loa, delegation;
    char        *dn, *p, envname1[30], envname2[30], 
                *grst_cred_auri_0 = NULL, *dir_path, 
                *remotehost, s[99], *grst_cred_auri_i, *cookies, *file, *https,
                *gridauthpasscode = NULL, *cookiefile, oneline[1025], *key_i,
                *destination = NULL, *destination_uri = NULL, *querytmp, 
                *destination_prefix = NULL, *destination_translated = NULL,
                *aclpath = NULL, *grst_cred_valid_0 = NULL, *grst_cred_valid_i;
    char        *vomsAttribute = NULL, *loa;
    const char  *content_type;
    time_t       now, notbefore, notafter;
    apr_table_t *env;
    apr_finfo_t  cookiefile_info;
    apr_file_t  *fp;
    request_rec *destreq;
    GRSTgaclCred    *cred = NULL, *cred_0 = NULL;
    GRSTgaclUser    *user = NULL;
    GRSTgaclPerm     perm = GRST_PERM_NONE, destination_perm = GRST_PERM_NONE;
    GRSTgaclAcl     *acl = NULL;
    mod_gridsite_dir_cfg *cfg;
    SSLConnRec      *sslconn;
    STACK_OF(X509)  *certstack;
    X509	    *peercert;

    cfg = (mod_gridsite_dir_cfg *)
                    ap_get_module_config(r->per_dir_config, &gridsite_module);

    if (cfg == NULL) return DECLINED;

    if ((cfg->auth == 0) &&
        (cfg->envs == 0))
               return DECLINED; /* if not turned on, look invisible */

    env = r->subprocess_env;
    
    /* Get the user's attributes from Shibboleth and set up user credential
       based on the attributes if authentication has been carried out using
       a Shibboleth Identity Provider.*/

    /* Get DN from a Shibboleth attribute */

    dn = (char *) apr_table_get(r->headers_in, "User-Distinguished-Name");
#if 0
    if ((dn == NULL) || (*dn == '\0'))
     dn = (char *) apr_table_get(r->headers_in, "User-Distinguished-Name-2");
#endif

    if ((dn != NULL) && (*dn == '\0')) dn = NULL;
    
    if (dn != NULL) ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "DN: %s", dn);

    /* Get the NIST LoA attribute */
    loa = (char *) apr_table_get(r->headers_in, "nist-loa");

    if ((loa == NULL) || (*loa == '\0'))
     loa = (char *) apr_table_get(r->headers_in, "loa");
    
    if ((loa != NULL) && (*loa == '\0')) loa = NULL;

    if (loa != NULL) ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "nist-loa: %s", loa);

    /* Set up user credential based on the DN and LoA attributes */
                                  
    if (dn != NULL)
      {
        cred = GRSTgaclCredCreate("dn:", dn);

        if (loa != NULL) GRSTgaclCredSetNistLoa(cred, atoi(loa));
        else GRSTgaclCredSetNistLoa(cred, 2);

        user = GRSTgaclUserNew(cred);
      }
            
    /* Set up user credential based on VOMS Attribute from Shibboleth? */

    vomsAttribute = (char *) apr_table_get(r->headers_in, "VOMS-Attribute");
    if (vomsAttribute != NULL)
      {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, 
                 "VOMS-Attribute: %s", vomsAttribute);

        cred = GRSTgaclCredCreate("fqan:", vomsAttribute);
        if (user == NULL) user = GRSTgaclUserNew(cred);
        else GRSTgaclUserAddCred(user, cred);
      }

    p = (char *) apr_table_get(r->subprocess_env, "HTTPS");
    if ((p != NULL) && (strcmp(p, "on") == 0)) ishttps = 1;

    /* reload per-connection (SSL) cred variables? */

    sslconn = (SSLConnRec *) ap_get_module_config(r->connection->conn_config, 
                                                  &ssl_module);
    if ((user == NULL) &&
        (sslconn != NULL) && 
        (sslconn->ssl != NULL) &&
        (sslconn->ssl->session != NULL) &&
        (r->connection->notes != NULL) &&
        (apr_table_get(r->connection->notes, "GRST_save_ssl_creds") == NULL))
      {
        if (GRST_load_ssl_creds(sslconn->ssl, r->connection) == GRST_RET_OK)
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "Restored SSL session data from session cache file");
      }

    delegation = ((mod_gridsite_dir_cfg *) cfg)->gsiproxylimit + 1;
    
    if ((user == NULL) && 
        (r->connection->notes != NULL) &&
        ((grst_cred_auri_0 = (char *) 
         apr_table_get(r->connection->notes, "GRST_CRED_AURI_0")) != NULL) &&
        (strncmp(grst_cred_auri_0, "dn:", 3) == 0) &&
        ((grst_cred_valid_0 = (char *) 
         apr_table_get(r->connection->notes, "GRST_CRED_VALID_0")) != NULL) &&
        (sscanf(grst_cred_valid_0, 
                "notbefore=%ld notafter=%ld delegation=%d nist-loa=%d", 
                &notbefore, &notafter, &delegation, &nist_loa) == 4) &&
        (delegation <= ((mod_gridsite_dir_cfg *) cfg)->gsiproxylimit))
      {
        cred_0 = GRSTgaclCredCreate(grst_cred_auri_0, NULL);
        if (cred_0 != NULL)
          {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "Using identity %s from SSL/TLS", grst_cred_auri_0);

            GRSTgaclCredSetNotBefore( cred_0, notbefore);
            GRSTgaclCredSetNotAfter(  cred_0, notafter);
            GRSTgaclCredSetDelegation(cred_0, delegation);

            if (delegation == 0) GRSTgaclCredSetNistLoa(cred_0, 3);
            else                 GRSTgaclCredSetNistLoa(cred_0, 2);

            user = GRSTgaclUserNew(cred_0);

            /* check for VOMS etc in GRST_CRED_AURI_i too */
  
            for (i=1; ; ++i)
               {
                 snprintf(envname1, sizeof(envname1), "GRST_CRED_AURI_%d", i);
                 snprintf(envname2, sizeof(envname2), "GRST_CRED_VALID_%d", i);

                 if ((grst_cred_auri_i = (char *) 
                         apr_table_get(r->connection->notes,envname1)) &&
                     (grst_cred_valid_i = (char *) 
                         apr_table_get(r->connection->notes,envname2)))
                   { 
                     cred = GRSTgaclCredCreate(grst_cred_auri_i, NULL);
                     if (cred != NULL) 
                       {
                         notbefore  = 0;
                         notafter   = 0;
                         delegation = 0;
                         nist_loa   = 0;
                       
                         sscanf(grst_cred_valid_i, 
                       "notbefore=%ld notafter=%ld delegation=%d nist-loa=%d", 
                                &notbefore, &notafter, &delegation, &nist_loa);
                        
                         GRSTgaclCredSetNotBefore( cred, notbefore);
                         GRSTgaclCredSetNotAfter(  cred, notafter);
                         GRSTgaclCredSetDelegation(cred, delegation);
                         GRSTgaclCredSetDelegation(cred, nist_loa);

                         GRSTgaclUserAddCred(user, cred);
                       }
                   }
                 else break; /* GRST_CRED_AURI_i are numbered consecutively */
               }
          }
      }

    if ((user != NULL) && ((mod_gridsite_dir_cfg *) cfg)->dnlists)
          GRSTgaclUserLoadDNlists(user, ((mod_gridsite_dir_cfg *) cfg)->dnlists);

    /* add DNS credential */
    
    remotehost = (char *) ap_get_remote_host(r->connection,
                                  r->per_dir_config, REMOTE_DOUBLE_REV, NULL);
    if ((remotehost != NULL) && (*remotehost != '\0'))
      {
        cred = GRSTgaclCredCreate("dns:", remotehost);
        GRSTgaclCredSetNotAfter(cred, GRST_MAX_TIME_T);

        if (user == NULL) user = GRSTgaclUserNew(cred);
        else              GRSTgaclUserAddCred(user, cred);
      }

    /* add IP credential */
    
    remotehost = (char *) ap_get_remote_host(r->connection,
                                  r->per_dir_config, REMOTE_DOUBLE_REV, NULL);
    if ((remotehost != NULL) && (*remotehost != '\0'))
      {
        cred = GRSTgaclCredCreate("ip:", r->connection->remote_ip);
        GRSTgaclCredSetNotAfter(cred, GRST_MAX_TIME_T);

        if (user == NULL) user = GRSTgaclUserNew(cred);
        else              GRSTgaclUserAddCred(user, cred);
      }

    /* write contents of user to per-request environment variables */

    if (((mod_gridsite_dir_cfg *) cfg)->envs && (user != NULL))
      {    
        cred = user->firstcred;
        
        /* old-style Compact Credentials have the same delegation level
           for all credentials. eg Using EEC delegation=0; using 1st GSI
           Proxy then delegation=1 for X509USER _and_ GSIPROXY credentials. 
           So we remember the delegation level of any X509USER here */
        if (cred != NULL) cc_delegation = cred->delegation;
      
        for (i=0; (cred != NULL) && (cred->auri != NULL); ++i)
             {                                    
               if (strncmp(cred->auri, "dn:", 3) == 0)
                 {
                   apr_table_setn(env, 
                                  apr_psprintf(r->pool, "GRST_CRED_%d", i),
                                  apr_psprintf(r->pool, 
                                               "%s %ld %ld %d %s",
                                               (i==0) ? "X509USER" : "GSIPROXY",
                                               cred->notbefore,
                                               cred->notafter,
                                               cc_delegation, 
                                               &(cred->auri[3])));
                 }
               else if (strncmp(cred->auri, "fqan:", 5) == 0)
                 {
                   apr_table_setn(env, 
                                  apr_psprintf(r->pool, "GRST_CRED_%d", i),
                                  apr_psprintf(r->pool, 
                                                  "VOMS %ld %ld 0 %s",
                                                  notbefore, notafter, 
                                                  &(cred->auri[5])));
                 }

               apr_table_setn(env,
                              apr_psprintf(r->pool, "GRST_CRED_AURI_%d", i),
                              apr_pstrdup(r->pool, cred->auri));

               apr_table_setn(env, 
                              apr_psprintf(r->pool, "GRST_CRED_VALID_%d", i),
                              apr_psprintf(r->pool,
                       "notbefore=%ld notafter=%ld delegation=%d nist-loa=%d",
                                           cred->notbefore,
                                           cred->notafter,
                                           cred->delegation,
                                           cred->nist_loa));
                 
               cred = cred->next;
             }    
      }

    /* check for Destination: header and evaluate if present */

    if ((destination = (char *) apr_table_get(r->headers_in,
                                              "Destination")) != NULL)
      {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "Destination header found, value=%s", destination);

        destination_prefix = apr_psprintf(r->pool, "https://%s:%d/", 
                         r->server->server_hostname, (int) r->server->port);

        if (strncmp(destination_prefix, destination,
                    strlen(destination_prefix)) == 0) 
           destination_uri = &destination[strlen(destination_prefix)-1];
        else if ((int) r->server->port == 443)
          {
            destination_prefix = apr_psprintf(r->pool, "https://%s/", 
                                              r->server->server_hostname);

            if (strncmp(destination_prefix, destination,
                                strlen(destination_prefix)) == 0)
              destination_uri = &destination[strlen(destination_prefix)-1];
          }
          
        if (destination_uri != NULL)
          {
            destreq = ap_sub_req_method_uri("GET", destination_uri, r, NULL);

            if ((destreq != NULL) && (destreq->filename != NULL) 
                                  && (destreq->path_info != NULL))
              {
                destination_translated = apr_pstrcat(r->pool, 
                               destreq->filename, destreq->path_info, NULL);

                apr_table_setn(r->notes, "GRST_DESTINATION_TRANSLATED", 
                               destination_translated);
                             
                if (((mod_gridsite_dir_cfg *) cfg)->envs)
                        apr_table_setn(env, "GRST_DESTINATION_TRANSLATED", 
                                                  destination_translated);
                                                  
                 p = rindex(destination_translated, '/');
                 if ((p != NULL) && (strcmp(&p[1], GRST_ACL_FILE) == 0))
                                                    destination_is_acl = 1;
              }
          }
      }
    
    if ((((mod_gridsite_dir_cfg *) cfg)->adminlist != NULL) && (user != NULL))
      {    
        cred = user->firstcred;
      
        while ((cred != NULL) && (cred->auri != NULL))
             {
               if (strcmp(((mod_gridsite_dir_cfg *) cfg)->adminlist,
                          cred->auri) == 0)
                 {
                   perm = GRST_PERM_ALL;
                   if (destination_translated != NULL) 
                          destination_perm = GRST_PERM_ALL;
                   break;
                 }
                 
               cred = cred->next;
             }    
      }
    
    if (perm != GRST_PERM_ALL) /* cannot improve on perfection... */
      {
        if (((mod_gridsite_dir_cfg *) cfg)->aclpath != NULL)
          {
            aclpath = make_aclpath(r,((mod_gridsite_dir_cfg *) cfg)->aclpath);
          
            if (aclpath != NULL) 
              {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                        "Examine ACL file %s (from ACL path %s)",
                        aclpath, ((mod_gridsite_dir_cfg *) cfg)->aclpath);

                acl = GRSTgaclAclLoadFile(aclpath);
              }
            else ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                        "Failed to make ACL file from ACL path %s, URI %s)",
                        ((mod_gridsite_dir_cfg *) cfg)->aclpath, r->uri);
          }
        else acl = GRSTgaclAclLoadforFile(r->filename);

        if (acl != NULL) perm = GRSTgaclAclTestUser(acl, user);
        GRSTgaclAclFree(acl);
        
        if (destination_translated != NULL)
          {
            acl = GRSTgaclAclLoadforFile(destination_translated);
            if (acl != NULL) destination_perm = GRSTgaclAclTestUser(acl, user);
            GRSTgaclAclFree(acl);

            apr_table_setn(r->notes, "GRST_DESTINATION_PERM",
                              apr_psprintf(r->pool, "%d", destination_perm));
          
            if (((mod_gridsite_dir_cfg *) cfg)->envs)
              apr_table_setn(env, "GRST_DESTINATION_PERM",
                              apr_psprintf(r->pool, "%d", destination_perm));
          }
      }
      
    /* first look for GRIDHTTP_PASSCODE cookie */
      
    if ((p = (char *) apr_table_get(r->headers_in, "Cookie")) != NULL)
      {
        cookies = apr_pstrcat(r->pool, " ", p, NULL);
        gridauthpasscode = strstr(cookies, " GRIDHTTP_PASSCODE=");
                
        if (gridauthpasscode != NULL)
          {
            gridauthpasscode = &gridauthpasscode[19];
          
            for (p = gridauthpasscode; 
                 (*p != '\0') && (*p != ';'); ++p)
                                      if (!isalnum(*p)) *p = '\0';
          }
      }

    /* then look for GRIDHTTP_PASSCODE in QUERY_STRING ie after ? */
      
    if (gridauthpasscode == NULL)
      {
        if ((r->parsed_uri.query != NULL) && (r->parsed_uri.query[0] != '\0'))
          {
            querytmp = apr_pstrcat(r->pool,"&",r->parsed_uri.query,"&",NULL);
            
            gridauthpasscode = strstr(querytmp, "&GRIDHTTP_PASSCODE=");
            
            if (gridauthpasscode != NULL)                         
              {
                gridauthpasscode = &gridauthpasscode[19];
              
                for (p = gridauthpasscode; 
                     (*p != '\0') && (*p != '&'); ++p)
                                          if (!isalnum(*p)) *p = '\0';
              }            
          }
      }

    if ((gridauthpasscode != NULL) && (gridauthpasscode[0] != '\0')) 
      {
        cookiefile = apr_psprintf(r->pool, "%s/passcode-%s",
                 ap_server_root_relative(r->pool,
                 sessionsdir),
                 gridauthpasscode);
                                      
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                             "Opening GridHTTP passcode file %s", cookiefile);
              
        if ((apr_stat(&cookiefile_info, cookiefile, 
                          APR_FINFO_TYPE, r->pool) == APR_SUCCESS) &&
            (cookiefile_info.filetype == APR_REG) &&
            (apr_file_open(&fp, cookiefile, APR_READ, 0, r->pool)
                                                         == APR_SUCCESS))
              {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                             "Reading GridHTTP passcode file %s", cookiefile);
              
                while (apr_file_gets(oneline, 
                                     sizeof(oneline), fp) == APR_SUCCESS)
                     {
                       p = index(oneline, '\n');
                       if (p != NULL) *p = '\0';
                       
                       ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                                    "%s: %s", cookiefile, oneline);

                       if ((strncmp(oneline, "expires=", 8) == 0) &&
                           (apr_time_from_sec(atoll(&oneline[8])) < 
                                                       apr_time_now()))
                                  break;                
                       else if ((strncmp(oneline, "domain=", 7) == 0) &&
                                (strcmp(&oneline[7], r->hostname) != 0))
                                  break; /* exact needed in the version */
                       else if ((strncmp(oneline, "path=", 5) == 0) &&
                                (strcmp(&oneline[5], r->uri) != 0))
                                  break;
                       else if  ((strncmp(oneline, "onetime=yes", 11) == 0)
                                 && !ishttps)
                                  apr_file_remove(cookiefile, r->pool);
                       else if  (strncmp(oneline, "method=PUT", 10) == 0)
                                  perm |= GRST_PERM_WRITE;
                       else if  (strncmp(oneline, "method=GET", 10) == 0)
                                  perm |= GRST_PERM_READ;
                     }

                apr_file_close(fp);
              }
      }
    
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "After GACL/Onetime evaluation, GRST_PERM=%d", perm);

    /* set permission and GACL environment variables */
    
    apr_table_setn(r->notes, "GRST_PERM", apr_psprintf(r->pool, "%d", perm));

    if (((mod_gridsite_dir_cfg *) cfg)->envs)
      {
        apr_table_setn(env, "GRST_PERM", apr_psprintf(r->pool, "%d", perm));

        if (((dir_path = apr_pstrdup(r->pool, r->filename)) != NULL) &&
            ((p = rindex(dir_path, '/')) != NULL))
          {
            *p = '\0';
            apr_table_setn(env, "GRST_DIR_PATH", dir_path);
          }

        if (((mod_gridsite_dir_cfg *) cfg)->helpuri != NULL)
                  apr_table_setn(env, "GRST_HELP_URI",
                              ((mod_gridsite_dir_cfg *) cfg)->helpuri);

        if (((mod_gridsite_dir_cfg *) cfg)->adminfile != NULL)
                  apr_table_setn(env, "GRST_ADMIN_FILE",
                              ((mod_gridsite_dir_cfg *) cfg)->adminfile);

        if (((mod_gridsite_dir_cfg *) cfg)->editable != NULL)
	          apr_table_setn(env, "GRST_EDITABLE",
                              ((mod_gridsite_dir_cfg *) cfg)->editable);

        if (((mod_gridsite_dir_cfg *) cfg)->headfile != NULL)
	          apr_table_setn(env, "GRST_HEAD_FILE",
                              ((mod_gridsite_dir_cfg *) cfg)->headfile);

        if (((mod_gridsite_dir_cfg *) cfg)->footfile != NULL)
	          apr_table_setn(env, "GRST_FOOT_FILE",
                              ((mod_gridsite_dir_cfg *) cfg)->footfile);

        if (((mod_gridsite_dir_cfg *) cfg)->dnlists != NULL)
	          apr_table_setn(env, "GRST_DN_LISTS",
                              ((mod_gridsite_dir_cfg *) cfg)->dnlists);

        if (((mod_gridsite_dir_cfg *) cfg)->dnlistsuri != NULL)
	          apr_table_setn(env, "GRST_DN_LISTS_URI",
                              ((mod_gridsite_dir_cfg *) cfg)->dnlistsuri);

        if (((mod_gridsite_dir_cfg *) cfg)->adminlist != NULL)
	          apr_table_setn(env, "GRST_ADMIN_LIST",
                              ((mod_gridsite_dir_cfg *) cfg)->adminlist);

	apr_table_setn(env, "GRST_GSIPROXY_LIMIT",
 	                     apr_psprintf(r->pool, "%d",
  	                           ((mod_gridsite_dir_cfg *)cfg)->gsiproxylimit));

        if (((mod_gridsite_dir_cfg *) cfg)->unzip != NULL)
	          apr_table_setn(env, "GRST_UNZIP",
                              ((mod_gridsite_dir_cfg *) cfg)->unzip);

        if (!(((mod_gridsite_dir_cfg *) cfg)->gridsitelink))
                  apr_table_setn(env, "GRST_NO_LINK", "1");

        if (((mod_gridsite_dir_cfg *) cfg)->aclformat != NULL)
	          apr_table_setn(env, "GRST_ACL_FORMAT",
                              ((mod_gridsite_dir_cfg *) cfg)->aclformat);

        if (((mod_gridsite_dir_cfg *) cfg)->aclpath != NULL)
	          apr_table_setn(env, "GRST_ACL_PATH",
                              ((mod_gridsite_dir_cfg *) cfg)->aclpath);

	if (((mod_gridsite_dir_cfg *) cfg)->delegationuri != NULL)
	          apr_table_setn(env, "GRST_DELEGATION_URI",
                              ((mod_gridsite_dir_cfg *) cfg)->delegationuri);


        if (((mod_gridsite_dir_cfg *) cfg)->execmethod != NULL)
          {
	    apr_table_setn(env, "GRST_EXEC_METHOD",
                              ((mod_gridsite_dir_cfg *) cfg)->execmethod);
                              
            if ((strcasecmp(((mod_gridsite_dir_cfg *) cfg)->execmethod,  
                           "directory") == 0) && (r->filename != NULL))
              {
                if ((r->content_type != NULL) && 
                    (strcmp(r->content_type, DIR_MAGIC_TYPE) == 0))
                  apr_table_setn(env, "GRST_EXEC_DIRECTORY", r->filename);
                else
                  {
                    file = apr_pstrdup(r->pool, r->filename);
                    p = rindex(file, '/');
                    if (p != NULL)
                      {
                        *p = '\0';
                        apr_table_setn(env, "GRST_EXEC_DIRECTORY", file);
                      }                    
                  }                 
              }
          }

        apr_table_setn(env, "GRST_DISK_MODE",
 	                     apr_psprintf(r->pool, "0x%04x",
    	                      ((mod_gridsite_dir_cfg *)cfg)->diskmode));
      }

    if (((mod_gridsite_dir_cfg *) cfg)->auth)
      {
        /* *** Check HTTP method to decide which perm bits to check *** */

        if ((r->filename != NULL) && 
            ((p = rindex(r->filename, '/')) != NULL) &&
            (strcmp(&p[1], GRST_ACL_FILE) == 0)) file_is_acl = 1;

        content_type = r->content_type;
        if ((content_type != NULL) &&
            (strcmp(content_type, DIR_MAGIC_TYPE) == 0) &&
            (((mod_gridsite_dir_cfg *) cfg)->dnlistsuri != NULL) &&
            (strncmp(r->uri,
                     ((mod_gridsite_dir_cfg *) cfg)->dnlistsuri,
                     strlen(((mod_gridsite_dir_cfg *) cfg)->dnlistsuri)) == 0) &&
            (strlen(r->uri) > strlen(((mod_gridsite_dir_cfg *) cfg)->dnlistsuri)))
            content_type = "text/html";

        if ( GRSTgaclPermHasNone(perm) ||

            /* first two M_GET conditions make the subtle distinction
               between .../ that maps to .../index.html (governed by
               Read perm) or to dir list (governed by List perm);
               third M_GET condition deals with typeless CGI requests */

            ((r->method_number == M_GET) &&
             !GRSTgaclPermHasRead(perm)  &&
             (content_type != NULL)   &&
             (strcmp(content_type, DIR_MAGIC_TYPE) != 0)) ||

            ((r->method_number == M_GET) &&
             !GRSTgaclPermHasList(perm)  &&
             (content_type != NULL)   &&
             (strcmp(content_type, DIR_MAGIC_TYPE) == 0)) ||

            ((r->method_number == M_GET) &&
             !GRSTgaclPermHasRead(perm)  &&
             (content_type == NULL))      ||

            ((r->method_number == M_POST) && !GRSTgaclPermHasRead(perm) ) ||

            (((r->method_number == M_PUT) || 
              (r->method_number == M_DELETE)) &&
             !GRSTgaclPermHasWrite(perm) && !file_is_acl) ||

            ((r->method_number == M_MOVE) &&
             ((!GRSTgaclPermHasWrite(perm) && !file_is_acl) || 
              (!GRSTgaclPermHasAdmin(perm) && file_is_acl)  ||
              (!GRSTgaclPermHasWrite(destination_perm) 
                                    && !destination_is_acl) || 
              (!GRSTgaclPermHasAdmin(destination_perm) 
                                     && destination_is_acl)) ) ||

            (((r->method_number == M_PUT) || 
              (r->method_number == M_DELETE)) &&
             !GRSTgaclPermHasAdmin(perm) && file_is_acl) ||

            /* for WebDAV/Subversion */
             
            (((r->method_number == M_PROPFIND) ||
              (r->method_number == M_REPORT)) &&
             !GRSTgaclPermHasRead(perm)) ||

            (((r->method_number == M_CHECKOUT) ||
              (r->method_number == M_MERGE) ||
              (r->method_number == M_MKACTIVITY) ||
              (r->method_number == M_MKCOL) ||
              (r->method_number == M_LOCK) ||
              (r->method_number == M_UNLOCK)) &&
             !GRSTgaclPermHasWrite(perm))
             
             ) retcode = HTTP_FORBIDDEN;
      }

    return retcode;
}

int GRST_X509_check_issued_wrapper(X509_STORE_CTX *ctx, X509 *x, X509 *issuer)
/* We change the default callback to use our wrapper and discard errors
   due to GSI proxy chains (ie where users certs act as CAs) */
{
    int ret;
    ret = X509_check_issued(issuer, x);
    if (ret == X509_V_OK)
                return 1;
         
    /* Non self-signed certs without signing are ok if they passed
           the other checks inside X509_check_issued. Is this enough? */
    if ((ret == X509_V_ERR_KEYUSAGE_NO_CERTSIGN) &&
        (X509_NAME_cmp(X509_get_subject_name(issuer),
                           X509_get_subject_name(x)) != 0)) return 1;
 
    /* If we haven't asked for issuer errors don't set ctx */
#if OPENSSL_VERSION_NUMBER < 0x00908000
    if (!(ctx->flags & X509_V_FLAG_CB_ISSUER_CHECK)) return 0;
#else
    if (!(ctx->param->flags & X509_V_FLAG_CB_ISSUER_CHECK)) return 0;
#endif 
  
    ctx->error = ret;
    ctx->current_cert = x;
    ctx->current_issuer = issuer;
    return ctx->verify_cb(0, ctx);
}

/* Later OpenSSL versions add a second pointer ... */
int GRST_verify_cert_wrapper(X509_STORE_CTX *ctx, void *p)

/* Earlier ones have a single argument ... */
// int GRST_verify_cert_wrapper(X509_STORE_CTX *ctx)

/* Before 0.9.7 we cannot change the check_issued callback directly in
   the X509_STORE, so we must insert it in another callback that gets
   called early enough */
{
   ctx->check_issued = GRST_X509_check_issued_wrapper;

   return X509_verify_cert(ctx);
}

int GRST_callback_SSLVerify_wrapper(int ok, X509_STORE_CTX *ctx)
{
   SSL *ssl            = (SSL *) X509_STORE_CTX_get_app_data(ctx);
   conn_rec *conn      = (conn_rec *) SSL_get_app_data(ssl);
   server_rec *s       = conn->base_server;
   SSLConnRec *sslconn = 
         (SSLConnRec *) ap_get_module_config(conn->conn_config, &ssl_module);
   int errnum          = X509_STORE_CTX_get_error(ctx);
   int errdepth        = X509_STORE_CTX_get_error_depth(ctx);
   int returned_ok;
   int first_non_ca;
   STACK_OF(X509) *certstack;
   GRSTx509Chain *grst_chain;

   /*
    * GSI Proxy user-cert-as-CA handling:
    * we skip Invalid CA errors at this stage, since we will check this
    * again at errdepth=0 for the full chain using GRSTx509ChainLoadCheck
    */
   if (errnum == X509_V_ERR_INVALID_CA)
     {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                    "Skip Invalid CA error in case a GSI Proxy");

        sslconn->verify_error = NULL;
        ok = TRUE;
        errnum = X509_V_OK;
        X509_STORE_CTX_set_error(ctx, errnum);
     }

   /*
    * New style GSI Proxy handling, with critical ProxyCertInfo
    * extension: we use GRSTx509KnownCriticalExts() to check this
    */
#ifndef X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION
#define X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION 34
#endif
   if (errnum == X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION)
     {
       if (GRSTx509KnownCriticalExts(X509_STORE_CTX_get_current_cert(ctx))
                                                              == GRST_RET_OK)
         {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                     "GRSTx509KnownCriticalExts() accepts previously "
                     "Unhandled Critical Extension (GSI Proxy?)");

            sslconn->verify_error = NULL;
            ok = TRUE;
            errnum = X509_V_OK;
            X509_STORE_CTX_set_error(ctx, errnum);
         }
     }

   returned_ok = ssl_callback_SSLVerify(ok, ctx);

   /* in case ssl_callback_SSLVerify changed it */
   errnum = X509_STORE_CTX_get_error(ctx); 

   if ((errdepth == 0) && (errnum == X509_V_OK))
   /*
    * We've now got the last certificate - the identity being used for
    * this connection. At this point we check the whole chain for valid
    * CAs or, failing that, GSI-proxy validity using GRSTx509CheckChain.
    */
     {
        certstack = (STACK_OF(X509) *) X509_STORE_CTX_get_chain(ctx);

        errnum = GRSTx509ChainLoadCheck(&grst_chain, certstack, NULL,
                                        "/etc/grid-security/certificates", 
                                        "/etc/grid-security/vomsdir");

        if (errnum != X509_V_OK)
          {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "Invalid certificate chain reported by "
                     "GRSTx509CheckChain()");

            sslconn->verify_error = X509_verify_cert_error_string(errnum);
            ok = FALSE;
          }
        else 
          {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "Valid certificate"
                              " chain reported by GRSTx509ChainLoadCheck()");

            /* Put result of GRSTx509ChainLoadCheck into connection notes */
            GRST_save_ssl_creds(conn, grst_chain);
          }
          
        GRSTx509ChainFree(grst_chain);
     }

   return returned_ok;
}

void sitecast_handle_NOP_request(server_rec *main_server, 
                                 GRSThtcpMessage *htcp_mesg, int igroup,
                                 struct sockaddr_in *client_addr_ptr)
{
  int  outbuf_len;
  char *outbuf;
  
  if (GRSThtcpNOPresponseMake(&outbuf, &outbuf_len,
                              htcp_mesg->trans_id) == GRST_RET_OK)
    {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, main_server,
            "SiteCast sends NOP response from port %d to %s:%d",
            sitecastgroups[0].port, inet_ntoa(client_addr_ptr->sin_addr),
            ntohs(client_addr_ptr->sin_port));

      sendto(sitecastgroups[0].socket, outbuf, outbuf_len, 0,
                 client_addr_ptr, sizeof(struct sockaddr_in));
                 
      free(outbuf);
    }
}

void sitecast_handle_TST_GET(server_rec *main_server, 
                             GRSThtcpMessage *htcp_mesg, int igroup,
                             struct sockaddr_in *client_addr_ptr)
{
  int             i, outbuf_len, ialias;
  char            *filename, *outbuf, *location, *local_uri = NULL;
  struct stat     statbuf;
  
  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, main_server,
        "SiteCast responder received TST GET with uri %s", 
        htcp_mesg->uri->text, GRSThtcpCountstrLen(htcp_mesg->uri));

  /* find if any GridSiteCastAlias lines match */

  for (ialias=0; ialias < GRST_SITECAST_ALIASES ; ++ialias)
     {
       if (sitecastaliases[ialias].sitecast_url == NULL) 
         {
           ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, main_server,
              "SiteCast responder does not handle %*s requested by %s:%d",
                        GRSThtcpCountstrLen(htcp_mesg->uri),
                        htcp_mesg->uri->text,
                        inet_ntoa(client_addr_ptr->sin_addr),
                        ntohs(client_addr_ptr->sin_port));
      
           return; /* no match */
         }
                             
       if ((strlen(sitecastaliases[ialias].sitecast_url)
                                <= GRSThtcpCountstrLen(htcp_mesg->uri)) &&
           (strncmp(sitecastaliases[ialias].sitecast_url,
                    htcp_mesg->uri->text,
                    strlen(sitecastaliases[ialias].sitecast_url))==0)) break;
     }

  if (ialias == GRST_SITECAST_ALIASES) 
    {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, main_server,
              "SiteCast responder does not handle %*s requested by %s:%d",
                        GRSThtcpCountstrLen(htcp_mesg->uri),
                        htcp_mesg->uri->text,
                        inet_ntoa(client_addr_ptr->sin_addr),
                        ntohs(client_addr_ptr->sin_port));
      
      return; /* no match */
    }
    
  /* convert URL to filename, using alias mapping */

  asprintf(&filename, "%s%*s", 
           sitecastaliases[ialias].local_path,
           GRSThtcpCountstrLen(htcp_mesg->uri) 
                        - strlen(sitecastaliases[ialias].sitecast_url),
           &(htcp_mesg->uri->text[strlen(sitecastaliases[ialias].sitecast_url)]) );

  if (stat(filename, &statbuf) == 0) /* found file */
    {
      asprintf(&location, "Location: %s://%s:%d/%s\r\n",
                  sitecastaliases[ialias].scheme,
                  sitecastaliases[ialias].local_hostname,
                  sitecastaliases[ialias].port,
      &(htcp_mesg->uri->text[strlen(sitecastaliases[ialias].sitecast_url)]) );

      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, main_server,
            "SiteCast finds %*s at %s, redirects with %s",
            GRSThtcpCountstrLen(htcp_mesg->uri),
            htcp_mesg->uri->text, filename, location);

      if (GRSThtcpTSTresponseMake(&outbuf, &outbuf_len,
                                  htcp_mesg->trans_id,
                                  location, "", "") == GRST_RET_OK)
        {
          ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, main_server,
            "SiteCast sends TST response from port %d to %s:%d",
            sitecastgroups[0].port, inet_ntoa(client_addr_ptr->sin_addr),
            ntohs(client_addr_ptr->sin_port));

          sendto(sitecastgroups[0].socket, outbuf, outbuf_len, 0,
                 client_addr_ptr, sizeof(struct sockaddr_in));
                 
          free(outbuf);
        }

      free(location);
    }
  else ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, main_server,
            "SiteCast does not find %*s (would be at %s)",
            GRSThtcpCountstrLen(htcp_mesg->uri),
            htcp_mesg->uri->text, filename);


  free(filename);                      
}

void sitecast_handle_request(server_rec *main_server, 
                             char *reqbuf, int reqbuf_len, int igroup,
                             struct sockaddr_in *client_addr_ptr)
{
  GRSThtcpMessage htcp_mesg;

  if (GRSThtcpMessageParse(&htcp_mesg,reqbuf,reqbuf_len) != GRST_RET_OK)
    {
      ap_log_error(APLOG_MARK, APLOG_ERR, 0, main_server,
              "SiteCast responder rejects format of UDP message from %s:%d",
                        inet_ntoa(client_addr_ptr->sin_addr),
                        ntohs(client_addr_ptr->sin_port));
      return;
    }

  if (htcp_mesg.rr != 0) /* ignore HTCP responses: we just do requests */
    {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, main_server,
              "SiteCast responder ignores HTCP response from %s:%d",
                        inet_ntoa(client_addr_ptr->sin_addr),
                        ntohs(client_addr_ptr->sin_port));
      return;
    }

  if (htcp_mesg.opcode == GRSThtcpNOPop)
    {
      sitecast_handle_NOP_request(main_server, &htcp_mesg, 
                                  igroup, client_addr_ptr);
      return;
    }

  if (htcp_mesg.opcode == GRSThtcpTSTop)
    {
      if (((GRSThtcpCountstrLen(htcp_mesg.method) == 3) &&
           (strncmp(htcp_mesg.method->text, "GET", 3) == 0)) ||
          ((GRSThtcpCountstrLen(htcp_mesg.method) == 4) &&
           (strncmp(htcp_mesg.method->text, "HEAD", 4) == 0)))
        {
          sitecast_handle_TST_GET(main_server, &htcp_mesg, 
                                  igroup, client_addr_ptr);
          return;
        }
        
      ap_log_error(APLOG_MARK, APLOG_ERR, 0, main_server,
          "SiteCast responder rejects method %*s in TST message from %s:%d",
          GRSThtcpCountstrLen(htcp_mesg.method), htcp_mesg.method->text,
          inet_ntoa(client_addr_ptr->sin_addr),
          ntohs(client_addr_ptr->sin_port));
      return;
    }

  ap_log_error(APLOG_MARK, APLOG_ERR, 0, main_server,
          "SiteCast does not implement HTCP op-code %d in message from %s:%d",
          htcp_mesg.opcode,
          inet_ntoa(client_addr_ptr->sin_addr),
          ntohs(client_addr_ptr->sin_port));
}

void sitecast_responder(server_rec *main_server)
{
#define GRST_SITECAST_MAXBUF 8192
  char   reqbuf[GRST_SITECAST_MAXBUF], *p;
  int    n, reqbuf_len, i, j, igroup,
         quad1, quad2, quad3, quad4, port, retval, client_addr_len;
  struct sockaddr_in srv, client_addr;
  struct ip_mreq mreq;
  fd_set readsckts;
  struct hostent *server_hostent;

  strcpy((char *) main_server->process->argv[0], "GridSiteCast UDP responder");

  /* initialise unicast/replies socket first */

  bzero(&srv, sizeof(srv));
  srv.sin_family = AF_INET;
  srv.sin_port = htons(sitecastgroups[0].port);

  if ((server_hostent = gethostbyname(main_server->server_hostname)) == NULL)
    {
      ap_log_error(APLOG_MARK, APLOG_ERR, 0, main_server,
              "SiteCast UDP Responder fails to look up servername %s",
              main_server->server_hostname);
      return;
    }

  srv.sin_addr.s_addr = (u_int32_t) (server_hostent->h_addr_list[0][0]);
  
  if (((sitecastgroups[0].socket 
                                = socket(AF_INET, SOCK_DGRAM, 0)) < 0) ||
       (bind(sitecastgroups[0].socket, 
                                (struct sockaddr *) &srv, sizeof(srv)) < 0))
    {
      ap_log_error(APLOG_MARK, APLOG_ERR, 0, main_server,
              "mod_gridsite: sitecast responder fails on unicast bind (%s)",
              strerror(errno));
      return;
    }

  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, main_server,
                "SiteCast UDP unicast/replies on %d.%d.%d.%d:%d",
                   server_hostent->h_addr_list[0][0],
                   server_hostent->h_addr_list[0][1],
                   server_hostent->h_addr_list[0][2],
                   server_hostent->h_addr_list[0][3],
                   sitecastgroups[0].port);

  /* initialise multicast listener sockets next */

  for (i=1; (i <= GRST_SITECAST_GROUPS) && 
            (sitecastgroups[i].port != 0); ++i)
     {
       bzero(&srv, sizeof(srv));
       srv.sin_family = AF_INET;
       srv.sin_port = htons(sitecastgroups[i].port);
       srv.sin_addr.s_addr = htonl(sitecastgroups[i].quad1*0x1000000
                                 + sitecastgroups[i].quad2*0x10000
                                 + sitecastgroups[i].quad3*0x100 
                                 + sitecastgroups[i].quad4);

       if (((sitecastgroups[i].socket 
                                     = socket(AF_INET, SOCK_DGRAM, 0)) < 0) ||
               (bind(sitecastgroups[i].socket, 
                                  (struct sockaddr *) &srv, sizeof(srv)) < 0))
         {
           ap_log_error(APLOG_MARK, APLOG_ERR, 0, main_server,
                "SiteCast UDP Responder fails on multicast bind (%s)",
                strerror(errno));
           return;
         }
     
       bzero(&mreq, sizeof(mreq));
       mreq.imr_multiaddr.s_addr = srv.sin_addr.s_addr;
       mreq.imr_interface.s_addr = htonl(INADDR_ANY);

       if (setsockopt(sitecastgroups[i].socket, IPPROTO_IP,
                      IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) 
         { 
           ap_log_error(APLOG_MARK, APLOG_ERR, 0, main_server,
                "SiteCast UDP Responder fails on setting multicast (%s)",
                strerror(errno));
           return; 
         }
         
       ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, main_server,
        "SiteCast UDP Responder listening on %d.%d.%d.%d:%d",
        sitecastgroups[i].quad1, sitecastgroups[i].quad2,
        sitecastgroups[i].quad3, sitecastgroups[i].quad4, 
        sitecastgroups[i].port);
     }

  for (i=0; (i < GRST_SITECAST_ALIASES) &&
            (sitecastaliases[i].sitecast_url != NULL) ; ++i)
     {
       ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, main_server,
                          "SiteCast alias for %s (%s,%d) to %s (%s)",
                          sitecastaliases[i].sitecast_url,
                          sitecastaliases[i].scheme,
                          sitecastaliases[i].port,
                          sitecastaliases[i].local_path,
                          sitecastaliases[i].local_hostname);
     }

  while (1) /* **** main listening loop **** */
       {
         /* set up bitmasks for select */
       
         FD_ZERO(&readsckts);
         
         n = 0;
         for (i=0; (i <= GRST_SITECAST_GROUPS) && 
                   (sitecastgroups[i].port != 0); ++i) /* reset bitmask */
            {
              FD_SET(sitecastgroups[i].socket, &readsckts);
              if (sitecastgroups[i].socket > n) n = sitecastgroups[i].socket;
            }

         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, main_server,
                      "SiteCast UDP Responder waiting for requests");

         if ((retval = select(n + 1, &readsckts, NULL, NULL, NULL)) < 1)
                                   continue; /* < 1 on timeout or error */

         for (igroup=0; (igroup <= GRST_SITECAST_GROUPS) && 
                   (sitecastgroups[igroup].port != 0); ++igroup)
            {
              if (FD_ISSET(sitecastgroups[igroup].socket, &readsckts))
                {
                  client_addr_len = sizeof(client_addr);

                  if ((reqbuf_len = recvfrom(sitecastgroups[igroup].socket, 
                                             reqbuf, GRST_SITECAST_MAXBUF, 0,
                     (struct sockaddr *) &client_addr, &client_addr_len)) >= 0)
                    {
                      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, main_server,
                        "SiteCast receives UDP message from %s:%d "
                        "to %d.%d.%d.%d:%d",
                        inet_ntoa(client_addr.sin_addr),
                        ntohs(client_addr.sin_port),
                        sitecastgroups[igroup].quad1,
                        sitecastgroups[igroup].quad2,
                        sitecastgroups[igroup].quad3,
                        sitecastgroups[igroup].quad4,
                        sitecastgroups[igroup].port);

                      sitecast_handle_request(main_server, reqbuf, 
                                              reqbuf_len, igroup,
                                              &client_addr);
                    }
                }
            }
            
       } /* **** end of main listening loop **** */
}

static int mod_gridsite_server_post_config(apr_pool_t *pPool,
                  apr_pool_t *pLog, apr_pool_t *pTemp, server_rec *main_server)
{
   SSL_CTX         *ctx;
   SSLSrvConfigRec *sc;
   server_rec      *this_server;
   apr_proc_t      *procnew = NULL;
   apr_status_t     status;
   char            *path;
   const char *userdata_key = "sitecast_init";

   apr_pool_userdata_get((void **) &procnew, userdata_key, 
                         main_server->process->pool);

   /* we only fork responder if one not already forked and we have at
      least one GridSiteCastAlias defined. This means it is possible
      to run a responder with no groups - listening on unicast only! */

   if ((procnew == NULL) &&
       (sitecastaliases[0].sitecast_url != NULL))
     {
       /* UDP multicast responder required but not yet started */

       procnew = apr_pcalloc(main_server->process->pool, sizeof(*procnew));
       apr_pool_userdata_set((const void *) procnew, userdata_key,
                     apr_pool_cleanup_null, main_server->process->pool);

       status = apr_proc_fork(procnew, pPool);

       if (status < 0)
         {
           ap_log_error(APLOG_MARK, APLOG_CRIT, status, main_server,
              "mod_gridsite: Failed to spawn SiteCast responder process");
           return HTTP_INTERNAL_SERVER_ERROR;
         }
       else if (status == APR_INCHILD)
         {
           ap_log_error(APLOG_MARK, APLOG_NOTICE, status, main_server,
              "mod_gridsite: Spawning SiteCast responder process");
           sitecast_responder(main_server);
           exit(-1);
         }

       apr_pool_note_subprocess(main_server->process->pool,
                                procnew, APR_KILL_AFTER_TIMEOUT);
     }

   /* continue with normal HTTP/HTTPS servers */

   ap_add_version_component(pPool,
                            apr_psprintf(pPool, "mod_gridsite/%s", VERSION));

   for (this_server = main_server; 
        this_server != NULL; 
        this_server = this_server->next)
      {
        /* we do some GridSite OpenSSL magic for HTTPS servers */
      
        sc = ap_get_module_config(this_server->module_config, &ssl_module);

        if ((sc                  != NULL)  &&
            (sc->enabled)                  &&
            (sc->server          != NULL)  &&
            (sc->server->ssl_ctx != NULL))
          {
            ctx = sc->server->ssl_ctx;

            /* in 0.9.7 we could set the issuer-checking callback directly */
//          ctx->cert_store->check_issued = GRST_X509_check_issued_wrapper;
     
            /* but in case 0.9.6 we do it indirectly with another wrapper */
            SSL_CTX_set_cert_verify_callback(ctx, 
                                             GRST_verify_cert_wrapper,
                                             (void *) NULL);

            /* whatever version, we can set the SSLVerify wrapper properly */
            SSL_CTX_set_verify(ctx, ctx->verify_mode, 
                               GRST_callback_SSLVerify_wrapper);

            if (main_server->loglevel >= APLOG_DEBUG)
                 ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, main_server,
                      "Set mod_ssl verify callbacks to GridSite wrappers");
          }
      }

   /* create sessions directory if necessary */

   path = ap_server_root_relative(pPool, sessionsdir);
   apr_dir_make_recursive(path, APR_UREAD | APR_UWRITE | APR_UEXECUTE, pPool);
   chown(path, unixd_config.user_id, unixd_config.group_id);

   return OK;
}

static server_rec *mod_gridsite_log_func_server;
static void mod_gridsite_log_func(char *file, int line, int level,
                                                    char *fmt, ...)
{
   char *mesg;
   va_list ap;

   va_start(ap, fmt);
   vasprintf(&mesg, fmt, ap);
   va_end(ap);

   ap_log_error(file, line, level, 
                0, mod_gridsite_log_func_server, "%s", mesg);
   
   free(mesg);
}
      
static void mod_gridsite_child_init(apr_pool_t *pPool, server_rec *pServer)
{
   apr_time_t cutoff_time;
   apr_dir_t *dir;
   char *filename;
   apr_finfo_t finfo;
   SSLSrvConfigRec *sc = ap_get_module_config(pServer->module_config, 
                                                        &ssl_module);          
   GRSTgaclInit();
   mod_gridsite_log_func_server = pServer;
   GRSTerrorLogFunc = mod_gridsite_log_func;

   /* expire old ssl creds files */
                                    
   if (sc != NULL)
     {
       cutoff_time = apr_time_now() 
                      - apr_time_from_sec(sc->session_cache_timeout);

       ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, pServer,
                        "Cutoff time for ssl creds cache: %ld", 
                        (long) apr_time_sec(cutoff_time));

       if (apr_dir_open(&dir, 
           ap_server_root_relative(pPool, sessionsdir), pPool) == APR_SUCCESS)
         {
           while (apr_dir_read(&finfo, 
                        APR_FINFO_CTIME | APR_FINFO_NAME, dir) == APR_SUCCESS)
                {
                  if ((finfo.ctime < cutoff_time) &&
                      (strncmp(finfo.name, "sslcreds-", 9) == 0))
                    {
                      filename = apr_pstrcat(pPool, 
                                   ap_server_root_relative(pPool, sessionsdir),
                                   "/", finfo.name, NULL);
                    
                      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, pServer,
                        "Remove %s from ssl creds cache", filename);

                      apr_file_remove(filename, pPool);
                    }
                }

           apr_dir_close(dir);
         }       
     }
}

static int mod_gridsite_handler(request_rec *r)
{
   mod_gridsite_dir_cfg *conf;
    
   conf = (mod_gridsite_dir_cfg *)
                    ap_get_module_config(r->per_dir_config, &gridsite_module);

   if ((conf->dnlistsuri != NULL) &&
       (strncmp(r->uri, conf->dnlistsuri, strlen(conf->dnlistsuri)) == 0))
     {
       if (strcmp(r->uri, conf->dnlistsuri) == 0)
              return mod_gridsite_dnlistsuri_dir_handler(r, conf);

       return mod_gridsite_dnlistsuri_handler(r, conf);
    }

   if (strcmp(r->handler, DIR_MAGIC_TYPE) == 0)
                   return mod_gridsite_dir_handler(r, conf);
   
   return mod_gridsite_nondir_handler(r, conf);
}

static ap_unix_identity_t *mod_gridsite_get_suexec_id_doer(const request_rec *r)
{
   mod_gridsite_dir_cfg *conf;
    
   conf = (mod_gridsite_dir_cfg *)
                    ap_get_module_config(r->per_dir_config, &gridsite_module);

   if ((conf->execugid.uid != UNSET) && 
       (conf->execmethod != NULL)) 
     {
     
     /* also push GRST_EXEC_DIRECTORY into request environment here too */
     
       return &(conf->execugid);
     }
              
   return NULL;
}

static void register_hooks(apr_pool_t *p)
{
    /* config and handler stuff */

    ap_hook_post_config(mod_gridsite_server_post_config, NULL, NULL, 
                                                              APR_HOOK_LAST);
    ap_hook_child_init(mod_gridsite_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    
    ap_hook_check_user_id(mod_gridsite_check_user_id, NULL, NULL, 
                                                      APR_HOOK_REALLY_FIRST);

    ap_hook_fixups(mod_gridsite_first_fixups,NULL,NULL,APR_HOOK_FIRST);
    
    ap_hook_fixups(mod_gridsite_perm_handler,NULL,NULL,APR_HOOK_LAST);
    
    ap_hook_handler(mod_gridsite_handler, NULL, NULL, APR_HOOK_FIRST);    
    
    ap_hook_get_suexec_identity(mod_gridsite_get_suexec_id_doer,
                                NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA gridsite_module =
{
    STANDARD20_MODULE_STUFF,
    create_gridsite_dir_config, /* dir config creater */
    merge_gridsite_dir_config,  /* dir merger */
    create_gridsite_srv_config, /* create server config */
    NULL,			/* merge server config */
    mod_gridsite_cmds,          /* command apr_table_t */
    register_hooks              /* register hooks */
};
