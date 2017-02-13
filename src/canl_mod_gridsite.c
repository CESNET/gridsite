/*
   Copyright (c) 2003-10, Andrew McNab, Shiv Kaushal, Joseph Dada,
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

   This work has been partially funded by the EU Commission (contract 
   INFSO-RI-222667) under the EGEE-III collaboration.
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
/* for ap_uname2id() */
#include <mpm_common.h>

#if AP_MODULE_MAGIC_AT_LEAST(20051115,0)
#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif
#endif

#include <unixd.h>

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>              
#include <netdb.h>
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

#include <openssl/x509v3.h>

#include "canl_mod_ssl-private.h"
#include "mod_ap-compat.h"

#include "gridsite.h"

#include <canl.h>
#include <canl_ssl.h>

#ifndef IPV6_ADD_MEMBERSHIP
#ifdef  IPV6_JOIN_GROUP
#define IPV6_ADD_MEMBERSHIP IPV6_JOIN_GROUP
#endif
#endif

#ifndef UNSET
#define UNSET -1
#endif

#define GRST_SESSIONS_DIR "/var/www/sessions"

module AP_MODULE_DECLARE_DATA gridsite_module;

#define GRST_SITECAST_GROUPS 32

struct sitecast_group
   { char *address; int port; };

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

 /* This global records whether the SSLSrvConfigRec struct will have 
    the extra  BOOL insecure_reneg  member */
int                     mod_ssl_with_insecure_reneg = 0;

struct sitecast_sockets {
    fd_set fds;
    int max_fd;
} sitecast_sockets;

typedef struct
{
   int			auth;
   int                  autopasscode;
   int			requirepasscode;
   int			zoneslashes;
   int			envs;
   int			format;
   int			indexes;
   char			*indexheader;
   int			gridsitelink;
   char			*adminfile;
   char			*adminuri;
   char			*helpuri;
   char			*loginuri;
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

    escaped = apr_palloc(pool, strlen(s) + htmlspecials * 6 + 1);
        
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
                  apr_table_get(r->notes, "GRST_CRED_AURI_0");
      }                       

    if ((grst_cred_auri_0 != NULL) && 
        (strncmp(grst_cred_auri_0, "dn:", 3) == 0))
      {
         dn = GRSThttpUrlDecode(&grst_cred_auri_0[3]);
         if (dn[0] == '\0') 
           {
             free(dn);
             dn = NULL;
           }         
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
          
        free(dn);
      }
    
    if ((https != NULL) && (strcasecmp(https, "on") == 0))
         temp = apr_psprintf(r->pool,
                   "<a href=\"http://%s%s\">Switch&nbsp;to&nbsp;HTTP</a> \n", 
                   r->server->server_hostname, r->unparsed_uri);
    else temp = apr_psprintf(r->pool,
                   "<a href=\"https://%s%s\">Switch&nbsp;to&nbsp;HTTPS</a> \n",
                   r->server->server_hostname, r->unparsed_uri);
    
    out = apr_pstrcat(r->pool, out, temp, NULL);

    if ((conf->loginuri != NULL) && (conf->loginuri[0] != '\0'))
      {
        temp = apr_psprintf(r->pool,
                   ". <a href=\"%s%s\">Login/Logout</a>\n", 
                   conf->loginuri, r->unparsed_uri);
        out = apr_pstrcat(r->pool, out, temp, NULL);
      }

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
    int   fd;
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

    fd = -1;

    if (conf->headfile[0] == '/') /* try absolute */
      {
        fd = open(conf->headfile, O_RDONLY);
      }
    else /* try relative */
      {
        /* first make a buffer big enough to hold path names we want to try */
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

    fd = -1;

    if (conf->footfile[0] == '/') /* try absolute */
      {
        fd = open(conf->footfile, O_RDONLY);
      }
    else /* try relative */
      {
        /* first make a buffer big enough to hold path names we want to try */
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
    int   fd, n, nn;
    char  *p, *s, *head_formatted, *header_formatted,
          *body_formatted, *admin_formatted, *footer_formatted, *temp,
           modified[999], *d_namepath, *indexheaderpath, *indexheadertext,
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

               encoded = GRSThttpUrlEncode(namelist[n]->d_name);
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

char *make_passcode_file(request_rec *r, mod_gridsite_dir_cfg *conf, 
                         char *path, apr_time_t expires_time)
{
    int           i;
    char         *filetemplate, *notename_i, *grst_cred_i, *cookievalue=NULL;
    apr_uint64_t  gridauthcookie;
    apr_file_t   *fp;

    /* create random for use in GRIDHTTP_PASSCODE cookies and file name */

    if (apr_generate_random_bytes((char *) &gridauthcookie, 
                                  sizeof(gridauthcookie))
         != APR_SUCCESS) return NULL;
    
    filetemplate = apr_psprintf(r->pool, "%s/passcode-%016lxXXXXXX", 
     ap_server_root_relative(r->pool,
     sessionsdir),
     gridauthcookie);

    if (apr_file_mktemp(&fp, 
                        filetemplate, 
                        APR_CREATE | APR_WRITE | APR_EXCL,
                        r->pool)
                      != APR_SUCCESS) return NULL;
                      
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
               "Created passcode file %s", filetemplate);

    if (expires_time > 0) apr_file_printf(fp, "expires=%lu\n",
                                      (time_t) apr_time_sec(expires_time));

    apr_file_printf(fp, "domain=%s\npath=%s\n", r->hostname, path);

    for (i=0; ; ++i)
       {
         notename_i = apr_psprintf(r->pool, "GRST_CRED_AURI_%d", i);
         if (grst_cred_i = (char *)
                           apr_table_get(r->connection->notes, notename_i))
           {
             apr_file_printf(fp, "%s=%s\n", notename_i, grst_cred_i);
           }
         else break; /* GRST_CRED_AURI_i are numbered consecutively */

         notename_i = apr_psprintf(r->pool, "GRST_CRED_VALID_%d", i);
         if (grst_cred_i = (char *)
                           apr_table_get(r->connection->notes, notename_i))
           {
             apr_file_printf(fp, "%s=%s\n", notename_i, grst_cred_i);
           }
         else break; /* GRST_CRED_VALID_i are numbered consecutively */
       }

    if (apr_file_close(fp) != APR_SUCCESS) 
      {
        apr_file_remove(filetemplate, r->pool); /* try to clean up */
        return NULL;
      }
      
    cookievalue = rindex(filetemplate, '-');
    if (cookievalue != NULL) 
      {
        ++cookievalue;
        return cookievalue;
      }
    else return NULL;
}

int http_gridhttp(request_rec *r, mod_gridsite_dir_cfg *conf)
{ 
    char        *httpurl, *cookievalue, expires_str[APR_RFC822_DATE_LEN];
    apr_time_t   expires_time;

    /* passcode cookies are valid for only 5 mins! */
    expires_time = apr_time_now() + apr_time_from_sec(300);

    /* try to generate passcode and make passcode file */
    cookievalue = make_passcode_file(r, conf, r->uri, expires_time);
    
    if (cookievalue == NULL) return HTTP_INTERNAL_SERVER_ERROR;
    
    /* send redirection header back to client */
       
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
                             request_rec *r, char **body,
                             int recurse_level)
/* try to find DN Lists in dir[] and its subdirs that match the fulluri[]
   prefix. add blobs of HTML to body as they are found. */
{
   char          *unencname, modified[99], *oneline, *d_namepath,
                 *mildencoded;
   DIR           *oneDIR;
   struct dirent *onedirent;
   struct tm      mtime_tm;
   struct stat    statbuf;

   if ((stat(dirname, &statbuf) != 0) ||
       (!S_ISDIR(statbuf.st_mode)) ||
       ((oneDIR = opendir(dirname)) == NULL)) return;

   if (statbuf.st_mtime > *dirs_time) *dirs_time = statbuf.st_mtime;

   while ((onedirent = readdir(oneDIR)) != NULL)
        {
          if (onedirent->d_name[0] == '.') continue;
        
          d_namepath = apr_psprintf(r->pool, "%s/%s", dirname, onedirent->d_name);

          if (stat(d_namepath, &statbuf) != 0) continue;

          if (S_ISDIR(statbuf.st_mode))
            {
              if (recurse_level < GRST_RECURS_LIMIT)
                 recurse4dirlist(d_namepath, dirs_time, fulluri,
                                 fullurilen, encfulluri, enclen, 
                                 r, body, recurse_level + 1);
            }
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
                 
                  oneline = apr_psprintf(r->pool,
                                     "<tr><td><a href=\"%s\" "
                                     "content-length=\"%ld\" "
                                     "last-modified=\"%ld\">"
                                     "%s</a></td>"
                                     "<td align=right>%ld</td>%s</tr>\n", 
                                     mildencoded, statbuf.st_size, 
                                     statbuf.st_mtime, 
                                     html_escape(r->pool, unencname), 
                                     statbuf.st_size, modified);

                  free(mildencoded);

                  *body = apr_pstrcat(r->pool, *body, oneline, NULL);
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
    char          *fulluri, *encfulluri, *dn_list_ptr, *dirname,
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
                                    r->hostname, conf->dnlistsuri);
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

        fd = -1;

        if (conf->headfile[0] == '/') /* try absolute */
          {
            fd = open(conf->headfile, O_RDONLY);
          }
        else /* try relative */
          {
            /* first make a buffer big enough to hold path names we want to try */
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
            
    body = apr_psprintf(r->pool, 
      "<h1>Directory listing %s</h1>\n<table>", r->uri);

    if ((r->uri)[1] != '\0')
     body = apr_pstrcat(r->pool, body, 
       "<tr><td>[<a href=\"../\">Parent directory</a>]</td></tr>\n",
       NULL);

    while ((dirname = strsep(&dn_list_ptr, ":")) != NULL)
        recurse4dirlist(dirname, &dirs_time, fulluri, fullurilen,
                                 encfulluri, enclen, r, &body, 0);

    p = (char *) apr_table_get(r->subprocess_env, "HTTPS");
    if ((p != NULL) && (strcmp(p, "on") == 0))
      {
        oneline = apr_psprintf(r->pool,
           "<form action=\"%s%s\" method=post>\n"
           "<input type=hidden name=cmd value=managednlists>"
           "<tr><td colspan=4 align=center><small><input type=submit "
           "value=\"Manage DN lists\"></small></td></tr></form>\n",
           r->uri, conf->adminfile);
          
        body = apr_pstrcat(r->pool, body, oneline, NULL);
      }

    body = apr_pstrcat(r->pool, body, "</table>\n", NULL);

    free(encfulluri); /* libgridsite doesnt use pools */

    if (conf->format)
      {
        /* **** try to find a footer file in this or parent directories **** */

        fd = -1;

        if (conf->headfile[0] == '/') /* try absolute */
          {
            fd = open(conf->headfile, O_RDONLY);
          }
        else /* try relative */
          {
            /* first make a buffer big enough to hold path names we want to try */
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
      
    if (r->uri[strlen(r->uri) - 1] == '/') 
      {
        apr_table_setn(r->headers_out, apr_pstrdup(r->pool, "Location"), 
                                       apr_pstrdup(r->pool, conf->dnlistsuri));

        r->status = HTTP_MOVED_TEMPORARILY;
        return OK;                   
      }

    fulluri = apr_psprintf(r->pool, "https://%s%s", 
                                    r->hostname, r->uri);

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

        sitecastgroups[0].port  = GRST_HTCP_PORT;
                                      /* GridSiteCastUniPort udp-port */

        for (i=1; i <= GRST_SITECAST_GROUPS; ++i)
           {
             sitecastgroups[i].port = 0; /* GridSiteCastGroup mcast-list */
           }

        for (i=0; i < GRST_SITECAST_ALIASES; ++i)
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
        conf->autopasscode  = 1;     /* GridSiteAutoPasscode  on/off       */
        conf->requirepasscode = 0;   /* GridSiteRequirePasscode on/off     */
        conf->zoneslashes   = 1;     /* GridSiteZoneSlashes   number       */
        conf->envs          = 1;     /* GridSiteEnvs          on/off       */
        conf->format        = 0;     /* GridSiteHtmlFormat    on/off       */
        conf->indexes       = 0;     /* GridSiteIndexes       on/off       */
        conf->indexheader   = NULL;  /* GridSiteIndexHeader   File-value   */
        conf->gridsitelink  = 1;     /* GridSiteLink          on/off       */
        conf->adminfile     = apr_pstrdup(p, GRST_ADMIN_FILE);
                                /* GridSiteAdminFile      File-value   */
        conf->adminuri      = NULL;  /* GridSiteAdminURI      URI-value    */
        conf->helpuri       = NULL;  /* GridSiteHelpURI       URI-value    */
        conf->loginuri      = NULL;  /* GridSiteLoginURI      URI-value    */
        conf->dnlists       = NULL;  /* GridSiteDNlists       Search-path  */
        conf->dnlistsuri    = NULL;  /* GridSiteDNlistsURI    URI-value    */
        conf->adminlist     = NULL;  /* GridSiteAdminList     URI-value    */
        conf->gsiproxylimit = 1000;  /* GridSiteGSIProxyLimit number       */
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
        conf->autopasscode  = UNSET; /* GridSiteAutoPasscode  on/off       */
        conf->requirepasscode = UNSET; /* GridSiteRequirePasscode on/off   */
        conf->zoneslashes   = UNSET; /* GridSiteZoneSlashes   number       */
        conf->envs          = UNSET; /* GridSiteEnvs          on/off       */
        conf->format        = UNSET; /* GridSiteHtmlFormat    on/off       */
        conf->indexes       = UNSET; /* GridSiteIndexes       on/off       */
        conf->indexheader   = NULL;  /* GridSiteIndexHeader   File-value   */
        conf->gridsitelink  = UNSET; /* GridSiteLink          on/off       */
        conf->adminfile     = NULL;  /* GridSiteAdminFile     File-value   */
        conf->adminuri      = NULL;  /* GridSiteAdminURI      URI-value    */
        conf->helpuri       = NULL;  /* GridSiteHelpURI       URI-value    */
        conf->loginuri      = NULL;  /* GridSiteLoginURI      URI-value    */
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

    if (direct->autopasscode != UNSET) conf->autopasscode = direct->autopasscode;
    else                               conf->autopasscode = server->autopasscode;

    if (direct->requirepasscode != UNSET) conf->requirepasscode = direct->requirepasscode;
    else                               conf->requirepasscode = server->requirepasscode;

    if (direct->zoneslashes != UNSET) conf->zoneslashes = direct->zoneslashes;
    else                              conf->zoneslashes = server->zoneslashes;

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
        
    if (direct->loginuri != NULL) conf->loginuri = direct->loginuri;
    else                          conf->loginuri = server->loginuri;

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
    else if (strcasecmp(a->cmd->name, "GridSiteZoneSlashes") == 0)
    {
      ((mod_gridsite_dir_cfg *) cfg)->zoneslashes = atoi(parm);
      
      if (((mod_gridsite_dir_cfg *) cfg)->zoneslashes < 1)
       return "GridSiteZoneSlashes must be greater than 0";
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
             
               if (sscanf(parm, "%s:%d",
                          &(sitecastgroups[i].address), 
                          &(sitecastgroups[i].port)) < 1)
                 return "Failed parsing GridSiteCastGroup";
                 
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
    
      if ((sscanf(parm, "%d", &n) == 1) && (n >= 0)) {
		  if (n == 0)
		      n = 1000; /* thousand is an African for "unlimited" */
                  ((mod_gridsite_dir_cfg *) cfg)->gsiproxylimit = n;
      }
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
      if (!(ap_unixd_config.suexec_enabled))
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
    else if (strcasecmp(a->cmd->name, "GridSiteAutoPasscode") == 0)
    {
      ((mod_gridsite_dir_cfg *) cfg)->autopasscode = flag;
    }
    else if (strcasecmp(a->cmd->name, "GridSiteRequirePasscode") == 0)
    {
      ((mod_gridsite_dir_cfg *) cfg)->requirepasscode = flag;
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
    AP_INIT_FLAG("GridSiteAutoPasscode", mod_gridsite_flag_cmds,
                 NULL, OR_FILEINFO, "on or off"),
    AP_INIT_FLAG("GridSiteRequirePasscode", mod_gridsite_flag_cmds,
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
    AP_INIT_TAKE1("GridSiteLoginURI", mod_gridsite_take1_cmds,
                   NULL, OR_FILEINFO, "URI prefix of login/logout page"),
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
    AP_INIT_TAKE1("GridSiteZoneSlashes", mod_gridsite_take1_cmds,
                 NULL, OR_FILEINFO, "number of slashes in passcode cookie paths"),

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
   unsigned int sess_len;
   const unsigned char *sess_id;

   session = SSL_get_session(ssl);
   if (session == NULL)
      return GRST_RET_FAILED;

   sess_id = SSL_SESSION_get_id(session, &sess_len);
   if (sess_len == 0)
      return GRST_RET_FAILED;

   if (2 * sess_len + 1 > len) 
      return GRST_RET_FAILED;

   for (i=0; i < sess_len; ++i)
    sprintf(&(session_id[i*2]), "%02X", sess_id[i]);

   session_id[i*2] = '\0';
   
   return GRST_RET_OK;
}

int GRST_load_ssl_creds(SSL *ssl, conn_rec *conn)
{
   char session_id[(SSL_MAX_SSL_SESSION_ID_LENGTH+1)*2+1], *sessionfile = NULL,
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
   int          i, lowest_voms_delegation = 65535;
   char        *tempfile = NULL, *encoded, *voms_fqans = NULL,
               *sessionfile, session_id[(SSL_MAX_SSL_SESSION_ID_LENGTH+1)*2];
   apr_file_t  *fp = NULL;
   SSL         *ssl;
   SSLConnRec  *sslconn;
   GRSTx509Cert  *grst_cert = NULL;

   /* check if already done */

   if ((grst_chain != NULL) && (conn->notes != NULL) &&
       (apr_table_get(conn->notes, "GRST_save_ssl_creds") != NULL)) return;

   /* we at least need to say we've been run - even if creds not save-able*/

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
        if (grst_cert->errors) continue;
        
        if (grst_cert->type == GRST_CERT_TYPE_VOMS)
          {
            /* want to record the delegation level 
               of the last proxy with VOMS attributes */
          
            lowest_voms_delegation = grst_cert->delegation;
          }
        else if ((grst_cert->type == GRST_CERT_TYPE_EEC) ||
                 (grst_cert->type == GRST_CERT_TYPE_PROXY))
          {
            encoded = GRSThttpUrlMildencode(grst_cert->dn);
          
            apr_table_setn(conn->notes,
                   apr_psprintf(conn->pool, "GRST_CRED_AURI_%d", i),
                   apr_pstrcat(conn->pool, "dn:", encoded, NULL));

            if (fp != NULL) apr_file_printf(fp, "GRST_CRED_AURI_%d=dn:%s\n",
                                                i, encoded);

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
                      "store GRST_CRED_AURI_%d=dn:%s", i, encoded);

            free(encoded);

            ++i;
          }
        else if (grst_cert->type == GRST_CERT_TYPE_ROBOT)
          {
            apr_table_setn(conn->notes, "GRST_ROBOT_DN", apr_pstrdup(conn->pool, grst_cert->dn));
            /* I ignore the sslcreds cache here */
          }
      }

   for (grst_cert = grst_chain->firstcert; 
        grst_cert != NULL; grst_cert = grst_cert->next)
      {
        if (grst_cert->errors) continue;
        
        if ((grst_cert->type == GRST_CERT_TYPE_VOMS) &&
            (grst_cert->delegation == lowest_voms_delegation))
          {
            /* only export attributes from the last proxy to contain them */

            encoded = GRSThttpUrlMildencode(grst_cert->value);
          
            apr_table_setn(conn->notes,
                   apr_psprintf(conn->pool, "GRST_CRED_AURI_%d", i),
                   apr_pstrcat(conn->pool, "fqan:", encoded, NULL));

            if (voms_fqans != NULL)
              {
                voms_fqans = apr_pstrcat(conn->pool, encoded, ";", voms_fqans, NULL);
              }
            else
              {
                voms_fqans = apr_pstrcat(conn->pool, encoded, NULL);
              }
            if (fp != NULL) apr_file_printf(fp, "GRST_CRED_AURI_%d=fqan:%s\n",
                                                i, encoded);

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
                      "store GRST_CRED_AURI_%d=fqan:%s", i, encoded);

            free(encoded);

            ++i;
          }
      }

   if (voms_fqans != NULL)
     {
       apr_table_setn(conn->notes, "GRST_VOMS_FQANS", voms_fqans);
       if (fp != NULL) apr_file_printf(fp, "GRST_VOMS_FQANS=%s\n", voms_fqans);
       ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, conn->base_server,
                      "store GRST_VOMS_FQANS=%s", voms_fqans);
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
    int          retcode = DECLINED, i, j, n, file_is_acl = 0, cc_delegation,
                 destination_is_acl = 0, ishttps = 0, nist_loa, delegation,
                 from_cookie = 0;
    char        *p, *q, envname1[30], envname2[30], 
                *grst_cred_auri_0 = NULL, *dir_path,
                *remotehost, *grst_cred_auri_i, *cookies, *file,
                *cookiefile, oneline[1025], *decoded,
                *destination = NULL, *destination_uri = NULL, *querytmp, 
                *destination_prefix = NULL, *destination_translated = NULL,
                *aclpath = NULL, *grst_cred_valid_0 = NULL, *grst_cred_valid_i,
                *gridauthpasscode = NULL, *grst_voms_fqans;
    const char  *content_type, *robot;
    time_t      notbefore, notafter;
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

    cfg = (mod_gridsite_dir_cfg *)
                    ap_get_module_config(r->per_dir_config, &gridsite_module);

    if (cfg == NULL) return DECLINED;

    if ((cfg->auth == 0) && (cfg->envs == 0))
               return DECLINED; /* if not turned on, look invisible */

    env = r->subprocess_env;

    p = (char *) apr_table_get(env, "HTTPS");
    if ((p != NULL) && (strcmp(p, "on") == 0)) ishttps = 1;

    delegation = ((mod_gridsite_dir_cfg *) cfg)->gsiproxylimit + 1;

    /* reload per-connection (SSL) cred variables? (TO CONNECTION) */

    sslconn = (SSLConnRec *) ap_get_module_config(r->connection->conn_config, 
                                                  &ssl_module);
    if ((user == NULL) &&
        (sslconn != NULL) && 
        (sslconn->ssl != NULL) &&
        (r->connection->notes != NULL) &&
        (apr_table_get(r->connection->notes, "GRST_save_ssl_creds") == NULL))
      {
        if (GRST_load_ssl_creds(sslconn->ssl, r->connection) == GRST_RET_OK)
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "Restored SSL session data from session cache file");
      }

    /* look for GRIDHTTP_PASSCODE in QUERY_STRING ie after ? */
      
    if ((r->parsed_uri.query != NULL) && (r->parsed_uri.query[0] != '\0'))
      {
        querytmp = apr_pstrcat(r->pool,"&",r->parsed_uri.query,"&",NULL);
            
        gridauthpasscode = strstr(querytmp, "&GRIDHTTP_PASSCODE=");
        if (gridauthpasscode != NULL)
          {
            gridauthpasscode = &gridauthpasscode[19];

            for (p = gridauthpasscode; (*p != '\0') && (*p != '&'); ++p)
                                                if (!isalnum(*p)) *p = '\0';
          }
      }

    /* then look for GRIDHTTP_PASSCODE cookie */
      
    if ((gridauthpasscode == NULL) &&
        ((q = (char *) apr_table_get(r->headers_in, "Cookie")) != NULL))
      {
        cookies = apr_pstrcat(r->pool, " ", q, NULL);
        gridauthpasscode = strstr(cookies, " GRIDHTTP_PASSCODE=");

        if (gridauthpasscode != NULL)
          {
            gridauthpasscode = &gridauthpasscode[19];
          
            for (p = gridauthpasscode; 
                 (*p != '\0') && (*p != ';'); ++p)
                                      if (!isalnum(*p)) *p = '\0';

            if (gridauthpasscode[0] != '\0') from_cookie = 1;
          }
      }

    /* try to load user structure from passcode file */

    if ((user == NULL) && 
        (gridauthpasscode != NULL) &&
        (gridauthpasscode[0] != '\0'))
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
               
                i = -1;
                cred = NULL;
              
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
                         {
                           if (user != NULL) 
                             {
                               ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, 
                                            r->server, "Bad expires");
                               GRSTgaclUserFree(user);
                               user = NULL;
                             }
                           break;
                         }
                       else if ((strncmp(oneline, "domain=", 7) == 0) &&
                                (strcmp(&oneline[7], r->hostname) != 0))
                         {
                           if (user != NULL) 
                             {
                               ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, 
                                            r->server, "Bad domain/host");
                               GRSTgaclUserFree(user);
                               user = NULL;
                             }
                           break;
                         }
                       else if (strncmp(oneline, "path=", 5) == 0)
                         {
                           /* count number of slashes in Request URI */
                           
                           for (n=0,p=r->uri; *p != '\0'; ++p)
                                                     if (*p == '/') ++n;

                           /* if too few slashes or path mismatch, then stop */
                              
                           if ((n < ((mod_gridsite_dir_cfg *) cfg)->zoneslashes) ||
                               (strncmp(&oneline[5], r->uri, strlen(&oneline[5])) != 0))
                             {
                               if (user != NULL)
                                 {
                                   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, 
                                            r->server, "Bad path");
                                   GRSTgaclUserFree(user);
                                   user = NULL;
                                 }

                               break;
                             }
                         }
                       else if ((sscanf(oneline,"GRST_CRED_AURI_%d=",&j) == 1)
                                && (j == i+1)
                                && ((p = index(oneline, '=')) != NULL))
                         {
                           cred = GRSTgaclCredCreate(&p[1], NULL);
                           
                           if (cred != NULL) ++i;
                           
                           if (user == NULL) user = GRSTgaclUserNew(cred);
                           else GRSTgaclUserAddCred(user, cred);                           
                         }
                       else if ((sscanf(oneline,"GRST_CRED_VALID_%d=",&j) == 1)
                                && (j == i)
                                && ((p = index(oneline, '=')) != NULL)
                                && (sscanf(&p[1], 
                       "notbefore=%ld notafter=%ld delegation=%d nist-loa=%d", 
                                  &notbefore, &notafter, &delegation, 
                                  &nist_loa) == 4))
                         {
                           if ((i == 0) && 
             (delegation > ((mod_gridsite_dir_cfg *) cfg)->gsiproxylimit))
                             {
                               ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, 
                                            r->server, "Bad delegation");
                               if (user != NULL) GRSTgaclUserFree(user);
                               user = NULL;
                               break;
                             }
                         
                           GRSTgaclCredSetNotBefore( cred, notbefore);
                           GRSTgaclCredSetNotAfter(  cred, notafter);
                           GRSTgaclCredSetDelegation(cred, delegation);
 
                           if (delegation == 0) GRSTgaclCredSetNistLoa(cred, 3);
                           else                 GRSTgaclCredSetNistLoa(cred, 2);
                         }
                     }

                apr_file_close(fp);

                /* delete passcode file if used over HTTP not HTTPS */
                if (!ishttps) remove(cookiefile);

                /* if successful and we got passcode from a cookie, then
                   we put cookie value into environment variables, so
                   can be used for double-submit cookie CSRF protection */

                if ((user != NULL) && 
                    from_cookie && 
                    ((mod_gridsite_dir_cfg *) cfg)->envs)
                        apr_table_setn(env, "GRST_PASSCODE_COOKIE",
                                            gridauthpasscode);
              }
      }

    /* 
        if not succeeded from passcode file, try from connection notes
        if a GSI Proxy or have  GridSiteAutoPasscode on  (the default)
        If  GridSiteAutoPasscode off  and  GridSiteRequirePasscode on
        then interactive websites must use a login script to make passcode
        and file instead.
    */
    
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
        (delegation <= ((mod_gridsite_dir_cfg *) cfg)->gsiproxylimit) &&
        ((delegation > 0) || 
         ((mod_gridsite_dir_cfg *) cfg)->autopasscode ||
         !(((mod_gridsite_dir_cfg *) cfg)->requirepasscode)))
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

         /* if user from SSL ok and not a GSI Proxy and have 
            GridSiteAutoPasscode on  we create passcode and file
            automatically, and return cookie to client. 
            (if  GridSiteAutoPasscode off  then the site must use
            a login script to make passcode and file instead.) */

         if (((mod_gridsite_dir_cfg *) cfg)->autopasscode &&
             (user != NULL) &&
             (GRSTgaclCredGetDelegation(cred_0) == 0))
           {
             n = 0; /* number of slashes seen */

             for (i=0; r->uri[i] != '\0'; ++i)
                {
                  if (n >= ((mod_gridsite_dir_cfg *) cfg)->zoneslashes) break;

                  if (r->uri[i] == '/') ++n;
                }
 
             if ((n >= ((mod_gridsite_dir_cfg *) cfg)->zoneslashes)
                 && (i > 0))
               {
                 p = apr_pstrdup(r->pool, r->uri);
                 p[i] = '\0';
               
                 /* try to generate passcode and make passcode file */
                 gridauthpasscode = make_passcode_file(r, cfg, p, 0);

                 if (gridauthpasscode != NULL)
                   {
                     apr_table_add(r->headers_out,
                        apr_pstrdup(r->pool, "Set-Cookie"),
                        apr_psprintf(r->pool,
                        "GRIDHTTP_PASSCODE=%s; "
                        "domain=%s; "
                        "path=%s; "
                        "secure", gridauthpasscode, r->hostname, p));
                   }
               }
           }
      }

    /* 
       GridSite passcode files don't include groups, IP or DNS so we add
       them last so they're not written to passcode files by GridSite.

       (site-supplied login scripts might create passcode files with 
       optional or additional AURIs. for example, valid roles selected by
       the user on the login page.)
       
    */
      
    /* first add groups from DN lists - ie non-optional attributes */

    if ((user != NULL) && ((mod_gridsite_dir_cfg *) cfg)->dnlists)
          GRSTgaclUserLoadDNlists(user, ((mod_gridsite_dir_cfg *) cfg)->dnlists);

    /* then add DNS credential */
    
    remotehost = (char *) ap_get_remote_host(r->connection,
                                  r->per_dir_config, REMOTE_DOUBLE_REV, NULL);
    if ((remotehost != NULL) && (*remotehost != '\0'))
      {
        cred = GRSTgaclCredCreate("dns:", remotehost);
        GRSTgaclCredSetNotAfter(cred, GRST_MAX_TIME_T);

        if (user == NULL) user = GRSTgaclUserNew(cred);
        else              GRSTgaclUserAddCred(user, cred);
      }

    /* finally add IP credential */
    
    if (GRST_AP_CLIENT_IP(r->connection))
      {
        cred = GRSTgaclCredCreate("ip:", GRST_AP_CLIENT_IP(r->connection));
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
                   decoded = GRSThttpUrlDecode(&(cred->auri[3]));
                   apr_table_setn(env, 
                                  apr_psprintf(r->pool, "GRST_CRED_%d", i),
                                  apr_psprintf(r->pool, 
                                               "%s %ld %ld %d %s",
                                               (i==0) ? "X509USER" : "GSIPROXY",
                                               cred->notbefore,
                                               cred->notafter,
                                               cc_delegation, 
                                               decoded));
                   free(decoded);
                 }
               else if (strncmp(cred->auri, "fqan:", 5) == 0)
                 {
                   decoded = GRSThttpUrlDecode(&(cred->auri[5]));
                   apr_table_setn(env, 
                                  apr_psprintf(r->pool, "GRST_CRED_%d", i),
                                  apr_psprintf(r->pool, 
                                                  "VOMS %ld %ld 0 %s",
                                                  notbefore, notafter, 
                                                  decoded));
                   free(decoded);
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
        else if ((((mod_gridsite_dir_cfg *) cfg)->dnlistsuri == NULL) ||
                 (strncmp(r->uri,
                          ((mod_gridsite_dir_cfg *) cfg)->dnlistsuri,
                          strlen(((mod_gridsite_dir_cfg *) cfg)->dnlistsuri)) != 0) ||
                 (strlen(r->uri) <= strlen(((mod_gridsite_dir_cfg *) cfg)->dnlistsuri)))
          {
            acl = GRSTgaclAclLoadforFile(r->filename);
          }

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
    
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "After GACL/Onetime evaluation, GRST_PERM=%d", perm);

    /* add permission and first AURI to request notes */
    
    apr_table_setn(r->notes, "GRST_PERM", apr_psprintf(r->pool, "%d", perm));

    cred = NULL;
    if (user)
	cred = user->firstcred;
    if ((cred != NULL) && (strncmp(cred->auri, "dn:", 3) == 0))
      {
        apr_table_setn(r->notes, "GRST_CRED_AURI_0",
                       apr_psprintf(r->pool, "%s", cred->auri));
      }
        

    if (((mod_gridsite_dir_cfg *) cfg)->envs)
      {
        /* copy any credentials from (SSL) connection to environment */
        
        for (i=0; ; ++i) 
           {
             snprintf(envname1, sizeof(envname1), "GRST_CRED_AURI_%d",  i);
             snprintf(envname2, sizeof(envname2), "GRST_CRED_VALID_%d", i);

             if ((grst_cred_auri_i = (char *) 
                         apr_table_get(r->connection->notes,envname1)) &&
                 (grst_cred_valid_i = (char *) 
                         apr_table_get(r->connection->notes,envname2)))
               { 
                 apr_table_setn(env,
                                apr_psprintf(r->pool, "GRST_CONN_AURI_%d", i),
                                apr_pstrdup(r->pool, grst_cred_auri_i));

                 apr_table_setn(env,
                                apr_psprintf(r->pool, "GRST_CONN_VALID_%d", i),
                                apr_pstrdup(r->pool, grst_cred_valid_i));
               }
             else break;
           }

        robot = apr_table_get(r->connection->notes, "GRST_ROBOT_DN");
        if (robot)
            apr_table_setn(env, "GRST_ROBOT_DN", robot);

        if (grst_voms_fqans  = (char *)
                apr_table_get(r->connection->notes, "GRST_VOMS_FQANS"))
          {
            apr_table_setn(env, "GRST_VOMS_FQANS",
                           apr_pstrdup(r->pool, grst_voms_fqans));
          }

        apr_table_setn(env, "GRST_PERM", apr_psprintf(r->pool, "%d", perm));

        if (((mod_gridsite_dir_cfg *) cfg)->requirepasscode == 0)
             apr_table_set(env, "GRST_REQUIRE_PASSCODE", "off");
        else apr_table_set(env, "GRST_REQUIRE_PASSCODE", "on");

        if (((dir_path = apr_pstrdup(r->pool, r->filename)) != NULL) &&
            ((p = rindex(dir_path, '/')) != NULL))
          {
            *p = '\0';
            apr_table_setn(env, "GRST_DIR_PATH", dir_path);
          }

        if (((mod_gridsite_dir_cfg *) cfg)->helpuri != NULL)
                  apr_table_setn(env, "GRST_HELP_URI",
                              ((mod_gridsite_dir_cfg *) cfg)->helpuri);

        if (((mod_gridsite_dir_cfg *) cfg)->loginuri != NULL)
                  apr_table_setn(env, "GRST_LOGIN_URI",
                              ((mod_gridsite_dir_cfg *) cfg)->loginuri);

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

    if (user != NULL) GRSTgaclUserFree(user);

    return retcode;
}

int GRST_callback_SSLVerify_wrapper(int ok, X509_STORE_CTX *ctx)
{
   SSL *ssl            = (SSL *) X509_STORE_CTX_get_app_data(ctx);
   conn_rec *conn      = (conn_rec *) SSL_get_app_data(ssl);
   int errnum          = X509_STORE_CTX_get_error(ctx);
   int errdepth        = X509_STORE_CTX_get_error_depth(ctx);
   int returned_ok;
   STACK_OF(X509) *certstack;
   GRSTx509Chain *grst_chain;

   /* Call caNl callback directly */
   returned_ok = canl_direct_pv_clb(NULL, ctx, ok);

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

       errnum = GRSTx509ChainLoad(&grst_chain, certstack, NULL,
               "/etc/grid-security/certificates",
               "/etc/grid-security/vomsdir");

       if (returned_ok)
           /* Put result of GRSTx509ChainLoadCheck into connection notes */
           GRST_save_ssl_creds(conn, grst_chain);
       if (grst_chain)
           GRSTx509ChainFree(grst_chain);
   }

   return returned_ok;
}

void sitecast_handle_NOP_request(server_rec *main_server, 
                                 GRSThtcpMessage *htcp_mesg, int s,
                                 struct sockaddr *client_addr_ptr,
				 socklen_t client_addr_len)
{
  int  outbuf_len;
  char *outbuf;
  char host[INET6_ADDRSTRLEN];
  char serv[8];
  
  if (GRSThtcpNOPresponseMake(&outbuf, &outbuf_len,
                              htcp_mesg->trans_id) == GRST_RET_OK)
    {
      getnameinfo(client_addr_ptr, client_addr_len,
		  host, sizeof(host), serv, sizeof(serv), NI_NUMERICHOST);
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, main_server,
            "SiteCast sends NOP response to %s:%s",
            host, serv);

      sendto(s, outbuf, outbuf_len, 0,
             client_addr_ptr, client_addr_len);
                 
      free(outbuf);
    }
}

void sitecast_handle_TST_GET(server_rec *main_server, 
                             GRSThtcpMessage *htcp_mesg, int s,
                             struct sockaddr *client_addr_ptr,
			     socklen_t client_addr_len)
{
  int             outbuf_len, ialias;
  char            *filename, *outbuf, *location;
  struct stat     statbuf;
  char host[INET6_ADDRSTRLEN];
  char serv[8];
  
  getnameinfo(client_addr_ptr, client_addr_len,
	      host, sizeof(host), serv, sizeof(serv), NI_NUMERICHOST);
  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, main_server,
        "SiteCast responder received TST GET with uri %s", 
        htcp_mesg->uri->text, GRSThtcpCountstrLen(htcp_mesg->uri));

  /* find if any GridSiteCastAlias lines match */

  for (ialias=0; ialias < GRST_SITECAST_ALIASES ; ++ialias)
     {
       if (sitecastaliases[ialias].sitecast_url == NULL) 
         {
           ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, main_server,
              "SiteCast responder does not handle %*s requested by %s:%s",
                        GRSThtcpCountstrLen(htcp_mesg->uri),
                        htcp_mesg->uri->text,
			host, serv);
      
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
              "SiteCast responder does not handle %*s requested by %s:%s",
                        GRSThtcpCountstrLen(htcp_mesg->uri),
                        htcp_mesg->uri->text,
                        host, serv);
      
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
            "SiteCast sends TST response to %s:%s",
	    host, serv);

          sendto(s, outbuf, outbuf_len, 0,
                 client_addr_ptr, client_addr_len);
                 
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
                             char *reqbuf, int reqbuf_len,
			     int s,
                             struct sockaddr *client_addr_ptr,
			     socklen_t client_addr_len)
{
  GRSThtcpMessage htcp_mesg;
  char host[INET6_ADDRSTRLEN];
  char serv[8];

  getnameinfo(client_addr_ptr, client_addr_len,
	      host, sizeof(host),
	      serv, sizeof(serv), NI_NUMERICHOST);
  if (GRSThtcpMessageParse(&htcp_mesg,reqbuf,reqbuf_len) != GRST_RET_OK)
    {
      ap_log_error(APLOG_MARK, APLOG_ERR, 0, main_server,
              "SiteCast responder rejects format of UDP message from %s:%s",
                        host, serv);
      return;
    }

  if (htcp_mesg.rr != 0) /* ignore HTCP responses: we just do requests */
    {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, main_server,
              "SiteCast responder ignores HTCP response from %s:%s",
                        host, serv);
      return;
    }

  if (htcp_mesg.opcode == GRSThtcpNOPop)
    {
      sitecast_handle_NOP_request(main_server, &htcp_mesg, s,
                                  client_addr_ptr, client_addr_len);
      return;
    }

  if (htcp_mesg.opcode == GRSThtcpTSTop)
    {
      if (((GRSThtcpCountstrLen(htcp_mesg.method) == 3) &&
           (strncmp(htcp_mesg.method->text, "GET", 3) == 0)) ||
          ((GRSThtcpCountstrLen(htcp_mesg.method) == 4) &&
           (strncmp(htcp_mesg.method->text, "HEAD", 4) == 0)))
        {
          sitecast_handle_TST_GET(main_server, &htcp_mesg, s,
                                  client_addr_ptr, client_addr_len);
          return;
        }
        
      ap_log_error(APLOG_MARK, APLOG_ERR, 0, main_server,
          "SiteCast responder rejects method %*s in TST message from %s:%s",
          GRSThtcpCountstrLen(htcp_mesg.method), htcp_mesg.method->text,
          host, serv);
      return;
    }

  ap_log_error(APLOG_MARK, APLOG_ERR, 0, main_server,
          "SiteCast does not implement HTCP op-code %d in message from %s:%s",
          htcp_mesg.opcode,
          host, serv);
}

static int
bind_sitecast_sockets(server_rec *main_server, const char *node,
		      unsigned int port, int is_unicast)
{
    int s, open, ret;
    struct addrinfo *ai;
    struct addrinfo hints;
    struct ipv6_mreq mreq6;
    struct ip_mreq mreq;
    char serv[8];
    struct addrinfo *a;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;
    if (!is_unicast)
	hints.ai_flags |= AI_NUMERICHOST;

    snprintf(serv, sizeof(serv), "%u", port);

    ret = getaddrinfo(node, serv, &hints, &ai);
    if (ret) {
	ap_log_error(APLOG_MARK, APLOG_ERR, 0, main_server,
		"%s UDP Responder fails to look up %s",
		(is_unicast) ? "Unicast" : "Multicast", node);
	return -1;
    }

    open = 0;
    for (a = ai; a != NULL; a = a->ai_next) {
	s = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
	if (s < 0)
	    continue;

	ret = bind(s, a->ai_addr, a->ai_addrlen);
	if (ret < 0) {
	    close (s);
	    continue;
	}

	if (!is_unicast) {
	    switch (a->ai_family) {
		case AF_INET:
		    bzero(&mreq, sizeof(mreq));
		    mreq.imr_multiaddr = ((struct sockaddr_in *)(a->ai_addr))->sin_addr;
		    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
		    ret = setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP,
				     &mreq, sizeof(mreq));
		    break;
		case AF_INET6:
		    mreq6.ipv6mr_multiaddr = 
			    ((struct sockaddr_in6 *)a->ai_addr)->sin6_addr;
		    mreq6.ipv6mr_interface = 
			    ((struct sockaddr_in6 *)a->ai_addr)->sin6_scope_id;
		    ret = setsockopt(s, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
				     &mreq6, sizeof(mreq6));
		    break;
		default:
		    continue;
	    }
	    if (ret < 0) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, main_server,
			     "SiteCast UDP Responder fails on setting multicast (%s)",
			     strerror(errno));
		continue;
	    }
	}

	FD_SET(s, &sitecast_sockets.fds);
	if (s > sitecast_sockets.max_fd)
	    sitecast_sockets.max_fd = s;
	open = 1;
    }
    freeaddrinfo(ai);

    if (!open) {
      ap_log_error(APLOG_MARK, APLOG_ERR, 0, main_server,
	           "mod_gridsite: sitecast responder fails on unicast");
      return -1;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, main_server,
                 "SiteCast UDP %s responder on %s:%s",
		 (is_unicast) ? "unicast" : "multicast",
		 node, serv);
    return 0;
}

void sitecast_responder(server_rec *main_server)
{
#define GRST_SITECAST_MAXBUF 8192
  char   reqbuf[GRST_SITECAST_MAXBUF];
  int    reqbuf_len, ret, retval, i;
  struct sockaddr client_addr;
  socklen_t client_addr_len;
  fd_set readsckts;
  int s;
  char host[INET6_ADDRSTRLEN];
  char serv[8];

  strcpy((char *) main_server->process->argv[0], "GridSiteCast UDP responder");

  FD_ZERO(&sitecast_sockets.fds);
  sitecast_sockets.max_fd = -1;

  /* initialise unicast/replies socket first */
  ret =  bind_sitecast_sockets(main_server, main_server->server_hostname, sitecastgroups[0].port, 1);
  if (ret)
      return;

  /* initialise multicast listener sockets next */

  for (i=1; (i <= GRST_SITECAST_GROUPS) && 
            (sitecastgroups[i].port != 0); ++i)
     {
       ret = bind_sitecast_sockets(main_server, sitecastgroups[i].address, sitecastgroups[i].port, 0);
       if (ret)
	   continue;

       ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, main_server,
        "SiteCast UDP Responder listening on %s:%d",
	sitecastgroups[i].address,
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
       
         readsckts = sitecast_sockets.fds;

         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, main_server,
                      "SiteCast UDP Responder waiting for requests");

         if ((retval = select(sitecast_sockets.max_fd + 1, &readsckts, NULL, NULL, NULL)) < 1)
                                   continue; /* < 1 on timeout or error */

	 for (s = 0; s <= sitecast_sockets.max_fd; s++) {
	     if (FD_ISSET(s, &readsckts))
		 break;
	 }
	 if (s > sitecast_sockets.max_fd)
	     continue;

	 client_addr_len = sizeof(client_addr);
	 reqbuf_len = recvfrom(s, reqbuf, GRST_SITECAST_MAXBUF, 0,
			       &client_addr, &client_addr_len);
	 if (reqbuf_len < 0)
	     continue;

	 getnameinfo(&client_addr, client_addr_len,
		     host, sizeof(host), serv, sizeof(serv), NI_NUMERICHOST);
	 ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, main_server,
		      "SiteCast receives UDP message from %s:%s",
		      host, serv);

	 sitecast_handle_request(main_server, reqbuf, reqbuf_len, s,
				 &client_addr, client_addr_len);
       } /* **** end of main listening loop **** */
}

static int mod_gridsite_server_post_config(apr_pool_t *pPool,
                  apr_pool_t *pLog, apr_pool_t *pTemp, server_rec *main_server)
{
   SSL_CTX         *ctx;
   SSLSrvConfigRec *sc;
   int              i = 0;
   server_rec      *this_server;
   apr_proc_t      *procnew = NULL;
   apr_status_t     status;
   char            *path;   
   const char *userdata_key   = "sitecast_init";
   const char *insecure_reneg = "SSLInsecureRenegotiation";
   canl_ctx c_ctx = NULL;

   c_ctx = canl_create_ctx();
   if (!c_ctx){
           ap_log_error(APLOG_MARK, APLOG_CRIT, status, main_server,
              "mod_gridsite: Failed to create caNl context.");
       return HTTP_INTERNAL_SERVER_ERROR;
   }

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

   /* look for a SSLInsecureRenegotiation flag - if it exists then the mod_ssl
      internal variable 'SSLSrvConfigRec' is different */
   while ( ssl_module.cmds[i].name && !mod_ssl_with_insecure_reneg)
   {
       mod_ssl_with_insecure_reneg = (strncmp( ssl_module.cmds[i].name, 
                                      insecure_reneg, sizeof(insecure_reneg) ) == 0);
       i++;
   }

   ap_log_error(APLOG_MARK, APLOG_NOTICE, status, main_server,
              "mod_gridsite: mod_ssl_with_insecure_reneg = %d", mod_ssl_with_insecure_reneg);

   for (this_server = main_server; 
        this_server != NULL; 
        this_server = this_server->next)
      {
        /* we do some GridSite OpenSSL magic for HTTPS servers */
     
        sc = ap_get_module_config(this_server->module_config, &ssl_module);
        
        if ((sc                                  != NULL)  &&
            (sc->enabled)                                  &&
            (SSLSrvConfigRec_server(sc)          != NULL)  &&
            (SSLSrvConfigRec_server(sc)->ssl_ctx != NULL))
          {
            ctx = SSLSrvConfigRec_server(sc)->ssl_ctx;

            /*We do not support TLS tickets*/
#ifdef SSL_OP_NO_TICKET
            SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
#endif

            /* Use default caNl callbacks to verify certificates*/
            canl_ssl_ctx_set_clb(c_ctx, ctx, SSL_CTX_get_verify_mode(ctx),
                    GRST_callback_SSLVerify_wrapper);

            if (GRST_AP_LOGLEVEL(main_server) >= APLOG_DEBUG)
                 ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, main_server,
                      "Set mod_ssl verify callbacks to GridSite wrappers: %s",
                      canl_get_error_message(c_ctx));
          }
      }

   /* create sessions directory if necessary */

   path = ap_server_root_relative(pPool, sessionsdir);
   apr_dir_make_recursive(path, APR_UREAD | APR_UWRITE | APR_UEXECUTE, pPool);
   chown(path, ap_unixd_config.user_id, ap_unixd_config.group_id);

   canl_free_ctx(c_ctx);
   return OK;
}

static server_rec *mod_gridsite_log_func_server;
static int mod_gridsite_log_func(char *file, int line, int level,
                                                    char *fmt, ...)
{
   char *mesg;
   va_list ap;

   va_start(ap, fmt);
   vasprintf(&mesg, fmt, ap);
   va_end(ap);

/*
 * since >=2.3.6: added module_index argument to ap_log_error()
 */
#if GRST_AP_VERSION < 20306
   ap_log_error(file, line, level, 
                0, mod_gridsite_log_func_server, "%s", mesg);
#else
   ap_log_error(file, line, APLOG_NO_MODULE, level,
                0, mod_gridsite_log_func_server, "%s", mesg);
#endif
   
   free(mesg);
   return 0;
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

   if (conf->dnlistsuri != NULL)
     {
       if (strcmp(r->uri, conf->dnlistsuri) == 0)
              return mod_gridsite_dnlistsuri_dir_handler(r, conf);

       if (strncmp(r->uri, conf->dnlistsuri, strlen(conf->dnlistsuri)) == 0)
              return mod_gridsite_dnlistsuri_handler(r, conf);

       if ((strncmp(r->uri, conf->dnlistsuri, strlen(r->uri)) == 0)
           && (strlen(r->uri) == strlen(conf->dnlistsuri) - 1))
         {
           apr_table_setn(r->headers_out, apr_pstrdup(r->pool, "Location"), 
                          apr_pstrcat(r->pool, r->uri, "/", NULL));

           r->status = HTTP_MOVED_TEMPORARILY;  
           return OK;           
         }      
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
    static const char * const aszPre[] = { "mod_ssl.c", NULL };

    ap_hook_post_config(mod_gridsite_server_post_config, NULL, NULL, 
                                                              APR_HOOK_LAST);
    ap_hook_child_init(mod_gridsite_child_init, aszPre, NULL, APR_HOOK_MIDDLE);
    
    ap_hook_check_user_id(mod_gridsite_check_user_id, NULL, NULL, 
                                                      APR_HOOK_REALLY_FIRST);

    ap_hook_fixups(mod_gridsite_first_fixups,NULL,NULL,APR_HOOK_FIRST);
    
    ap_hook_fixups(mod_gridsite_perm_handler,NULL,NULL,APR_HOOK_REALLY_LAST);
    
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
