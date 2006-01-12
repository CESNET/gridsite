/*
   Copyright (c) 2003-5, Andrew McNab and Shiv Kaushal, 
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


   This program includes dav_parse_range() from Apache mod_dav.c and
   associated code contributed by  David O Callaghan
   
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

module AP_MODULE_DECLARE_DATA gridsite_module;

#define GRST_SITECAST_GROUPS 32

struct sitecast_group
   { int socket; int quad1; int quad2; int quad3; int quad4; int port; };

#define GRST_SITECAST_ALIASES 32
   
struct sitecast_alias
   { const char *sitecast_url; const char *local_path; server_rec *server; };

/* Globals, defined by main server directives in httpd.conf  
   These are assigned default values in create_gridsite_srv_config() */

int			gridhttpport = 0;
char                    *passcodesdir = NULL;
char			*sitecastdnlists = NULL;
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
   int			soap2cgi;
   char			*aclformat;
   char			*execmethod;
   ap_unix_identity_t	execugid;
   apr_fileperms_t	diskmode;
}  mod_gridsite_dir_cfg; /* per-directory config choices */

typedef struct
{
  xmlDocPtr doc;
//  char *outbuffer;
} soap2cgi_ctx; /* store per-request context for Soap2cgi in/out filters */

static const char Soap2cgiFilterName[]="Soap2cgiFilter";

static void mod_gridsite_soap2cgi_insert(request_rec *r)
{
    mod_gridsite_dir_cfg *conf;
    soap2cgi_ctx     *ctx;
    
    conf = (mod_gridsite_dir_cfg *) ap_get_module_config(r->per_dir_config,
                                                      &gridsite_module);
                                                      
    if (conf->soap2cgi) 
      {
        ctx = (soap2cgi_ctx *) malloc(sizeof(soap2cgi_ctx));        
        ctx->doc = NULL;
        
        ap_add_output_filter(Soap2cgiFilterName, ctx, r, r->connection);

        ap_add_input_filter(Soap2cgiFilterName, NULL, r, r->connection);
      }
}

xmlNodePtr find_one_child(xmlNodePtr parent_node, char *name)
{
    xmlNodePtr cur;

    for (cur = parent_node->children; cur != NULL; cur = cur->next)
       {
         if ((cur->type == XML_ELEMENT_NODE) &&
             (strcmp(cur->name, name) == 0)) return cur;
       }

    return NULL;
}

int add_one_node(xmlDocPtr doc, char *line)
{
    char *p, *name, *aftername, *attrname = NULL, *value = NULL;
    xmlNodePtr cur, cur_child;

    cur = xmlDocGetRootElement(doc);

    p = index(line, '=');
    if (p == NULL) return 1;

    *p = '\0';
    value = &p[1];

    name = line;

    while (1) /* go through each .-deliminated segment of line[] */
         {
           if ((p = index(name, '.')) != NULL)
             {
               *p = '\0';
               aftername = &p[1];
             }
           else aftername = &name[strlen(name)];

           if ((p = index(name, '_')) != NULL)
             {
               *p = '\0';
               attrname = &p[1];
             }

           cur_child = find_one_child(cur, name);

           if (cur_child == NULL)
                    cur_child = xmlNewChild(cur, NULL, name, NULL);

           cur = cur_child;

           name = aftername;

           if (attrname != NULL)
             {
               xmlSetProp(cur, attrname, value);
               return 0;
             }

           if (*name == '\0')
             {
               xmlNodeSetContent(cur, value);
               return 0;
             }             
         }
}

static apr_status_t mod_gridsite_soap2cgi_out(ap_filter_t *f,
                                              apr_bucket_brigade *bbIn)
{
    char        *p, *name, *outbuffer;
    request_rec *r = f->r;
    conn_rec    *c = r->connection;
    apr_bucket         *bucketIn, *pbktEOS;
    apr_bucket_brigade *bbOut;

    const char *data;
    apr_size_t len;
    char *buf;
    apr_size_t n;
    apr_bucket *pbktOut;

    soap2cgi_ctx *ctx;
    xmlNodePtr   root_node = NULL;
    xmlBufferPtr buff;

    ctx = (soap2cgi_ctx *) f->ctx;

// LIBXML_TEST_VERSION;

    bbOut = apr_brigade_create(r->pool, c->bucket_alloc);

    if (ctx->doc == NULL)
      {
        ctx->doc = xmlNewDoc("1.0");
             
        root_node = xmlNewNode(NULL, "Envelope");
        xmlDocSetRootElement(ctx->doc, root_node);
                                                                                
        xmlNewChild(root_node, NULL, "Header", NULL);
        xmlNewChild(root_node, NULL, "Body",   NULL);
      }
    
    apr_brigade_pflatten(bbIn, &outbuffer, &len, r->pool);
       
    /* split up buffer and feed each line to add_one_node() */
    
    name = outbuffer;
    
    while (*name != '\0')
         {
           p = index(name, '\n');
           if (p != NULL) 
             {
               *p = '\0';
               ++p;             
             }
           else p = &name[strlen(name)]; /* point to final NUL */
           
           add_one_node(ctx->doc, name);
           
           name = p;
         }

    APR_BRIGADE_FOREACH(bucketIn, bbIn)
       {
         if (APR_BUCKET_IS_EOS(bucketIn))
           {
             /* write out XML tree we have built */

             buff = xmlBufferCreate();
             xmlNodeDump(buff, ctx->doc, root_node, 0, 0);

// TODO: simplify/reduce number of copies or libxml vs APR buffers?

             buf = (char *) xmlBufferContent(buff);

             pbktOut = apr_bucket_heap_create(buf, strlen(buf), NULL, 
                                              c->bucket_alloc);

             APR_BRIGADE_INSERT_TAIL(bbOut, pbktOut);
       
             xmlBufferFree(buff);

             pbktEOS = apr_bucket_eos_create(c->bucket_alloc);
             APR_BRIGADE_INSERT_TAIL(bbOut, pbktEOS);

             continue;
           }
       }
       
    return ap_pass_brigade(f->next, bbOut);
}

static apr_status_t mod_gridsite_soap2cgi_in(ap_filter_t *f,
                                             apr_bucket_brigade *pbbOut,
                                             ap_input_mode_t eMode,
                                             apr_read_type_e eBlock,
                                             apr_off_t nBytes)
{
    request_rec *r = f->r;
    conn_rec *c = r->connection;
//    CaseFilterInContext *pCtx;
    apr_status_t ret;

#ifdef NEVERDEFINED

    ret = ap_get_brigade(f->next, pCtx->pbbTmp, eMode, eBlock, nBytes);    
 
    if (!(pCtx = f->ctx)) {
        f->ctx = pCtx = apr_palloc(r->pool, sizeof *pCtx);
        pCtx->pbbTmp = apr_brigade_create(r->pool, c->bucket_alloc);
    }
 
    if (APR_BRIGADE_EMPTY(pCtx->pbbTmp)) {
        ret = ap_get_brigade(f->next, pCtx->pbbTmp, eMode, eBlock, nBytes);
 
        if (eMode == AP_MODE_EATCRLF || ret != APR_SUCCESS)
            return ret;
    }
 
    while(!APR_BRIGADE_EMPTY(pCtx->pbbTmp)) {
        apr_bucket *pbktIn = APR_BRIGADE_FIRST(pCtx->pbbTmp);
        apr_bucket *pbktOut;
        const char *data;
        apr_size_t len;
        char *buf;
        int n;
 
        /* It is tempting to do this...
         * APR_BUCKET_REMOVE(pB);
         * APR_BRIGADE_INSERT_TAIL(pbbOut,pB);
         * and change the case of the bucket data, but that would be wrong
         * for a file or socket buffer, for example...
         */
                                                                                
        if(APR_BUCKET_IS_EOS(pbktIn)) {
            APR_BUCKET_REMOVE(pbktIn);
            APR_BRIGADE_INSERT_TAIL(pbbOut, pbktIn);
            break;
        }
                                                                                
        ret=apr_bucket_read(pbktIn, &data, &len, eBlock);
        if(ret != APR_SUCCESS)
            return ret;
                                                                                
        buf = malloc(len);
        for(n=0 ; n < len ; ++n)
            buf[n] = apr_toupper(data[n]);
                                                                                
        pbktOut = apr_bucket_heap_create(buf, len, 0, c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(pbbOut, pbktOut);
        apr_bucket_delete(pbktIn);
    }
#endif
                                                                                
    return APR_SUCCESS;
}


/*
 * dav_parse_range() is based on modules/dav/main/mod_dav.c from Apache
 */

int dav_parse_range(request_rec *r, apr_off_t *range_start, 
                    apr_off_t *range_end)
{
    const char *range_c;
    char *range;
    char *dash;
    char *slash;

    range_c = apr_table_get(r->headers_in, "content-range");
    if (range_c == NULL)
        return 0;

    range = apr_pstrdup(r->pool, range_c);
    if (strncasecmp(range, "bytes ", 6) != 0
        || (dash = ap_strchr(range, '-')) == NULL
        || (slash = ap_strchr(range, '/')) == NULL) {
        /* malformed header. ignore it (per S14.16 of RFC2616) */
        return 0;
    }

    *dash = *slash = '\0';

    *range_start = apr_atoi64(range + 6);
    *range_end = apr_atoi64(dash + 1);

    if (*range_end < *range_start
        || (slash[1] != '*' && apr_atoi64(slash + 1) <= *range_end)) {
        /* invalid range. ignore it (per S14.16 of RFC2616) */
        return 0;
    }

    /* we now have a valid range */
    return 1;
}

char *make_admin_footer(request_rec *r, mod_gridsite_dir_cfg *conf,
                        int isdirectory)
/*
    make string holding last modified text and admin links
*/
{
    char     *out, *https, *p, *dn = NULL, *file = NULL, *permstr = NULL, 
             *temp, modified[99], *dir_uri, *grst_cred_0 = NULL;
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
         grst_cred_0 = (char *) 
                       apr_table_get(r->connection->notes, "GRST_CRED_0");

    if ((grst_cred_0 != NULL) && 
        (strncmp(grst_cred_0, "X509USER ", sizeof("X509USER")) == 0))
      {
         p = index(grst_cred_0, ' ');
         if (p != NULL)
           {
             p = index(++p, ' ');
             if (p != NULL)
               {
                 p = index(++p, ' ');
                 if (p != NULL)
                   {
                     p = index(++p, ' ');
                     if (p != NULL) dn = p;
                   }
               }
           }
      }
  
    if (dn != NULL) 
      {
        temp = apr_psprintf(r->pool, "You are %s<br>\n", dn);
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
    int    i, fd, n;
    char  *buf, *p, *s, *head_formatted, *header_formatted,
          *body_formatted, *admin_formatted, *footer_formatted, *temp,
           modified[99], *d_namepath, *indexheaderpath, *indexheadertext;
    size_t length;
    struct stat statbuf;
    struct tm   mtime_tm;
    struct dirent **namelist;
    
    if (r->finfo.filetype == APR_NOFILE) return HTTP_NOT_FOUND;
        
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
      
    n = scandir(r->filename, &namelist, 0, versionsort);
    while (n--)
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
                              
               if (S_ISDIR(statbuf.st_mode))
                    temp = apr_psprintf(r->pool, 
                      "<tr><td><a href=\"%s/\" content-length=\"%ld\" "
                      "last-modified=\"%ld\">"
                      "%s/</a></td>"
                      "<td align=right>%ld</td>%s</tr>\n", 
                      namelist[n]->d_name, statbuf.st_size, statbuf.st_mtime,
                      namelist[n]->d_name, 
                      statbuf.st_size, modified);
               else temp = apr_psprintf(r->pool, 
                      "<tr><td><a href=\"%s\" content-length=\"%ld\" "
                      "last-modified=\"%ld\">"
                      "%s</a></td>"
                      "<td align=right>%ld</td>%s</tr>\n", 
                      namelist[n]->d_name, statbuf.st_size, statbuf.st_mtime,
                      namelist[n]->d_name, 
                      statbuf.st_size, modified);

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

    filetemplate = apr_psprintf(r->pool, "%s/%016llxXXXXXX", 
     ap_server_root_relative(r->pool,
     passcodesdir),
     gridauthcookie);

    if (apr_file_mktemp(&fp, 
                        filetemplate, 
                        APR_CREATE | APR_WRITE | APR_EXCL,
                        r->pool)
                      != APR_SUCCESS) return HTTP_INTERNAL_SERVER_ERROR;
                                    
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
               "Created passcode file %s", filetemplate);

    expires_time = apr_time_now() + apr_time_from_sec(3600);
    /* passcode cookies are valid for only 60 mins! */

    apr_file_printf(fp, 
                   "expires=%lu\ndomain=%s\npath=%s\nmethod=%s\n", 
                   (time_t) apr_time_sec(expires_time),
                   r->hostname, r->uri, r->method);
    /* above variables are evaluated in order and method= MUST be last! */

    for (i=0; ; ++i)
       {
         envname_i = apr_psprintf(r->pool, "GRST_CRED_%d", i);
         if (grst_cred_i = (char *)
                           apr_table_get(r->connection->notes, envname_i))
           {
             apr_file_printf(fp, "%s=%s\n", envname_i, grst_cred_i);
           }
         else break; /* GRST_CRED_i are numbered consecutively */
       }

    if (apr_file_close(fp) != APR_SUCCESS) 
      {
        apr_file_remove(filetemplate, r->pool); /* try to clean up */
        return HTTP_INTERNAL_SERVER_ERROR;
      }
    
    /* send redirection header back to client */
       
    cookievalue = rindex(filetemplate, '/');
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
  char        buf[2048];
  size_t      length, total_length;
  int         retcode, stat_ret;
  apr_file_t *fp;
  apr_int32_t open_flag;
  struct stat statbuf;
    
  int       has_range = 0, is_done = 0;
  apr_off_t range_start;
  apr_off_t range_end;
  size_t range_length;
  
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

  has_range = dav_parse_range(r, &range_start, &range_end);

  if (has_range)
      open_flag = APR_WRITE | APR_CREATE | APR_BUFFERED;
  else
      open_flag = APR_WRITE | APR_CREATE | APR_BUFFERED | APR_TRUNCATE;

  if (apr_file_open(&fp, r->filename, open_flag,
      conf->diskmode, r->pool) != 0) return HTTP_INTERNAL_SERVER_ERROR;
   
  /* we force the permissions, rather than accept any existing ones */

  apr_file_perms_set(r->filename, conf->diskmode);

  if (has_range)
    {
      if (apr_file_seek(fp, APR_SET, &range_start) != 0) 
        {
          retcode = HTTP_INTERNAL_SERVER_ERROR;
          //break;
          return retcode;
        }

      range_length = range_end - range_start + 1;
    }

  retcode = ap_setup_client_block(r, REQUEST_CHUNKED_DECHUNK);
  if (retcode == OK)
    {
      if (has_range) total_length = 0;
      if (ap_should_client_block(r))
          while ((length = ap_get_client_block(r, buf, sizeof(buf))) > 0)
            {
              if (has_range && (total_length + length > range_length))
                {
                  length = range_length - total_length;
                  is_done = 1;
                }

              if (apr_file_write(fp, buf, &length) != 0) 
                {
                  retcode = HTTP_INTERNAL_SERVER_ERROR;
                  break;
                }

              if (has_range)
                {
                  if (is_done) break;
                  else total_length += length;
                }
            }
      ap_set_content_length(r, 0);
      ap_set_content_type(r, "text/html");
    }

  if (apr_file_close(fp) != 0) return HTTP_INTERNAL_SERVER_ERROR;

  if (retcode == OK) retcode = (stat_ret == 0) ? HTTP_OK : HTTP_CREATED;

  return retcode;
}

int http_delete_method(request_rec *r, mod_gridsite_dir_cfg *conf)
{
  if (apr_file_remove(r->filename, r->pool) != 0) return HTTP_FORBIDDEN;
       
  ap_set_content_length(r, 0);
  ap_set_content_type(r, "text/html");

  return OK;
}

int http_move_method(request_rec *r, mod_gridsite_dir_cfg *conf)
{
  char *destination_translated = NULL;
  
  if (r->notes != NULL) destination_translated = 
            (char *) apr_table_get(r->notes, "GRST_DESTINATION_TRANSLATED");


  if ((destination_translated == NULL) ||  
      (apr_file_rename(r->filename, destination_translated, r->pool) != 0))
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
   char          *unencname, modified[99], *oneline, *d_namepath;
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

                  oneline = apr_psprintf(pool,
                                     "<tr><td><a href=\"%s\" "
                                     "content-length=\"%ld\" "
                                     "last-modified=\"%ld\">"
                                     "%s</a></td>"
                                     "<td align=right>%ld</td>%s</tr>\n", 
                                     &unencname[fullurilen], statbuf.st_size, 
                                     statbuf.st_mtime, unencname, 
                                     statbuf.st_size, modified);

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

    if (!(s->is_virtual))
      {
        gridhttpport = GRST_HTTP_PORT;
      
        passcodesdir = apr_pstrdup(p, "/var/www/passcodes");
                                      /* GridSiteOnetimesDir dir-path   */

        sitecastdnlists = NULL;

        sitecastgroups[0].quad1 = 0;
        sitecastgroups[0].quad2 = 0;
        sitecastgroups[0].quad3 = 0;
        sitecastgroups[0].quad4 = 0;
        sitecastgroups[0].port  = GRST_HTCP_PORT;
                                      /* GridSiteCastUniPort udp-port */

        for (i=1; i <= GRST_SITECAST_GROUPS; ++i)
                   sitecastgroups[i].port = 0;
                                      /* GridSiteCastGroup mcast-list */

        for (i=1; i <= GRST_SITECAST_ALIASES; ++i)
           {
             sitecastaliases[i].sitecast_url = NULL;
             sitecastaliases[i].local_path   = NULL;
             sitecastaliases[i].server       = NULL;                   
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
                                        /* GridSiteMethods      methods   */

        conf->editable = apr_pstrdup(p, " txt shtml html htm css js php jsp ");
                                        /* GridSiteEditable     types   */

        conf->headfile = apr_pstrdup(p, GRST_HEADFILE);
        conf->footfile = apr_pstrdup(p, GRST_FOOTFILE);
               /* GridSiteHeadFile and GridSiteFootFile  file name */

        conf->gridhttp      = 0;     /* GridSiteGridHTTP      on/off       */
        conf->soap2cgi      = 0;     /* GridSiteSoap2cgi      on/off       */
	conf->aclformat     = apr_pstrdup(p, "GACL");
                                     /* GridSiteACLFormat     gacl/xacml */
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
        conf->soap2cgi      = UNSET; /* GridSiteSoap2cgi      on/off       */
	conf->aclformat     = NULL;  /* GridSiteACLFormat     gacl/xacml   */
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
        
    if (direct->soap2cgi != UNSET) conf->soap2cgi = direct->soap2cgi;
    else                           conf->soap2cgi = server->soap2cgi;

    if (direct->aclformat != NULL) conf->aclformat = direct->aclformat;
    else                           conf->aclformat = server->aclformat;

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
  
    if (strcasecmp(a->cmd->name, "GridSiteOnetimesDir") == 0)
    {
      if (a->server->is_virtual)
       return "GridSiteOnetimesDir cannot be used inside a virtual server";
    
      passcodesdir = apr_pstrdup(a->pool, parm);
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
    int i;
    
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
      for (i=0; i < GRST_SITECAST_ALIASES; ++i) /* look for free slot */
         {
           if (sitecastaliases[i].sitecast_url == NULL)
             {
               sitecastaliases[i].sitecast_url  = parm1;
               sitecastaliases[i].local_path    = parm2;
               sitecastaliases[i].server        = a->server;              
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
    else if (strcasecmp(a->cmd->name, "GridSiteSoap2cgi") == 0)
    {
      ((mod_gridsite_dir_cfg *) cfg)->soap2cgi = flag;
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

    AP_INIT_FLAG("GridSiteSoap2cgi", mod_gridsite_flag_cmds,
                 NULL, OR_FILEINFO, "on or off"),

    AP_INIT_TAKE1("GridSiteACLFormat", mod_gridsite_take1_cmds,
                 NULL, OR_FILEINFO, "format to save access control lists in"),

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

void GRST_creds_to_conn(conn_rec *conn, 
                        STACK_OF(X509) *certstack, X509 *peercert)
{
   int i, lastcred;
   const int maxcreds = 99;
   const size_t credlen = 1024;
   char creds[maxcreds][credlen+1], envname[14];

   if ((certstack != NULL) && (conn->notes != NULL) &&
       (apr_table_get(conn->notes, "GRST_creds_to_conn") != NULL)) return;

   /* Put result of GRSTx509CompactCreds() into connection notes */

   apr_table_set(conn->notes, "GRST_creds_to_conn", "yes");
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, conn->base_server,
                                            "set GRST_creds_to_conn");

   if (GRSTx509CompactCreds(&lastcred, maxcreds, credlen, (char *) creds,
                          certstack, GRST_VOMS_DIR, peercert) == GRST_RET_OK)
     {
       for (i=0; i <= lastcred; ++i)
          {
            apr_table_setn(conn->notes,
                                 apr_psprintf(conn->pool, "GRST_CRED_%d", i),
                                 apr_pstrdup(conn->pool, creds[i]));

            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, conn->base_server,
                                      "store GRST_CRED_%d=%s", i, creds[i]);

          }
                                   
       /* free remaining dup'd certs? */
     }     
}

static int mod_gridsite_perm_handler(request_rec *r)
/*
    Do authentication/authorization here rather than in the normal module
    auth functions since the results of mod_ssl are available.

    We also publish environment variables here if requested by GridSiteEnv.
*/
{
    int          retcode = DECLINED, i, n, file_is_acl = 0,
                 destination_is_acl = 0, proxylevel;
    char        *dn, *p, envname[14], *grst_cred_0 = NULL, *dir_path, 
                *remotehost, s[99], *grst_cred_i, *cookies, *file,
                *gridauthpasscode = NULL, *cookiefile, oneline[1025], *key_i,
                *destination = NULL, *destination_uri = NULL, *querytmp, 
                *destination_prefix = NULL, *destination_translated = NULL;
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

    /* do we need/have per-connection (SSL) cred variable(s)? */
    
    sslconn = (SSLConnRec *) ap_get_module_config(r->connection->conn_config, 
                                                  &ssl_module);

    if ((sslconn != NULL) && (sslconn->ssl != NULL) &&
        (r->connection->notes != NULL) &&
        (apr_table_get(r->connection->notes, "GRST_creds_to_conn") == NULL))
      {
        certstack = SSL_get_peer_cert_chain(sslconn->ssl);
        peercert  = SSL_get_peer_certificate(sslconn->ssl);
      
        GRST_creds_to_conn(r->connection, certstack, peercert);
      }

    proxylevel = ((mod_gridsite_dir_cfg *) cfg)->gsiproxylimit + 1;
    
    if ((user == NULL) && 
        (r->connection->notes != NULL) &&
        ((grst_cred_0 = (char *) 
            apr_table_get(r->connection->notes, "GRST_CRED_0")) != NULL) &&
        (sscanf(grst_cred_0, "X509USER %*d %*d %d ", &proxylevel) == 1) &&
        (proxylevel <= ((mod_gridsite_dir_cfg *) cfg)->gsiproxylimit))
      {
        apr_table_setn(env, "GRST_CRED_0", grst_cred_0);
                                    
        cred_0 = GRSTx509CompactToCred(grst_cred_0);
        if (cred_0 != NULL)
          {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "Using identity %s from SSL/TLS", grst_cred_0);

            user = GRSTgaclUserNew(cred_0);

            /* check for VOMS GRST_CRED_i too */
  
            for (i=1; ; ++i)
               {
                 snprintf(envname, sizeof(envname), "GRST_CRED_%d", i);
                 if (grst_cred_i = (char *) 
                                   apr_table_get(r->connection->notes,envname))
                   { 
                     if (((mod_gridsite_dir_cfg *) cfg)->envs)
                              apr_table_setn(env,
                                             apr_pstrdup(r->pool, envname),
                                             grst_cred_i);
                                    
                     if (cred = GRSTx509CompactToCred(grst_cred_i))
                                        GRSTgaclUserAddCred(user, cred);
                   }
                 else break; /* GRST_CRED_i are numbered consecutively */
               }
          }
      }

    if ((user != NULL) && ((mod_gridsite_dir_cfg *) cfg)->dnlists)
          GRSTgaclUserSetDNlists(user, ((mod_gridsite_dir_cfg *) cfg)->dnlists);

    /* add DNS credential */
    
    remotehost = (char *) ap_get_remote_host(r->connection,
                                  r->per_dir_config, REMOTE_DOUBLE_REV, NULL);
    if ((remotehost != NULL) && (*remotehost != '\0'))
      {            
        cred = GRSTgaclCredNew("dns");
        GRSTgaclCredAddValue(cred, "hostname", remotehost);

        if (user == NULL) user = GRSTgaclUserNew(cred);
        else              GRSTgaclUserAddCred(user, cred);
      }

    /* check for Destination: header and evaluate if present */

    if ((destination = (char *) apr_table_get(r->headers_in,
                                              "Destination")) != NULL)
      {
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
    
    /* this checks for NULL arguments itself */
    if (GRSTgaclDNlistHasUser(((mod_gridsite_dir_cfg *) cfg)->adminlist, user))
      {
        perm = GRST_PERM_ALL;
        if (destination_translated != NULL) destination_perm = GRST_PERM_ALL;
      }
    else
      {
        acl = GRSTgaclAclLoadforFile(r->filename);
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
            for (p = &gridauthpasscode[18]; 
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
                for (p = &gridauthpasscode[18]; 
                     (*p != '\0') && (*p != '&'); ++p)
                                          if (!isalnum(*p)) *p = '\0';
              }            
          }
      }

    if ((gridauthpasscode != NULL) && (gridauthpasscode[0] != '\0')) 
      {
        cookiefile = apr_psprintf(r->pool, "%s/%s",
                 ap_server_root_relative(r->pool,
                 passcodesdir),
                 &gridauthpasscode[18]);
                                      
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
                       else if  (strncmp(oneline, "onetime=yes", 11) == 0)
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
             !GRSTgaclPermHasAdmin(perm) && file_is_acl) 
             
             ) retcode = HTTP_FORBIDDEN;
      }

    return retcode;
}

int GRST_X509_check_issued_wrapper(X509_STORE_CTX *ctx,X509 *x,X509 *issuer)
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
    if (!(ctx->flags & X509_V_FLAG_CB_ISSUER_CHECK)) return 0;
  
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

   /*
    * GSI Proxy user-cert-as-CA handling:
    * we skip Invalid CA errors at this stage, since we will check this
    * again at errdepth=0 for the full chain using GRSTx509CheckChain
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
        errnum = GRSTx509CheckChain(&first_non_ca, ctx);

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
                                   " chain reported by GRSTx509CheckChain()");

            /* Put result of GRSTx509CompactCreds() into connection notes */
            if ((certstack = 
                  (STACK_OF(X509) *) X509_STORE_CTX_get_chain(ctx)) != NULL)
             GRST_creds_to_conn(conn, certstack, NULL);
          }
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
  int             i, outbuf_len, ialias, port;
  char            *filename, *outbuf, *location, *local_uri = NULL;
  struct stat     statbuf;
  SSLSrvConfigRec *ssl_srv;
  
  /* check sanity of requested uri */

  if (strncmp(htcp_mesg->uri->text, "http://", 7) == 0)
    {
      for (i=7; i < GRSThtcpCountstrLen(htcp_mesg->uri); ++i)
         if (htcp_mesg->uri->text[i] == '/') 
           {
             local_uri = &(htcp_mesg->uri->text[i]);
             break;
           }
    }
  else if (strncmp(htcp_mesg->uri->text, "https://", 8) == 0)
    {
      for (i=8; i < GRSThtcpCountstrLen(htcp_mesg->uri); ++i)
         if (htcp_mesg->uri->text[i] == '/') 
           {
             local_uri = &(htcp_mesg->uri->text[i]);
             break;
           }
    }

  if (local_uri == NULL)
    {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, main_server,
              "SiteCast responder only handles http(s):// (%*s requested by %s:%d)",
                        GRSThtcpCountstrLen(htcp_mesg->uri),
                        htcp_mesg->uri->text,
                        inet_ntoa(client_addr_ptr->sin_addr),
                        ntohs(client_addr_ptr->sin_port));      
      return;
    }

  /* find if any GridSiteCastAlias lines match */

  for (ialias=0; ialias < GRST_SITECAST_ALIASES ; ++ialias)
     {
       if (sitecastaliases[ialias].sitecast_url == NULL) return; /* no match */
                             
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
      ssl_srv = (SSLSrvConfigRec *)
       ap_get_module_config(sitecastaliases[ialias].server->module_config,
                                                             &ssl_module);

      port = sitecastaliases[ialias].server->addrs->host_port;
      if (port == 0) port = ((ssl_srv != NULL) && (ssl_srv->enabled))
                                 ? GRST_HTTPS_PORT : GRST_HTTP_PORT;
                
      asprintf(&location, "Location: http%s://%s:%d%s\r\n",
                  ((ssl_srv != NULL) && (ssl_srv->enabled)) ? "s" : "",
                  sitecastaliases[ialias].server->server_hostname, port,
                  local_uri);

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
                "SiteCast UDP Responder fails on setting multicast");
           return; 
         }
         
       ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, main_server,
        "SiteCast UDP Responder listening on %d.%d.%d.%d:%d",
        sitecastgroups[i].quad1, sitecastgroups[i].quad2,
        sitecastgroups[i].quad3, sitecastgroups[i].quad4, sitecastgroups[i].port);
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
      
   return OK;
}
      
static void mod_gridsite_child_init(apr_pool_t *pPool, server_rec *pServer)
{
   GRSTgaclInit();
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
    /* set up the Soap2cgi input and output filters */

    ap_hook_insert_filter(mod_gridsite_soap2cgi_insert, NULL, NULL,
                          APR_HOOK_MIDDLE);

    ap_register_output_filter(Soap2cgiFilterName, mod_gridsite_soap2cgi_out,
                              NULL, AP_FTYPE_RESOURCE);

//    ap_register_input_filter(Soap2cgiFilterName, mod_gridsite_soap2cgi_in,
//                              NULL, AP_FTYPE_RESOURCE);

    /* config and handler stuff */

    ap_hook_post_config(mod_gridsite_server_post_config, NULL, NULL, 
                                                              APR_HOOK_LAST);
    ap_hook_child_init(mod_gridsite_child_init, NULL, NULL, APR_HOOK_MIDDLE);

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
