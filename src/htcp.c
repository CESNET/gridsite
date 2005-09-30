/*
   Copyright (c) 2002-5, Andrew McNab, University of Manchester
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

#ifndef VERSION
#define VERSION "0.0.0"
#endif

#define _GNU_SOURCE

#include <pwd.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <malloc.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <curl/curl.h>

#include "gridsite.h"

/* deal with older versions of libcurl and curl.h */

#ifndef CURLOPT_WRITEDATA
#define CURLOPT_WRITEDATA CURLOPT_FILE
#endif
 
#ifndef CURLOPT_READDATA
#define CURLOPT_READDATA CURLOPT_FILE
#endif

#ifndef CURLE_HTTP_RETURNED_ERROR
#define CURLE_HTTP_RETURNED_ERROR CURLE_HTTP_NOT_FOUND
#endif
 
#define HTCP_GET	1
#define HTCP_PUT	2
#define HTCP_DELETE	3
#define HTCP_LIST	4
#define HTCP_LONGLIST	5
#define HTCP_MKDIR	6
#define HTCP_MOVE	7
#define HTCP_PING	8

#define HTCP_SITECAST_GROUPS 32

struct grst_stream_data { char *source;
                          char *destination;
                          int   ishttps;
                          int   method;
                          FILE *fp;
                          char *cert;
                          char *key;
                          char *capath;
                          char *useragent;
                          char *errorbuf;
                          int   noverify;
                          int   anonymous;
                          int   gridhttp;
                          int   verbose;	
                          int   timeout;
                          char *groups;    } ;
                          
struct grst_index_blob { char   *text;
                         size_t  used;
                         size_t  allocated; } ;

struct grst_dir_list { char   *filename;
                       size_t  length;
                       int     length_set;
                       time_t  modified;
                       int     modified_set; } ; 

struct grst_header_data { int    retcode;                         
                          char  *location;
                          char  *gridhttponetime;
                          size_t length;
                          int    length_set;
                          time_t modified;                           
                          int    modified_set;
                          struct grst_stream_data *common_data; } ;

struct grst_sitecast_group { unsigned char quad1; unsigned char quad2; 
                             unsigned char quad3; unsigned char quad4;
                             int port; int timewait; int ttl; };

size_t headers_callback(void *ptr, size_t size, size_t nmemb, void *p)
/* Find the values of the return code, Content-Length, Last-Modified
   and Location headers */
{
  float f;
  char  *s, *q;
  size_t realsize;
  struct tm modified_tm;
  struct grst_header_data *header_data;
   
  header_data = (struct grst_header_data *) p;
  realsize = size * nmemb;
  s = malloc(realsize + 1);
  memcpy(s, ptr, realsize);
  s[realsize] = '\0';

  if      (sscanf(s, "Content-Length: %d", &(header_data->length)) == 1) 
            header_data->length_set = 1;
  else if (sscanf(s, "HTTP/%f %d ", &f, &(header_data->retcode)) == 2) ;
  else if (strncmp(s, "Location: ", 10) == 0) 
      {
        header_data->location = strdup(&s[10]);
        
        for (q=header_data->location; *q != '\0'; ++q)
         if ((*q == '\r') || (*q == '\n')) *q = '\0';
         
        if (header_data->common_data->verbose > 0)
             fprintf(stderr, "Received Location: %s\n", header_data->location);
      }
  else if (strncmp(s, "Set-Cookie: GRIDHTTP_ONETIME=", 29) == 0) 
      {
        header_data->gridhttponetime = strdup(&s[12]);
        q = index(header_data->gridhttponetime, ';');
        if (q != NULL) *q = '\0';       

        if (header_data->common_data->verbose > 0)
             fprintf(stderr, "Received GridHTTP Auth Cookie: %s\n", 
                             header_data->gridhttponetime);
      }
  else if (strncmp(s, "Last-Modified: ", 15) == 0)
      {
        /* follow RFC 2616: first try RFC 822 (kosher), then RFC 850 and 
           asctime() formats too. Must be GMT whatever the format. */

        if (strptime(&s[15], "%a, %d %b %Y %T GMT", &modified_tm) != NULL)
          {
            header_data->modified = mktime(&modified_tm);
            header_data->modified_set = 1;
          }
        else if (strptime(&s[15], "%a, %d-%b-%y %T GMT", &modified_tm) != NULL)
          {
            header_data->modified = mktime(&modified_tm);
            header_data->modified_set = 1;
          }
        else if (strptime(&s[15], "%a %b %d %T %Y", &modified_tm) != NULL)
          {
            header_data->modified = mktime(&modified_tm);
            header_data->modified_set = 1;
          }
      }
    
  free(s);
  return realsize;
}

int set_std_opts(CURL *easyhandle, struct grst_stream_data *common_data)
{
  struct stat statbuf;

  curl_easy_setopt(easyhandle, CURLOPT_FOLLOWLOCATION, 0);

  if ((common_data->cert != NULL) && (common_data->key != NULL))
    {
       curl_easy_setopt(easyhandle, CURLOPT_SSLENGINE,   NULL);
       curl_easy_setopt(easyhandle, CURLOPT_SSLCERTTYPE, "PEM");
       curl_easy_setopt(easyhandle, CURLOPT_SSLCERT,     common_data->cert);
       curl_easy_setopt(easyhandle, CURLOPT_SSLKEY,      common_data->key);
    }
  else
    {
       curl_easy_setopt(easyhandle, CURLOPT_SSLENGINE,   "RSA");
       curl_easy_setopt(easyhandle, CURLOPT_SSLCERTTYPE, "ENG");
    }

  if (common_data->capath != NULL)
    {
#if (LIBCURL_VERSION_NUM >= 0x070908)
       if ((stat(common_data->capath, &statbuf) == 0) &&
           S_ISDIR(statbuf.st_mode))
            curl_easy_setopt(easyhandle, CURLOPT_CAPATH, common_data->capath);
       else 
#endif       
            curl_easy_setopt(easyhandle, CURLOPT_CAINFO, common_data->capath);
    }

  if (common_data->noverify)
    {
      curl_easy_setopt(easyhandle, CURLOPT_SSL_VERIFYPEER, 0);
      curl_easy_setopt(easyhandle, CURLOPT_SSL_VERIFYHOST, 0);
    }      
  else 
    {
      curl_easy_setopt(easyhandle, CURLOPT_SSL_VERIFYPEER, 2);
      curl_easy_setopt(easyhandle, CURLOPT_SSL_VERIFYHOST, 2);
    }
  
  return 1;
}

int do_copies(char *sources[], char *destination,
              struct grst_stream_data *common_data)
{
  char        *p, *thisdestination;
  int          isrc, anyerror = 0, thiserror, isdirdest;
  CURL        *easyhandle;
  struct stat  statbuf;
  struct       grst_header_data header_data;
  struct curl_slist *gh_header_slist = NULL, *nogh_header_slist = NULL;
  
  easyhandle = curl_easy_init();
  
  if (common_data->gridhttp)
    {               
      asprintf(&p, "Upgrade: GridHTTP/1.0");
      gh_header_slist = curl_slist_append(gh_header_slist, p);
      free(p);
      
      nogh_header_slist = curl_slist_append(nogh_header_slist, "Upgrade:");
    }
  
  curl_easy_setopt(easyhandle, CURLOPT_USERAGENT, common_data->useragent);
  if (common_data->verbose > 1)
                   curl_easy_setopt(easyhandle, CURLOPT_VERBOSE, 1);

  curl_easy_setopt(easyhandle, CURLOPT_HEADERFUNCTION, headers_callback);
  curl_easy_setopt(easyhandle, CURLOPT_WRITEHEADER,   &header_data);

  set_std_opts(easyhandle, common_data);

  curl_easy_setopt(easyhandle, CURLOPT_ERRORBUFFER, common_data->errorbuf);

  if (destination[strlen(destination) - 1] != '/') 
    {
      isdirdest = 0;
      thisdestination = destination;
    }
  else isdirdest = 1;

  for (isrc=0; sources[isrc] != NULL; ++isrc)
     {
       if (isdirdest)
         {
           p = rindex(sources[isrc], '/');
           if (p == NULL) p = sources[isrc];
           else           p++;

           asprintf(&thisdestination, "%s%s", destination, p);
         }
 
       if (common_data->verbose > 0)
            fprintf(stderr, "%s -> %s\n", sources[isrc], thisdestination);

       if (common_data->method == HTCP_GET)
         {
           common_data->fp = fopen(thisdestination, "w");
           if (common_data->fp == NULL)
             {
               fprintf(stderr,"... failed to open destination source file %s\n",
                               thisdestination);
               anyerror = 99;
               if (isdirdest) free(thisdestination);
               continue;
             }

           curl_easy_setopt(easyhandle, CURLOPT_WRITEDATA, common_data->fp);
           curl_easy_setopt(easyhandle, CURLOPT_URL,       sources[isrc]);
           
           if ((common_data->gridhttp) &&
               (strncmp(sources[isrc], "https://", 8) == 0))
             {
               if (common_data->verbose > 0)
                 fprintf(stderr, "Add  Upgrade: GridHTTP/1.0\n");
                 
               curl_easy_setopt(easyhandle,CURLOPT_HTTPHEADER,gh_header_slist);
             }
           else 
             curl_easy_setopt(easyhandle,CURLOPT_HTTPHEADER,nogh_header_slist);
         }
       else if (common_data->method == HTCP_PUT)
         {
           if (stat(sources[isrc], &statbuf) != 0)
             {
               fprintf(stderr, "... source file %s not found\n", sources[isrc]);
               anyerror = 99;
               if (isdirdest) free(thisdestination);
               continue;
             }
           
           common_data->fp = fopen(sources[isrc], "r");
           if (common_data->fp == NULL)
             {
               fprintf(stderr, "... failed to open source file %s\n",
                               sources[isrc]);
               anyerror = 99;
               if (isdirdest) free(thisdestination);
               continue;
             }

           curl_easy_setopt(easyhandle, CURLOPT_READDATA,   common_data->fp);
           curl_easy_setopt(easyhandle, CURLOPT_URL,        thisdestination);
           curl_easy_setopt(easyhandle, CURLOPT_INFILESIZE, statbuf.st_size);
           curl_easy_setopt(easyhandle, CURLOPT_UPLOAD,   1);

           if ((common_data->gridhttp) &&
               (strncmp(thisdestination, "https://", 8) == 0))
               curl_easy_setopt(easyhandle,CURLOPT_HTTPHEADER,gh_header_slist);
           else 
             curl_easy_setopt(easyhandle,CURLOPT_HTTPHEADER,nogh_header_slist);
         }

       header_data.retcode  = 0;
       header_data.location = NULL;
       header_data.gridhttponetime = NULL;
       header_data.common_data = common_data;
       thiserror = curl_easy_perform(easyhandle);
       
       fclose(common_data->fp);

       if ((common_data->gridhttp) &&
           (thiserror == 0) &&
           (header_data.retcode == 302) &&
           (header_data.location != NULL) &&
           (strncmp(header_data.location, "http://", 7) == 0) &&
           (header_data.gridhttponetime != NULL))
         {
           if (common_data->verbose > 0)
             fprintf(stderr, "... Found (%d)\nGridHTTP redirect to %s\n",
                     header_data.retcode, header_data.location);

           /* try again with new URL and all the previous CURL options */

           if (common_data->method == HTCP_GET)
             {
               common_data->fp = fopen(thisdestination, "w");
               if (common_data->fp == NULL)
                 {
                   fprintf(stderr, "... failed to open destination source "
                                   "file %s\n", thisdestination);
                   anyerror = 99;
                   if (isdirdest) free(thisdestination);
                   continue;
                 }
             }
           else if (common_data->method == HTCP_PUT)
             {
               common_data->fp = fopen(sources[isrc], "r");
               if (common_data->fp == NULL)
                 {
                   fprintf(stderr, "... failed to open source file %s\n",
                               sources[isrc]);
                   anyerror = 99;
                   if (isdirdest) free(thisdestination);
                   continue;
                 }
             }

           header_data.retcode  = 0;           
           curl_easy_setopt(easyhandle, CURLOPT_URL, header_data.location);
           curl_easy_setopt(easyhandle, CURLOPT_HTTPHEADER, nogh_header_slist);
           curl_easy_setopt(easyhandle, CURLOPT_COOKIE, 
                                                  header_data.gridhttponetime);
           thiserror = curl_easy_perform(easyhandle);

           fclose(common_data->fp);
         }

       if ((thiserror != 0) ||
           (header_data.retcode <  200) ||
           (header_data.retcode >= 300))
         {
           fprintf(stderr, "... curl error: %s (%d), HTTP error: %d\n",
                   common_data->errorbuf, thiserror, header_data.retcode);
                   
           if (thiserror != 0) anyerror = thiserror;
           else                anyerror = header_data.retcode;
         }
       else if (common_data->verbose > 0) 
                  fprintf(stderr, "... OK (%d)\n", header_data.retcode);
        
       if (isdirdest) free(thisdestination);
     }

  curl_easy_cleanup(easyhandle);
     
  return anyerror;
}

int do_deletes(char *sources[], struct grst_stream_data *common_data)
{
  int    isrc, anyerror = 0, thiserror;
  CURL  *easyhandle;
  struct grst_header_data header_data;
  
  header_data.common_data = common_data;

  easyhandle = curl_easy_init();
  
  curl_easy_setopt(easyhandle, CURLOPT_USERAGENT, common_data->useragent);
  if (common_data->verbose > 1)
                   curl_easy_setopt(easyhandle, CURLOPT_VERBOSE, 1);

  curl_easy_setopt(easyhandle, CURLOPT_HEADERFUNCTION, headers_callback);
  curl_easy_setopt(easyhandle, CURLOPT_WRITEHEADER,   &header_data);

  curl_easy_setopt(easyhandle, CURLOPT_ERRORBUFFER,   common_data->errorbuf);
  curl_easy_setopt(easyhandle, CURLOPT_CUSTOMREQUEST, "DELETE");
  curl_easy_setopt(easyhandle, CURLOPT_NOBODY,        1);

  set_std_opts(easyhandle, common_data);

  for (isrc=0; sources[isrc] != NULL; ++isrc)
     {
       if (common_data->verbose > 0)
            fprintf(stderr, "Deleting %s\n", sources[isrc]);

       curl_easy_setopt(easyhandle, CURLOPT_URL, sources[isrc]);

       header_data.retcode = 0;
       thiserror = curl_easy_perform(easyhandle);
       
       if ((thiserror != 0) ||
           (header_data.retcode <  200) ||
           (header_data.retcode >= 300))
         {
           fprintf(stderr, "... curl error: %s (%d), HTTP error: %d\n",
                   common_data->errorbuf, thiserror, header_data.retcode);
           
           if (thiserror != 0) anyerror = thiserror;
           else                anyerror = header_data.retcode;
         }
       else if (common_data->verbose > 0) 
                     fprintf(stderr, "... OK (%d)\n", header_data.retcode);
     }

  curl_easy_cleanup(easyhandle);
     
  return anyerror;
}

int do_move(char *source, char *destination, 
            struct grst_stream_data *common_data)
{
  int    anyerror = 0, thiserror;
  char  *destination_header;
  CURL  *easyhandle;
  struct grst_header_data header_data;
  struct curl_slist *header_slist = NULL;
  
  easyhandle = curl_easy_init();
  
  header_data.common_data = common_data;

  easyhandle = curl_easy_init();
  
  asprintf(&destination_header, "Destination: %s", destination);
  header_slist = curl_slist_append(header_slist, destination_header);
  curl_easy_setopt(easyhandle, CURLOPT_HTTPHEADER, header_slist);

  curl_easy_setopt(easyhandle, CURLOPT_USERAGENT, common_data->useragent);
  if (common_data->verbose > 1)
                   curl_easy_setopt(easyhandle, CURLOPT_VERBOSE, 1);

  curl_easy_setopt(easyhandle, CURLOPT_HEADERFUNCTION, headers_callback);
  curl_easy_setopt(easyhandle, CURLOPT_WRITEHEADER,   &header_data);

  curl_easy_setopt(easyhandle, CURLOPT_ERRORBUFFER,   common_data->errorbuf);
  curl_easy_setopt(easyhandle, CURLOPT_CUSTOMREQUEST, "MOVE");
  curl_easy_setopt(easyhandle, CURLOPT_NOBODY,        1);

  set_std_opts(easyhandle, common_data);

  if (common_data->verbose > 0)
            fprintf(stderr, "Moving %s to %s\n", source, destination);

  curl_easy_setopt(easyhandle, CURLOPT_URL, source);

  header_data.retcode = 0;
  thiserror = curl_easy_perform(easyhandle);
       
  if ((thiserror != 0) ||
           (header_data.retcode <  200) ||
           (header_data.retcode >= 300))
         {
           fprintf(stderr, "... curl error: %s (%d), HTTP error: %d\n",
                   common_data->errorbuf, thiserror, header_data.retcode);
           
           if (thiserror != 0) anyerror = thiserror;
           else                anyerror = header_data.retcode;
         }
  else if (common_data->verbose > 0) 
                     fprintf(stderr, "... OK (%d)\n", header_data.retcode);

  curl_easy_cleanup(easyhandle);
     
  return anyerror;
}

int do_mkdirs(char *sources[], struct grst_stream_data *common_data)
{
  int    isrc, anyerror = 0, thiserror;
  CURL  *easyhandle;
  struct grst_header_data header_data;
  
  header_data.common_data = common_data;

  easyhandle = curl_easy_init();
  
  curl_easy_setopt(easyhandle, CURLOPT_USERAGENT, common_data->useragent);
  if (common_data->verbose > 1)
                   curl_easy_setopt(easyhandle, CURLOPT_VERBOSE, 1);

  curl_easy_setopt(easyhandle, CURLOPT_HEADERFUNCTION, headers_callback);
  curl_easy_setopt(easyhandle, CURLOPT_WRITEHEADER,   &header_data);

  curl_easy_setopt(easyhandle, CURLOPT_ERRORBUFFER,   common_data->errorbuf);
  curl_easy_setopt(easyhandle, CURLOPT_CUSTOMREQUEST, "PUT");
  curl_easy_setopt(easyhandle, CURLOPT_NOBODY,        1);

  set_std_opts(easyhandle, common_data);

  for (isrc=0; sources[isrc] != NULL; ++isrc)
     {
       if (common_data->verbose > 0)
            fprintf(stderr, "Make directory %s\n", sources[isrc]);

       curl_easy_setopt(easyhandle, CURLOPT_URL, sources[isrc]);

       header_data.retcode = 0;
       thiserror = curl_easy_perform(easyhandle);
       
       if ((thiserror != 0) ||
           (header_data.retcode <  200) ||
           (header_data.retcode >= 300))
         {
           fprintf(stderr, "... curl error: %s (%d), HTTP error: %d\n",
                   common_data->errorbuf, thiserror, header_data.retcode);
           
           if (thiserror != 0) anyerror = thiserror;
           else                anyerror = header_data.retcode;
         }
       else if (common_data->verbose > 0)  
                        fprintf(stderr, "... OK (%d)\n", header_data.retcode);
     }

  curl_easy_cleanup(easyhandle);
     
  return anyerror;
}

int do_ping(struct grst_stream_data *common_data_ptr)
{
  int request_length, response_length, i, ret, s, igroup;
  struct sockaddr_in srv, from;
  socklen_t fromlen;
#define MAXBUF 8192  
  char *request, response[MAXBUF], *p;
  GRSThtcpMessage msg;
  struct timeval start_timeval, wait_timeval, response_timeval;
  struct grst_sitecast_group sitecast_groups[HTCP_SITECAST_GROUPS];
  fd_set readsckts;

  /* parse common_data_ptr->groups */ 

  p = common_data_ptr->groups;
  igroup = -1;

  for (igroup=-1; igroup+1 < HTCP_SITECAST_GROUPS; ++igroup)
     {  
       sitecast_groups[igroup+1].port     = GRST_HTCP_PORT;
       sitecast_groups[igroup+1].timewait = 1;
       sitecast_groups[igroup+1].ttl      = 1;
       
       ret = sscanf(p, "%d.%d.%d.%d:%d:%d:%d", 
                 &(sitecast_groups[igroup+1].quad1),
                 &(sitecast_groups[igroup+1].quad2),    
                 &(sitecast_groups[igroup+1].quad3),
                 &(sitecast_groups[igroup+1].quad4),    
                 &(sitecast_groups[igroup+1].port),
                 &(sitecast_groups[igroup+1].timewait), 
                 &(sitecast_groups[igroup+1].ttl));

       if (ret == 0) break; /* end of list ? */
         
       if (ret < 4)
         {
           fprintf(stderr, "Failed to parse multicast group "
                     "parameter %s\n", p);
           return CURLE_FAILED_INIT;
         }
           
       ++igroup;
       
       if ((p = index(p, ',')) == NULL) break;       
       ++p;
     }

  if (igroup == -1)
    {
      fprintf(stderr, "Failed to parse multicast group parameter %s\n", p);
      return CURLE_FAILED_INIT;
    }

  if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
    {
      fprintf(stderr, "Failed to open UDP socket\n");
      return CURLE_FAILED_INIT;
    }

  /* loop through multicast groups and send off the NOP pings */

  gettimeofday(&start_timeval, NULL);

  for (i=0; i <= igroup; ++i)
     {
       bzero(&srv, sizeof(srv));
       srv.sin_family = AF_INET;
       srv.sin_port = htons(sitecast_groups[i].port);
       srv.sin_addr.s_addr = htonl(sitecast_groups[i].quad1*0x1000000
                                 + sitecast_groups[i].quad2*0x10000
                                 + sitecast_groups[i].quad3*0x100
                                 + sitecast_groups[i].quad4);

       GRSThtcpNOPrequestMake(&request, &request_length, 
                              (int) (start_timeval.tv_usec + i));
     
       sendto(s, request, request_length, 0, (struct sockaddr *) &srv,
                                                    sizeof(srv));
       free(request);
     }

  /* reusing wait_timeval is a Linux-specific feature of select() */
  wait_timeval.tv_sec = common_data_ptr->timeout 
                                 ? common_data_ptr->timeout : 60;
  wait_timeval.tv_usec = 0;

  while ((wait_timeval.tv_sec > 0) || (wait_timeval.tv_usec > 0))
       {
         FD_ZERO(&readsckts);
         FD_SET(s, &readsckts);
  
         ret = select(s + 1, &readsckts, NULL, NULL, &wait_timeval);
         gettimeofday(&response_timeval, NULL);

         if (ret > 0)
           {
             response_length = recvfrom(s, response, MAXBUF,
                                        0, &from, &fromlen);
  
             if ((GRSThtcpMessageParse(&msg, response, response_length) 
                                                      == GRST_RET_OK) &&
                 (msg.opcode == 0) && (msg.rr == 1) && 
                 (msg.trans_id >= (int) start_timeval.tv_usec) &&
                 (msg.trans_id <= (int) (start_timeval.tv_usec + igroup)))
               {
                 printf("%s:%d %.3fms\n", 
                          inet_ntoa(from.sin_addr),
                          ntohs(from.sin_port), 
                          (((long) 1000000 * response_timeval.tv_sec) +
                           ((long) response_timeval.tv_usec) -
                           ((long) 1000000 * start_timeval.tv_sec) -
                           ((long) start_timeval.tv_usec)) / 1000.0);
               }
           }
       }

   return GRST_RET_OK;
}

size_t rawindex_callback(void *ptr, size_t size, size_t nmemb, void *data)
{
  if ( ((struct grst_index_blob *) data)->used + size * nmemb >=
                             ((struct grst_index_blob *) data)->allocated )
    {
      ((struct grst_index_blob *) data)->allocated = 
        ((struct grst_index_blob *) data)->used + size * nmemb + 4096;

      ((struct grst_index_blob *) data)->text = 
         realloc( ((struct grst_index_blob *) data)->text,
                  ((struct grst_index_blob *) data)->allocated );
    }
    
  memcpy( &( ((struct grst_index_blob *) 
                 data)->text[((struct grst_index_blob *) data)->used] ),
          ptr, size * nmemb);
          
  ((struct grst_index_blob *) data)->used += size * nmemb;
  
  return size * nmemb;
}

char *canonicalise(char *link, char *source)
{
  int   i, j, srclen;
  char *s;

  srclen = strlen(source);

  if ((strncmp(link, "https://", 8) == 0) ||
      (strncmp(link, "http://", 7) == 0))
    {
      if (strncmp(link, source, srclen) != 0) return NULL; /* other site */
      
      if (link[srclen] == '\0') return NULL; /* we dont self-link! */
      
      for (i=0; link[srclen + i] != '\0'; ++i)
        if (link[srclen + i] == '/')
          { 
            if (link[srclen + i + 1] != '\0') return NULL; /* no subdirs */
            else return strdup(&link[srclen]); /* resolves to this dir */
          }
    }
  else if (link[0] != '/') /* relative link - need to check for subsubdirs */
    {
      for (i=0; link[i] != '\0'; ++i) 
        if ((link[i] == '/') && (link[i+1] != '\0')) return NULL;

      s = strdup(link);
      
      for (i=0; s[i] != '\0'; ++i) 
       if (s[i] == '#')
         {
           s[i] = '\0';
           break;
         }

      return s;
    }

  /* absolute link on this server, starting / */

  for (i=8; source[i] != '\0'; ++i) if (source[i] == '/') break;
       
  if (strncmp(link, &source[i], srclen - i) != 0) return NULL;

  for (j = srclen - i; link[j] != '\0'; ++j) 
        if ((link[j] == '/') && (link[j+1] != '\0')) return NULL;
        
  s = strdup(&link[srclen - i]);
      
  for (i=0; s[i] != '\0'; ++i) 
       if (s[i] == '#')
         {
           s[i] = '\0';
           break;
         }

  if (s[0] == '\0') /* on second thoughts... */
    {
      free(s);
      return NULL;
    }
         
  return s;      
}

int grst_dir_list_cmp(const void *a, const void *b)
{
  return strcmp( ((struct grst_dir_list *) a)->filename, 
                 ((struct grst_dir_list *) b)->filename);
}

struct grst_dir_list *index_to_dir_list(char *text, char *source)
{
  int   taglevel = 0, wordnew = 1, i, namestart, used = 0, 
        allocated = 256;
  char *p, *s;
  struct grst_dir_list *list;
  
  list = (struct grst_dir_list *)
              malloc(allocated * sizeof(struct grst_dir_list));
              
  list[0].filename     = NULL;
  list[0].length       = 0;
  list[0].length_set   = 0;
  list[0].modified     = 0;
  list[0].modified_set = 0;
    
  for (p=text; *p != '\0'; ++p)
     {
       if (*p == '<') 
         {
           ++taglevel;
           
           if ((taglevel == 1) && (list[used].filename != NULL))
             {
               ++used;
               if (used >= allocated) 
                 {
                   allocated += 256;
                   list = (struct grst_dir_list *)
                           realloc((void *) list,
                                   allocated * sizeof(struct grst_dir_list));
                 }
                 
               list[used].filename     = NULL;
               list[used].length       = 0;
               list[used].length_set   = 0;
               list[used].modified     = 0;
               list[used].modified_set = 0;
             }

           wordnew = 1;
           continue;
         }

       if (*p == '>') 
         {
           --taglevel;
           wordnew = 1;
           continue;
         }
         
       if (isspace(*p))
         {
           wordnew = 1;
           continue;
         }

       if ((wordnew) && (taglevel == 1))
         {        
           if (((*p == 'h') || (*p == 'H')) && 
               (strncasecmp(p, "href=", 5) == 0))
             {
               if (p[5] == '"') { namestart = 6;
                                  for (i=namestart; (p[i] != '\0') &&
                                                    (p[i] != '"' ) &&
                                                    (p[i] != '\n') &&
                                                    (p[i] != '\t') &&
                                                    (p[i] != '>' ) ; ++i) ; }
               else { namestart = 5;
                      for (i=namestart; (p[i] != '\0') &&
                                        (p[i] != '"' ) &&
                                        (p[i] != ' ' ) &&
                                        (p[i] != '\n') &&
                                        (p[i] != '\t') &&
                                        (p[i] != ')' ) &&
                                        (p[i] != '>' ) ; ++i) ; }
               if (i > namestart) 
                 {
                   s = malloc(1 + i - namestart);
                   memcpy(s, &p[namestart], i - namestart);
                   s[i - namestart] = '\0';

                   list[used].filename = canonicalise(s, source);
                   free(s);
                 }
                 
               p = &p[i-1]; /* -1 since continue results in ++i */
               continue;
             }

           if (((*p == 'c') || (*p == 'C')) && 
               (strncasecmp(p, "content-length=", 15) == 0))
             {
               list[used].length     = 0;
               list[used].length_set = 1;
               
               if (p[15] == '"') list[used].length = atoi(&p[16]);
               else              list[used].length = atoi(&p[15]);

               p = &p[15];
               continue;
             }

           if (((*p == 'l') || (*p == 'L')) && 
               (strncasecmp(p, "last-modified=", 14) == 0))
             {
               list[used].modified     = 0;
               list[used].modified_set = 1;
               
               if (p[14] == '"') list[used].modified = atoi(&p[15]);
               else              list[used].modified = atoi(&p[14]);

               p = &p[14];
               continue;
             }
         }
         
       wordnew = 0;
     }  

  qsort((void *) list, used, sizeof(struct grst_dir_list), grst_dir_list_cmp);

  return list;  
}

int do_listings(char *sources[], struct grst_stream_data *common_data,
                int islonglist)
{
  int          isrc, anyerror = 0, thiserror, i, isdir, ilast;
  CURL        *easyhandle;
  const char  *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", 
                            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
  char        *s;
  struct       grst_index_blob  rawindex;
  struct       grst_dir_list   *list;
  struct       grst_header_data header_data;
  struct       tm               modified_tm;
  time_t                        now;

  time(&now);

  header_data.common_data = common_data;

  easyhandle = curl_easy_init();
  
  curl_easy_setopt(easyhandle, CURLOPT_USERAGENT, common_data->useragent);
  if (common_data->verbose > 1)
                   curl_easy_setopt(easyhandle, CURLOPT_VERBOSE, 1);

  curl_easy_setopt(easyhandle, CURLOPT_WRITEHEADER,   &header_data);
  curl_easy_setopt(easyhandle, CURLOPT_HEADERFUNCTION, headers_callback);

  curl_easy_setopt(easyhandle, CURLOPT_ERRORBUFFER, common_data->errorbuf);

  set_std_opts(easyhandle, common_data);

  for (isrc=0; sources[isrc] != NULL; ++isrc)
     {
       if (common_data->verbose > 0)
            fprintf(stderr, "Listing %s\n", sources[isrc]);
            
       if (sources[1] != NULL) printf("\n%s:\n", sources[isrc]);

       curl_easy_setopt(easyhandle, CURLOPT_URL, sources[isrc]);

       if (sources[isrc][strlen(sources[isrc])-1] == '/')
         {
           isdir = 1;
           curl_easy_setopt(easyhandle,CURLOPT_WRITEFUNCTION,rawindex_callback);
           curl_easy_setopt(easyhandle,CURLOPT_WRITEDATA,(void *) &rawindex);
           curl_easy_setopt(easyhandle,CURLOPT_NOBODY,0);
           rawindex.text      = NULL;
           rawindex.used      = 0;
           rawindex.allocated = 0;
         }
       else
         {
           isdir = 0;
           curl_easy_setopt(easyhandle, CURLOPT_WRITEFUNCTION, NULL);
           curl_easy_setopt(easyhandle, CURLOPT_WRITEDATA, NULL);
           curl_easy_setopt(easyhandle, CURLOPT_NOBODY, 1);
         }

       header_data.gridhttponetime = NULL;
       header_data.length_set   = 0;
       header_data.modified_set = 0;
       header_data.retcode      = 0;
       thiserror = curl_easy_perform(easyhandle);
       
       if ((thiserror != 0) ||
           (header_data.retcode <  200) ||
           (header_data.retcode >= 300))
         {
           fprintf(stderr, "... curl error: %s (%d), HTTP error: %d\n",
                   common_data->errorbuf, thiserror, header_data.retcode);
           
           if (thiserror != 0) anyerror = thiserror;
           else                anyerror = header_data.retcode;
         }
       else if (isdir)
         {
           if (common_data->verbose > 0) 
                  fprintf(stderr, "... OK (%d)\n", header_data.retcode);
           
           rawindex.text[rawindex.used] = '\0';

           list  = index_to_dir_list(rawindex.text, sources[isrc]);
           ilast = -1;

           for (i=0; list[i].filename != NULL; ++i)
              {
                if (list[i].filename[0] == '.') continue;
                
                if (strncmp(list[i].filename, "mailto:", 7) == 0) continue;
                
                if ((ilast >= 0) && 
                    (strcmp(list[i].filename, list[ilast].filename) == 0))
                                                                 continue;
                ilast=i;

                if (islonglist)
                  {
                    if (!list[i].length_set || !list[i].modified_set)
                      {
                        curl_easy_setopt(easyhandle, CURLOPT_WRITEFUNCTION, 
                                                                        NULL);
                        curl_easy_setopt(easyhandle, CURLOPT_WRITEDATA, NULL);
                        curl_easy_setopt(easyhandle, CURLOPT_NOBODY, 1);
                        
                        asprintf(&s, "%s%s", sources[isrc], list[i].filename);                        
                        curl_easy_setopt(easyhandle, CURLOPT_URL, s);

                        header_data.gridhttponetime = NULL;
                        header_data.length_set   = 0;
                        header_data.modified_set = 0;
                        header_data.retcode = 0;
                        thiserror = curl_easy_perform(easyhandle);                        
                        free(s);
                        
                        if ((thiserror == 0) && 
                            (header_data.retcode >= 200) &&
                            (header_data.retcode <= 299))
                          {
                            if (header_data.length_set)
                              {
                                list[i].length_set = 1;
                                list[i].length     = header_data.length;
                              }
                          
                            if (header_data.modified_set)
                              {
                                list[i].modified_set = 1;
                                list[i].modified     = header_data.modified;
                              }
                          }
                      }

                    if (list[i].length_set) printf("%10ld ", list[i].length);
                    else fputs("         ? ", stdout);
                    
                    if (list[i].modified_set)
                      {
                        localtime_r(&(list[i].modified), &modified_tm);

                        if (list[i].modified < now - 15552000)
                             printf("%s %2d  %4d ", 
                               months[modified_tm.tm_mon],
                               modified_tm.tm_mday, 
                               modified_tm.tm_year + 1900);
                        else printf("%s %2d %02d:%02d ",
                               months[modified_tm.tm_mon],
                               modified_tm.tm_mday, 
                               modified_tm.tm_hour,
                               modified_tm.tm_min);
                      }
                    else fputs("  ?  ?     ? ", stdout);
                  }

                puts(list[i].filename);                  
              }
         }
       else
         {
           if (islonglist)
             {
               printf("%10ld ", header_data.length);
                    
               localtime_r(&(header_data.modified), &modified_tm);

               if (header_data.modified < now - 15552000)
                         printf("%s %2d  %4d ", 
                             months[modified_tm.tm_mon],
                             modified_tm.tm_mday, 
                             modified_tm.tm_year + 1900);
               else printf("%s %2d %02d:%02d ",
                             months[modified_tm.tm_mon],
                             modified_tm.tm_mday, 
                             modified_tm.tm_hour,
                             modified_tm.tm_min);
             }

           puts(sources[isrc]);
         }
     }

  curl_easy_cleanup(easyhandle);
     
  return anyerror;
}

#if (LIBCURL_VERSION_NUM < 0x070908)
char *make_tmp_ca_roots(char *dir)
/* libcurl before 7.9.8 doesnt support CURLOPT_CAPATH and the directory,
   so we make a temporary file with the concatenated CA root certs: that
   is, all the files in that directory which end in .0 */
{
  int    ofd, ifd, c;
  size_t size;
  char   tmp_ca_roots[] = "/tmp/.ca-roots-XXXXXX", buffer[4096], *s;
  DIR   *rootsDIR;
  struct dirent *root_ent;
  
  if ((rootsDIR = opendir(dir)) == NULL) return NULL;
  
  if ((ofd = mkstemp(tmp_ca_roots)) == -1)
    {
      closedir(rootsDIR);
      return NULL;
    }

  while ((root_ent = readdir(rootsDIR)) != NULL)
       {
         if ((root_ent->d_name[0] != '.') &&
             (strlen(root_ent->d_name) > 2) && 
             (strncmp(&(root_ent->d_name[strlen(root_ent->d_name)-2]),
                                                        ".0", 2) == 0))
           {
             asprintf(&s, "%s/%s", dir, root_ent->d_name);           
             ifd = open(s, O_RDONLY);             
             free(s);
             
             if (ifd != -1)
               {
                 while ((size = read(ifd, buffer, sizeof(buffer))) > 0)
                                                 write(ofd, buffer, size);             
                 close(ifd);
               }
           }
       }

  closedir(rootsDIR);
  
  if (close(ofd) == 0) return strdup(tmp_ca_roots);

  unlink(tmp_ca_roots); /* try to clean up */
  
  return NULL;
}
#endif

void printsyntax(char *argv0)
{
  char *p;
  
  p = rindex(argv0, '/');
  if (p != NULL) ++p;
  else           p = argv0;

  fprintf(stderr, "%s [options]  Source-URL[s]  [Destination URL]\n"
  "%s is one of a set of clients to fetch files or directory listings\n"
"from remote servers using HTTP or HTTPS, or to put or delete files or\n"
"directories onto remote servers using HTTPS. htcp is similar to scp(1)\n"
"but uses HTTP/HTTPS rather than ssh as its transfer protocol.\n"
"See the htcp(1) or http://www.gridsite.org/ for details.\n"
"(Version: %s)\n", p, p, VERSION);
}

int main(int argc, char *argv[])
{
  char **sources, *destination = NULL, *executable, *p;
  int    c, i, option_index, anyerror;
  struct stat statbuf;
  struct grst_stream_data common_data;
  struct grst_sitecast_group sitecast_groups[HTCP_SITECAST_GROUPS];
  struct passwd *userpasswd;
  struct option long_options[] = {	{"verbose",		0, 0, 'v'},
                			{"cert",		1, 0, 0},
			                {"key",			1, 0, 0},
             				{"capath",		1, 0, 0},
                			{"delete",		0, 0, 0},
					{"list",		0, 0, 0},
                			{"long-list",		0, 0, 0},
                			{"mkdir",		0, 0, 0},
                			{"no-verify",		0, 0, 0},
                			{"anon",		0, 0, 0},
                			{"grid-http",		0, 0, 0},
                			{"move",		0, 0, 0},
                			{"ping",		0, 0, 0},
                			{"groups",		1, 0, 0},
                			{"timeout",		1, 0, 0},
                			{0, 0, 0, 0}  };

#if (LIBCURL_VERSION_NUM < 0x070908)
  char *tmp_ca_roots = NULL;
#endif

  if (argc == 1) 
    {
      printsyntax(argv[0]);
      return 0;
    }
 
  common_data.cert      = NULL;
  common_data.key       = NULL;
  common_data.capath    = NULL;
  common_data.method    = 0;
  common_data.errorbuf  = malloc(CURL_ERROR_SIZE);
  asprintf(&(common_data.useragent),
                          "htcp/%s (http://www.gridsite.org/)", VERSION);
  common_data.verbose   = 0;
  common_data.noverify  = 0;
  common_data.anonymous = 0;
  common_data.gridhttp  = 0;
  
  common_data.groups    = NULL;
  common_data.timeout   = 0;
    
  while (1)
       {
         option_index = 0;

         c = getopt_long(argc, argv, "v", long_options, &option_index);

         if      (c == -1) break;
         else if (c == 0)
           {
             if      (option_index == 1) common_data.cert      = optarg;
             else if (option_index == 2) common_data.key       = optarg; 
             else if (option_index == 3) common_data.capath    = optarg;
             else if (option_index == 4) common_data.method    = HTCP_DELETE;
             else if (option_index == 5) common_data.method    = HTCP_LIST;
             else if (option_index == 6) common_data.method    = HTCP_LONGLIST;
             else if (option_index == 7) common_data.method    = HTCP_MKDIR;
             else if (option_index == 8) common_data.noverify  = 1;
             else if (option_index == 9) common_data.anonymous = 1;
             else if (option_index ==10) common_data.gridhttp  = 1;
             else if (option_index ==11) common_data.method    = HTCP_MOVE;
             else if (option_index ==12) common_data.method    = HTCP_PING;
             else if (option_index ==13) common_data.groups    = optarg;
             else if (option_index ==14) common_data.timeout   = atoi(optarg);
           }
         else if (c == 'v') ++(common_data.verbose);
       }

  if (common_data.verbose > 0) 
    {
      p = rindex(argv[0], '/');
      if (p != NULL) ++p;
      else           p = argv[0];
      fprintf(stderr, "%s version %s\n", p, VERSION);
    }

  if (common_data.anonymous) /* prevent any use of user certs */
    {
      common_data.cert = NULL;
      common_data.key  = NULL;
    }  
  else if ((common_data.cert == NULL) && (common_data.key != NULL)) 
           common_data.cert = common_data.key;
  else if ((common_data.cert != NULL) && (common_data.key == NULL))
           common_data.key = common_data.cert;
  else if ((common_data.cert == NULL) && (common_data.key == NULL))
    {
      common_data.cert = getenv("X509_USER_PROXY");
      if (common_data.cert != NULL) common_data.key = common_data.cert;
      else
        {
          asprintf(&(common_data.cert), "/tmp/x509up_u%d", geteuid());
          
          /* one fine day, we will check the proxy file for expiry too ... */
          
          if (stat(common_data.cert, &statbuf) == 0)
                     common_data.key = common_data.cert;                     
          else
            {
              common_data.cert = getenv("X509_USER_CERT");
              common_data.key  = getenv("X509_USER_KEY");
              
              userpasswd = getpwuid(geteuid());
              
              if ((common_data.cert == NULL) &&
                  (userpasswd != NULL) &&
                  (userpasswd->pw_dir != NULL))
                asprintf(&(common_data.cert), "%s/.globus/usercert.pem", 
                                                    userpasswd->pw_dir);
              
              if ((common_data.key == NULL) &&
                  (userpasswd != NULL) &&
                  (userpasswd->pw_dir != NULL))
                asprintf(&(common_data.key), "%s/.globus/userkey.pem", 
                                                    userpasswd->pw_dir);              
            }            
        }    
    }

  if (common_data.capath == NULL) common_data.capath = getenv("X509_CERT_DIR");

  if (common_data.capath == NULL) 
                        common_data.capath = "/etc/grid-security/certificates";

#if (LIBCURL_VERSION_NUM < 0x070908)
  /* libcurl before 7.9.8 doesnt support CURLOPT_CAPATH and the directory */

  if ((common_data.capath != NULL) && 
      (stat(common_data.capath, &statbuf) == 0) && S_ISDIR(statbuf.st_mode))
    {
      tmp_ca_roots = make_tmp_ca_roots(common_data.capath);
      common_data.capath = tmp_ca_roots;
    }
#endif

  executable = rindex(argv[0], '/');
  if (executable != NULL) executable++;
  else                    executable = argv[0];
  
  if (common_data.method == 0) /* command-line options override exec name */
    {
      if      (strcmp(executable,"htls")==0) common_data.method=HTCP_LIST;
      else if (strcmp(executable,"htll")==0) common_data.method=HTCP_LONGLIST;
      else if (strcmp(executable,"htrm")==0) common_data.method=HTCP_DELETE;
      else if (strcmp(executable,"htmkdir")==0) common_data.method=HTCP_MKDIR;
      else if (strcmp(executable,"htmv")==0) common_data.method=HTCP_MOVE;
      else if (strcmp(executable,"htping")==0) common_data.method=HTCP_PING;
    }
    
  if (common_data.method == HTCP_PING)
    {
      if (common_data.groups != NULL) return do_ping(&common_data);

      fprintf(stderr, "Must specify at least one multicast group\n\n"); 
      printsyntax(argv[0]);      
      return CURLE_FAILED_INIT;      
    }

  if ((common_data.method == HTCP_DELETE) || 
      (common_data.method == HTCP_LIST)   ||
      (common_data.method == HTCP_MKDIR)  ||
      (common_data.method == HTCP_LONGLIST))
    {
      if (optind >= argc)
          {
            fprintf(stderr, "Must give at least 1 non-option argument\n\n"); 
            printsyntax(argv[0]);
            return CURLE_URL_MALFORMAT;
          }
          
      sources = (char **) malloc(sizeof(char *) * (1 + argc - optind));  
      for (i=0; i < argc - optind; ++i) 
         {
           sources[i] = argv[optind + i];
           
           if ((common_data.method == HTCP_MKDIR) &&
               (sources[i][strlen(sources[i])-1] != '/'))
             {
               fprintf(stderr, "Argument \"%s\" is not a "
                       "directory URL (no trailing /)\n\n", sources[i]);
               printsyntax(argv[0]);
               return CURLE_URL_MALFORMAT;
             }
         }

      sources[i]  = NULL;  

      if (common_data.method == HTCP_DELETE) 
                            anyerror = do_deletes(sources, &common_data);
      else if (common_data.method == HTCP_MKDIR) 
                            anyerror = do_mkdirs(sources, &common_data);
      else if (common_data.method == HTCP_LONGLIST) 
                            anyerror = do_listings(sources, &common_data, 1);
      else anyerror = do_listings(sources, &common_data, 0);

      if (anyerror > 99) anyerror = CURLE_HTTP_RETURNED_ERROR;

      return anyerror;
    }

  if (common_data.method == HTCP_MOVE)
    {
      if (optind >= argc - 1)
        {
          fputs("Must give exactly 2 non-option arguments\n\n", stderr);
          printsyntax(argv[0]);
          return CURLE_URL_MALFORMAT;
        }
      
      anyerror = do_move(argv[optind], argv[optind + 1], &common_data);

      if (anyerror > 99) anyerror = CURLE_HTTP_RETURNED_ERROR;

      return anyerror;
    }

  if (optind >= argc - 1) 
    {
      fputs("Must give at least 2 non-option arguments\n\n", stderr);
      printsyntax(argv[0]);
      return CURLE_URL_MALFORMAT;
    }
    
  sources = (char **) malloc(sizeof(char *) * (argc - optind));
  
  for (i=0; i < (argc - optind - 1); ++i) 
     {
       if (strncmp(argv[optind + i], "file:", 5) == 0)
            sources[i] = &argv[optind + i][5];
       else sources[i] =  argv[optind + i];
       
       if (sources[i][0] == '\0') 
         {
           fprintf(stderr, "Source argument %d is empty\n\n", i + 1);
           printsyntax(argv[0]);
           return CURLE_URL_MALFORMAT;
         }
     }
  
  sources[i]  = NULL;  

  if (strncmp(argv[optind + i], "file:", 5) == 0)
       destination = &argv[optind + i][5];
  else destination =  argv[optind + i];
  
  if (destination[0] == '\0')
    {
      fputs("Destination argument is empty\n\n", stderr);
      printsyntax(argv[0]);
      return CURLE_URL_MALFORMAT;
    }

  if ((argc - optind > 2) && (destination[strlen(destination)-1] != '/'))
    {
      fputs("For multiple sources, destination "
            "must be a directory (end in /)\n\n", stderr);
      printsyntax(argv[0]);
      return CURLE_URL_MALFORMAT;
    }
  
  if ((strncmp(destination, "http://",  7) == 0) ||
      (strncmp(destination, "https://", 8) == 0)) 
       common_data.method = HTCP_PUT;
  else common_data.method = HTCP_GET;
  
  for (i=0; sources[i] != NULL; ++i)
         {
           if ((common_data.method == HTCP_PUT) && 
               ((strncmp(sources[i], "http://",  7) == 0) ||
                (strncmp(sources[i], "https://", 8) == 0)))
             {
               fputs("Cannot have both source and destination remote\n\n",stderr);
               printsyntax(argv[0]);
               return CURLE_URL_MALFORMAT;
             }
         
           if ((common_data.method == HTCP_GET) && 
               ((strncmp(sources[i], "http://",  7) != 0) &&
                (strncmp(sources[i], "https://", 8) != 0)))
             {
               fputs("Cannot have both source and "
                     "destination local (for now)\n\n",stderr);
               printsyntax(argv[0]);
               return CURLE_URL_MALFORMAT;
             }
         }
         
  anyerror = do_copies(sources, destination, &common_data);
  if (anyerror > 99) anyerror = CURLE_HTTP_RETURNED_ERROR;
  
  return anyerror;
}
