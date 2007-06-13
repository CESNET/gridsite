/*
   Copyright (c) 2002-6, Andrew McNab, University of Manchester
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
 
#define HTCP_SITECAST_GROUPS 32

struct grst_sitecast_group { unsigned char quad1; unsigned char quad2; 
                             unsigned char quad3; unsigned char quad4;
                             int port; int timewait; int ttl; }
                           sitecast_groups[HTCP_SITECAST_GROUPS];
int last_group;

void handle_sitecast_get(void)
{
  int request_length, response_length, i, ret, s;
  struct sockaddr_in srv, from;
  socklen_t fromlen;
#define MAXBUF 8192  
  char *https, *server_port, *request_uri, *url, *sitecast_port,
       *sitecast_domain, *request, response[MAXBUF], *p, *groups;
  GRSThtcpMessage msg;
  struct timeval start_timeval, wait_timeval;
  fd_set readsckts;

  sitecast_domain = getenv("GRIDSITE_SRM_DOMAIN");
  if (sitecast_domain == NULL)
    {
      puts("Status: 500 Internal Server Error\n"
           "Content-Type: text/plain\n\n"
           "No GRIDSITE_SRM_DOMAIN defined");
      return;
    }  

  sitecast_port = getenv("GRIDSITE_SRM_PORT");
  if (sitecast_port == NULL)
    {
      puts("Status: 500 Internal Server Error\n"
           "Content-Type: text/plain\n\n"
           "No GRIDSITE_SRM_PORT defined");
      return;
    }  

  request_uri = getenv("REQUEST_URI");
  https = getenv("HTTPS");
  
  if (request_uri == NULL)
    {
      puts("Status: 500 Internal Server Error\n"
           "Content-Type: text/plain\n\n"
           "REQUEST_URI not found");
      return;
    }
  
  if (https == NULL) asprintf(&url,  "http://%s:%s%s", 
                              sitecast_domain, sitecast_port, request_uri);
  else asprintf(&url, "https://%s:%s%s",
                sitecast_domain, sitecast_port, request_uri);
  
  if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
    {
      puts("Status: 500 Internal Server Error\n"
           "Content-Type: text/plain\n\n"
           "Failed to open UDP socket");
      return;
    }

  /* loop through multicast groups since we need to take each 
     ones timewait into account */

  gettimeofday(&start_timeval, NULL);

  for (i=0; i <= last_group; ++i)
     {
/*
       if (verbose)
        fprintf(stderr, "Querying multicast group %d.%d.%d.%d:%d:%d:%d\n",
                sitecast_groups[i].quad1, sitecast_groups[i].quad2,
                sitecast_groups[i].quad3, sitecast_groups[i].quad4,
                sitecast_groups[i].port, sitecast_groups[i].ttl,
                sitecast_groups[i].timewait);
*/      
       bzero(&srv, sizeof(srv));
       srv.sin_family = AF_INET;
       srv.sin_port = htons(sitecast_groups[i].port);
       srv.sin_addr.s_addr = htonl(sitecast_groups[i].quad1*0x1000000
                                 + sitecast_groups[i].quad2*0x10000
                                 + sitecast_groups[i].quad3*0x100
                                 + sitecast_groups[i].quad4);

       /* send off query for this group */

       GRSThtcpTSTrequestMake(&request, &request_length, 
                                   (int) (start_timeval.tv_usec),
                                   "GET", url, "");

       sendto(s, request, request_length, 0, 
                       (struct sockaddr *) &srv, sizeof(srv));

       free(request);
          
       /* reusing wait_timeval is a Linux-specific feature of select() */
       wait_timeval.tv_usec = 0;
       wait_timeval.tv_sec  = sitecast_groups[i].timewait;

       while ((wait_timeval.tv_sec > 0) || (wait_timeval.tv_usec > 0))
            {
              FD_ZERO(&readsckts);
              FD_SET(s, &readsckts);
  
              ret = select(s + 1, &readsckts, NULL, NULL, &wait_timeval);

              if (ret > 0)
                {
                  response_length = recvfrom(s, response, MAXBUF,
                                             0, &from, &fromlen);
  
                  if ((GRSThtcpMessageParse(&msg, response, response_length) 
                                                      == GRST_RET_OK) &&
                      (msg.opcode == GRSThtcpTSTop) && (msg.rr == 1) && 
                      (msg.trans_id == (int) start_timeval.tv_usec) &&
                      (msg.resp_hdrs != NULL) &&
                      (GRSThtcpCountstrLen(msg.resp_hdrs) > 12))
                    { 
                      /* found one */ 
/*
                      if (verbose > 0)
                        fprintf(stderr, "Sitecast %s -> %.*s\n",
                                *source_ptr, 
                                GRSThtcpCountstrLen(msg.resp_hdrs) - 12,
                                &(msg.resp_hdrs->text[10]));
*/
                      free(url);
                      
                      printf("Status: 302 Moved\nLocation: %.*s\n\n",
                          GRSThtcpCountstrLen(msg.resp_hdrs) - 12, 
                          &(msg.resp_hdrs->text[10]));
                          
                      return;
                    }
                }
            }
     }
     
  free(url);
  puts("Status: 404 Not Found\nContent-Type: text/plain\n\nNot found");
}


int main()
{
  int   ret;
  char *method, *groups, *p;

  groups = getenv("GRIDSITE_SRM_GROUPS");
  if (groups == NULL)
    {
      puts("Status: 500 Internal Server Error\n"
           "Content-Type: text/plain\n\n"
           "No GRIDSITE_SRM_GROUPS defined");
      return 0;
    }

  p = groups;
    
  for (last_group=-1; last_group+1 < HTCP_SITECAST_GROUPS;)
     {  
       sitecast_groups[last_group+1].port     = GRST_HTCP_PORT;
       sitecast_groups[last_group+1].timewait = 1;
       sitecast_groups[last_group+1].ttl      = 1;
       
       ret = sscanf(p, "%d.%d.%d.%d:%d:%d:%d", 
                 &(sitecast_groups[last_group+1].quad1),
                 &(sitecast_groups[last_group+1].quad2),    
                 &(sitecast_groups[last_group+1].quad3),
                 &(sitecast_groups[last_group+1].quad4),    
                 &(sitecast_groups[last_group+1].port),
                 &(sitecast_groups[last_group+1].ttl),
                 &(sitecast_groups[last_group+1].timewait));

       if (ret == 0) break; /* end of list ? */

       if (ret < 5)
         {
           puts("Status: 500 Internal Server Error\n"
                "Content-Type: text/plain\n\n"
                "Failed to parse GRIDSITE_SRM_GROUPS");
           return 0;
         }
       
       ++last_group;

       if ((p = index(p, ',')) == NULL) break;       
       ++p;
     }

  if (last_group == -1)
    {
      puts("Status: 500 Internal Server Error\n"
           "Content-Type: text/plain\n\n"
           "No groups found in GRIDSITE_SRM_GROUPS");
      return;
    }

  method = getenv("METHOD");

  if ((method != NULL) && (strcmp(method, "GET") == 0))
    {
      handle_sitecast_get();
      return 0;      
    }
    
  puts("Status: 400 Bad Request\n");
  return 0;
}
