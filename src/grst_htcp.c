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

#ifndef VERSION
#define VERSION "x.x.x"
#endif

#define _GNU_SOURCE
#include <stdio.h>

#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 

#include "gridsite.h"

int GRSThtcpNOPrequestMake(char **request, int *request_length,
                           unsigned int trans_id)
/* 
    Make a complete HTCP NOP request and return a pointer to malloc'd
    memory pointing to it.
*/
{
   *request_length = 
     asprintf(request,"%c%c"		/* place holder for total length */
                      "%c%c"		/* HTCP version 0.0 */
                      "%c%c"		/* DATA length place holder */
                      "%c%c"		/* OPCODE,RESPONSE,RESERVED,F1,RR */
                      "%c%c%c%c"	/* TRANS-ID placeholder */
                      "%c%c",		/* AUTH (LENGTH=2 means no AUTH) */
                     0, 0,
                     0, 0,
                     0, 0,
                     GRSThtcpNOPop * 16, 2,
                     0, 0, 0, 0,
                     0, 2);

   if (*request_length < 0) return GRST_RET_FAILED;
   
   (*request)[0] = *request_length / 256;
   (*request)[1] = *request_length % 256;

   (*request)[4] = (*request_length - 6) / 256;
   (*request)[5] = (*request_length - 6) % 256;
   
   memcpy(&((*request)[8]), &trans_id, 4);

   return GRST_RET_OK;
}

int GRSThtcpNOPresponseMake(char **message, int *message_length,
                            unsigned int trans_id)
/* 
    Make a complete HTCP NOP response for a found file and return a pointer
    to malloc'd memory pointing to it.
*/
{
   *message_length = 
        asprintf(message, 
                       "%c%c"		/* place holder for total length */
                       "%c%c"		/* HTCP version 0.0 */
                       "%c%c"		/* DATA length place holder */
                       "%c%c"		/* OPCODE,RESPONSE,RESERVED,F1,RR */
                       "%c%c%c%c"	/* TRANS-ID place holder */
                       "%c%c",		/* AUTH (LENGTH=2 means no AUTH) */
            0, 0,
            0, 0,
            0, 0,
            GRSThtcpNOPop * 16, 1, /* RR=1, MO=0, RESPONSE=0 (ie found) */
            0, 0, 0, 0,
            0, 2);

   if (*message_length < 0) return GRST_RET_FAILED;
   
   (*message)[0] = *message_length / 256;
   (*message)[1] = *message_length % 256;

   (*message)[4] = (*message_length - 6) / 256;
   (*message)[5] = (*message_length - 6) % 256;

   memcpy(&((*message)[8]), &trans_id, 4);

   return GRST_RET_OK;
}

int GRSThtcpTSTrequestMake(char **request, int *request_length,
                           unsigned int trans_id,
                           char *method, char *uri, char *req_hdrs)
/* 
    Make a complete HTCP TST request and return a pointer to malloc'd
    memory pointing to it.
*/
{
   if ((method == NULL) || (uri == NULL) || (req_hdrs == NULL)) 
                                               return GRST_RET_FAILED;

   *request_length = 
     asprintf(request,"%c%c"		/* place holder for total length */
                      "%c%c"		/* HTCP version 0.0 */
                      "%c%c"		/* DATA length place holder */
                      "%c%c"		/* OPCODE,RESPONSE,RESERVED,F1,RR */
                      "%c%c%c%c"	/* TRANS-ID placeholder */		      
                      "%c%c%s"		/* OP-DATA: METHOD */
                      "%c%c%s"		/* OP-DATA: URI */
                      "%c%c%s"		/* OP-DATA: VERSION */
                      "%c%c%s"		/* OP-DATA: REQ-HDRS */
                      "%c%c",		/* AUTH (LENGTH=2 means no AUTH) */
                     0, 0, 
                     0, 0, 
                     0, 0,       
                     GRSThtcpTSTop * 16, 2,
                     0, 0, 0, 0,
                     strlen(method) / 256, strlen(method) % 256, method,
                     strlen(uri)    / 256, strlen(uri) % 256,    uri,
                     0,                    8,                    "HTTP/1.1",
                     strlen(req_hdrs)/256, strlen(req_hdrs) % 256, req_hdrs,
                     0, 2);

   if (*request_length < 0) return GRST_RET_FAILED;
   
   (*request)[0] = *request_length / 256;
   (*request)[1] = *request_length % 256;

   (*request)[4] = (*request_length - 6) / 256;
   (*request)[5] = (*request_length - 6) % 256;
   
   memcpy(&((*request)[8]), &trans_id, 4);

   return GRST_RET_OK;
}

int GRSThtcpTSTresponseMake(char **message, int *message_length,
                            unsigned int trans_id,
                            char *resp_hdrs, char *entity_hdrs, 
                            char *cache_hdrs)
/* 
    Make a complete HTCP TST response for a found file and return a pointer
    to malloc'd memory pointing to it.
*/
{
   if ((resp_hdrs != NULL) && (entity_hdrs != NULL) && (cache_hdrs != NULL)) 
      /* found file response */
      *message_length = 
        asprintf(message, 
                       "%c%c"		/* place holder for total length */
                       "%c%c"		/* HTCP version 0.0 */
                       "%c%c"		/* DATA length place holder */
                       "%c%c"		/* OPCODE,RESPONSE,RESERVED,F1,RR */
                       "%c%c%c%c"	/* TRANS-ID place holder */
                       "%c%c%s"		/* OP-DATA: RESP-HDRS */
                       "%c%c%s"		/* OP-DATA: ENTITY-HDRS */
                       "%c%c%s"		/* OP-DATA: CACHE-HDRS */
                       "%c%c",		/* AUTH (LENGTH=2 means no AUTH) */
            0, 0, 
            0, 0, 
            0, 0,       
            GRSThtcpTSTop * 16, 1, /* RR=1, MO=0, RESPONSE=0 (ie found) */
            0, 0, 0, 0,
            strlen(resp_hdrs) / 256,   strlen(resp_hdrs) % 256,   resp_hdrs,
            strlen(entity_hdrs) / 256, strlen(entity_hdrs) % 256, entity_hdrs,
            strlen(cache_hdrs) / 256,  strlen(cache_hdrs) % 256,  cache_hdrs,
            0, 2);
   else if (cache_hdrs != NULL) 
      /* not found file response, just cache_hdrs given */
      *message_length = 
        asprintf(message, 
                       "%c%c"		/* place holder for total length */
                       "%c%c"		/* HTCP version 0.0 */
                       "%c%c"		/* DATA length place holder */
                       "%c%c"		/* OPCODE,RESPONSE,RESERVED,F1,RR */
                       "%c%c%c%c"	/* TRANS-ID */		      
                       "%c%c%s"		/* OP-DATA: CACHE-HDRS */
                       "%c%c",		/* AUTH (LENGTH=2 means no AUTH) */
            0, 0, 
            0, 0, 
            0, 0,       
            GRSThtcpTSTop * 16 + 1, 1, /* RR=1, MO=0, RESPONSE=1 (missing) */
            0, 0, 0, 0,
            strlen(cache_hdrs) / 256,  strlen(cache_hdrs) % 256,  cache_hdrs,
            0, 2);
   else return GRST_RET_FAILED;

   if (*message_length < 0) return GRST_RET_FAILED;
   
   (*message)[0] = *message_length / 256;
   (*message)[1] = *message_length % 256;

   (*message)[4] = (*message_length - 6) / 256;
   (*message)[5] = (*message_length - 6) % 256;

   memcpy(&((*message)[8]), &trans_id, 4);

   return GRST_RET_OK;
}

int GRSThtcpMessageParse(GRSThtcpMessage *parsed, char *raw, int length)
{
   GRSThtcpCountstr *s;
   
   bzero(parsed, sizeof(GRSThtcpMessage));
   
   if (length < (void *) &(parsed->method) 
                - (void *) &(parsed->total_length_msb) + 2) 
           return GRST_RET_FAILED;

   memcpy(parsed, raw, (void *) &(parsed->method) 
                       - (void *) &(parsed->total_length_msb));
   
   if (parsed->opcode == GRSThtcpNOPop) return GRST_RET_OK;

   if ((parsed->opcode == GRSThtcpTSTop) && (parsed->rr == 0))
     {
       /* point to start of data/auth in raw */
       s = (GRSThtcpCountstr *) &(((GRSThtcpMessage *) raw)->method); 

       /* METHOD string */

       if ((void *) s + 2 + GRSThtcpCountstrLen(s) > (void *) raw + length)
                                                   return GRST_RET_FAILED;
       parsed->method = s;
       s = (GRSThtcpCountstr *) ((void *) s + 2 + GRSThtcpCountstrLen(s));
       
       /* URI string */

       if ((void *) s + 2 + GRSThtcpCountstrLen(s) > (void *) raw + length)
                                                   return GRST_RET_FAILED;
       parsed->uri = s;
       s = (GRSThtcpCountstr *) ((void *) s + 2 + GRSThtcpCountstrLen(s));

       /* VERSION string */
           
       if ((void *) s + 2 + GRSThtcpCountstrLen(s) > (void *) raw + length)
                                                   return GRST_RET_FAILED;
       parsed->version = s;
       s = (GRSThtcpCountstr *) ((void *) s + 2 + GRSThtcpCountstrLen(s));

       /* REQ-HDRS string */
           
       if ((void *) s + 2 + GRSThtcpCountstrLen(s) > (void *) raw + length)
                                                   return GRST_RET_FAILED;
       parsed->req_hdrs = s;
       s = (GRSThtcpCountstr *) ((void *) s + 2 + GRSThtcpCountstrLen(s));
                  
       return GRST_RET_OK;
     }   

   if ((parsed->opcode == GRSThtcpTSTop) && (parsed->rr == 1))
     {
       /* point to start of data/auth in raw */
       s = (GRSThtcpCountstr *) &(((GRSThtcpMessage *) raw)->method); 

       /* RESP-HDRS string */

       if ((void *) s + 2 + GRSThtcpCountstrLen(s) > (void *) raw + length)
                                                   return GRST_RET_FAILED;
       parsed->resp_hdrs = s;
       s = (GRSThtcpCountstr *) ((void *) s + 2 + GRSThtcpCountstrLen(s));
       
       /* ENTITY-HDRS string */

       if ((void *) s + 2 + GRSThtcpCountstrLen(s) > (void *) raw + length)
                                                   return GRST_RET_FAILED;
       parsed->entity_hdrs = s;
       s = (GRSThtcpCountstr *) ((void *) s + 2 + GRSThtcpCountstrLen(s));

       /* CACHE-HDRS string */
           
       if ((void *) s + 2 + GRSThtcpCountstrLen(s) > (void *) raw + length)
                                                   return GRST_RET_FAILED;
       parsed->cache_hdrs = s;
       s = (GRSThtcpCountstr *) ((void *) s + 2 + GRSThtcpCountstrLen(s));
                  
       return GRST_RET_OK;
     }   

   return GRST_RET_FAILED; 
}
