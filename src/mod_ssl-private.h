/*
   Copyright (c) 2003-4, Andrew McNab, University of Manchester
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

/*

 Portions of this code are derived from Apache mod_ssl, and are covered
 by the Apache Software License:

 * Copyright 2001-2004 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*------------------------------------------------------------------*
 * This program is part of GridSite: http://www.gridsite.org/       *
 *------------------------------------------------------------------*/


/*
 * After 2.0.49, Apache mod_ssl has most of the mod_ssl structures defined
 * in ssl_private.h, which is not installed along with httpd-devel (eg in
 * the FC2 RPM.) This include file provides SIMPLIFIED structures for use
 * by mod_gridsite: for example, pointers to unused structures are replaced
 * by  void *  and some of the structures are truncated when only the early
 * members are used.
 *
 * CLEARLY, THIS WILL BREAK IF THERE ARE MAJOR CHANGES TO ssl_private.h!!!
 */

#include <openssl/ssl.h>

typedef enum {
    SSL_SHUTDOWN_TYPE_UNSET,
    SSL_SHUTDOWN_TYPE_STANDARD,
    SSL_SHUTDOWN_TYPE_UNCLEAN,
    SSL_SHUTDOWN_TYPE_ACCURATE
} ssl_shutdown_type_e;

typedef struct {
  SSL *ssl;
  const char *client_dn;
  X509 *client_cert;
  ssl_shutdown_type_e shutdown_type;
  const char *verify_info;
  const char *verify_error;
  int verify_depth;
  int is_proxy;
  int disabled;
  int non_ssl_request;
} SSLConnRec;

typedef struct {
  void    *sc; /* pointer back to server config */
  SSL_CTX *ssl_ctx;
} modssl_ctx_t;

typedef struct {
  void            *mc;
  unsigned int     enabled;
  unsigned int     proxy_enabled;
  const char      *vhost_id;
  int              vhost_id_len;
  int              session_cache_timeout;
  modssl_ctx_t    *server;
  modssl_ctx_t    *proxy;
} SSLSrvConfigRec;

extern module AP_MODULE_DECLARE_DATA ssl_module;
