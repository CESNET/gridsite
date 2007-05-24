/*
   Copyright (c) 2003-7, Andrew McNab, University of Manchester.
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


/* 

 This example demonstrates how you can make your own Apache modules
 to consume credentials put into environment variables by mod_gridsite.

 With the Apache development libraries and includes installed on your
 system, you can build the module with something like:

  gcc -g -shared -Wl,-soname=gridsite_example_module \
           -I/usr/include/httpd -I/usr/include/apr-0 \
           -DVERSION=\"$(VERSION)\" -o mod_gridsite_example.so \
           mod_gridsite_example.c 

 and load it into Apache DIRECTLY AFTER the mod_gridsite LoadModule with: 

  LoadModule gridsite_module_example mod_gridsite_example.so

 This example will work with GridSite 1.6 onwards (AURIs) and older
 versions (Compact Credentials). If you define GRIDSITE_1_6, the 
 compatibility support for pre-1.6 won't be compiled in.

 The module adds the command GridSiteExample which you can use in
 the main section of Apache's httpd.conf file, outside any virtual
 server sections. It takes one parameter (surround it in " quotes if
 it contains spaces) which is an Attribute URI to be rejected.

 These AURIs look like:  dn:/C=UK/...
                         fqan:/dteam/Role=NULL
                         https://voms.xyz/listofDNs

 If the parameter matches the AURI, then we refuse the request.

 To reject clients with DN  /C=UK/... use  GridSiteExample "dn:/C=UK/..."
 
 The special values A_Bad_Example and never_nobody_nothing demonstrate
 how to reject bad parameters at start time, and during request handling.
 
 Please read through the rest of the comments in this file to see how it
 all goes together.
 
*/

#include <stdio.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <httpd.h>
#include <http_config.h>
#include <http_log.h>

module AP_MODULE_DECLARE_DATA gridsite_module;

char *example_parameter = NULL; /* Applies to all virtual servers */

int get_auri_i(char **auri, int i, request_rec *r)
/*
    Look for credentials from mod_gridsite passed as environment variables.
*/
{
    char *s, *p;

    /* Try AURI variables first. If you're using GridSite 1.6 onwards
       then you only need this part, but you do need to keep the return
       0 for failure right at the end. */

    *auri = (char *) apr_table_get(r->subprocess_env, 
                              apr_psprintf(r->pool, "GRST_CRED_AURI_%d", i));                              

    if (*auri != NULL) return 1;

#ifndef GRIDSITE_1_6
    /* Try old-style Compact Credential variables. If you're using 
       GridSite 1.6 onwards then you don't need this part, but you
       do need to keep the return 0 right at the end. */

    s = (char *) apr_table_get(r->subprocess_env, 
                               apr_psprintf(r->pool, "GRST_CRED_%d", i));

    if ((s != NULL) &&
        (strncmp(s, "X509USER ", 9) == 0) &&
        ((p = index(s, '/')) != NULL))
      {
        *auri = apr_psprintf(r->pool, "dn:%s", p);      
        return 1;
      }

    if ((s != NULL) &&
        (strncmp(s, "GSIPROXY ", 9) == 0) &&
        ((p = index(s, '/')) != NULL))
      {
        *auri = apr_psprintf(r->pool, "dn:%s", p);
        return 1;
      }

    if ((s != NULL) &&
        (strncmp(s, "VOMS ", 5) == 0) &&
        ((p = index(s, '/')) != NULL))
      {
        *auri = apr_psprintf(r->pool, "fqan:%s", p);
        return 1;
      }
#endif

    /* No credentials found: tell the caller with a 0. Keep this line
       even if you discard the old-style Compact Credentials handling. */
    return 0; 
}

static int mod_gridsite_example_fixups(request_rec *r)
/*
    We do access control here so results of mod_gridsite and mod_ssl
    are available.
*/
{
    char *auri;
    int  i;
    
    /* We return DECLINED (ie nothing for us to do) if a GridSiteExample
       command doesn't apply. This isn't the same as code 403 Forbidden. */
       
    if (example_parameter == NULL) return DECLINED; 
    
    /* If example_parameter has a special value, then immediately deny 
       access, causing Apache to return 403 Forbidden to the client.   */
    
    if (strcmp(example_parameter, "never_nobody_nothing") == 0)
                                   return HTTP_FORBIDDEN;

    /* Otherwise we go through the credentials from GridSite looking for
       ones to deny.                                                     */

    for (i=0; get_auri_i(&auri, i, r); ++i)
       {
         /* 
            Log what we get back. You can see these in the Apache
            ErrorLog file if you have  LogLevel debug  in httpd.conf 
            
            These lines will look like:  dn:/C=UK/...
                                         fqan:/dteam/Role=NULL
                                         https://voms.xyz/listofDNs
         */

         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                      "Examine AURI %s", auri);

         /* If the parameter matches the AURI, then we refuse. 
            For example, to reject clients with the DN  /C=UK/...
            use GridSiteExample "dn:/C=UK/..."  */
           
         if (strcmp(auri, example_parameter) == 0)
           {
             return HTTP_FORBIDDEN;
           }
      }

    return DECLINED; /* nothing more for us to do: that's ok */
}

static const char *mod_gridsite_example_take1_cmds(cmd_parms *a, void *cfg,
                                                   const char *parm)
{
/* 
   For the command we're allowed, check it doesn't set A_Bad_Example
   and otherwise store it via the global pointer example_parameter 
*/
    if (strcasecmp(a->cmd->name, "GridSiteExample") == 0)
    {
      if (strcmp(parm, "A_Bad_Example") == 0)
        return "Don't set A_Bad_Example in GridSiteExample command.";
    
      example_parameter = apr_pstrdup(a->pool, parm);
    }

    return NULL;
}

static const command_rec mod_gridsite_example_cmds[] =
{
/* 
   Define one command that we can use in the MAIN SERVER in httpd.conf,
   that takes a single parameter. Enclose in " quotes if it contains
   spaces.
   
   "In main server" = "outside any virtual server sections". You need
   to use Apache's per-server and per-directory module configuration
   machinery if you want to create and merge finer-grained parameters.
*/

    AP_INIT_TAKE1("GridSiteExample", mod_gridsite_example_take1_cmds, NULL,
                  RSRC_CONF, "Value to use in GridSite Example Module"),
    {NULL}
};

static void register_hooks(apr_pool_t *p)
{
/* 
   From GridSite 1.6.x onwards, credential handling and access control 
   are split into APR_HOOK_LAST and APR_HOOK_REALLY_LAST parts of the
   Apache fixups stage. This makes it possible for modules to consume
   credentials placed into environment variables by GridSite or Apache
   itself, and then put additional credentials into the environment 
   for access control processing by GridSite with GACL etc.
   
   In both pre-1.6 and 1.6+ cases, the line similar to

    LoadModule gridsite_module_example mod_gridsite_example.so

   must be placed DIRECTLY AFTER the mod_gridsite LoadModule line.
*/

#ifdef GRIDSITE_1_6
    ap_hook_fixups(mod_gridsite_example_fixups,NULL,NULL,APR_HOOK_LAST);
#else
    ap_hook_fixups(mod_gridsite_example_fixups,NULL,NULL,APR_HOOK_REALLY_LAST);
#endif
}

module AP_MODULE_DECLARE_DATA gridsite_example_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,                       /* dir config creater   */
    NULL,                       /* dir merger           */
    NULL,                       /* create server config */
    NULL,			/* merge server config  */
    mod_gridsite_example_cmds,  /* command apr_table_t  */
    register_hooks              /* register hooks       */
};
