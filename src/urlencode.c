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

/*------------------------------------------------------------------------*
 * For more about GridSite: http://www.gridpp.ac.uk/gridsite/             *
 *------------------------------------------------------------------------*/

#include <stdio.h>
#include <string.h>

#include "gridsite.h"

int main(int argn, char *argv[])
{
  int    i;

  if (argn == 1)
    {
      puts("urlencode [-m|-d] string-to-encode-or-decode");
      return 0;
    }

  if      (strcmp(argv[1], "-d") == 0) /* decode */
   for (i = 2; i < argn; ++i) 
      {
        if (i > 2) fputs(" ", stdout);
        fputs(GRSThttpUrlDecode(argv[i]), stdout);
      }
  else if (strcmp(argv[1], "-m") == 0) /* mild encode */
   for (i = 2; i < argn; ++i) 
      {
        if (i > 2) fputs("%20", stdout);
        fputs(GRSThttpUrlMildencode(argv[i]), stdout);
      }
  else /* standard encode */
   for (i = 1; i < argn; ++i) 
      {
        if (i > 1) fputs("%20", stdout);
        fputs(GRSThttpUrlEncode(argv[i]), stdout);
      }

  puts("");

  return 0;
}
