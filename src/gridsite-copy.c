/*
   Copyright (c) 2005, Yibiao Li, University of Manchester
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

///////////////////////////////////////////////////////////////////
//
// compile: gcc -lcurl gridsite-copy.c -o gridsite-copy.cgi
// usage: cp gridsite-copy.cgi to the cgi-bin directory
//        and map the COPY method to gridsite-copy.cgi
//        by adding a line in httpd.conf:
//        script COPY /cgi-bin/gridsite-copy.cgi
//
///////////////////////////////////////////////////////////////////
#ifdef GRST_USE_FASTCGI
#include <fcgi_stdio.h>
#endif
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <sys/types.h>
#include <sys/times.h>

extern char **environ;

size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream)
{
  int written = fwrite(ptr, size, nmemb, (FILE *)stream);
  return written;
}

int gridsite_copy()
{
	char *getenv();

	CURL *curl;
	CURLcode res;
	struct tms s_time, e_time;
	FILE *fout;

	char *requestURI;
	int grstPerm, srcsecure;
	char passcode[100];
	char destination[500], destDir[400], destName[100];
	char *ptr, *ptr1;

	times(&s_time);
	passcode[0]='\0';
	char *capath="/etc/grid-security/certificates";

		printf("Content-type: text/html\n\n");
		printf("<html><head><title>HTTP COPY</title></head>\n");
		printf("<body><h1>HTTP FILE COPY</h1>\n");

	curl = curl_easy_init();
	printf("Server: Initialized!\n");
	if(curl) {
	  //get the request URI
	  requestURI = curl_getenv("REQUEST_URI");
	  if( strncmp( requestURI, "https://", 8 )==0 )srcsecure=1;
	  else srcsecure=0;
	  printf("The request URL is %s\n", requestURI);

	  //get the destination directory and file name
	  strcpy(destination, getenv("HTTP_DESTINATION"));
	  ptr=destination;
	  ptr1 = strrchr(ptr, '/');
	  ptr1+=1;
	  strcpy( destName, ptr1 );
	  *ptr1 = '\0';
	  strcpy( destDir, ptr );

	  // get the one time passcode from cookie string.
	  // the segmenty of code is tested on 19th sep. 2005
	  if( (ptr=curl_getenv("HTTP_COOKIE")) != NULL)
	    {
	      ptr += 20;
	      strcpy( passcode, ptr );
	    }

	  //get permision attributes
	  grstPerm = atoi(curl_getenv("GRST_DESTINATION_PERM"));

       	  if( grstPerm & 8 )  // write right
	    {
	      curl_easy_setopt(curl, CURLOPT_VERBOSE, 0);

	      if( srcsecure == 1 )
		{
		  curl_easy_setopt(curl, CURLOPT_COOKIE, passcode );
		  curl_easy_setopt(curl, CURLOPT_CAPATH, capath );
		}

	      curl_easy_setopt(curl, CURLOPT_URL, requestURI );

	      strcpy( destination, getenv("GRST_DESTINATION_TRANSLATED"));
	      fout = fopen( destination, "w" );
	      if( fout == NULL ){
		printf("cannot open file to write,");
		printf(" maybe you have no right to write in the directory.\n");
		exit(-1);
	      }
	      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
	      curl_easy_setopt(curl, CURLOPT_WRITEDATA, fout );
	      res = curl_easy_perform(curl);
	      if( res!=0 )
		{
		  printf("Server: There are some things wrong with OPT parameters.%d \n", res);
		}
	      else printf("Server: The file has been successfully copied.\n");
	      fclose(fout);
	    }
	  else
	    {
	      printf("You have no permission to write in the destination directory.\n");
	    }

	  curl_easy_cleanup(curl);
	}
	else{
	  printf("Server: cannot initialize CURL!\n");
	}

	curl_global_cleanup();

	times(&e_time);
	printf("Server: copying time %ld seconds\n", e_time.tms_utime-s_time.tms_utime);
		printf("</body></html>\n");
	return 0;
}

int main( void )
{
#ifdef GRST_USE_FASTCGI
    while(FCGI_Accept() >= 0)
#endif
    {
        gridsite_copy();
    }
}
