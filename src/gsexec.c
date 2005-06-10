/* Copyright 1999-2004 The Apache Software Foundation
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

/*
 * suexec.c -- "Wrapper" support program for suEXEC behaviour for Apache
 *
 ***********************************************************************
 *
 * NOTE! : DO NOT edit this code!!!  Unless you know what you are doing,
 *         editing this code might open up your system in unexpected 
 *         ways to would-be crackers.  Every precaution has been taken 
 *         to make this code as safe as possible; alter it at your own
 *         risk.
 *
 ***********************************************************************
 *
 *
 */

#include "apr.h"
#include "apr_file_io.h"
#include "ap_config.h"
#include "gsexec.h"

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <time.h>
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifdef HAVE_GRP_H
#include <grp.h>
#endif

/*
 ***********************************************************************
 * There is no initgroups() in QNX, so I believe this is safe :-)
 * Use cc -osuexec -3 -O -mf -DQNX suexec.c to compile.
 *
 * May 17, 1997.
 * Igor N. Kovalenko -- infoh mail.wplus.net
 ***********************************************************************
 */

#if defined(NEED_INITGROUPS)
int initgroups(const char *name, gid_t basegid)
{
    /* QNX and MPE do not appear to support supplementary groups. */
    return 0;
}
#endif

#if defined(SUNOS4)
extern char *sys_errlist[];
#define strerror(x) sys_errlist[(x)]
#endif

#if defined(PATH_MAX)
#define AP_MAXPATH PATH_MAX
#elif defined(MAXPATHLEN)
#define AP_MAXPATH MAXPATHLEN
#else
#define AP_MAXPATH 8192
#endif

#define AP_ENVBUF 256

extern char **environ;
static FILE *log = NULL;

char *safe_env_lst[] =
{
    /* variable name starts with */
    "HTTP_",
    "SSL_",
    "GRST_",

    /* variable name is */
    "AUTH_TYPE=",
    "CONTENT_LENGTH=",
    "CONTENT_TYPE=",
    "DATE_GMT=",
    "DATE_LOCAL=",
    "DOCUMENT_NAME=",
    "DOCUMENT_PATH_INFO=",
    "DOCUMENT_ROOT=",
    "DOCUMENT_URI=",
    "GATEWAY_INTERFACE=",
    "HTTPS=",
    "LAST_MODIFIED=",
    "PATH_INFO=",
    "PATH_TRANSLATED=",
    "QUERY_STRING=",
    "QUERY_STRING_UNESCAPED=",
    "REMOTE_ADDR=",
    "REMOTE_HOST=",
    "REMOTE_IDENT=",
    "REMOTE_PORT=",
    "REMOTE_USER=",
    "REDIRECT_HANDLER=",
    "REDIRECT_QUERY_STRING=",
    "REDIRECT_REMOTE_USER=",
    "REDIRECT_STATUS=",
    "REDIRECT_URL=",
    "REQUEST_METHOD=",
    "REQUEST_URI=",
    "SCRIPT_FILENAME=",
    "SCRIPT_NAME=",
    "SCRIPT_URI=",
    "SCRIPT_URL=",
    "SERVER_ADMIN=",
    "SERVER_NAME=",
    "SERVER_ADDR=",
    "SERVER_PORT=",
    "SERVER_PROTOCOL=",
    "SERVER_SIGNATURE=",
    "SERVER_SOFTWARE=",
    "UNIQUE_ID=",
    "USER_NAME=",
    "TZ=",
    NULL
};


static void err_output(int is_error, const char *fmt, va_list ap)
{
#ifdef AP_LOG_EXEC
    time_t timevar;
    struct tm *lt;

    if (!log) {
        if ((log = fopen(AP_LOG_EXEC, "a")) == NULL) {
            fprintf(stderr, "suexec failure: could not open log file\n");
            perror("fopen");
            exit(1);
        }
    }

    if (is_error) {
        fprintf(stderr, "suexec policy violation: see suexec log for more "
                        "details\n");
    }

    time(&timevar);
    lt = localtime(&timevar);

    fprintf(log, "[%d-%.2d-%.2d %.2d:%.2d:%.2d]: ",
            lt->tm_year + 1900, lt->tm_mon + 1, lt->tm_mday,
            lt->tm_hour, lt->tm_min, lt->tm_sec);

    vfprintf(log, fmt, ap);

    fflush(log);
#endif /* AP_LOG_EXEC */
    return;
}

static void log_err(const char *fmt,...)
{
#ifdef AP_LOG_EXEC
    va_list ap;

    va_start(ap, fmt);
    err_output(1, fmt, ap); /* 1 == is_error */
    va_end(ap);
#endif /* AP_LOG_EXEC */
    return;
}

static void log_no_err(const char *fmt,...)
{
#ifdef AP_LOG_EXEC
    va_list ap;

    va_start(ap, fmt);
    err_output(0, fmt, ap); /* 0 == !is_error */
    va_end(ap);
#endif /* AP_LOG_EXEC */
    return;
}

static void clean_env(void)
{
    char pathbuf[512];
    char **cleanenv;
    char **ep;
    int cidx = 0;
    int idx;

    /* While cleaning the environment, the environment should be clean.
     * (e.g. malloc() may get the name of a file for writing debugging info.
     * Bad news if MALLOC_DEBUG_FILE is set to /etc/passwd.  Sprintf() may be
     * susceptible to bad locale settings....)
     * (from PR 2790)
     */
    char **envp = environ;
    char *empty_ptr = NULL;
 
    environ = &empty_ptr; /* VERY safe environment */
    
    if ((cleanenv = (char **) calloc(AP_ENVBUF, sizeof(char *))) == NULL) {
        log_err("failed to malloc memory for environment\n");
        exit(120);
    }

    sprintf(pathbuf, "PATH=%s", AP_SAFE_PATH);
    cleanenv[cidx] = strdup(pathbuf);
    cidx++;

    for (ep = envp; *ep && cidx < AP_ENVBUF-1; ep++) {
        for (idx = 0; safe_env_lst[idx]; idx++) {
            if (!strncmp(*ep, safe_env_lst[idx],
                         strlen(safe_env_lst[idx]))) {
                cleanenv[cidx] = *ep;
                cidx++;
                break;
            }
        }
    }

    cleanenv[cidx] = NULL;

    environ = cleanenv;
}

/* Pool account functions */


#include <utime.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pwd.h>
#include <sys/types.h>

/******************************************************************************
Function:   mapdir_otherlink
Description:
        find another link in map directory to the same inode as firstlink
        and change the modification time of firstlink to now (so that we
        always know when this pair was last used)
        
Parameters:
        firstlink, the filename of the link we already know

Returns:
        a pointer to the other link's filename (without path) or NULL if none
        found (this is malloc'd and will need freeing)

******************************************************************************/
static char *mapdir_otherlink(char *mapdir, char *firstlink)
{
     int            ret;
     char           *firstlinkpath, *otherlinkdup, *otherlinkpath;
     struct dirent  *mapdirentry;
     DIR            *mapdirstream;
     struct stat    statbuf;
     ino_t          firstinode;

     firstlinkpath = malloc(strlen(mapdir) + 2 + strlen(firstlink));
     sprintf(firstlinkpath, "%s/%s", mapdir, firstlink);     
     ret = stat(firstlinkpath, &statbuf);
     free(firstlinkpath);   
     if (ret != 0) return NULL;
     if (statbuf.st_nlink != 2) return NULL;
     
     firstinode = statbuf.st_ino; /* save for comparisons */
          
     mapdirstream = opendir(mapdir);

     if (mapdirstream != NULL)
       {
         while ((mapdirentry = readdir(mapdirstream)) != NULL)
              {       
                 if (strcmp(mapdirentry->d_name, firstlink) == 0) continue;
           
                 otherlinkpath = malloc(strlen(mapdir) + 2 + 
                                        strlen(mapdirentry->d_name));
                 sprintf(otherlinkpath, "%s/%s", mapdir, 
                                            mapdirentry->d_name);

                 ret = stat(otherlinkpath, &statbuf);     
                 if ((ret == 0) && (statbuf.st_ino == firstinode))
                   {
                      utime(otherlinkpath, (struct utimbuf *) NULL);
                      free(otherlinkpath);
                      otherlinkdup = strdup(mapdirentry->d_name);
                      closedir(mapdirstream);     
                      return otherlinkdup;
                   }
                 else free(otherlinkpath);
              }
         
         closedir(mapdirstream);     
       }

     return NULL;
}

/******************************************************************************
Function:   mapdir_urlencode
Description:
        Convert string to URL encoded and return pointer to the encoded
        version, obtained through malloc. Calling routine must free
        this. Here "URL encoded" means anything other than an isalnum()
        goes to %HH where HH is its ascii value in hex; also A-Z => a-z 
        This name is suitable for filenames since no / or spaces.

Parameters:
        rawstring, the string to be converted

Returns:
        a pointer to the encoded string or NULL if the malloc failed

******************************************************************************/
static char *mapdir_urlencode(char *rawstring)
{
     int          encodedchar = 0, rawchar = 0;
     char *       encodedstring;
     
     encodedstring = (char *) malloc(3 * strlen(rawstring) + 1);
     
     if (encodedstring == NULL) return (char *) NULL;

     while (rawstring[rawchar] != '\0')
          {
            if (isalnum(rawstring[rawchar]))
              {
                encodedstring[encodedchar] = tolower(rawstring[rawchar]);
                ++rawchar;
                ++encodedchar;
              }
            else
              {
                sprintf(&encodedstring[encodedchar], "%%%02x", 
                                               rawstring[rawchar]);
                ++rawchar;
                encodedchar = encodedchar + 3;
              }         
          }

     encodedstring[encodedchar] = '\0';
     
     return encodedstring;
}

/******************************************************************************
Function:   mapdir_newlease
Description:
        Search for an unleased local username to give to the X.509 DN or
        directory key corresponding to encodedfilename, and then lease it.

Parameters: 
        encodedfilename, URL-encoded X.509 DN or directory key to associate
         with an unlease pool username

Returns:
        no return value
******************************************************************************/

void mapdir_newlease(char *mapdir, char *encodedkey)
{
     int            ret;
     char           *userfilename, *encodedfilename;
     struct dirent  *mapdirentry;
     DIR            *mapdirstream;
     struct stat    statbuf;
     
     encodedfilename = malloc(strlen(mapdir) + (size_t) 2 + 
                              strlen(encodedkey));
     sprintf(encodedfilename, "%s/%s", mapdir, encodedkey);

     mapdirstream = opendir(mapdir);

     while ((mapdirentry = readdir(mapdirstream)) != NULL)
     {
       /* we dont want any files that dont look like acceptable usernames */
       if ((*(mapdirentry->d_name) == '%') || 
           (strcmp(mapdirentry->d_name, "root") == 0))   continue;
       else if (*(mapdirentry->d_name) == '.')           continue;
       else if (index(mapdirentry->d_name, '~') != NULL) continue;

       userfilename = malloc(strlen(mapdir) + (size_t) 2 + 
                             strlen(mapdirentry->d_name));
       sprintf(userfilename, "%s/%s", mapdir, mapdirentry->d_name);
       stat(userfilename, &statbuf);
       
       if (statbuf.st_nlink == 1) /* this one isnt leased yet */
       {   
           ret = link(userfilename, encodedfilename);
           free(userfilename);
           if (ret != 0) 
           {
               /* link failed: this is probably because a VERY lucky
                  other process has obtained a lease for encodedfilename 
                  while we were faffing around */
               closedir(mapdirstream);
               free(encodedfilename);
               return;
           }
     
           stat(encodedfilename, &statbuf);
           if (statbuf.st_nlink > 2) 
           {
              /* two keys have grabbed the same username: back off */
              unlink(encodedfilename);
              continue;
           }

           closedir(mapdirstream);
           free(encodedfilename);
           return; /* link worked ok, so return */
       }
       else free(userfilename); /* already in use, try next one */
     }
     
     closedir(mapdirstream);
     free(encodedfilename);
     return; /* no unleased names left: give up */     
}
     
/******************************************************************************
Function:   gridmapdir_userid
Description:
        This is equivalent to globus_gss_assist_gridmap but for the dynamic
        user ids in the gridmapdir: maps a globusID to a local unix user id,
        either one already leased, or calls gridmapdir_newlease() to obtain 
        a new lease. This is called by globus_gss_assist_gridmap if the 
        local user id in the static gridmap file begins . (for a dynamic id)

Parameters: 
        globusidp, globus client name who requested authentication 
        usernameprefix, prefix of the local usernames which would 
               be acceptable (or "\0" )
        *userid returned userid name for local system. 

Returns:
       
        0 on success
        !=0 on failure

******************************************************************************/



int GRSTexecGetMapping(char **target_uname, char **target_gname, 
                       char *mapdir, char *key) 
{
    char *encodedkey;
    
    if (key[0] != '/') return 1; /* must be a proper X.509 DN or path */
     
    encodedkey = mapdir_urlencode(key);
log_err("encodedkey=%s\n", encodedkey);
    *target_uname = mapdir_otherlink(mapdir, encodedkey);
log_err("*target_uname=%s\n", *target_uname);

    if (*target_uname == NULL) /* maybe no lease yet */
      {
         mapdir_newlease(mapdir, encodedkey);
         /* try making a lease */
         
         *target_uname = mapdir_otherlink(mapdir, encodedkey); 
         /* check if there is a now a lease - possibly made by someone else */

         if (*target_uname == NULL) 
           {
             free(encodedkey);
             return 1; /* still no good */
           }
      }

    free(encodedkey);
    
// nasty hack for now
*target_gname = strdup(*target_uname);
    
    return 0;
}

void internal_server_error(void)
{
    /* use this when its probably an httpd.conf configuration error */

    puts("Status: 500 Internal Server Error\n"
         "Content-Type: text/html\n\n"
         "<html><head><title>500 Internal Server Error</title></head>\n"
         "<body><h1>Internal Server Error</h1></body></html>");
}

void forbidden_error(void)
{
    /* use this when unix file permissions/ownerships are probably wrong */

    puts("Status: 403 Forbidden\n"
         "Content-Type: text/html\n\n"
         "<html><head><title>403 Forbidden</title></head>\n"
         "<body><h1>Forbidden</h1></body></html>");
}

int main(int argc, char *argv[])
{
    int userdir = 0;        /* ~userdir flag             */
    uid_t uid;              /* user information          */
    gid_t gid;              /* target group placeholder  */
    uid_t httpd_uid;	    /* uid for AP_HTTPD_USER     */
    gid_t httpd_gid;	    /* uid for AP_HTTPD_GROUP    */
    char *mapping_type;	    /* suexec / X509DN / directory */
    char *map_x509dn;	    /* DN to use as pool acct. key */
    char *map_directory;    /* directory as pool acct. key */

    char *diskmode_env;	          /* GRST_DISK_MODE as a string     */
    apr_fileperms_t diskmode_apr; /* GRST_DISK_MODE as Apache perms */
    mode_t diskmode_t;            /* GRST_DISK_MODE as mode_t       */

    char *target_uname;     /* target user name          */
    char *target_gname;     /* target group name         */
    char *target_homedir;   /* target home directory     */
    char *actual_uname;     /* actual user name          */
    char *actual_gname;     /* actual group name         */
    char *prog;             /* name of this program      */
    char *cmd;              /* command to be executed    */
    char cwd[AP_MAXPATH];   /* current working directory */
    char dwd[AP_MAXPATH];   /* docroot working directory */
    struct passwd *pw;      /* password entry holder     */
    struct group *gr;       /* group entry holder        */
    struct stat dir_info;   /* directory info holder     */
    struct stat prg_info;   /* program info holder       */

    /*
     * Start with a "clean" environment
     */
    clean_env();

    prog = argv[0];
    /*
     * Check existence/validity of the UID of the user
     * running this program.  Error out if invalid.
     */
    uid = getuid();
    if ((pw = getpwuid(uid)) == NULL) {
        log_err("crit: invalid uid: (%ld)\n", uid);
        internal_server_error();
        exit(102);
    }
    /*
     * Check existence/validity of the GID of the user
     * running this program.  Error out if invalid.
     */
    gid = getgid();
    if ((gr = getgrgid(gid)) == NULL) {
        log_err("crit: invalid gid: (%ld)\n", gid);
        internal_server_error();
        exit(102);
    }
    /*
     * See if this is a 'how were you compiled' request, and
     * comply if so.
     */
    if ((argc > 1)
        && (! strcmp(argv[1], "-V"))
        && ((uid == 0)
#ifdef _OSD_POSIX
        /* User name comparisons are case insensitive on BS2000/OSD */
            || (! strcasecmp(AP_HTTPD_USER, pw->pw_name)))
#else  /* _OSD_POSIX */
            || (! strcmp(AP_HTTPD_USER, pw->pw_name)))
#endif /* _OSD_POSIX */
        ) {
#ifdef AP_DOC_ROOT
        fprintf(stderr, " -D AP_DOC_ROOT=\"%s\"\n", AP_DOC_ROOT);
#endif
#ifdef AP_GID_MIN
        fprintf(stderr, " -D AP_GID_MIN=%d\n", AP_GID_MIN);
#endif
#ifdef AP_HTTPD_USER
        fprintf(stderr, " -D AP_HTTPD_USER=\"%s\"\n", AP_HTTPD_USER);
#endif
#ifdef AP_LOG_EXEC
        fprintf(stderr, " -D AP_LOG_EXEC=\"%s\"\n", AP_LOG_EXEC);
#endif
#ifdef AP_SAFE_PATH
        fprintf(stderr, " -D AP_SAFE_PATH=\"%s\"\n", AP_SAFE_PATH);
#endif
#ifdef AP_SUEXEC_UMASK
        fprintf(stderr, " -D AP_SUEXEC_UMASK=%03o\n", AP_SUEXEC_UMASK);
#endif
#ifdef AP_UID_MIN
        fprintf(stderr, " -D AP_UID_MIN=%d\n", AP_UID_MIN);
#endif
#ifdef AP_USERDIR_SUFFIX
        fprintf(stderr, " -D AP_USERDIR_SUFFIX=\"%s\"\n", AP_USERDIR_SUFFIX);
#endif
        exit(0);
    }
    /*
     * If there are a proper number of arguments, set
     * all of them to variables.  Otherwise, error out.
     */
    if (argc < 4) {
        log_err("too few arguments\n");
        internal_server_error();
        exit(101);
    }
    
    mapping_type = getenv("GRST_EXEC_METHOD");
log_err("mapping_type from GRST_EXEC_METHOD=%s\n",mapping_type);
    if ((mapping_type    == NULL) ||
        (mapping_type[0] == '\0') ||
        (strcasecmp(mapping_type, "suexec") == 0))
      {
        target_uname = argv[1];
        target_gname = argv[2];
        mapping_type = NULL;
      }
    else if (strcasecmp(mapping_type, "X509DN") == 0)
      {
log_err("X509DN mapping type\n");
        map_x509dn = getenv("SSL_CLIENT_S_DN");
        if (map_x509dn == NULL)
          {
            log_err("No SSL_CLIENT_S_DN despite X509DN mapping\n");
            internal_server_error();
            exit(151);
          }

        if (GRSTexecGetMapping(&target_uname, &target_gname, 
                               GRST_EXECMAPDIR, map_x509dn) 
            != 0)
          {
            log_err("GRSTexecGetMapping() failed mapping \"%s\"\n", 
                    map_x509dn);
            internal_server_error();
            exit(152);          
          }
      }
    else if (strcasecmp(mapping_type, "directory") == 0)
      {
        map_directory = getenv("GRST_EXEC_DIRECTORY");
        if (map_directory == NULL)
          {
            log_err("No GRST_EXEC_DIRECTORY despite directory mapping\n");
            internal_server_error();
            exit(153);
          }

        if (GRSTexecGetMapping(&target_uname, &target_gname, 
                               GRST_EXECMAPDIR, map_directory) 
            != 0)
          {
            log_err("GRSTexecGetMapping() failed mapping \"%s\"\n", 
                    map_directory);
            internal_server_error();
            exit(154);          
          }
      }
    else 
      {
        log_err("mapping type \"%s\" not recognised\n", mapping_type);
        internal_server_error();
        exit(155);
      }

    cmd = argv[3];

    /*
     * Check to see if the user running this program
     * is the user allowed to do so as defined in
     * suexec.h.  If not the allowed user, error out.
     */
#ifdef _OSD_POSIX
    /* User name comparisons are case insensitive on BS2000/OSD */
    if (strcasecmp(AP_HTTPD_USER, pw->pw_name)) {
        log_err("user mismatch (%s instead of %s)\n", pw->pw_name, AP_HTTPD_USER);
        internal_server_error();
        exit(103);
    }
    /* User name comparisons are case insensitive on BS2000/OSD */
    if (strcasecmp(AP_HTTPD_GROUP, gr->gr_name)) {
        log_err("group mismatch (%s instead of %s)\n", gr->gr_name, AP_HTTPD_GROUP);
        internal_server_error();
        exit(103);
    }
#else  /*_OSD_POSIX*/
    if (strcmp(AP_HTTPD_USER, pw->pw_name)) {
        log_err("user mismatch (%s instead of %s)\n", pw->pw_name, AP_HTTPD_USER);
        internal_server_error();
        exit(103);
    }
    if (strcmp(AP_HTTPD_GROUP, gr->gr_name)) {
        log_err("group mismatch (%s instead of %s)\n", gr->gr_name, AP_HTTPD_GROUP);
        internal_server_error();
        exit(103);
    }
#endif /*_OSD_POSIX*/

    /* Since they match (via name) save these for later */

    httpd_uid = uid;
    httpd_gid = gid;

    /*
     * Check for a leading '/' (absolute path) in the command to be executed,
     * or attempts to back up out of the current directory,
     * to protect against attacks.  If any are
     * found, error out.  Naughty naughty crackers.
     */
    if ((cmd[0] == '/') || (!strncmp(cmd, "../", 3))
        || (strstr(cmd, "/../") != NULL)) {
        log_err("invalid command (%s)\n", cmd);
        internal_server_error();
        exit(104);
    }

    /*
     * Check to see if this is a ~userdir request.  If
     * so, set the flag, and remove the '~' from the
     * target username.
     */
    if (!strncmp("~", target_uname, 1)) {
        target_uname++;
        userdir = 1;
    }

    /*
     * Error out if the target username is invalid.
     */
    if (strspn(target_uname, "1234567890") != strlen(target_uname)) {
        if ((pw = getpwnam(target_uname)) == NULL) {
            log_err("invalid target user name: (%s)\n", target_uname);
            internal_server_error();
            exit(105);
        }
    }
    else {
        if ((pw = getpwuid(atoi(target_uname))) == NULL) {
            log_err("invalid target user id: (%s)\n", target_uname);
            internal_server_error();
            exit(121);
        }
    }

    /*
     * Error out if the target group name is invalid.
     */
    if (strspn(target_gname, "1234567890") != strlen(target_gname)) {
        if ((gr = getgrnam(target_gname)) == NULL) {
            log_err("invalid target group name: (%s)\n", target_gname);
            internal_server_error();
            exit(106);
        }
        gid = gr->gr_gid;
        actual_gname = strdup(gr->gr_name);
    }
    else {
        gid = atoi(target_gname);
        actual_gname = strdup(target_gname);
    }

#ifdef _OSD_POSIX
    /*
     * Initialize BS2000 user environment
     */
    {
        pid_t pid;
        int status;

        switch (pid = ufork(target_uname)) {
        case -1:    /* Error */
            log_err("failed to setup bs2000 environment for user %s: %s\n",
                    target_uname, strerror(errno));
            internal_server_error();
            exit(150);
        case 0:     /* Child */
            break;
        default:    /* Father */
            while (pid != waitpid(pid, &status, 0))
                ;
            /* @@@ FIXME: should we deal with STOP signals as well? */
            if (WIFSIGNALED(status)) {
                kill (getpid(), WTERMSIG(status));
            }
            internal_server_error();
            exit(WEXITSTATUS(status));
        }
    }
#endif /*_OSD_POSIX*/
    
    /*
     * Save these for later since initgroups will hose the struct
     */
    uid = pw->pw_uid;
    actual_uname = strdup(pw->pw_name);
    target_homedir = strdup(pw->pw_dir);

    /*
     * Log the transaction here to be sure we have an open log 
     * before we setuid().
     */
    log_no_err("uid: (%s/%s) gid: (%s/%s) cmd: %s\n",
               target_uname, actual_uname,
               target_gname, actual_gname,
               cmd);

    /*
     * Error out if attempt is made to execute as root or as
     * a UID less than AP_UID_MIN.  Tsk tsk.
     */
    if ((uid == 0) || (uid < AP_UID_MIN)) {
        log_err("cannot run as forbidden uid (%d/%s)\n", uid, cmd);
        internal_server_error();
        exit(107);
    }

    /*
     * Error out if attempt is made to execute as root group
     * or as a GID less than AP_GID_MIN.  Tsk tsk.
     */
    if ((gid == 0) || (gid < AP_GID_MIN)) {
        log_err("cannot run as forbidden gid (%d/%s)\n", gid, cmd);
        internal_server_error();
        exit(108);
    }

    /*
     * Change UID/GID here so that the following tests work over NFS.
     *
     * Initialize the group access list for the target user,
     * and setgid() to the target group. If unsuccessful, error out.
     */
    if (((setgid(gid)) != 0) || (initgroups(actual_uname, gid) != 0)) {
        log_err("failed to setgid (%ld: %s)\n", gid, cmd);
        internal_server_error();
        exit(109);
    }

    /*
     * setuid() to the target user.  Error out on fail.
     */
    if ((setuid(uid)) != 0) {
        log_err("failed to setuid (%ld: %s)\n", uid, cmd);
        internal_server_error();
        exit(110);
    }

    /*
     * Get the current working directory, as well as the proper
     * document root (dependant upon whether or not it is a
     * ~userdir request).  Error out if we cannot get either one,
     * or if the current working directory is not in the docroot.
     * Use chdir()s and getcwd()s to avoid problems with symlinked
     * directories.  Yuck.
     */
    if (getcwd(cwd, AP_MAXPATH) == NULL) {
        log_err("cannot get current working directory\n");
        internal_server_error();
        exit(111);
    }

#if 0
    if (userdir) {
        if (((chdir(target_homedir)) != 0) ||
            ((chdir(AP_USERDIR_SUFFIX)) != 0) ||
            ((getcwd(dwd, AP_MAXPATH)) == NULL) ||
            ((chdir(cwd)) != 0)) {
            log_err("cannot get docroot information (%s)\n", target_homedir);
            internal_server_error();
            exit(112);
        }
    }
    else {
        if (((chdir(AP_DOC_ROOT)) != 0) ||
            ((getcwd(dwd, AP_MAXPATH)) == NULL) ||
            ((chdir(cwd)) != 0)) {
            log_err("cannot get docroot information (%s)\n", AP_DOC_ROOT);
            internal_server_error();
            exit(113);
        }
    }

    if ((strncmp(cwd, dwd, strlen(dwd))) != 0) {
        log_err("command not in docroot (%s/%s)\n", cwd, cmd);
        internal_server_error();
        exit(114);
    }
#endif

    /*
     * Stat the cwd and verify it is a directory, or error out.
     */
    if (((lstat(cwd, &dir_info)) != 0) || !(S_ISDIR(dir_info.st_mode))) {
        log_err("cannot stat directory: (%s)\n", cwd);
        internal_server_error();
        exit(115);
    }

    /*
     * Error out if cwd is writable by others.
     */
    if ((dir_info.st_mode & S_IWOTH) || (dir_info.st_mode & S_IWGRP)) {
        log_err("directory is writable by others: (%s)\n", cwd);
        forbidden_error();
        exit(116);
    }

    /*
     * Error out if we cannot stat the program.
     */
    if (((lstat(cmd, &prg_info)) != 0) || (S_ISLNK(prg_info.st_mode))) {
        log_err("cannot stat program: (%s)\n", cmd);
        forbidden_error();
        exit(117);
    }

    /*
     * Error out if the program is writable by others.
     */
    if (prg_info.st_mode & S_IWOTH) {
        log_err("file is writable by others: (%s/%s)\n", cwd, cmd);
        forbidden_error();
        exit(118);
    }

    /*
     * Error out if the file is setuid or setgid.
     */
    if ((prg_info.st_mode & S_ISUID) || (prg_info.st_mode & S_ISGID)) {
        log_err("file is either setuid or setgid: (%s/%s)\n", cwd, cmd);
        forbidden_error();
        exit(119);
    }

    /*
     * Error out if the target name/group is different from
     * the name/group of the cwd or the program AND the name/group 
     * of the cwd and program are not the AP_HTTPD_USER/AP_HTTPD_GROUP
     * AND the name/group of the cwd and program are not root
     */
    if (((uid != dir_info.st_uid) && (httpd_uid != dir_info.st_uid)
                                  && (0 != dir_info.st_uid)) ||
        ((gid != dir_info.st_gid) && (httpd_gid != dir_info.st_gid)
                                  && (0 != dir_info.st_gid)) ||
        ((uid != prg_info.st_uid) && (httpd_uid != prg_info.st_uid)
                                  && (0 != prg_info.st_uid)) ||
        ((gid != prg_info.st_gid) && (httpd_gid != prg_info.st_gid)
                                  && (0 != prg_info.st_gid)))
      {
        log_err("target (%ld/%ld) or %s (%ld/%ld) or root (0/0) uid/gid "
                "mismatch with directory (%ld/%ld) or program (%ld/%ld)\n",
                uid, gid, AP_HTTPD_USER, httpd_uid, httpd_gid,
                dir_info.st_uid, dir_info.st_gid,
                prg_info.st_uid, prg_info.st_gid);
        forbidden_error();
        exit(120);
      }
    /*
     * Error out if the program is not executable for the user.
     * Otherwise, she won't find any error in the logs except for
     * "[error] Premature end of script headers: ..."
     */
    if (!(prg_info.st_mode & S_IXUSR)) {
        log_err("file has no execute permission: (%s/%s)\n", cwd, cmd);
        forbidden_error();
        exit(121);
    }

    diskmode_env = getenv("GRST_DISK_MODE");
    if (diskmode_env != NULL)
      {
        diskmode_apr = 0;
        sscanf(diskmode_env, "%d", &diskmode_apr);
      
        diskmode_t = S_IRUSR | S_IWUSR;
        
        if (diskmode_apr & APR_GREAD ) diskmode_t |= S_IRGRP;
        if (diskmode_apr & APR_GWRITE) diskmode_t |= S_IWGRP;
        if (diskmode_apr & APR_WREAD ) diskmode_t |= S_IROTH;
        
        diskmode_t &= (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
        
        umask(~diskmode_t);
      }
#ifdef AP_SUEXEC_UMASK
    else umask(AP_SUEXEC_UMASK);
#else
    else umask(~(S_IRUSR | S_IWUSR));
#endif /* AP_SUEXEC_UMASK */
    
    

    /* 
     * Be sure to close the log file so the CGI can't
     * mess with it.  If the exec fails, it will be reopened 
     * automatically when log_err is called.  Note that the log
     * might not actually be open if AP_LOG_EXEC isn't defined.
     * However, the "log" cell isn't ifdef'd so let's be defensive
     * and assume someone might have done something with it
     * outside an ifdef'd AP_LOG_EXEC block.
     */
    if (log != NULL) {
        fclose(log);
        log = NULL;
    }

    /*
     * Execute the command, replacing our image with its own.
     */
#ifdef NEED_HASHBANG_EMUL
    /* We need the #! emulation when we want to execute scripts */
    {
        extern char **environ;

        ap_execve(cmd, &argv[3], environ);
    }
#else /*NEED_HASHBANG_EMUL*/
   execv(cmd, &argv[3]);
#endif /*NEED_HASHBANG_EMUL*/

    /*
     * (I can't help myself...sorry.)
     *
     * Uh oh.  Still here.  Where's the kaboom?  There was supposed to be an
     * EARTH-shattering kaboom!
     *
     * Oh well, log the failure and error out.
     */
    log_err("(%d)%s: exec failed (%s)\n", errno, strerror(errno), cmd);
    internal_server_error();
    exit(255);
}
