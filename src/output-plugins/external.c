/*
** Copyright (C) 2009-2022 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2022 Champ Clark III <cclark@quadrantsec.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* external.c
 *
 * Threaded function for user defined external system (execl) calls.  This
 * allows sagan to pass information to a external program.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif


#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "version.h"

#include "lockfile.h"
#include "references.h"
#include "sagan-config.h"
#include "util-time.h"
#include "output-plugins/external.h"

extern struct _Rule_Struct *rulestruct;
extern struct _SaganDebug *debug;
extern struct _SaganConfig *config;

pthread_mutex_t ext_mutex = PTHREAD_MUTEX_INITIALIZER;

void External_Thread ( char *alert_data, char *execute_script )
{

#ifndef HAVE_LIBFASTJSON
    Sagan_Log(WARN, "[%s, line %d] The 'external' rule option requires Sagan to be compiled with 'linfastjson'.",  __FILE__, __LINE__);
#endif

#ifdef HAVE_LIBFASTJSON

    int in[2];
    int out[2];
    uint_fast32_t n;
    uint_fast32_t pid;

    char *buf = malloc( MAX_SYSLOGMSG );

    if ( buf == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __FILE__, __LINE__);
        }

    memset( buf, 0, MAX_SYSLOGMSG );

    if ( debug->debugexternal )
        {
            Sagan_Log(WARN, "[%s, line %d] Sending: %s", __FILE__, __LINE__, alert_data);
        }

    pthread_mutex_lock( &ext_mutex );

    if ( pipe(in) < 0 )
        {
            Remove_Lock_File();
            free(buf);
            Sagan_Log(ERROR, "[%s, line %d] Cannot create input pipe!", __FILE__, __LINE__);
        }


    if ( pipe(out) < 0 )
        {
            Remove_Lock_File();
            free(buf);
            Sagan_Log(ERROR, "[%s, line %d] Cannot create output pipe!", __FILE__, __LINE__);
        }

    pid=fork();
    if ( pid < 0 )
        {
            free(buf);
            Sagan_Log(ERROR, "[%s, line %d] Cannot create external program process", __FILE__, __LINE__);
        }
    else if ( pid == 0 )
        {
            /* Causes problems with alert.log */

            close(0);
            close(1);
            close(2);

            dup2(in[0],0);		// Stdin..
            dup2(out[1],1);
            dup2(out[1],2);

            close(in[1]);
            close(out[0]);

            execl(execute_script, execute_script, NULL, (char *)NULL);

            Remove_Lock_File();
            Sagan_Log(WARN, "[%s, line %d] Cannot execute %s", __FILE__, __LINE__, execute_script);
        }

    close(in[0]);
    close(out[1]);

    /* Write to child input */

    n = write(in[1], alert_data, strlen(alert_data));
    close(in[1]);

    n = read(out[0], buf, MAX_SYSLOGMSG);
    close(out[0]);
    buf[n] = 0;

    waitpid(pid, NULL, 0);

    pthread_mutex_unlock( &ext_mutex );

    if ( debug->debugexternal == 1 )
        {
            Sagan_Log(DEBUG, "[%s, line %d] Executed %s", __FILE__, __LINE__, execute_script);
        }

    free(buf);

#endif

}

