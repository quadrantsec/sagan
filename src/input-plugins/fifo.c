/*
** Copyright (C) 2009-2025 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2025 Champ Clark III <cclark@quadrantsec.com>
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

/* fifo.c - reads data in from a named pipe */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <zlib.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>

#include <fcntl.h>           /* Definition of AT_* constants */
#include <sys/stat.h>


#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"
#include "ignore.h"

#include "lockfile.h"
#include "stats.h"

extern struct _SaganCounters *counters;
extern struct _SaganConfig *config;
extern struct _SaganDebug *debug;

extern struct _Sagan_Pass_Syslog *SaganPassSyslog;
extern pthread_cond_t SaganProcDoWork;
extern pthread_mutex_t SaganProcWorkMutex;

extern uint_fast16_t proc_msgslot;
extern uint_fast16_t proc_running;

extern bool death;



void FIFO_Input ( void )
{

    FILE *fd;

    char *syslogstring = malloc( config->message_buffer_size );

    if ( syslogstring == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __FILE__, __LINE__);
        }

    syslogstring[0] = '\0';

    Sagan_Log(NORMAL, "Attempting to open syslog FIFO (%s).", config->sagan_fifo);

    bool fifoerr = false;
    bool ignore_flag = false;

    uint_fast16_t batch_count = 0;
    uint_fast16_t i = 0;
    uint_fast16_t z = 0;

    struct _Sagan_Pass_Syslog *SaganPassSyslog_LOCAL = NULL;

    SaganPassSyslog_LOCAL = malloc(sizeof(_Sagan_Pass_Syslog));

    if ( SaganPassSyslog_LOCAL == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SaganPassSyslog_LOCAL. Abort!", __FILE__, __LINE__);
        }

    for ( z = 0; z < config->max_batch; z++ )
        {
            SaganPassSyslog_LOCAL->batch[z] = malloc( config->message_buffer_size );

            if ( SaganPassSyslog_LOCAL->batch[z] == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for *SaganPassSyslog_LOCAL->batch[z]. Abort!", __FILE__, __LINE__);
                }

        }

    while( death == false )
        {

            /* Open the FIFO */

            if (( fd = fopen(config->sagan_fifo, "r" )) == NULL )
                {

                    /* Opening FIFO failed,  try a few things */


                    Sagan_Log(NORMAL, "Fifo not found, creating it (%s).", config->sagan_fifo);

                    if (mkfifo(config->sagan_fifo, 0700) == -1)
                        {
                            Remove_Lock_File();
                            Sagan_Log(ERROR, "Could not create FIFO '%s'. Abort!", config->sagan_fifo);
                        }

                    fd = fopen(config->sagan_fifo, "r");

                    if ( fd == NULL )
                        {
                            Remove_Lock_File();
                            Sagan_Log(ERROR, "Error opening %s. Abort!", config->sagan_fifo);
                        }

                }

            Sagan_Log(NORMAL, "Successfully opened FIFO (%s).", config->sagan_fifo);

#if defined(HAVE_GETPIPE_SZ) && defined(HAVE_SETPIPE_SZ)
            Set_Pipe_Size(fd);
#endif

            while(fd != NULL)
                {

                    clearerr( fd );

                    while(fgets(syslogstring, config->message_buffer_size, fd) != NULL)
                        {

                            /* If the FIFO was in a error state,  let user know the FIFO writer has resumed */

                            if ( fifoerr == true )
                                {

                                    Sagan_Log(NORMAL, "FIFO writer has restarted. Processing events.");

#if defined(HAVE_GETPIPE_SZ) && defined(HAVE_SETPIPE_SZ)

                                    Set_Pipe_Size(fd);

#endif
                                    fifoerr = false;
                                }

                            counters->events_received++;

                            /* Copy log line to batch/queue if we haven't reached our batch limit */

                            if (debug->debugsyslog)
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] [batch position %d] Raw log: %s",  __FILE__, __LINE__, batch_count, syslogstring);
                                }

                            /* We're not threads here so no reason to lock */

                            uint_fast32_t bytes_total = strlen( syslogstring );

                            counters->bytes_total = counters->bytes_total + bytes_total;

                            if ( bytes_total > counters->max_bytes_length )
                                {
                                    counters->max_bytes_length = bytes_total;
                                }

                            if ( bytes_total >= config->message_buffer_size )
                                {

				    Sagan_Log(WARN, "Received log over the 'message-buffer-size' size.  Consider increasing this value!");
                                    counters->max_bytes_over++;

                                }

                            /* Check for "drop" to save CPU from "ignore list" */

                            if ( config->sagan_droplist_flag == true )
                                {

                                    ignore_flag = false;

                                    if ( Ignore( syslogstring ) == true )
                                        {
                                            ignore_flag = true;
                                        }

                                }

                            if ( ignore_flag == false )
                                {
                                    strlcpy(SaganPassSyslog_LOCAL->batch[batch_count], syslogstring, config->message_buffer_size);
                                    batch_count++;
                                }

                            /* Do we have enough threads? */

                            if ( proc_msgslot < config->max_processor_threads )
                                {

                                    /* Has our batch count been reached */

                                    if ( batch_count >= config->max_batch )
                                        {

                                            batch_count=0;              /* Reset batch/queue */

                                            pthread_mutex_lock(&SaganProcWorkMutex);

                                            /* Copy local thread data to global thread */

                                            for ( i = 0; i < config->max_batch; i++)
                                                {

                                                    strlcpy(SaganPassSyslog[proc_msgslot].batch[i], SaganPassSyslog_LOCAL->batch[i], config->message_buffer_size);
                                                }

                                            counters->events_processed = counters->events_processed + config->max_batch;

                                            proc_msgslot++;

                                            /* Send work to thread */

                                            pthread_cond_signal(&SaganProcDoWork);
                                            pthread_mutex_unlock(&SaganProcWorkMutex);

                                        }

                                }

                            else
                                {

                                    /* If there's no thread, we lose the entire batch */

                                    counters->worker_thread_exhaustion = counters->worker_thread_exhaustion + config->max_batch;
                                    batch_count = 0;

                                }

                        } /* while(fgets) */

                    /* fgets() has returned a error,  likely due to the FIFO writer leaving */

                    if ( fifoerr == false )
                        {

                            Sagan_Log(WARN, "FIFO writer closed.  Waiting for FIFO writer to restart....");
                            clearerr(fd);
                            fifoerr = true;                     /* Set flag so our wile(fgets) knows */

                        }

                    sleep(1);           /* So we don't eat 100% CPU */

                } /* while(fd != NULL)  */

        }

    free(syslogstring);
    free(SaganPassSyslog_LOCAL);
}
