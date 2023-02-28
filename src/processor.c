/*
** Copyright (C) 2009-2023 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2023 Champ Clark III <cclark@quadrantsec.com>
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

/* processor.c
*
* This becomes a threaded operation.  This handles all CPU intensive processes.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <atomic.h>

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include "sagan.h"
#include "sagan-defs.h"
#include "ignore-list.h"
#include "sagan-config.h"
#include "input-pipe.h"
#include "geoip.h"
#include "routing.h"
#include "parsers/parsers.h"
#include "processor-memory.h"

#ifdef HAVE_LIBLOGNORM
#include "liblognormalize.h"
#endif

#ifdef HAVE_LIBFASTJSON
#include "input-json.h"
#endif

#include "processors/engine.h"
#include "processors/track-clients.h"
#include "processors/blacklist.h"
#include "processors/dynamic-rules.h"
#include "processors/client-stats.h"

extern struct _SaganCounters *counters;
extern struct _Sagan_Pass_Syslog *SaganPassSyslog;
extern struct _SaganConfig *config;
extern struct _SaganDebug *debug;

struct _Sagan_Proc_Syslog *SaganProcSyslog;

extern uint_fast16_t proc_msgslot; 		/* Comes from sagan.c */
extern uint_fast16_t proc_running;  	        /* Comes from sagan.c */

bool dynamic_rule_flag = NORMAL_RULE;
uint_fast16_t dynamic_line_count = 0;

extern bool death;

extern pthread_cond_t SaganProcDoWork;
extern pthread_mutex_t SaganProcWorkMutex;

extern pthread_cond_t SaganReloadCond;
extern pthread_mutex_t SaganReloadMutex;

extern pthread_mutex_t SaganDynamicFlag;

void Processor ( void )
{

    uint_fast16_t z = 0;

#ifdef HAVE_SYS_PRCTL_H
    (void)SetThreadName("SaganProcessor");
#endif

    struct _Sagan_Proc_Syslog *SaganProcSyslog = NULL;
    SaganProcSyslog = malloc(sizeof(struct _Sagan_Proc_Syslog));

    if ( SaganProcSyslog == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SaganProcSyslog. Abort!", __FILE__, __LINE__);
        }

    /* ----------------------------------------------- */

    struct _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL = NULL;
    SaganProcSyslog_LOCAL = malloc(sizeof(struct _Sagan_Proc_Syslog));

    if ( SaganProcSyslog_LOCAL == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SaganProcSyslog_LOCAL. Abort!", __FILE__, __LINE__);
        }

    Processor_Memory ( SaganProcSyslog_LOCAL );

    /* ----------------------- */

    struct _Sagan_Pass_Syslog *SaganPassSyslog_LOCAL = NULL;
    SaganPassSyslog_LOCAL = malloc(sizeof(struct _Sagan_Pass_Syslog));

    if ( SaganPassSyslog_LOCAL == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SaganPassSyslog_LOCAL. Abort!", __FILE__, __LINE__);
        }

    for ( z = 0; z < config->max_batch; z++ )
        {
            SaganPassSyslog_LOCAL->batch[z] = malloc( config->message_buffer_size );

            if ( SaganPassSyslog_LOCAL->batch[z] == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for *SaganPassSyslog_LOCAL[z].batch. Abort!", __FILE__, __LINE__);
                }

        }

    struct _Sagan_JSON *JSON_LOCAL = NULL;

#if defined(HAVE_LIBFASTJSON)

    JSON_LOCAL = malloc(sizeof(struct _Sagan_JSON));

    if ( JSON_LOCAL == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for _Sagan_JSON. ABort!", __FILE__, __LINE__);
        }

    JSON_LOCAL->json_count = 0;

    if ( config->input_type == INPUT_JSON || config->json_parse_data == true )
        {

            for ( z = 0; z < JSON_MAX_OBJECTS; z++ )
                {
                    JSON_LOCAL->json_key[z] = malloc ( JSON_MAX_KEY_SIZE );

                    if ( JSON_LOCAL->json_key[z] == NULL )
                        {
                            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __FILE__, __LINE__);
                        }

                    JSON_LOCAL->json_key[z][0] = '\0';

                    JSON_LOCAL->json_value[z] = malloc ( config->message_buffer_size );

                    if ( JSON_LOCAL->json_value[z] == NULL )
                        {
                            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __FILE__, __LINE__);
                        }

                    JSON_LOCAL->json_value[z][0] = '\0';

                }

        }

#endif

    uint_fast8_t i;

    while (death == false)
        {

            pthread_mutex_lock(&SaganProcWorkMutex);

            while ( proc_msgslot == 0 ) pthread_cond_wait(&SaganProcDoWork, &SaganProcWorkMutex);

            if ( config->sagan_reload )
                {
                    pthread_cond_wait(&SaganReloadCond, &SaganReloadMutex);
                }

            proc_msgslot--;     /* This was ++ before coming over, so we now -- it to get to
                                   original value */

            /* Copy inbound array from global to local */

            for (i=0; i < config->max_batch; i++)
                {

                    if (debug->debugsyslog)
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] [batch position %d] Raw log: %s",  __FILE__, __LINE__, i, SaganPassSyslog[proc_msgslot].batch[i]);
                        }

                    strlcpy(SaganPassSyslog_LOCAL->batch[i],  SaganPassSyslog[proc_msgslot].batch[i], config->message_buffer_size);

                }

            pthread_mutex_unlock(&SaganProcWorkMutex);

            __atomic_add_fetch(&proc_running, 1, __ATOMIC_SEQ_CST);

            if ( proc_running > counters->max_threads_used )
                {
                    __atomic_store_n(&counters->max_threads_used, proc_running, __ATOMIC_SEQ_CST);
                }


            /* Processes local buffer */

            for (i=0; i < config->max_batch; i++)
                {

                    /* Reset json_count to 0 from previous value.  This is for input or JSON
                     * detected within the log */

                    if ( config->json_parse_data || config->input_type == INPUT_JSON )
                        {
                            JSON_LOCAL->json_count = 0;
                            SaganProcSyslog_LOCAL->json_normalize[0] = '\0';
                            SaganProcSyslog_LOCAL->json_original[0] = '\0';
                        }


                    if ( config->input_type == INPUT_PIPE )
                        {
                            SyslogInput_Pipe( SaganPassSyslog_LOCAL->batch[i], SaganProcSyslog_LOCAL );
                        }

#ifdef HAVE_LIBFASTJSON

                    else
                        {
                            SyslogInput_JSON( SaganPassSyslog_LOCAL->batch[i], SaganProcSyslog_LOCAL, JSON_LOCAL );
                        }

#endif

                    if (debug->debugsyslog)
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] **[Parsed Syslog]*********************************", __FILE__, __LINE__);
                            Sagan_Log(DEBUG, "[%s, line %d] Host: %s | Program: %s | Facility: %s | Priority: %s | Level: %s | Tag: %s | Date: %s | Time: %s", __FILE__, __LINE__, SaganProcSyslog_LOCAL->syslog_host, SaganProcSyslog_LOCAL->syslog_program, SaganProcSyslog_LOCAL->syslog_facility, SaganProcSyslog_LOCAL->syslog_priority, SaganProcSyslog_LOCAL->syslog_level, SaganProcSyslog_LOCAL->syslog_tag, SaganProcSyslog_LOCAL->syslog_date, SaganProcSyslog_LOCAL->syslog_time);
                            Sagan_Log(DEBUG, "[%s, line %d] Parsed message: %s", __FILE__, __LINE__,  SaganProcSyslog_LOCAL->syslog_message);
                        }

                    /* Dynamic goes here */

                    if ( config->dynamic_load_flag == true )
                        {

                            __atomic_add_fetch(&dynamic_line_count, 1, __ATOMIC_SEQ_CST);

                            if ( dynamic_line_count >= config->dynamic_load_sample_rate )
                                {
                                    dynamic_rule_flag = DYNAMIC_RULE;

                                    __atomic_store_n (&dynamic_line_count, 0, __ATOMIC_SEQ_CST);

                                }
                        }

                    Sagan_Engine( SaganProcSyslog_LOCAL, JSON_LOCAL, dynamic_rule_flag );

                    /* If this is a dynamic run,  reset back to normal */

                    if ( dynamic_rule_flag == DYNAMIC_RULE )
                        {
                            dynamic_rule_flag = NORMAL_RULE;
                        }

                    if ( config->client_stats_flag )
                        {

                            uint_fast32_t bytes = strlen(SaganProcSyslog_LOCAL->syslog_host) +
                                                  strlen(SaganProcSyslog_LOCAL->syslog_facility) +
                                                  strlen(SaganProcSyslog_LOCAL->syslog_priority) +
                                                  strlen(SaganProcSyslog_LOCAL->syslog_level) +
                                                  strlen(SaganProcSyslog_LOCAL->syslog_tag) +
                                                  strlen(SaganProcSyslog_LOCAL->syslog_date) +
                                                  strlen(SaganProcSyslog_LOCAL->syslog_time) +
                                                  strlen(SaganProcSyslog_LOCAL->syslog_program) +
                                                  strlen(SaganProcSyslog_LOCAL->syslog_message) + 9; /* 9 == delimiters! */

                            Client_Stats_Add_Update_IP ( SaganProcSyslog_LOCAL->syslog_host, SaganProcSyslog_LOCAL->syslog_program, SaganProcSyslog_LOCAL->syslog_message, SaganProcSyslog_LOCAL->syslog_tag, bytes );

                        }

                    if ( config->sagan_track_clients_flag && SaganProcSyslog_LOCAL->syslog_host[0] != '\0' )
                        {
                            Track_Clients( SaganProcSyslog_LOCAL->syslog_host );
                        }

                }

            __atomic_sub_fetch(&proc_running, 1, __ATOMIC_SEQ_CST);

        } /*  for (;;) */

    /* Exit thread on shutdown. */

// DEBUGME: Faults
    free( SaganProcSyslog_LOCAL->json_normalize );
    free( SaganProcSyslog_LOCAL );
    /*
        for ( z = 0; z < config->max_batch; z++ )
        {
    	    free(SaganPassSyslog_LOCAL[z].batch);
    	}

        free( SaganPassSyslog_LOCAL );
    */
#if defined(HAVE_LIBFASTJSON)
    free(JSON_LOCAL);
#endif

    __atomic_sub_fetch(&config->max_processor_threads, 1, __ATOMIC_SEQ_CST);

    /* Cleans up valgrind */

    pthread_exit(NULL);

}

