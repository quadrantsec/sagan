/*
** Copyright (C) 2009-2021 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2021 Champ Clark III <cclark@quadrantsec.com>
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
extern struct _Sagan_Proc_Syslog *SaganProcSyslog;
extern struct _Sagan_Pass_Syslog *SaganPassSyslog;
extern struct _SaganConfig *config;
extern struct _SaganDebug *debug;


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

#ifdef HAVE_SYS_PRCTL_H
    (void)SetThreadName("SaganProcessor");
#endif

    struct _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL = NULL;
    SaganProcSyslog_LOCAL = malloc(sizeof(struct _Sagan_Proc_Syslog));

    if ( SaganProcSyslog_LOCAL == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SaganProcSyslog_LOCAL. Abort!", __FILE__, __LINE__);
        }

    memset(SaganProcSyslog_LOCAL, 0, sizeof(struct _Sagan_Proc_Syslog));

    struct _Sagan_Pass_Syslog *SaganPassSyslog_LOCAL = NULL;
    SaganPassSyslog_LOCAL = malloc(sizeof(struct _Sagan_Pass_Syslog));

    if ( SaganPassSyslog_LOCAL == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SaganPassSyslog_LOCAL. Abort!", __FILE__, __LINE__);
        }

    memset(SaganPassSyslog_LOCAL, 0, sizeof(struct _Sagan_Pass_Syslog));

    struct _Sagan_JSON *JSON_LOCAL = NULL;

#if defined(HAVE_LIBFASTJSON)

    if ( config->input_type == INPUT_JSON || config->json_parse_data == true )
        {

            JSON_LOCAL = malloc(sizeof(struct _Sagan_JSON));

            if ( JSON_LOCAL == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for _Sagan_JSON. ABort!", __FILE__, __LINE__);
                }

            memset(JSON_LOCAL, 0, sizeof(struct _Sagan_JSON));
        }

#endif

    struct _GeoIP *GeoIP_SRC = NULL;
    GeoIP_SRC = malloc(sizeof(struct _GeoIP));

    if ( GeoIP_SRC == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for _GeoIP (SRC). Abort!", __FILE__, __LINE__);
        }

    struct _GeoIP *GeoIP_DEST = NULL;
    GeoIP_DEST = malloc(sizeof(struct _GeoIP));

    if ( GeoIP_DEST == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for _GeoIP (DEST). Abort!", __FILE__, __LINE__);
        }

    struct _Sagan_Routing *SaganRouting = NULL;
    SaganRouting = malloc(sizeof(struct _Sagan_Routing));

    if ( SaganRouting == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for _Sagan_Routing, Abort!", __FILE__, __LINE__);
        }

    struct _NormalizeLiblognorm *NormalizeLiblognorm = NULL;

#ifdef HAVE_LIBLOGNORM

    NormalizeLiblognorm = malloc(sizeof(struct _NormalizeLiblognorm));

    if ( NormalizeLiblognorm == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for _NormalizeLiblognorm, Abort!", __FILE__, __LINE__);
        }

#endif


    uint_fast8_t i;

    while(death == false)
        {

            pthread_mutex_lock(&SaganProcWorkMutex);

            while ( proc_msgslot == 0 ) pthread_cond_wait(&SaganProcDoWork, &SaganProcWorkMutex);

            if ( config->sagan_reload )
                {
                    pthread_cond_wait(&SaganReloadCond, &SaganReloadMutex);
                }

            proc_msgslot--;     /* This was ++ before coming over, so we now -- it to get to
                                 * original value */


            /* Copy inbound array from global to local */

            for (i=0; i < config->max_batch; i++)
                {

                    if (debug->debugsyslog)
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] [batch position %d] Raw log: %s",  __FILE__, __LINE__, i, SaganPassSyslog[proc_msgslot].syslog[i]);
                        }

                    strlcpy(SaganPassSyslog_LOCAL->syslog[i],  SaganPassSyslog[proc_msgslot].syslog[i], sizeof(SaganPassSyslog_LOCAL->syslog[i]));

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
                        }

                    if ( config->input_type == INPUT_PIPE )
                        {
                            SyslogInput_Pipe( SaganPassSyslog_LOCAL->syslog[i], SaganProcSyslog_LOCAL );
                        }

#ifdef HAVE_LIBFASTJSON

                    else
                        {
                            SyslogInput_JSON( SaganPassSyslog_LOCAL->syslog[i], SaganProcSyslog_LOCAL, JSON_LOCAL );
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

		    /* Zero GeoIP SRC */

		    GeoIP_SRC->city[0] = '\0'; 
		    GeoIP_SRC->country[0] = '\0';
		    GeoIP_SRC->subdivision[0] = '\0';
		    GeoIP_SRC->postal[0] = '\0';
		    GeoIP_SRC->timezone[0] = '\0';
		    GeoIP_SRC->latitude[0] = '\0';
		    GeoIP_SRC->longitude[0] = '\0';

		    /* Zero GeoIP DEST */

		    GeoIP_DEST->city[0] = '\0'; 
		    GeoIP_DEST->country[0] = '\0';
		    GeoIP_DEST->subdivision[0] = '\0';
		    GeoIP_DEST->postal[0] = '\0';
		    GeoIP_DEST->timezone[0] = '\0';
		    GeoIP_DEST->latitude[0] = '\0';
		    GeoIP_DEST->longitude[0] = '\0';

//                    memset(GeoIP_SRC, 0, sizeof(_GeoIP));
//                    memset(GeoIP_DEST, 0, sizeof(_GeoIP));
//                    memset(SaganRouting, 0, sizeof(_Sagan_Routing));
//		      memset(NormalizeLiblognorm, 0, sizeof(_NormalizeLiblognorm));

                    SaganRouting->check_flow_return = true;

                    Sagan_Engine( SaganProcSyslog_LOCAL, JSON_LOCAL, GeoIP_SRC, GeoIP_DEST, SaganRouting, NormalizeLiblognorm, dynamic_rule_flag );

                    /* If this is a dynamic run,  reset back to normal */

                    if ( dynamic_rule_flag == DYNAMIC_RULE )
                        {
                            dynamic_rule_flag = NORMAL_RULE;
                        }

                    if ( config->client_stats_flag )
                        {

                            Client_Stats_Add_Update_IP ( SaganProcSyslog_LOCAL->syslog_host, SaganProcSyslog_LOCAL->syslog_program, SaganProcSyslog_LOCAL->syslog_message );

                        }

                    if ( config->sagan_track_clients_flag && SaganProcSyslog_LOCAL->syslog_host[0] != '\0' )
                        {
                            Track_Clients( SaganProcSyslog_LOCAL->syslog_host );
                        }

                }

            __atomic_sub_fetch(&proc_running, 1, __ATOMIC_SEQ_CST);

        } /*  for (;;) */

    /* Exit thread on shutdown. */

    free( SaganProcSyslog_LOCAL );
    free( SaganPassSyslog_LOCAL );
    free( SaganRouting );
    free( GeoIP_SRC );
    free( GeoIP_DEST );

#ifdef HAVE_LIBLOGNORM
    free(NormalizeLiblognorm);
#endif


#if defined(HAVE_LIBFASTJSON)
    free(JSON_LOCAL);
#endif

    __atomic_sub_fetch(&config->max_processor_threads, 1, __ATOMIC_SEQ_CST);

    /* Cleans up valgrind */

    pthread_exit(NULL);

}

