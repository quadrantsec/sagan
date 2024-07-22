/*
** Copyright (C) 2009-2024 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2024 Adam Hall <ahall@quadrantsec.com>
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

/* track-clients.c
*
* Simple processors that keeps track of reporting syslog clients/agents.
* This is based off the IP address the clients,  not based on normalization.
* If a client/agent hasn't sent a syslog/event message in X minutes,  then
* generate an alert.
*
*/

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/time.h>
#include <unistd.h>
#include <syslog.h>

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"
#include "geoip.h"
#include "send-alert.h"
#include "util-time.h"

#include "processors/track-clients.h"

pthread_mutex_t IPCTrackClients=PTHREAD_MUTEX_INITIALIZER;

struct _Sagan_Processor_Info *processor_info_track_client = NULL;

extern struct _Sagan_Proc_Syslog *SaganProcSyslog;
extern struct _Sagan_Track_Clients_IPC *SaganTrackClients_ipc;
extern struct _Sagan_IPC_Counters *counters_ipc;

extern struct _SaganConfig *config;
extern struct _Track_Clients_Networks *Track_Clients_Networks;
extern struct _SaganCounters *counters;
extern struct _SaganDebug *debug;

extern bool death;

/****************************************************************************
 * Sagan_Track_Clients - Main routine to "tracks" via IPC/memory IPs that
 * are reporting or not.
 ****************************************************************************/

void Track_Clients ( const char *host )
{

    char utime_tmp[20] = { 0 };
    time_t t;
    struct tm *now;
    uint32_t i;
    uint64_t utime_u64;
    unsigned char hostbits[MAXIPBIT] = { 0 };

    t = time(NULL);
    now=localtime(&t);
    strftime(utime_tmp, sizeof(utime_tmp), "%s",  now);
    utime_u64 = atol(utime_tmp);

    uint32_t expired_time = config->pp_sagan_track_clients * 60;

    bool network_results = false;

    IP2Bit( (char*)host, hostbits);

    /* Search array and see if the host is within our range of "networks".  This will
       be skipped if no "networks" are specified. */

    for ( i = 0; i < counters->track_clients_count; i++ )
        {

            if ( is_inrange(hostbits, (unsigned char *)&Track_Clients_Networks[i].range, 1) )
                {
                    network_results = true;
                    continue;
                }
        }

    /* If no "networks" have been specified,  everything is fair game */

    if ( counters->track_clients_count == 0 )
        {
            network_results = true;
        }

    if ( network_results == true )
        {

            /********************************************/
            /** Record update tracking if record exsist */
            /********************************************/

            pthread_mutex_lock(&IPCTrackClients);
            File_Lock(config->shm_track_clients);

            for (i=0; i<counters_ipc->track_clients_client_count; i++)
                {
                    if ( !memcmp(SaganTrackClients_ipc[i].hostbits, hostbits, MAXIPBIT ) )
                        {

                            if ( debug->debugtrack_clients == true )
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] Already have %s.  Updating status.",  __FILE__, __LINE__, host);
                                }

                            SaganTrackClients_ipc[i].utime = utime_u64;
                            SaganTrackClients_ipc[i].expire = expired_time;

                            File_Unlock(config->shm_track_clients);
                            pthread_mutex_unlock(&IPCTrackClients);

                            return;
                        }
                }

            if ( counters_ipc->track_clients_client_count < config->max_track_clients )
                {

                    if ( debug->debugtrack_clients == true )
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] Adding new IP %s to be monitored.",  __FILE__, __LINE__, host);
                        }

                    memcpy(SaganTrackClients_ipc[counters_ipc->track_clients_client_count].hostbits, hostbits, sizeof(hostbits));
                    SaganTrackClients_ipc[counters_ipc->track_clients_client_count].utime = utime_u64;
                    SaganTrackClients_ipc[counters_ipc->track_clients_client_count].status = 0;
                    SaganTrackClients_ipc[counters_ipc->track_clients_client_count].expire = expired_time;

                    File_Lock(config->shm_counters);

                    counters_ipc->track_clients_client_count++;

                    File_Unlock(config->shm_counters);
                    File_Unlock(config->shm_track_clients);

                    pthread_mutex_unlock(&IPCTrackClients);

                    return;

                }
            else
                {

                    File_Unlock(config->shm_track_clients);
                    pthread_mutex_unlock(&IPCTrackClients);

                    Sagan_Log(WARN, "[%s, line %d] TRACK_CLIENT_ERROR - Client tracking has reached it's max! (%d).  Increase 'track_clients' in your configuration!", __FILE__, __LINE__, config->max_track_clients);

                }

        }

} /* Close sagan_track_clients */

/****************************************************************************
 * Sagan_Report_Clients - Main routine to "report" via IPC/memory IPs that
 * are reporting or not.
 ****************************************************************************/

void Track_Clients_Thread ( void )
{

    while(death == false)
        {

#ifdef HAVE_SYS_PRCTL_H
            (void)SetThreadName("SaganClientTrck");
#endif

            uint32_t i;
            uint64_t utime_u32;

            const char *tmp_ip = NULL;

            char utime_tmp[20] = { 0 };
            time_t t;
            struct tm *now;

            char tmp_message[1024] = { 0 };

            struct timeval tp;

            t = time(NULL);
            now=localtime(&t);
            strftime(utime_tmp, sizeof(utime_tmp), "%s",  now);
            utime_u32 = atol(utime_tmp);

            uint32_t expired_time = config->pp_sagan_track_clients * 60;

            /*********************************/
            /* Look through "known" system   */
            /*********************************/

            for (i=0; i<counters_ipc->track_clients_client_count; i++)
                {

                    /* Check if host is in a down state */

                    if ( SaganTrackClients_ipc[i].status == 1 )
                        {

                            /* If host was done, verify host last seen time is still not an expired time */

                            if ( ( utime_u32 - SaganTrackClients_ipc[i].utime ) < expired_time )
                                {

                                    /* Update status and seen time */

                                    pthread_mutex_lock(&IPCTrackClients);
                                    File_Lock(config->shm_track_clients);

                                    SaganTrackClients_ipc[i].status = 0;

                                    /* Update counters */

                                    File_Lock(config->shm_counters);

                                    counters_ipc->track_clients_down--;

                                    File_Unlock(config->shm_counters);
                                    File_Unlock(config->shm_track_clients);

                                    pthread_mutex_unlock(&IPCTrackClients);


                                    tmp_ip = Bit2IP(SaganTrackClients_ipc[i].hostbits, NULL, 0);

                                    snprintf(tmp_message, sizeof(tmp_message), "TRACK-CLIENT-LOGS - The IP address %s was previously not sending logs. The system is now sending logs again at %s", tmp_ip, ctime(&SaganTrackClients_ipc[i].utime) );

                                    tmp_message[ sizeof(tmp_message) - 1 ] = '\0';

                                    Sagan_Log(WARN, tmp_message );

                                    openlog("sagan", LOG_PID, LOG_DAEMON);
                                    syslog(LOG_INFO, tmp_message);
                                    closelog();

                                    gettimeofday(&tp, 0);

                                } /* End last seen check time */

                        }
                    else
                        {

                            /**** Check if last seen time of host has exceeded track time meaning it's down! ****/

                            if ( ( utime_u32 - SaganTrackClients_ipc[i].utime ) >= expired_time )
                                {

                                    /* Update status and utime */

                                    pthread_mutex_lock(&IPCTrackClients);

                                    File_Lock(config->shm_track_clients);

                                    SaganTrackClients_ipc[i].status = 1;

                                    /* Update counters */

                                    File_Lock(config->shm_counters);

                                    counters_ipc->track_clients_down++;

                                    File_Unlock(config->shm_counters);
                                    File_Unlock(config->shm_track_clients);

                                    pthread_mutex_unlock(&IPCTrackClients);

                                    tmp_ip = Bit2IP(SaganTrackClients_ipc[i].hostbits, NULL, 0);

                                    snprintf(tmp_message, sizeof(tmp_message), "TRACK-CLIENT-NOLOGS - Logs have not been received from IP address %s in over %d minutes.  The last log received from this host was at %s.", tmp_ip, config->pp_sagan_track_clients, ctime(&SaganTrackClients_ipc[i].utime));

                                    tmp_message[ sizeof(tmp_message) - 1 ] = '\0';

                                    Sagan_Log(WARN, tmp_message );

                                    openlog("sagan", LOG_PID, LOG_DAEMON);
                                    syslog(LOG_INFO, tmp_message);
                                    closelog();


                                    gettimeofday(&tp, 0);

                                }  /* End of existing utime check */

                        } /* End of else */

                }  /* End for 'for' loop */

            sleep(60);

        } /* End Ifinite Loop */

    pthread_exit(NULL);


} /* End Sagan_report_clients */
