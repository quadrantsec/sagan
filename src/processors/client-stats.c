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

/* client-stats.c
 *
 * This writes out data about clients reporting to Sagan.  In particular,  the last
 * time a client send Sagan data along with a copy of "example" data (program/
 * message) every so often (via the "data-interval" option).
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#ifdef HAVE_LIBFASTJSON

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"
#include "util-time.h"
#include "lockfile.h"

#include "processors/client-stats.h"

extern bool death;

uint64_t old_epoch = 0;

extern struct _SaganConfig *config;
extern struct _SaganCounters *counters;
extern struct _SaganDebug *debug;

struct _Client_Stats_Struct *Client_Stats = NULL;

pthread_mutex_t ClientStatsMutex=PTHREAD_MUTEX_INITIALIZER;

/****************************************************************************
 * Client_Stats_Iint
 ****************************************************************************/

void Client_Stats_Init( void )
{

    if (( config->client_stats_file_stream = fopen(config->client_stats_file_name, "a" )) == NULL )
        {
            Remove_Lock_File();
            Sagan_Log(ERROR, "[%s, line %d] Can't open %s - %s!", __FILE__, __LINE__, config->client_stats_file_name, strerror(errno));
        }

    config->client_stats_file_stream_int = fileno( config->client_stats_file_stream );

    config->client_stats_file_stream_status = true;
    counters->client_stats_count = 0;

    Client_Stats = malloc(config->client_stats_max * sizeof(struct _Client_Stats_Struct));

    if ( Client_Stats == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for _Client_Stats_Struct. Abort!", __FILE__, __LINE__);
        }

}

/****************************************************************************
 * Client_Stats_Close - Closes clients stats files
 ****************************************************************************/

void Client_Stats_Close( void )
{

    config->client_stats_file_stream_status = false;
    fclose(config->client_stats_file_stream);

}

/****************************************************************************
 * Client_Stats_Handler - Thread that writes out client stat data
 ****************************************************************************/

void Client_Stats_Handler( void )
{

#ifdef HAVE_SYS_PRCTL_H
    (void)SetThreadName("SaganClientStats");
#endif

    struct json_object *jobj = NULL;

    struct timeval tp;
    char timebuf[64] = { 0 };

    uint_fast32_t i=0;

    /* Wait some time before dumping stats */

    /* DEBUG: Potential fault here.  Should look for 1 second and look for "death" */

    sleep(config->client_stats_time);

    while(death == false)
        {

            if ( debug->debugclient_stats )
                {
                    Sagan_Log(DEBUG,"[%s, line %d] Writing client stats %s.", __FILE__, __LINE__, config->client_stats_file_name );
                }

            for ( i = 0; i < counters->client_stats_count; i++ )
                {

                    gettimeofday(&tp, 0);
                    CreateIsoTimeString(&tp, timebuf, sizeof(timebuf));

                    jobj = json_object_new_object();

                    json_object *jclient_stats_type;

                    if ( config->client_stats_type == 0 )
                        {
                            jclient_stats_type = json_object_new_string( "ip" );
                        }
                    else
                        {
                            jclient_stats_type = json_object_new_string( "tag" );
                        }

                    json_object_object_add(jobj,"client_stats_type", jclient_stats_type);


                    json_object *jdate = json_object_new_string(timebuf);
                    json_object_object_add(jobj,"timestamp", jdate);

                    json_object *jevent_type = json_object_new_string( "client_stats" );
                    json_object_object_add(jobj,"event_type", jevent_type);

                    json_object *jarray_sensor = json_object_new_string( config->sagan_sensor_name );
                    json_object_object_add(jobj,"sensor_name", jarray_sensor);

                    json_object *jsrc_addr = json_object_new_string( Client_Stats[i].ip  );
                    json_object_object_add(jobj,"src_ip", jsrc_addr);

                    json_object *jdest_addr = json_object_new_string( config->sagan_host  );
                    json_object_object_add(jobj,"dest_ip", jdest_addr);

                    json_object *jflow_id = json_object_new_int64( FlowGetId(tp) );
                    json_object_object_add(jobj,"flow_id", jflow_id);

                    json_object *jtimestamp = json_object_new_int64( Client_Stats[i].epoch );
                    json_object_object_add(jobj,"timestamp", jtimestamp);

                    json_object *jprogram = json_object_new_string( Client_Stats[i].program );
                    json_object_object_add(jobj,"program", jprogram);

                    json_object *jtag = json_object_new_string( Client_Stats[i].tag );
                    json_object_object_add(jobj,"tag", jtag);

                    json_object *jmessage = json_object_new_string( Client_Stats[i].message );
                    json_object_object_add(jobj,"message", jmessage);

                    json_object *jbytes = json_object_new_int64( Client_Stats[i].bytes );
                    json_object_object_add(jobj,"bytes", jbytes);

                    json_object *jevents = json_object_new_int64( Client_Stats[i].number_of_events );
                    json_object_object_add(jobj,"events", jevents);

                    File_Lock( config->client_stats_file_stream_int );

                    fprintf(config->client_stats_file_stream, "%s\n", json_object_to_json_string(jobj));
                    fflush(config->client_stats_file_stream);

                    File_Unlock( config->client_stats_file_stream_int );


                    json_object_put(jobj);
                }

            /* DEBUG: Potential fault here.  Should look for 1 second and look for "death" */

            sleep(config->client_stats_time);
        }

    /* Got "exit" (death) event */

    free(Client_Stats);
    pthread_exit(NULL);

}

/****************************************************************************
 * Client_Stats_Add_Update_IP - Adds IP addresses and other data to the
 * array of systems Sagan is keeping track of.
 ****************************************************************************/

void Client_Stats_Add_Update_IP( const char *ip, const char *program, const char *message, const char *tag, uint_fast32_t bytes )
{

    uint_fast32_t hash = 0;
    uint_fast32_t i = 0;
    time_t t;
    struct tm *now;
    uint64_t epoch = 0;
    char timet[20];

    unsigned char ip_convert[MAXIPBIT] = { 0 };

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);
    epoch = atol(timet);

    if ( config->client_stats_type == 0 )
        {

            /* Track by "src_ip" / Validate inbound IP */

            if ( config->client_stats_private_only == true )
                {

                    IP2Bit(ip, ip_convert);

                    if ( is_notroutable(ip_convert) != true )
                        {
                            return;
                        }
                    else
                        {
                            hash = Djb2_Hash( ip );
                        }

                }

            /* Doesn't matter if IP is private or not */

            else
                {

                    /* Make sure its a valid IP address */

                    if ( Is_IP( ip, IPv4) == true || Is_IP( ip, IPv6 ) == true )
                        {
                            hash = Djb2_Hash( ip );
                        }
                    else
                        {
                            return;
                        }
                }

        }
    else
        {

            /* Track by "tag" */

            hash = Djb2_Hash( tag );

        }

    for ( i = 0; i < counters->client_stats_count; i++ )
        {

            /* Search here */

            if ( Client_Stats[i].hash == hash )
                {
                    Client_Stats[i].epoch = epoch;
                    Client_Stats[i].number_of_events++;
                    Client_Stats[i].bytes = Client_Stats[i].bytes + bytes;

                    if ( Client_Stats[i].epoch > Client_Stats[i].old_epoch + config->client_stats_interval)
                        {

                            if ( debug->debugclient_stats )
                                {
                                    Sagan_Log(DEBUG,"[%s, line %d] Updating program/message data for IP address %s [%d]", __FILE__, __LINE__, ip, i);
                                }

                            pthread_mutex_lock(&ClientStatsMutex);

                            strlcpy( Client_Stats[i].program, program, sizeof(Client_Stats[i].program) );
                            strlcpy( Client_Stats[i].message, message, sizeof(Client_Stats[i].message) );
                            strlcpy( Client_Stats[i].tag, tag, sizeof(Client_Stats[i].tag) );

                            Client_Stats[i].old_epoch = epoch;

                            pthread_mutex_unlock(&ClientStatsMutex);

                        }

                    return;

                }
        }

    if ( counters->client_stats_count < config->client_stats_max )
        {

            pthread_mutex_lock(&ClientStatsMutex);

            if ( debug->debugclient_stats )
                {
                    Sagan_Log(DEBUG,"[%s, line %d] Adding client IP address %s [%d]", __FILE__, __LINE__, ip, counters->client_stats_count);
                }


            Client_Stats[counters->client_stats_count].hash = hash;
            Client_Stats[counters->client_stats_count].epoch = epoch;
            Client_Stats[counters->client_stats_count].old_epoch = epoch;

            strlcpy(Client_Stats[counters->client_stats_count].ip, ip, sizeof(Client_Stats[counters->client_stats_count].ip));
            strlcpy( Client_Stats[counters->client_stats_count].program, program, sizeof(Client_Stats[counters->client_stats_count].program ) );
            strlcpy( Client_Stats[counters->client_stats_count].message, message, sizeof(Client_Stats[counters->client_stats_count].message ) );
            strlcpy( Client_Stats[counters->client_stats_count].tag, tag, sizeof(Client_Stats[counters->client_stats_count].tag ) );


            counters->client_stats_count++;

            pthread_mutex_unlock(&ClientStatsMutex);

        }
    else

        {

            Sagan_Log(WARN, "[%s, line %d] 'clients-stats' processors ran out of space.  Consider increasing 'max-clients'!", __FILE__, __LINE__);


        }

}

#endif
