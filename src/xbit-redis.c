/* $Id$ */
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

/* xbit-redis.c - Redis stored xbit support a la 'Suricata' style */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBHIREDIS

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <stdbool.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "ipc.h"
#include "xbit.h"
#include "xbit-redis.h"
#include "rules.h"
#include "redis.h"
#include "sagan-config.h"
#include "util-base64.h"

#define 	REDIS_PREFIX	"sagan"

extern struct _SaganCounters *counters;
extern struct _Rule_Struct *rulestruct;
extern struct _SaganDebug *debug;
extern struct _SaganConfig *config;
extern struct _Sagan_Redis_Write *Sagan_Redis_Write;

extern pthread_cond_t SaganRedisDoWork;
extern pthread_mutex_t SaganRedisWorkMutex;

extern uint_fast16_t redis_msgslot;

/*******************************************************/
/* Xbit_Set_Redis - set/unset xbit in Redis (threaded) */
/*******************************************************/

void Xbit_Set_Redis(uint_fast32_t rule_position, struct _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL )
{

    struct json_object *jobj;

    int r = 0;
    char tmp_ip[MAXIP] = { 0 };

    unsigned long b64_len = strlen(SaganProcSyslog_LOCAL->syslog_message) * 2;
    uint8_t b64_target[b64_len];

    char *proto = "UNKNOWN";

    char *tmp_data = malloc ( config->message_buffer_size * 2 );

    if ( tmp_data == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __LINE__, __FILE__);
        }

    tmp_data[0] = '\0';

    char *tmp_key = malloc( MAX_REDIS_KEY_SIZE + 1 );

    if ( tmp_key == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __LINE__, __FILE__);
        }

    tmp_key[0] = '\0';

    for (r = 0; r < rulestruct[rule_position].xbit_count; r++)
        {

            if ( rulestruct[rule_position].xbit_type[r] == XBIT_SET )
                {

                    Xbit_Return_Tracking_IP( rule_position, r, SaganProcSyslog_LOCAL->src_ip, SaganProcSyslog_LOCAL->dst_ip, tmp_ip, sizeof(tmp_ip));

                    if ( debug->debugxbit )
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] Xbit '%s' set in Redis for %s for %d seconds", __FILE__, __LINE__, rulestruct[rule_position].xbit_name[r], tmp_ip, rulestruct[rule_position].xbit_expire[r]);
                        }

                    if ( redis_msgslot < config->redis_max_writer_threads )
                        {

                            jobj = json_object_new_object();

                            json_object *jsensor = json_object_new_string(config->sagan_sensor_name);
                            json_object_object_add(jobj,"sensor", jsensor);

                            json_object *jexpire = json_object_new_int(rulestruct[rule_position].xbit_expire[r]);
                            json_object_object_add(jobj,"expire", jexpire);

                            json_object *jsource_ip = json_object_new_string(SaganProcSyslog_LOCAL->syslog_host);
                            json_object_object_add(jobj,"syslog_source", jsource_ip);


                            json_object *jsrc_ip = json_object_new_string(SaganProcSyslog_LOCAL->src_ip);
                            json_object_object_add(jobj,"src_ip", jsrc_ip );

                            json_object *jdest_ip = json_object_new_string(SaganProcSyslog_LOCAL->dst_ip);
                            json_object_object_add(jobj,"dest_ip", jdest_ip );

                            json_object *jusername = json_object_new_string(SaganProcSyslog_LOCAL->username);
                            json_object_object_add(jobj,"username", jusername );

                            json_object *jpriority = json_object_new_string(SaganProcSyslog_LOCAL->syslog_priority);
                            json_object_object_add(jobj,"priority", jpriority);

                            json_object *jfacility = json_object_new_string(SaganProcSyslog_LOCAL->syslog_facility);
                            json_object_object_add(jobj,"facility", jfacility);

                            json_object *jlevel = json_object_new_string(SaganProcSyslog_LOCAL->syslog_level);
                            json_object_object_add(jobj,"level", jlevel);

                            json_object *jtag = json_object_new_string(SaganProcSyslog_LOCAL->syslog_tag);
                            json_object_object_add(jobj,"tag", jtag);

                            json_object *jdate = json_object_new_string(SaganProcSyslog_LOCAL->syslog_date);
                            json_object_object_add(jobj,"date", jdate);

                            json_object *jtime = json_object_new_string(SaganProcSyslog_LOCAL->syslog_time);
                            json_object_object_add(jobj,"time", jtime);

                            json_object *jprogram = json_object_new_string(SaganProcSyslog_LOCAL->syslog_program);
                            json_object_object_add(jobj,"program", jprogram);

                            json_object *jmessage;

                            if ( config->eve_alerts_base64 == true )
                                {

                                    Base64Encode( (const unsigned char*)SaganProcSyslog_LOCAL->syslog_message, strlen(SaganProcSyslog_LOCAL->syslog_message), b64_target, &b64_len);

                                    jmessage = json_object_new_string( (const char *)b64_target );

                                }
                            else
                                {

                                    jmessage = json_object_new_string(SaganProcSyslog_LOCAL->syslog_message);
                                }


                            json_object_object_add(jobj,"payload", jmessage);

                            json_object *jsignature = json_object_new_string(rulestruct[rule_position].s_msg);
                            json_object_object_add(jobj,"signature", jsignature);

                            json_object *jsid = json_object_new_int64(rulestruct[rule_position].s_sid);
                            json_object_object_add(jobj,"sid", jsid);

                            json_object *jrev = json_object_new_int(rulestruct[rule_position].s_rev);
                            json_object_object_add(jobj,"rev", jrev);

                            json_object *jtype = json_object_new_string("xbit");
                            json_object_object_add(jobj,"type", jtype);

                            json_object *jstorage = json_object_new_string("redis");
                            json_object_object_add(jobj,"storage", jstorage);

                            json_object *jsignature_copy = json_object_new_string( rulestruct[rule_position].signature_copy );
                            json_object_object_add(jobj,"rule", jsignature_copy);


                            if ( SaganProcSyslog_LOCAL->proto == 17 )
                                {
                                    proto = "UDP";
                                }

                            else if ( SaganProcSyslog_LOCAL->proto == 6 )
                                {
                                    proto = "TCP";
                                }

                            else if ( SaganProcSyslog_LOCAL->proto == 1 )
                                {
                                    proto = "ICMP";
                                }

                            json_object *jproto = json_object_new_string( proto );
                            json_object_object_add(jobj,"proto", jproto);

                            snprintf(tmp_data, config->message_buffer_size * 2, "%s", json_object_to_json_string(jobj));
                            tmp_data[ (config->message_buffer_size * 2) - 1] = '\0';

                            json_object_put(jobj);

                            /* Send to redis */

                            pthread_mutex_lock(&SaganRedisWorkMutex);

                            strlcpy(Sagan_Redis_Write[redis_msgslot].command, "SET", sizeof(Sagan_Redis_Write[redis_msgslot].command));

                            snprintf(tmp_key, MAX_REDIS_KEY_SIZE, "%s:%s:%s:%s", REDIS_PREFIX, config->sagan_cluster_name, rulestruct[rule_position].xbit_name[r], tmp_ip);

                            /* Use memcpy not strlcpy to avoid memory corruption */

                            memcpy(Sagan_Redis_Write[redis_msgslot].key, tmp_key, MAX_REDIS_KEY_SIZE);
                            Sagan_Redis_Write[redis_msgslot].key[ MAX_REDIS_KEY_SIZE - 1] = '\0';


                            memcpy(Sagan_Redis_Write[redis_msgslot].value, tmp_data, config->message_buffer_size * 2);
                            Sagan_Redis_Write[redis_msgslot].value[ (config->message_buffer_size * 2) - 1] = '\0';


                            Sagan_Redis_Write[redis_msgslot].expire = rulestruct[rule_position].xbit_expire[r];

                            redis_msgslot++;

                            pthread_cond_signal(&SaganRedisDoWork);
                            pthread_mutex_unlock(&SaganRedisWorkMutex);

                        }
                    else
                        {
                            Sagan_Log(WARN, "[%s, line %d] Out of Redis 'writer' threads for 'set'.  Skipping!", __FILE__, __LINE__);
                            __atomic_add_fetch(&counters->redis_writer_threads_drop, 1, __ATOMIC_SEQ_CST);
                        }

                }

            else if ( rulestruct[rule_position].xbit_type[r] == XBIT_UNSET )
                {

                    Xbit_Return_Tracking_IP( rule_position, r, SaganProcSyslog_LOCAL->src_ip, SaganProcSyslog_LOCAL->dst_ip, tmp_ip, sizeof(tmp_ip));

                    if ( debug->debugxbit )
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] Xbit '%s' for %s unset in Redis", __FILE__, __LINE__, rulestruct[rule_position].xbit_name[r], tmp_ip);
                        }

                    if ( redis_msgslot < config->redis_max_writer_threads )
                        {

                            pthread_mutex_lock(&SaganRedisWorkMutex);

                            strlcpy(Sagan_Redis_Write[redis_msgslot].command, "DEL", sizeof(Sagan_Redis_Write[redis_msgslot].command));
                            snprintf(Sagan_Redis_Write[redis_msgslot].key, sizeof(Sagan_Redis_Write[redis_msgslot].key), "%s:%s:%s:%s", REDIS_PREFIX, config->sagan_cluster_name, rulestruct[rule_position].xbit_name[r], tmp_ip);
                            Sagan_Redis_Write[redis_msgslot].value[0] = '\0';
                            Sagan_Redis_Write[redis_msgslot].expire = 0;

                            redis_msgslot++;

                            pthread_cond_signal(&SaganRedisDoWork);
                            pthread_mutex_unlock(&SaganRedisWorkMutex);
                        }
                    else
                        {
                            Sagan_Log(WARN, "[%s, line %d] Out of Redis 'writer' threads for 'set'.  Skipping!", __FILE__, __LINE__);
                            __atomic_add_fetch(&counters->redis_writer_threads_drop, 1, __ATOMIC_SEQ_CST);
                        }
                }
        }

    free(tmp_data);
    free(tmp_key);
}

/****************************************************************/
/* Xbit_Condition_Redis - Tests for Redis xbit (isset/isnotset) */
/****************************************************************/

bool Xbit_Condition_Redis( uint_fast32_t rule_position, struct _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL )
{

    int r;
    char redis_command[512] = { 0 };
    char tmp_ip[MAXIP] = { 0 };

    char *redis_results = malloc( config->message_buffer_size );

    if ( redis_results == NULL )
        {
            fprintf(stderr, "[%s, line %d] Fatal Error: Can't allocate memory! Abort!\n", __FILE__, __LINE__);
            exit(-1);
        }

    redis_results[0] = '\0';

    for (r = 0; r < rulestruct[rule_position].xbit_count; r++)
        {

            Xbit_Return_Tracking_IP( rule_position, r, SaganProcSyslog_LOCAL->src_ip, SaganProcSyslog_LOCAL->dst_ip, tmp_ip, sizeof(tmp_ip));

            snprintf(redis_command, sizeof(redis_command),
                     "GET %s:%s:%s:%s", REDIS_PREFIX, config->sagan_cluster_name, rulestruct[rule_position].xbit_name[r], tmp_ip);

            Redis_Reader ( redis_command, redis_results, config->message_buffer_size);

            /* Was not found */

            if ( redis_results[0] == '\0' )
                {

                    if ( rulestruct[rule_position].xbit_type[r] == XBIT_ISSET )
                        {

                            if ( debug->debugxbit )
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] Xbit '%s' was not found IP address %s for isset. Returning false.", __FILE__, __LINE__, rulestruct[rule_position].xbit_name[r], tmp_ip);
                                }

                            free(redis_results);
                            return(false);
                        }

                    else if ( rulestruct[rule_position].xbit_type[r] == XBIT_ISNOTSET )
                        {

                            if ( debug->debugxbit )
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] Xbit '%s' was found for IP address %s for isnotset. Returning false.", __FILE__, __LINE__, rulestruct[rule_position].xbit_name[r], tmp_ip);
                                }

                            free(redis_results);
                            return(false);
                        }

                }
            else
                {

                    /* Was found,  need to copy correlation data */

                    if ( rulestruct[rule_position].xbit_type[r] == XBIT_ISSET )
                        {
                            strlcpy( SaganProcSyslog_LOCAL->correlation_json, redis_results, config->message_buffer_size);
                        }

                }

        }

    if ( debug->debugxbit )
        {
            Sagan_Log(DEBUG, "[%s, line %d] Rule matches all xbit conditions. Returning true.", __FILE__, __LINE__);
        }

    free(redis_results);
    return(true);

}

/******************************************************************************************
 * Xbit_Return_Tracking_IP - We don't use tracking hashes with Redis.  We use the actual
 * Actual IP addresses so that it's easier to "see" in Redis.
 ******************************************************************************************/

void Xbit_Return_Tracking_IP ( uint_fast32_t rule_position, uint_fast8_t xbit_position, const char *ip_src_char, const char *ip_dst_char, char *str, size_t size )
{

    /* These 1,2,3 values should really be defined */

    if ( rulestruct[rule_position].xbit_direction[xbit_position] == 1 )
        {
            snprintf(str, size, "%s", ip_src_char);
        }

    else if ( rulestruct[rule_position].xbit_direction[xbit_position] == 2 )
        {
            snprintf(str, size, "%s", ip_dst_char);
        }

    else if (  rulestruct[rule_position].xbit_direction[xbit_position] == 3 )
        {
            snprintf(str, size, "%s:%s",  ip_src_char, ip_dst_char);
        }

}

#endif
