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

/* Read data from fifo in a JSON format */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#if defined(HAVE_LIBFASTJSON)

#include <stdio.h>
#include <string.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"
#include "version.h"
#include "input-pipe.h"
#include "debug.h"

#include "parsers/json.h"

extern struct _SaganCounters *counters;
extern struct _SaganConfig *config;
extern struct _SaganDebug *debug;

extern struct _Syslog_JSON_Map *Syslog_JSON_Map;

void SyslogInput_JSON( char *syslog_string, struct _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL, struct _Sagan_JSON *JSON_LOCAL )
{

    uint_fast16_t i = 0;
    uint_fast8_t a = 0;

    bool program_found = false;
    bool message_found = false;
    bool s_host_found = false;
    bool facility_found = false;
    bool level_found = false;
    bool priority_found = false;
    bool tag_found = false;
    bool username_found = false;
    bool time_found = false;
    bool date_found = false;
    bool src_ip_found = false;
    bool dst_ip_found = false;
    bool src_port_found = false;
    bool dst_port_found = false;
    bool md5_found = false;
    bool sha1_found = false;
    bool sha256_found = false;
    bool filename_found = false;
    bool hostname_found = false;
    bool url_found = false;
    bool ja3_found = false;
    bool flow_id_found = false;
    bool event_id_found = false;
    bool proto_found = false;

//    memset(SaganProcSyslog_LOCAL, 0, sizeof(_Sagan_Proc_Syslog)); // DEBUGME : CAUSES SEGFAULT

    memcpy(SaganProcSyslog_LOCAL->syslog_program, "UNDEFINED", 9);
    memcpy(SaganProcSyslog_LOCAL->syslog_time, "UNDEFINED", 9);
    memcpy(SaganProcSyslog_LOCAL->syslog_date, "UNDEFINED", 9);
    memcpy(SaganProcSyslog_LOCAL->syslog_tag, "UNDEFINED", 9);
    memcpy(SaganProcSyslog_LOCAL->syslog_level, "UNDEFINED", 9);
    memcpy(SaganProcSyslog_LOCAL->syslog_priority, "UNDEFINED", 9);
    memcpy(SaganProcSyslog_LOCAL->syslog_facility, "UNDEFINED", 9);
    memcpy(SaganProcSyslog_LOCAL->syslog_host, "0.0.0.0", 8);

    /* Copy the "original" JSON so we can use it in alerts later */

    memcpy(SaganProcSyslog_LOCAL->json_original, syslog_string, JSON_MAX_SIZE);

    /* Search through all key/values looking for embedded JSON */

    Parse_JSON( syslog_string, JSON_LOCAL );

    /* User wants the entire JSON to become the "message" */

    if ( !strcmp(Syslog_JSON_Map->syslog_map_message[0], "%JSON%" ) )
        {
            snprintf(SaganProcSyslog_LOCAL->syslog_message, sizeof(SaganProcSyslog_LOCAL->syslog_message), "%s", syslog_string);
            SaganProcSyslog_LOCAL->syslog_message[ sizeof(SaganProcSyslog_LOCAL->syslog_message) -1 ] = '\0';
        }

    for (i = 0; i < JSON_LOCAL->json_count; i++ )
        {

            /* Strings - Don't use else if, because all values need to be parsed */

            if ( Syslog_JSON_Map->syslog_map_message[0][0] != '\0' && message_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->syslog_map_message_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->syslog_map_message[a], JSON_LOCAL->json_key[i] ) )
                                {

                                    /* Space added for further "normalization" */

                                    snprintf(SaganProcSyslog_LOCAL->syslog_message, sizeof(SaganProcSyslog_LOCAL->syslog_message), " %s", JSON_LOCAL->json_value[i]);
                                    SaganProcSyslog_LOCAL->syslog_message[ sizeof(SaganProcSyslog_LOCAL->syslog_message) -1 ] = '\0';

                                    message_found = true;
                                    break;

                                }
                        }
                }

            if ( Syslog_JSON_Map->event_id[0][0] != '\0' && event_id_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->event_id_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->event_id[a], JSON_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->event_id, JSON_LOCAL->json_value[i], MAX_EVENTID);
                                    event_id_found = true;
                                    break;

                                }
                        }
                }

            if ( Syslog_JSON_Map->syslog_map_host[0][0] != '\0' && s_host_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->syslog_map_host_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->syslog_map_host[a], JSON_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->syslog_host, JSON_LOCAL->json_value[i], MAX_SYSLOG_HOST);
                                    s_host_found = true;
                                    break;

                                }
                        }
                }


            if ( Syslog_JSON_Map->syslog_map_facility[0][0] != '\0' && facility_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->syslog_map_facility_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->syslog_map_facility[a], JSON_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->syslog_facility, JSON_LOCAL->json_value[i], MAX_SYSLOG_FACILITY);
                                    facility_found = true;
                                    break;

                                }
                        }
                }

            if ( Syslog_JSON_Map->syslog_map_priority[0][0] != '\0' && priority_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->syslog_map_priority_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->syslog_map_priority[a], JSON_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->syslog_priority, JSON_LOCAL->json_value[i], MAX_SYSLOG_PRIORITY);
                                    priority_found = true;
                                    break;

                                }
                        }
                }


            if ( Syslog_JSON_Map->syslog_map_level[0][0] != '\0' && level_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->syslog_map_level_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->syslog_map_level[a], JSON_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->syslog_level, JSON_LOCAL->json_value[i], MAX_SYSLOG_LEVEL);
                                    level_found = true;
                                    break;

                                }
                        }
                }


            if ( Syslog_JSON_Map->syslog_map_tag[0][0] != '\0' && tag_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->syslog_map_tag_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->syslog_map_tag[a], JSON_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->syslog_tag, JSON_LOCAL->json_value[i], MAX_SYSLOG_TAG);
                                    tag_found = true;
                                    break;

                                }
                        }
                }


            if ( Syslog_JSON_Map->syslog_map_date[0][0] != '\0' && date_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->syslog_map_date_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->syslog_map_date[a], JSON_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->syslog_date, JSON_LOCAL->json_value[i], MAX_SYSLOG_DATE);
                                    date_found = true;
                                    break;

                                }
                        }
                }


            if ( Syslog_JSON_Map->syslog_map_time[0][0] != '\0' && time_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->syslog_map_time_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->syslog_map_time[a], JSON_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->syslog_time, JSON_LOCAL->json_value[i], MAX_SYSLOG_TIME);
                                    time_found = true;
                                    break;

                                }
                        }
                }


            if ( Syslog_JSON_Map->syslog_map_program[0][0] != '\0' && program_found == false )
                {

                    for ( a = 0; a < Syslog_JSON_Map->syslog_map_program_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->syslog_map_program[a], JSON_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->syslog_program, JSON_LOCAL->json_value[i], MAX_SYSLOG_PROGRAM);
                                    program_found = true;
                                    break;

                                }
                        }
                }


            if ( Syslog_JSON_Map->username[0][0] != '\0' && username_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->username_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->username[a], JSON_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->username, JSON_LOCAL->json_value[i], MAX_USERNAME_SIZE);
                                    username_found = true;
                                    break;

                                }
                        }
                }

            if ( Syslog_JSON_Map->src_ip[0][0] != '\0' && src_ip_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->src_ip_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->src_ip[a], JSON_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->src_ip, JSON_LOCAL->json_value[i], MAXIP);
                                    IP2Bit(SaganProcSyslog_LOCAL->src_ip, SaganProcSyslog_LOCAL->ip_src_bits);
                                    src_ip_found = true;
                                    break;

                                }
                        }
                }


            if ( Syslog_JSON_Map->dst_ip[0][0] != '\0' && dst_ip_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->dst_ip_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->dst_ip[a], JSON_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->dst_ip, JSON_LOCAL->json_value[i], MAXIP);
                                    IP2Bit(SaganProcSyslog_LOCAL->dst_ip, SaganProcSyslog_LOCAL->ip_dst_bits);
                                    dst_ip_found = true;
                                    break;

                                }
                        }
                }

            if ( Syslog_JSON_Map->md5[0][0] != '\0' && md5_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->md5_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->md5[a], JSON_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->md5, JSON_LOCAL->json_value[i], MD5_HASH_SIZE);
                                    md5_found = true;
                                    break;

                                }
                        }
                }

            if ( Syslog_JSON_Map->sha1[0][0] != '\0' && sha1_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->sha1_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->sha1[a], JSON_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->sha1, JSON_LOCAL->json_value[i], SHA1_HASH_SIZE);
                                    sha1_found = true;
                                    break;

                                }
                        }
                }

            if ( Syslog_JSON_Map->sha256[0][0] != '\0' && sha256_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->sha256_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->sha256[a], JSON_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->sha256, JSON_LOCAL->json_value[i], SHA256_HASH_SIZE);
                                    sha256_found = true;
                                    break;

                                }
                        }
                }

            if ( Syslog_JSON_Map->filename[0][0] != '\0' && filename_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->filename_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->filename[a], JSON_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->filename, JSON_LOCAL->json_value[i], MAX_FILENAME_SIZE);
                                    filename_found = true;
                                    break;

                                }
                        }
                }

            if ( Syslog_JSON_Map->hostname[0][0] != '\0' && hostname_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->hostname_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->hostname[a], JSON_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->hostname, JSON_LOCAL->json_value[i], MAX_HOSTNAME_SIZE);
                                    hostname_found = true;
                                    break;

                                }
                        }
                }

            if ( Syslog_JSON_Map->url[0][0] != '\0' && url_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->url_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->url[a], JSON_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->url, JSON_LOCAL->json_value[i], MAX_URL_SIZE);
                                    url_found = true;
                                    break;

                                }
                        }
                }

            if ( Syslog_JSON_Map->ja3[0][0] != '\0' && ja3_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->ja3_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->ja3[a], JSON_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->ja3, JSON_LOCAL->json_value[i], MD5_HASH_SIZE);
                                    ja3_found = true;
                                    break;

                                }
                        }
                }

            /* Math */

            if ( Syslog_JSON_Map->src_port[0][0] != '\0' && src_port_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->src_port_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->src_port[a], JSON_LOCAL->json_key[i] ) )
                                {

                                    SaganProcSyslog_LOCAL->src_port = atoi(JSON_LOCAL->json_value[i]);

                                    src_port_found = true;
                                    break;

                                }
                        }
                }

            if ( Syslog_JSON_Map->dst_port[0][0] != '\0' && dst_port_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->dst_port_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->dst_port[a], JSON_LOCAL->json_key[i] ) )
                                {

                                    SaganProcSyslog_LOCAL->dst_port = atoi(JSON_LOCAL->json_value[i]);

                                    dst_port_found = true;
                                    break;

                                }
                        }
                }

            if ( Syslog_JSON_Map->flow_id[0][0] != '\0' && flow_id_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->flow_id_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->flow_id[a], JSON_LOCAL->json_key[i] ) )
                                {

                                    SaganProcSyslog_LOCAL->flow_id = atol(JSON_LOCAL->json_value[i]);

                                    flow_id_found = true;
                                    break;

                                }
                        }
                }


            /* Multi-function */

            if ( Syslog_JSON_Map->proto[0][0] != '\0' && proto_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->proto_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->proto[a], JSON_LOCAL->json_key[i] ) )
                                {

                                    if ( !strcasecmp( JSON_LOCAL->json_value[i], "tcp" ) )
                                        {
                                            SaganProcSyslog_LOCAL->proto = 6;
                                            proto_found = true;
                                            break;
                                        }

                                    else if ( !strcasecmp( JSON_LOCAL->json_value[i], "udp" ) )
                                        {
                                            SaganProcSyslog_LOCAL->proto = 17;
                                            proto_found = true;
                                            break;
                                        }

                                    else if ( !strcasecmp( JSON_LOCAL->json_value[i], "icmp" ) )
                                        {
                                            SaganProcSyslog_LOCAL->proto = 1;
                                            proto_found = true;
                                            break;
                                        }

                                }

                        }

                }

        } /* for i */

    /* If debugging, dump data that was located */

    if ( debug->debugjson )
        {
            Debug_Sagan_Proc_Syslog( SaganProcSyslog_LOCAL );
        }

}

#endif
