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

/* engine.c
 *
 * Threaded engine that looks for events & patterns based on 'Snort like'
 * rules.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "aetas.h"
#include "meta-content.h"
#include "geoip.h"
#include "send-alert.h"
#include "flexbit.h"
#include "flexbit-mmap.h"
#include "rules.h"
#include "sagan-config.h"
#include "ipc.h"
#include "flow.h"
#include "after.h"
#include "threshold.h"
#include "xbit.h"
#include "event-id.h"
#include "routing.h"
#include "content.h"
#include "offload.h"
#include "pcre-s.h"
#include "json-pcre.h"
#include "json-content.h"
#include "json-meta-content.h"
#include "liblognormalize.h"

#include "parsers/parsers.h"
#include "parsers/json.h"

#include "processors/engine.h"

#include "processors/zeek-intel.h"
#include "processors/blacklist.h"
#include "processors/dynamic-rules.h"

#ifdef WITH_BLUEDOT
#include "processors/bluedot.h"
#endif

#include "output-plugins/eve.h"

extern struct _SaganCounters *counters;
extern struct _Rule_Struct *rulestruct;
extern struct _Sagan_Ruleset_Track *Ruleset_Track;
extern struct _SaganDebug *debug;
extern struct _SaganConfig *config;

extern struct _Sagan_IPC_Counters *counters_ipc;

extern bool reload_rules;

void Sagan_Engine ( struct _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL, struct _Sagan_JSON *JSON_LOCAL,  bool dynamic_rule_flag )
{

    struct _Sagan_Lookup_Cache_Entry *lookup_cache = NULL;
    lookup_cache = malloc(sizeof(struct _Sagan_Lookup_Cache_Entry) * MAX_PARSE_IP);

    if ( lookup_cache == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for lookup_cache. Abort!", __FILE__, __LINE__);
        }

    memset(lookup_cache, 0, sizeof(_Sagan_Lookup_Cache_Entry) * MAX_PARSE_IP);

    struct _Sagan_Routing *SaganRouting = NULL;
    SaganRouting = malloc(sizeof(struct _Sagan_Routing));

    if ( SaganRouting == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for _Sagan_Routing, Abort!", __FILE__, __LINE__);
        }

    SaganRouting->check_flow_return = true;

#ifdef HAVE_LIBMAXMINDDB

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

#endif

    bool after_log_flag = false;
    bool thresh_log_flag = false;

    int threadid = 0;

    uint_fast32_t b = 0;
    uint_fast16_t i = 0;

    bool pre_match = false;

    char *ptmp = NULL;
    char *tok2 = NULL;

    char tmpbuf[256] = { 0 };

    char *syslog_append_orig_message = malloc( config->message_buffer_size );

    if ( syslog_append_orig_message == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Fatal Error: Can't allocate memory! Abort!\n", __FILE__, __LINE__);
        }

    syslog_append_orig_message[0] = '\0';

    bool append_program_flag = false;

    struct timeval tp;
    uint_fast8_t lookup_cache_size = 0;

    /* These do not need to be reset each time as they are _only_
     * set through normalize */

#ifdef HAVE_LIBMAXMINDDB

    unsigned char geoip2_return = GEOIP_MISS;

#endif

    /* Needs to be outside ifdef */

    unsigned char bluedot_results = 0;

    /* Outside the WITH_BLUEDOT because we use it in passing to Send_Alert() */

    char bluedot_json[BLUEDOT_JSON_SIZE] = { 0 };

    /* This needs to be included,  even if liblognorm isn't in use */

    bool liblognorm_status = false;

    /* Get time we received the event */

    gettimeofday(&tp, 0);       /* Store event time as soon as we get it */

#ifdef HAVE_LIBFASTJSON

    char *o_syslog_message = malloc( config->message_buffer_size );

    if ( o_syslog_message == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Fatal Error: Can't allocate memory! Abort!\n", __FILE__, __LINE__);
        }

    o_syslog_message[0] = '\0';

    bool o_syslog_message_flag = false;

    char o_syslog_program[MAX_SYSLOG_PROGRAM] = { 0 };
    bool o_syslog_program_flag = false;

    /* If "parse-json-program" is enabled, we'll look for signs in the program
       field for JSON.  If we find it,  we'll append the program and message
       field */

    if ( config->json_parse_data == true )
        {

            /* If we detect JSON in the "program" field,  append the program with the
            * message */

            if ( SaganProcSyslog_LOCAL->syslog_program[0] == '{' ||
                    SaganProcSyslog_LOCAL->syslog_program[1] == '{' )
                {

                    char *tmp_json = malloc( config->message_buffer_size + MAX_SYSLOG_PROGRAM );

                    if ( tmp_json == NULL )
                        {
                            fprintf(stderr, "[%s, line %d] Fatal Error: Can't allocate memory! Abort!\n", __FILE__, __LINE__);
                            exit(-1);
                        }

                    tmp_json[0] = '\0';

                    if ( debug->debugjson )
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] Found possible JSON within program \"%s\", appending to syslog 'message'.", __FILE__, __LINE__, SaganProcSyslog_LOCAL->syslog_program );
                        }

                    /* Merge program+message */

                    snprintf(tmp_json, config->message_buffer_size + MAX_SYSLOG_PROGRAM, "%s%s", SaganProcSyslog_LOCAL->syslog_program, SaganProcSyslog_LOCAL->syslog_message );

                    /* Zero out program (might get set by JSON) */

                    SaganProcSyslog_LOCAL->syslog_program[0] = '\0';
                    strlcpy(SaganProcSyslog_LOCAL->syslog_message, tmp_json, config->message_buffer_size);

                    free( tmp_json );

                }

            /* Check the "message" for possible JSON.  Keep in mind,  it could have been appended
             * from above! */

            if ( SaganProcSyslog_LOCAL->syslog_message[0] == '{' ||
                    SaganProcSyslog_LOCAL->syslog_message[1] == '{' ||
                    SaganProcSyslog_LOCAL->syslog_message[2] == '{'  )
                {

                    if ( debug->debugjson )
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] Found possible JSON within message \"%s\".", __FILE__, __LINE__, SaganProcSyslog_LOCAL->syslog_message);
                        }

                    strlcpy( SaganProcSyslog_LOCAL->json_original, SaganProcSyslog_LOCAL->syslog_message, config->message_buffer_size);
                    Parse_JSON( SaganProcSyslog_LOCAL->syslog_message, JSON_LOCAL);

                }

        } /* if ( config->json_parse_data */

#endif


    append_program_flag = false;

    /* Search for matches */

    /* First we search for 'program' and such.   This way,  we don't waste CPU
     * time with pcre/content.  */


    for(b=0; b < counters->rulecount; b++)
        {

            /* Process "normal" rules.  Skip dynamic rules if it's not time to process them */

            while ( reload_rules == true )
                {
                    usleep(10);
                }

            if ( rulestruct[b].type == NORMAL_RULE || ( rulestruct[b].type == DYNAMIC_RULE && dynamic_rule_flag == true ) )
                {

                    /* Reset for next run */

                    SaganProcSyslog_LOCAL->src_ip[0] = '\0';
                    SaganProcSyslog_LOCAL->dst_ip[0] = '\0';

                    SaganProcSyslog_LOCAL->src_port = 0;
                    SaganProcSyslog_LOCAL->dst_port = 0;

                    SaganProcSyslog_LOCAL->proto = 0;

                    SaganProcSyslog_LOCAL->src_host[0] = '\0';
                    SaganProcSyslog_LOCAL->dst_host[0] = '\0';

                    SaganProcSyslog_LOCAL->event_id[0] = '\0';
                    SaganProcSyslog_LOCAL->md5[0] = '\0';
                    SaganProcSyslog_LOCAL->sha1[0] = '\0';
                    SaganProcSyslog_LOCAL->sha256[0] = '\0';
                    SaganProcSyslog_LOCAL->filename[0] = '\0';
                    SaganProcSyslog_LOCAL->hostname[0] = '\0';
                    SaganProcSyslog_LOCAL->url[0] = '\0';
                    SaganProcSyslog_LOCAL->ja3[0] = '\0';
                    SaganProcSyslog_LOCAL->username[0] = '\0';

                    SaganProcSyslog_LOCAL->ip_src_is_valid = false;
                    SaganProcSyslog_LOCAL->ip_dst_is_valid = false;
                    SaganProcSyslog_LOCAL->port_src_is_valid = false;
                    SaganProcSyslog_LOCAL->port_dst_is_valid = false;



                    /* If we have JSON maps, apply them (if we actually have JSON ! */

#ifdef HAVE_LIBFASTJSON

                    if ( config->json_parse_data == true )
                        {

                            if ( JSON_LOCAL->json_count > 0 && rulestruct[b].json_map_count > 0 )
                                {

                                    for ( i = 0; i < rulestruct[b].json_map_count; i++ )
                                        {

                                            char *tmp_json_value = malloc( config->message_buffer_size );

                                            if ( tmp_json_value == NULL )
                                                {
                                                    Sagan_Log(ERROR, "[%s, lines %d] Error allocation memory.", __FILE__, __LINE__);
                                                }

                                            tmp_json_value[0] = '\0';

                                            Get_Key_Value( JSON_LOCAL, rulestruct[b].json_map_key[i], tmp_json_value, config->message_buffer_size );

                                            if ( rulestruct[b].json_map_type[i] == JSON_MAP_SRC_IP )
                                                {

                                                    /* Make sure we have a "good" value to copy */

                                                    if ( tmp_json_value[0] != '\0' )
                                                        {
                                                            strlcpy(SaganProcSyslog_LOCAL->src_ip, tmp_json_value, MAXIP);
                                                        }
                                                    else
                                                        {
                                                            strlcpy(SaganProcSyslog_LOCAL->src_ip, config->sagan_host, MAXIP);
                                                        }

                                                    IP2Bit(SaganProcSyslog_LOCAL->src_ip, SaganProcSyslog_LOCAL->ip_src_bits);
                                                    SaganProcSyslog_LOCAL->ip_src_is_valid = true;
                                                }

                                            else if ( rulestruct[b].json_map_type[i] == JSON_MAP_DEST_IP )
                                                {

                                                    /* Make sure we have a "good" value to copy */

                                                    if ( tmp_json_value[0] != '\0' )
                                                        {
                                                            strlcpy(SaganProcSyslog_LOCAL->dst_ip, tmp_json_value, MAXIP);
                                                        }
                                                    else
                                                        {
                                                            strlcpy(SaganProcSyslog_LOCAL->dst_ip, config->sagan_host, MAXIP);
                                                        }

                                                    IP2Bit(SaganProcSyslog_LOCAL->dst_ip, SaganProcSyslog_LOCAL->ip_dst_bits);
                                                    SaganProcSyslog_LOCAL->ip_dst_is_valid = true;
                                                }

                                            else if ( rulestruct[b].json_map_type[i] == JSON_MAP_SRC_PORT )
                                                {
                                                    SaganProcSyslog_LOCAL->src_port = atoi( tmp_json_value );
                                                }

                                            else if ( rulestruct[b].json_map_type[i] == JSON_MAP_DEST_PORT )
                                                {
                                                    SaganProcSyslog_LOCAL->dst_port = atoi( tmp_json_value );
                                                }

                                            else if ( rulestruct[b].json_map_type[i] == JSON_MAP_USERNAME )
                                                {
                                                    strlcpy(SaganProcSyslog_LOCAL->username, tmp_json_value, MAX_USERNAME_SIZE);
                                                }

                                            else if ( rulestruct[b].json_map_type[i] == JSON_MAP_MESSAGE )
                                                {

                                                    o_syslog_message_flag = true;

                                                    strlcpy(o_syslog_message, SaganProcSyslog_LOCAL->syslog_message, config->message_buffer_size);
                                                    strlcpy(SaganProcSyslog_LOCAL->syslog_message, tmp_json_value, config->message_buffer_size);
                                                }

                                            else if ( rulestruct[b].json_map_type[i] == JSON_MAP_PROGRAM )
                                                {

                                                    o_syslog_program_flag = true;

                                                    strlcpy(o_syslog_program, SaganProcSyslog_LOCAL->syslog_program, MAX_SYSLOG_PROGRAM);
                                                    strlcpy(SaganProcSyslog_LOCAL->syslog_program, tmp_json_value, MAX_SYSLOG_PROGRAM);

                                                }

                                            else if ( rulestruct[b].json_map_type[i] == JSON_MAP_EVENT_ID )
                                                {
                                                    strlcpy( SaganProcSyslog_LOCAL->event_id, tmp_json_value, sizeof( SaganProcSyslog_LOCAL->event_id) );
                                                }

                                            else if ( rulestruct[b].json_map_type[i] == JSON_MAP_FLOW_ID )
                                                {
                                                    SaganProcSyslog_LOCAL->flow_id = atol( tmp_json_value );
                                                }

                                            else if ( rulestruct[b].json_map_type[i] == JSON_MAP_MD5 )
                                                {
                                                    strlcpy(SaganProcSyslog_LOCAL->md5, tmp_json_value, MD5_HASH_SIZE);
                                                }

                                            else if ( rulestruct[b].json_map_type[i] == JSON_MAP_SHA1 )
                                                {
                                                    strlcpy(SaganProcSyslog_LOCAL->sha1, tmp_json_value, SHA1_HASH_SIZE);
                                                }

                                            else if ( rulestruct[b].json_map_type[i] == JSON_MAP_SHA256 )
                                                {
                                                    strlcpy(SaganProcSyslog_LOCAL->sha256, tmp_json_value, SHA256_HASH_SIZE);
                                                }

                                            else if ( rulestruct[b].json_map_type[i] == JSON_MAP_FILENAME )
                                                {
                                                    strlcpy(SaganProcSyslog_LOCAL->filename, tmp_json_value, MAX_FILENAME_SIZE);
                                                }

                                            else if ( rulestruct[b].json_map_type[i] == JSON_MAP_HOSTNAME )
                                                {
                                                    strlcpy(SaganProcSyslog_LOCAL->filename, tmp_json_value, MAX_HOSTNAME_SIZE);
                                                }

                                            else if ( rulestruct[b].json_map_type[i] == JSON_MAP_URL )
                                                {
                                                    strlcpy(SaganProcSyslog_LOCAL->url, tmp_json_value, MAX_URL_SIZE);
                                                }

                                            else if ( rulestruct[b].json_map_type[i] == JSON_MAP_JA3 )
                                                {
                                                    strlcpy(SaganProcSyslog_LOCAL->url, tmp_json_value, MD5_HASH_SIZE);
                                                }

                                            else if ( rulestruct[b].json_map_type[i] == JSON_MAP_PROTO )
                                                {

                                                    if ( !Sagan_stristr(tmp_json_value, "tcp", true))
                                                        {
                                                            SaganProcSyslog_LOCAL->proto = 6;
                                                        }

                                                    else if ( !Sagan_stristr(tmp_json_value, "udp", true))
                                                        {
                                                            SaganProcSyslog_LOCAL->proto = 17;
                                                        }

                                                    else if ( !Sagan_stristr(tmp_json_value, "icmp", true))
                                                        {
                                                            SaganProcSyslog_LOCAL->proto = 1;
                                                        }

                                                }

                                            free( tmp_json_value );

                                        } /* for ( i = 0; i < rulestruct[b].json_map_count ... */

                                }

                        }

#endif

                    pre_match = false;

                    if ( rulestruct[b].s_program[0] != '\0' )
                        {

                            strlcpy(tmpbuf, rulestruct[b].s_program, sizeof(tmpbuf));

                            ptmp = strtok_r(tmpbuf, "|", &tok2);
                            pre_match = true;

                            while ( ptmp != NULL )
                                {
                                    if ( Wildcard(ptmp, SaganProcSyslog_LOCAL->syslog_program) == 1 )
                                        {
                                            pre_match = false;
                                        }

                                    ptmp = strtok_r(NULL, "|", &tok2);
                                }
                        }

                    if ( rulestruct[b].s_facility[0] != '\0' && pre_match == false )
                        {

                            strlcpy(tmpbuf, rulestruct[b].s_facility, sizeof(tmpbuf));
                            ptmp = strtok_r(tmpbuf, "|", &tok2);
                            pre_match = true;

                            while ( ptmp != NULL )
                                {
                                    if (!strcmp(ptmp, SaganProcSyslog_LOCAL->syslog_facility))
                                        {
                                            pre_match = false;
                                        }

                                    ptmp = strtok_r(NULL, "|", &tok2);
                                }
                        }

                    if ( rulestruct[b].s_level[0] != '\0' && pre_match == false )
                        {

                            strlcpy(tmpbuf, rulestruct[b].s_level, sizeof(tmpbuf));
                            ptmp = strtok_r(tmpbuf, "|", &tok2);
                            pre_match = true;

                            while ( ptmp != NULL )
                                {
                                    if (!strcmp(ptmp, SaganProcSyslog_LOCAL->syslog_level))
                                        {
                                            pre_match = false;
                                        }

                                    ptmp = strtok_r(NULL, "|", &tok2);
                                }
                        }

                    if ( rulestruct[b].s_tag[0] != '\0' && pre_match == false )
                        {

                            strlcpy(tmpbuf, rulestruct[b].s_tag, sizeof(tmpbuf));
                            ptmp = strtok_r(tmpbuf, "|", &tok2);
                            pre_match = true;

                            while ( ptmp != NULL )
                                {
                                    if (!strcmp(ptmp, SaganProcSyslog_LOCAL->syslog_tag))
                                        {
                                            pre_match = false;
                                        }

                                    ptmp = strtok_r(NULL, "|", &tok2);
                                }
                        }

                    if ( rulestruct[b].s_syspri[0] != '\0' && pre_match == false )
                        {

                            strlcpy(tmpbuf, rulestruct[b].s_syspri, sizeof(tmpbuf));
                            ptmp = strtok_r(tmpbuf, "|", &tok2);
                            pre_match = true;

                            while ( ptmp != NULL )
                                {
                                    if (!strcmp(ptmp, SaganProcSyslog_LOCAL->syslog_priority))
                                        {
                                            pre_match = false;
                                        }

                                    ptmp = strtok_r(NULL, "|", &tok2);
                                }
                        }

                    /* If there has been a pre_match above,  or NULL on all,  then we continue with
                     * PCRE/content search */

                    /* Search via strstr (content:) */

                    bool flag = false;

                    if ( pre_match == false )
                        {

                            /* If the "append_program" rule option is used,  we append the program here */

                            if ( rulestruct[b].append_program == true && append_program_flag == false &&
                                    SaganProcSyslog_LOCAL->syslog_program[0] != '\0' )
                                {

                                    char *syslog_append_program = malloc( config->message_buffer_size + MAX_SYSLOG_PROGRAM + 6 );

                                    if ( syslog_append_program == NULL )
                                        {
                                            fprintf(stderr, "[%s, line %d] Fatal Error: Can't allocate memory! Abort!\n", __FILE__, __LINE__);
                                            exit(-1);
                                        }

                                    syslog_append_program[0] = '\0';

                                    strlcpy(syslog_append_orig_message, SaganProcSyslog_LOCAL->syslog_message, config->message_buffer_size );

                                    snprintf(syslog_append_program, config->message_buffer_size + MAX_SYSLOG_PROGRAM + 6, "%s | %s", SaganProcSyslog_LOCAL->syslog_message, SaganProcSyslog_LOCAL->syslog_program);
                                    syslog_append_program[ (config->message_buffer_size + MAX_SYSLOG_PROGRAM + 6) - 1 ] = '\0';
                                    strlcpy(SaganProcSyslog_LOCAL->syslog_message, syslog_append_program, config->message_buffer_size);
                                    append_program_flag = true;

                                    free( syslog_append_program) ;
                                }

                            /* If the signature _doesn't_ have an "append_program" but we've already
                               appended,  we undo that action (back the the orginal string */

                            if ( rulestruct[b].append_program == false && append_program_flag == true )
                                {
                                    strlcpy(SaganProcSyslog_LOCAL->syslog_message,syslog_append_orig_message, config->message_buffer_size);

                                    append_program_flag = false;
                                }

                            /* Start processing searches from rule optison */

                            flag = true;

                            bool validate_flag = ValidateMessage( SaganProcSyslog_LOCAL->syslog_message );

                            if ( rulestruct[b].content_count > 0 )
                                {

                                    if ( validate_flag == true )
                                        {
                                            flag = Content(b, SaganProcSyslog_LOCAL->syslog_message );
                                        }
                                    else
                                        {
                                            __atomic_add_fetch(&counters->null_message, 1, __ATOMIC_SEQ_CST);
                                            flag = false;
                                        }

                                }

                            if ( flag == true && rulestruct[b].pcre_count > 0 )
                                {

                                    if ( validate_flag == true )
                                        {
                                            flag = PcreS(b, SaganProcSyslog_LOCAL->syslog_message );
                                        }
                                    else
                                        {
                                            __atomic_add_fetch(&counters->null_message, 1, __ATOMIC_SEQ_CST);
                                            flag = false;
                                        }

                                }

                            if ( flag == true && rulestruct[b].meta_content_count > 0 )
                                {

                                    if ( validate_flag == true )
                                        {
                                            flag = Meta_Content(b, SaganProcSyslog_LOCAL->syslog_message);
                                        }
                                    else
                                        {
                                            __atomic_add_fetch(&counters->null_message, 1, __ATOMIC_SEQ_CST);
                                            flag = false;
                                        }

                                }

#ifdef HAVE_LIBFASTJSON

                            if ( flag == true && rulestruct[b].json_pcre_count > 0 )
                                {

                                    if ( validate_flag == true )
                                        {
                                            flag = JSON_Pcre(b, JSON_LOCAL );
                                        }
                                    else
                                        {
                                            __atomic_add_fetch(&counters->null_message, 1, __ATOMIC_SEQ_CST);
                                            flag = false;
                                        }

                                }

                            if ( flag == true && rulestruct[b].json_content_count > 0 )
                                {
                                    if ( validate_flag == true )
                                        {
                                            flag = JSON_Content(b, JSON_LOCAL );
                                        }
                                    else
                                        {
                                            __atomic_add_fetch(&counters->null_message, 1, __ATOMIC_SEQ_CST);
                                            flag = false;
                                        }

                                }

                            if ( flag == true && rulestruct[b].json_meta_content_count > 0 )
                                {
                                    if ( validate_flag == true )
                                        {
                                            flag = JSON_Meta_Content(b, JSON_LOCAL );
                                        }
                                    else
                                        {
                                            __atomic_add_fetch(&counters->null_message, 1, __ATOMIC_SEQ_CST);
                                            flag = false;
                                        }
                                }

#endif

#ifdef HAVE_LIBLOGNORM
                            /************************************************************/
                            /* Liblognorm - Do normalization before event_id processing */
                            /************************************************************/

			    /* LOCAL->username is getting cleared on next run */

                            if ( flag == true )
                                {

                                    /* We only want to run normalization on the log _one_ time.  If
                                     * multiple sigs want normalization, reuse the normalization data. */

                                    if ( liblognorm_status == false && rulestruct[b].normalize == true )
                                        {

                                            Normalize_Liblognorm( SaganProcSyslog_LOCAL );
                                            liblognorm_status = true;

                                        }

                                }

#endif

                            /* Event ID */

                            if ( flag == true && rulestruct[b].event_id_count > 0 )
                                {

                                    if ( validate_flag == true )
                                        {
                                            flag = Event_ID( b, SaganProcSyslog_LOCAL );
                                        }
                                    else
                                        {
                                            __atomic_add_fetch(&counters->null_message, 1, __ATOMIC_SEQ_CST);
                                            flag = false;
                                        }

                                }


                            /* Offload - we do this last, because it might be the most CPU consuming. */

#ifdef WITH_OFFLOAD
                            if ( flag == true && rulestruct[b].offload_flag == true )
                                {

                                    if ( validate_flag == true )
                                        {
                                            flag = Offload( b, SaganProcSyslog_LOCAL->syslog_host, SaganProcSyslog_LOCAL->syslog_facility, SaganProcSyslog_LOCAL->syslog_priority, SaganProcSyslog_LOCAL->syslog_level, SaganProcSyslog_LOCAL->syslog_tag, SaganProcSyslog_LOCAL->syslog_date, SaganProcSyslog_LOCAL->syslog_time, SaganProcSyslog_LOCAL->syslog_program, SaganProcSyslog_LOCAL->syslog_message );
                                        }
                                    else
                                        {
                                            __atomic_add_fetch(&counters->null_message, 1, __ATOMIC_SEQ_CST);
                                            flag = false;
                                        }

                                }
#endif
                        }

                    /* Check for match from content, pcre, etc... */

                    if ( pre_match == false && flag == true )
                        {

                            /* Normalization should always over ride parse_src_ip/parse_dst_ip/parse_port,
                             * _unless_ liblognorm fails and both are in a rule or liblognorm failed to get src or dst */

                            /* parse_src_ip: {position} - Parse_IP build a cache table for IPs, ports, etc.  This way,
                            we only parse the syslog string one time regardless of the rule options! */

                            if ( ( rulestruct[b].s_find_src_ip == true && SaganProcSyslog_LOCAL->ip_src_is_valid == false ) ||
                                    ( rulestruct[b].s_find_dst_ip == true && SaganProcSyslog_LOCAL->ip_dst_is_valid == false ) )
                                {

                                    lookup_cache_size = Parse_IP(SaganProcSyslog_LOCAL->syslog_message, lookup_cache );

                                }

                            if ( SaganProcSyslog_LOCAL->ip_src_is_valid == false && rulestruct[b].s_find_src_ip == true )
                                {


                                    if ( lookup_cache[rulestruct[b].s_find_src_pos-1].status == true )
                                        {

                                            memcpy(SaganProcSyslog_LOCAL->src_ip, lookup_cache[rulestruct[b].s_find_src_pos-1].ip, MAXIP );
                                            memcpy(SaganProcSyslog_LOCAL->ip_src_bits, lookup_cache[rulestruct[b].s_find_src_pos-1].ip_bits, MAXIPBIT);

                                            SaganProcSyslog_LOCAL->src_port = lookup_cache[rulestruct[b].s_find_src_pos-1].port;
                                            SaganProcSyslog_LOCAL->proto = lookup_cache[0].proto;
                                            SaganProcSyslog_LOCAL->ip_src_is_valid = true;

                                        }

                                }

                            /* parse_dst_ip: {position} */

                            if ( SaganProcSyslog_LOCAL->ip_dst_is_valid == false && rulestruct[b].s_find_dst_ip == true )
                                {

                                    if ( lookup_cache[rulestruct[b].s_find_dst_pos-1].status == true )
                                        {

                                            memcpy(SaganProcSyslog_LOCAL->dst_ip, lookup_cache[rulestruct[b].s_find_dst_pos-1].ip, MAXIP );
                                            memcpy(SaganProcSyslog_LOCAL->ip_dst_bits, lookup_cache[rulestruct[b].s_find_dst_pos-1].ip_bits, MAXIPBIT);

                                            SaganProcSyslog_LOCAL->dst_port = lookup_cache[rulestruct[b].s_find_dst_pos-1].port;
                                            SaganProcSyslog_LOCAL->proto = lookup_cache[0].proto;
                                            SaganProcSyslog_LOCAL->ip_dst_is_valid = true;

                                        }

                                }

                            /* If the syslog_host is localhost, then we set it to the sagan_host value */

                            IP2Bit(SaganProcSyslog_LOCAL->syslog_host, SaganProcSyslog_LOCAL->syslog_bits);

                            if ( is_notlocalhost( SaganProcSyslog_LOCAL->syslog_bits ) )
                                {
                                    strlcpy(SaganProcSyslog_LOCAL->syslog_host, config->sagan_host, MAXIP);
                                }

                            /* We never want the source or destiniation to be null or localhost */

                            if ( is_notlocalhost( SaganProcSyslog_LOCAL->ip_src_bits ) ||
                                    SaganProcSyslog_LOCAL->src_ip[0] == '\0' ||
                                    SaganProcSyslog_LOCAL->ip_src_is_valid == false )
                                {
                                    SaganProcSyslog_LOCAL->ip_src_is_valid = false;
                                    strlcpy(SaganProcSyslog_LOCAL->src_ip, SaganProcSyslog_LOCAL->syslog_host, MAXIP);
                                }

                            if ( is_notlocalhost( SaganProcSyslog_LOCAL->ip_dst_bits ) ||
                                    SaganProcSyslog_LOCAL->dst_ip[0] == '\0' ||
                                    SaganProcSyslog_LOCAL->ip_dst_is_valid == false)
                                {
                                    SaganProcSyslog_LOCAL->ip_dst_is_valid = false;
                                    strlcpy(SaganProcSyslog_LOCAL->dst_ip, SaganProcSyslog_LOCAL->syslog_host, MAXIP);
                                }

                            /* parse_hash: md5 */

                            if ( SaganProcSyslog_LOCAL->md5[0] == '\0' && rulestruct[b].s_find_hash_type == PARSE_HASH_MD5 )
                                {
                                    Parse_Hash(SaganProcSyslog_LOCAL->syslog_message, PARSE_HASH_MD5, SaganProcSyslog_LOCAL->md5, MD5_HASH_SIZE+1 );
                                }

                            else if ( SaganProcSyslog_LOCAL->sha1[0] == '\0' && rulestruct[b].s_find_hash_type == PARSE_HASH_SHA1 )
                                {
                                    Parse_Hash(SaganProcSyslog_LOCAL->syslog_message, PARSE_HASH_SHA1, SaganProcSyslog_LOCAL->sha1, SHA1_HASH_SIZE+1 );
                                }

                            else if ( SaganProcSyslog_LOCAL->sha256[0] == '\0' && rulestruct[b].s_find_hash_type == PARSE_HASH_SHA256 )
                                {
                                    Parse_Hash(SaganProcSyslog_LOCAL->syslog_message, PARSE_HASH_SHA256, SaganProcSyslog_LOCAL->sha256, SHA256_HASH_SIZE+1 );
                                }


                            /* If the rule calls for proto searching,  we do it now */

                            if ( rulestruct[b].s_find_proto == true )
                                {
                                    SaganProcSyslog_LOCAL->proto = Parse_Proto_Program(SaganProcSyslog_LOCAL->syslog_message);
                                }

                            if ( rulestruct[b].s_find_proto_program == true )
                                {
                                    SaganProcSyslog_LOCAL->proto = Parse_Proto_Program(SaganProcSyslog_LOCAL->syslog_program);
                                }

                            /* No source port was normalized, Use the rules default */

                            if ( rulestruct[b].default_src_port != 0 && SaganProcSyslog_LOCAL->port_src_is_valid == false )
                                {
                                    SaganProcSyslog_LOCAL->src_port=rulestruct[b].default_src_port;
                                }

                            /* No destination port was normalzied. Use the rules default */

                            if ( rulestruct[b].default_dst_port != 0 && SaganProcSyslog_LOCAL->port_dst_is_valid == false )
                                {
                                    SaganProcSyslog_LOCAL->dst_port=rulestruct[b].default_dst_port;
                                }

                            /* No protocol was normalized.  Use the rules default */

                            if ( rulestruct[b].default_proto != 0 )
                                {
                                    SaganProcSyslog_LOCAL->proto = rulestruct[b].default_proto;
                                }

                            /* Check for flow of rule - has_flow is set as rule loading.  It 1, then
                            the rule has some sort of flow.  It 0,  rule is set any:any/any:any */

                            if ( rulestruct[b].has_flow == true )
                                {

                                    SaganRouting->check_flow_return = Check_Flow( b, SaganProcSyslog_LOCAL->proto, SaganProcSyslog_LOCAL->ip_src_bits, SaganProcSyslog_LOCAL->src_port, SaganProcSyslog_LOCAL->ip_dst_bits, SaganProcSyslog_LOCAL->dst_port);

                                    if( SaganRouting->check_flow_return == false)
                                        {

                                            __atomic_add_fetch(&counters->follow_flow_drop, 1, __ATOMIC_SEQ_CST);

                                        }

                                    __atomic_add_fetch(&counters->follow_flow_total, 1, __ATOMIC_SEQ_CST);

                                }


                            /****************************************************************************
                                             * flexbit/xbit "upause".  This lets flexbits/xbit settle in "tight" timing situations.
                              ****************************************************************************/


                            /* pause (seconds) */

                            if ( rulestruct[b].flexbit_pause_time != 0 )
                                {

                                    if ( debug->debugxbit )
                                        {
                                            Sagan_Log(DEBUG, "[%s, line %d] flexbit_pause for %d seconds", __FILE__, __LINE__, rulestruct[b].flexbit_pause_time);
                                        }


                                    sleep( rulestruct[b].flexbit_pause_time );
                                }

                            /* upause (millisecond) */

                            if ( rulestruct[b].flexbit_upause_time != 0 )
                                {
                                    if ( debug->debugxbit )
                                        {
                                            Sagan_Log(DEBUG, "[%s, line %d] flexbit_pause for %d microseconds", __FILE__, __LINE__, rulestruct[b].flexbit_upause_time);
                                        }

                                    usleep( rulestruct[b].flexbit_upause_time );
                                }

                            /* pause (second) */

                            if ( rulestruct[b].xbit_pause_time != 0 )
                                {

                                    if ( debug->debugxbit )
                                        {
                                            Sagan_Log(DEBUG, "[%s, line %d] xbit_pause for %d seconds", __FILE__, __LINE__, rulestruct[b].xbit_pause_time);
                                        }

                                    sleep( rulestruct[b].xbit_pause_time );
                                }

                            if ( rulestruct[b].xbit_upause_time != 0 )
                                {
                                    if ( debug->debugxbit )
                                        {
                                            Sagan_Log(DEBUG, "[%s, line %d] xbit_upause for %d microseconds", __FILE__, __LINE__, rulestruct[b].xbit_upause_time);
                                        }


                                    usleep( rulestruct[b].xbit_upause_time );
                                }

                            /****************************************************************************
                             * xbit - ISSET || ISNOTSET
                             ****************************************************************************/

                            if ( rulestruct[b].xbit_flag && ( rulestruct[b].xbit_isset_count || rulestruct[b].xbit_isnotset_count ) )
                                {
                                    SaganRouting->xbit_return = Xbit_Condition(b, SaganProcSyslog_LOCAL);
                                }

                            /****************************************************************************
                             * flexbit - ISSET || ISNOTSET
                             ****************************************************************************/

                            if ( rulestruct[b].flexbit_flag )
                                {

                                    if ( rulestruct[b].flexbit_condition_count )
                                        {
                                            SaganRouting->flexbit_return = Flexbit_Condition(b, SaganProcSyslog_LOCAL->src_ip, SaganProcSyslog_LOCAL->dst_ip, SaganProcSyslog_LOCAL->src_port, SaganProcSyslog_LOCAL->dst_port, SaganProcSyslog_LOCAL->username, SaganProcSyslog_LOCAL);
                                        }

                                    if ( rulestruct[b].flexbit_count_flag )
                                        {
                                            SaganRouting->flexbit_count_return = Flexbit_Count(b, SaganProcSyslog_LOCAL->src_ip, SaganProcSyslog_LOCAL->dst_ip);
                                        }

                                }


                            /****************************************************************************
                             * Country code
                             ****************************************************************************/

#ifdef HAVE_LIBMAXMINDDB

                            /* Reset values */

                            GeoIP_SRC->results = 0;
                            GeoIP_DEST->results = 0;

                            GeoIP_SRC->country[0] = '\0';
                            GeoIP_DEST->country[0] = '\0';

                            GeoIP_SRC->city[0] = '\0';
                            GeoIP_DEST->city[0] = '\0';

                            GeoIP_SRC->subdivision[0] = '\0';
                            GeoIP_DEST->subdivision[0] = '\0';

                            if ( rulestruct[b].geoip2_flag && config->have_geoip2 == true )
                                {

                                    /* Set geoip2_return to GEOIP_SKIP in case ip_src_is_valid
                                       or ip_dst_is_valid is false! This way it will short
                                       circuit past the rest of the GeoIP logic. */

                                    geoip2_return = GEOIP_SKIP;
                                    SaganRouting->geoip2_isset = false;

                                    if ( SaganProcSyslog_LOCAL->ip_src_is_valid == true && rulestruct[b].geoip2_src_or_dst == 1 )
                                        {
                                            geoip2_return = GeoIP2_Lookup_Country(SaganProcSyslog_LOCAL->src_ip, b, GeoIP_SRC );
                                        }

                                    else if ( SaganProcSyslog_LOCAL->ip_dst_is_valid == true && rulestruct[b].geoip2_src_or_dst == 2 )
                                        {
                                            geoip2_return = GeoIP2_Lookup_Country(SaganProcSyslog_LOCAL->dst_ip, b, GeoIP_DEST );
                                        }

                                    if ( geoip2_return != GEOIP_SKIP )
                                        {

                                            /* If country IS NOT {my value} return 1 */

                                            if ( rulestruct[b].geoip2_type == 1 )    		/* isnot */
                                                {

                                                    if ( geoip2_return == GEOIP_HIT )
                                                        {
                                                            SaganRouting->geoip2_isset = false;
                                                        }
                                                    else
                                                        {
                                                            SaganRouting->geoip2_isset = true;

                                                            __atomic_add_fetch(&counters->geoip2_hit, 1, __ATOMIC_SEQ_CST);

                                                        }
                                                }

                                            /* If country IS {my value} return 1 */

                                            else if ( rulestruct[b].geoip2_type == 2 )             /* is */
                                                {

                                                    if ( geoip2_return == GEOIP_HIT )
                                                        {
                                                            SaganRouting->geoip2_isset = true;

                                                            __atomic_add_fetch(&counters->geoip2_hit, 1, __ATOMIC_SEQ_CST);

                                                        }
                                                    else
                                                        {

                                                            SaganRouting->geoip2_isset = false;
                                                        }
                                                }
                                        }

                                }
                            else
                                {


                                    /* If we want to store all GeoIP information for all alerts event
                                    not GeoIP related events */

                                    if ( config->have_geoip2 == true )
                                        {

                                            (void)GeoIP2_Lookup_Country(SaganProcSyslog_LOCAL->src_ip, b, GeoIP_SRC );
                                            (void)GeoIP2_Lookup_Country(SaganProcSyslog_LOCAL->dst_ip, b, GeoIP_DEST );

                                        }

                                }

#endif

                            /****************************************************************************
                             * Time based alerting
                             ****************************************************************************/

                            if ( rulestruct[b].alert_time_flag )
                                {

                                    SaganRouting->alert_time_trigger = false;

                                    if ( Check_Time(b) )
                                        {
                                            SaganRouting->alert_time_trigger = true;
                                        }
                                }

                            /****************************************************************************
                             * Blacklist
                             ****************************************************************************/

                            if ( rulestruct[b].blacklist_flag )
                                {

                                    SaganRouting->blacklist_results = false;

                                    if ( rulestruct[b].blacklist_ipaddr_src && SaganProcSyslog_LOCAL->ip_src_is_valid == true )
                                        {
                                            SaganRouting->blacklist_results = Sagan_Blacklist_IPADDR( SaganProcSyslog_LOCAL->ip_src_bits );
                                        }

                                    if ( SaganRouting->blacklist_results == false && rulestruct[b].blacklist_ipaddr_dst && SaganProcSyslog_LOCAL->ip_dst_is_valid == true )
                                        {
                                            SaganRouting->blacklist_results = Sagan_Blacklist_IPADDR( SaganProcSyslog_LOCAL->ip_dst_bits );
                                        }

                                    if ( SaganRouting->blacklist_results == false && rulestruct[b].blacklist_ipaddr_all )
                                        {
                                            SaganRouting->blacklist_results = Sagan_Blacklist_IPADDR_All(SaganProcSyslog_LOCAL->syslog_message, lookup_cache, lookup_cache_size);
                                        }

                                    if ( SaganRouting->blacklist_results == false && rulestruct[b].blacklist_ipaddr_both && SaganProcSyslog_LOCAL->ip_src_is_valid == true && SaganProcSyslog_LOCAL->ip_dst_is_valid == true )
                                        {
                                            if ( Sagan_Blacklist_IPADDR( SaganProcSyslog_LOCAL->ip_src_bits ) || Sagan_Blacklist_IPADDR( SaganProcSyslog_LOCAL->ip_dst_bits ) )
                                                {
                                                    SaganRouting->blacklist_results = true;
                                                }
                                        }
                                }

#ifdef WITH_BLUEDOT

                            if ( config->bluedot_flag )
                                {

                                    bluedot_results = 0;
                                    bluedot_json[0] = '\0';

                                    if ( rulestruct[b].bluedot_ipaddr_type )
                                        {

                                            /* 1 == src,  2 == dst,  3 == both,  4 == all */

                                            if ( rulestruct[b].bluedot_ipaddr_type == 1 && SaganProcSyslog_LOCAL->ip_src_is_valid == true )
                                                {
                                                    bluedot_results = Sagan_Bluedot_Lookup(SaganProcSyslog_LOCAL->src_ip, BLUEDOT_LOOKUP_IP, b, bluedot_json, sizeof(bluedot_json));
                                                    SaganRouting->bluedot_ip_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_IP);
                                                }

                                            if ( rulestruct[b].bluedot_ipaddr_type == 2 && SaganProcSyslog_LOCAL->ip_dst_is_valid == true )
                                                {
                                                    bluedot_results = Sagan_Bluedot_Lookup(SaganProcSyslog_LOCAL->dst_ip, BLUEDOT_LOOKUP_IP, b, bluedot_json, sizeof(bluedot_json));
                                                    SaganRouting->bluedot_ip_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_IP);
                                                }

                                            if ( rulestruct[b].bluedot_ipaddr_type == 3 && SaganProcSyslog_LOCAL->ip_src_is_valid == true && SaganProcSyslog_LOCAL->ip_dst_is_valid == true )
                                                {

                                                    bluedot_results = Sagan_Bluedot_Lookup(SaganProcSyslog_LOCAL->src_ip, BLUEDOT_LOOKUP_IP, b, bluedot_json, sizeof(bluedot_json));
                                                    SaganRouting->bluedot_ip_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_IP);
                                                    /* If the source isn't found,  then check the dst */

                                                    if ( SaganRouting->bluedot_ip_flag == 0 )
                                                        {
                                                            bluedot_results = Sagan_Bluedot_Lookup(SaganProcSyslog_LOCAL->dst_ip, BLUEDOT_LOOKUP_IP, b, bluedot_json, sizeof(bluedot_json));
                                                            SaganRouting->bluedot_ip_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_IP);
                                                        }

                                                }

                                            if ( lookup_cache_size > 0 && rulestruct[b].bluedot_ipaddr_type == 4 )
                                                {

                                                    SaganRouting->bluedot_ip_flag = Sagan_Bluedot_IP_Lookup_All(SaganProcSyslog_LOCAL->syslog_message, b, lookup_cache, lookup_cache_size );

                                                }


                                        }


                                    if ( rulestruct[b].bluedot_file_hash )
                                        {


                                            if ( SaganProcSyslog_LOCAL->md5[0] != '\0')
                                                {

                                                    bluedot_results = Sagan_Bluedot_Lookup( SaganProcSyslog_LOCAL->md5, BLUEDOT_LOOKUP_HASH, b, bluedot_json, sizeof(bluedot_json));
                                                    SaganRouting->bluedot_hash_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_HASH);

                                                }

                                            if ( SaganProcSyslog_LOCAL->sha1[0] != '\0' )
                                                {

                                                    bluedot_results = Sagan_Bluedot_Lookup( SaganProcSyslog_LOCAL->sha1, BLUEDOT_LOOKUP_HASH, b, bluedot_json, sizeof(bluedot_json));
                                                    SaganRouting->bluedot_hash_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_HASH );

                                                }

                                            if ( SaganProcSyslog_LOCAL->sha256[0] != '\0')
                                                {

                                                    bluedot_results = Sagan_Bluedot_Lookup( SaganProcSyslog_LOCAL->sha256, BLUEDOT_LOOKUP_HASH, b, bluedot_json, sizeof(bluedot_json));
                                                    SaganRouting->bluedot_hash_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_HASH);

                                                }

                                        }

                                    if ( rulestruct[b].bluedot_url && SaganProcSyslog_LOCAL->url[0] != '\0' )
                                        {

                                            bluedot_results = Sagan_Bluedot_Lookup( SaganProcSyslog_LOCAL->url, BLUEDOT_LOOKUP_URL, b, bluedot_json, sizeof(bluedot_json));
                                            SaganRouting->bluedot_url_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_URL);

                                        }

                                    if ( rulestruct[b].bluedot_filename && SaganProcSyslog_LOCAL->filename[0] != '\0' )
                                        {

                                            bluedot_results = Sagan_Bluedot_Lookup( SaganProcSyslog_LOCAL->filename, BLUEDOT_LOOKUP_FILENAME, b, bluedot_json, sizeof(bluedot_json));
                                            SaganRouting->bluedot_filename_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_FILENAME);

                                        }

                                    if ( rulestruct[b].bluedot_ja3 && SaganProcSyslog_LOCAL->ja3[0] != '\0' )
                                        {

                                            bluedot_results = Sagan_Bluedot_Lookup( SaganProcSyslog_LOCAL->ja3, BLUEDOT_LOOKUP_JA3, b, bluedot_json, sizeof(bluedot_json));
                                            SaganRouting->bluedot_ja3_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_JA3);

                                        }



                                    /* Do cleanup at the end in case any "hits" above refresh the cache.  This why we don't
                                     * "delete" an entry only to re-add it! */

                                    Sagan_Bluedot_Check_Cache_Time();


                                }
#endif


                            /****************************************************************************
                            * Zeek Intel
                            ****************************************************************************/

                            if ( rulestruct[b].zeekintel_flag )
                                {

                                    SaganRouting->zeekintel_results = false;

                                    if ( rulestruct[b].zeekintel_ipaddr_src && SaganProcSyslog_LOCAL->ip_src_is_valid == true )
                                        {
                                            SaganRouting->zeekintel_results = ZeekIntel_IPADDR( SaganProcSyslog_LOCAL->ip_src_bits, SaganProcSyslog_LOCAL->src_ip );
                                        }

                                    if ( SaganRouting->zeekintel_results == false && rulestruct[b].zeekintel_ipaddr_dst && SaganProcSyslog_LOCAL->ip_dst_is_valid == true )
                                        {
                                            SaganRouting->zeekintel_results = ZeekIntel_IPADDR( SaganProcSyslog_LOCAL->ip_dst_bits, SaganProcSyslog_LOCAL->dst_ip );
                                        }

                                    if ( SaganRouting->zeekintel_results == false && rulestruct[b].zeekintel_ipaddr_all )
                                        {
                                            SaganRouting->zeekintel_results = ZeekIntel_IPADDR_All ( SaganProcSyslog_LOCAL->syslog_message, lookup_cache, MAX_PARSE_IP);
                                        }

                                    if ( SaganRouting->zeekintel_results == false && rulestruct[b].zeekintel_ipaddr_both && SaganProcSyslog_LOCAL->ip_src_is_valid == true && SaganProcSyslog_LOCAL->ip_dst_is_valid == true )
                                        {
                                            if ( ZeekIntel_IPADDR( SaganProcSyslog_LOCAL->ip_src_bits, SaganProcSyslog_LOCAL->src_ip ) || ZeekIntel_IPADDR( SaganProcSyslog_LOCAL->ip_dst_bits, SaganProcSyslog_LOCAL->dst_ip ) )
                                                {
                                                    SaganRouting->zeekintel_results = true;
                                                }
                                        }

                                    if ( SaganRouting->zeekintel_results == false && rulestruct[b].zeekintel_domain )
                                        {
                                            SaganRouting->zeekintel_results = ZeekIntel_DOMAIN(SaganProcSyslog_LOCAL->syslog_message);
                                        }

                                    if ( SaganRouting->zeekintel_results == false && rulestruct[b].zeekintel_file_hash )
                                        {
                                            SaganRouting->zeekintel_results = ZeekIntel_FILE_HASH(SaganProcSyslog_LOCAL->syslog_message);
                                        }

                                    if ( SaganRouting->zeekintel_results == false && rulestruct[b].zeekintel_url )
                                        {
                                            SaganRouting->zeekintel_results = ZeekIntel_URL(SaganProcSyslog_LOCAL->syslog_message);
                                        }

                                    if ( SaganRouting->zeekintel_results == false && rulestruct[b].zeekintel_software )
                                        {
                                            SaganRouting->zeekintel_results = ZeekIntel_SOFTWARE(SaganProcSyslog_LOCAL->syslog_message);
                                        }

                                    if ( SaganRouting->zeekintel_results == false && rulestruct[b].zeekintel_user_name )
                                        {
                                            SaganRouting->zeekintel_results = ZeekIntel_USER_NAME(SaganProcSyslog_LOCAL->syslog_message);
                                        }

                                    if ( SaganRouting->zeekintel_results == false && rulestruct[b].zeekintel_file_name )
                                        {
                                            SaganRouting->zeekintel_results = ZeekIntel_FILE_NAME(SaganProcSyslog_LOCAL->syslog_message);
                                        }

                                    if ( SaganRouting->zeekintel_results == false && rulestruct[b].zeekintel_cert_hash )
                                        {
                                            SaganRouting->zeekintel_results = ZeekIntel_CERT_HASH(SaganProcSyslog_LOCAL->syslog_message);
                                        }

                                }

                            /****************************************************************************/
                            /* Populate the Sagan Event array with the information needed.  This info    */
                            /* will be passed to the threads.  No need to populate it _if_ we're in a   */
                            /* threshold state.                                                         */
                            /****************************************************************************/

                            SaganRouting->position = b;

                            if ( Sagan_Check_Routing( SaganRouting ) == true )
                                {

                                    /* After */

                                    after_log_flag = false;

                                    if ( rulestruct[b].after2 == true )
                                        {
                                            after_log_flag = After2 (b, SaganProcSyslog_LOCAL->src_ip, SaganProcSyslog_LOCAL->src_port, SaganProcSyslog_LOCAL->dst_ip, SaganProcSyslog_LOCAL->dst_port, SaganProcSyslog_LOCAL->username, SaganProcSyslog_LOCAL->syslog_message );
                                        }

                                    /* Threshold */

                                    thresh_log_flag = false;

                                    if ( rulestruct[b].threshold2_type != 0 && after_log_flag == false )
                                        {
                                            thresh_log_flag = Threshold2 (b, SaganProcSyslog_LOCAL->src_ip, SaganProcSyslog_LOCAL->src_port, SaganProcSyslog_LOCAL->dst_ip, SaganProcSyslog_LOCAL->dst_port, SaganProcSyslog_LOCAL->username, SaganProcSyslog_LOCAL->syslog_message );
                                        }


                                    if ( config->rule_tracking_flag == true )
                                        {
                                            Ruleset_Track[rulestruct[b].ruleset_id].trigger = true;
                                        }


                                    __atomic_add_fetch(&counters->saganfound, 1, __ATOMIC_SEQ_CST);

                                    /* Check for thesholding & "after" */

                                    if ( thresh_log_flag == false && after_log_flag == false )
                                        {

                                            if ( debug->debugengine )
                                                {

                                                    Sagan_Log(DEBUG, "[%s, line %d] **[Trigger]*********************************", __FILE__, __LINE__);
                                                    Sagan_Log(DEBUG, "[%s, line %d] Program: %s | Facility: %s | Priority: %s | Level: %s | Tag: %s | Event ID: %s", __FILE__, __LINE__, SaganProcSyslog_LOCAL->syslog_program, SaganProcSyslog_LOCAL->syslog_facility, SaganProcSyslog_LOCAL->syslog_priority, SaganProcSyslog_LOCAL->syslog_level, SaganProcSyslog_LOCAL->syslog_tag, SaganProcSyslog_LOCAL->event_id);
                                                    Sagan_Log(DEBUG, "[%s, line %d] Threshold flag: %d | After flag: %d | Flexbit Flag: %d | Flexbit status: %d", __FILE__, __LINE__, thresh_log_flag, after_log_flag, rulestruct[b].flexbit_flag, SaganRouting->flexbit_return);
                                                    Sagan_Log(DEBUG, "[%s, line %d] Triggering Message: %s", __FILE__, __LINE__, SaganProcSyslog_LOCAL->syslog_message);

                                                }

                                            /* Do we need to "set" an xbit? */

                                            if ( rulestruct[b].xbit_flag && ( rulestruct[b].xbit_set_count || rulestruct[b].xbit_unset_count ) )
                                                {
                                                    Xbit_Set(b, SaganProcSyslog_LOCAL);
                                                }

                                            /* Check to "set" a flexbit */

                                            if ( rulestruct[b].flexbit_flag && rulestruct[b].flexbit_set_count )
                                                {
                                                    Flexbit_Set(b, SaganProcSyslog_LOCAL->src_ip, SaganProcSyslog_LOCAL->dst_ip, SaganProcSyslog_LOCAL->src_port, SaganProcSyslog_LOCAL->dst_port, SaganProcSyslog_LOCAL->username, SaganProcSyslog_LOCAL->syslog_message);
                                                }

                                            threadid++;

                                            if ( threadid >= MAX_THREADS )
                                                {
                                                    threadid=0;
                                                }

                                            if ( rulestruct[b].flexbit_flag == false || rulestruct[b].flexbit_noalert == 0 )
                                                {

                                                    if ( rulestruct[b].type == NORMAL_RULE )
                                                        {

                                                            Send_Alert(SaganProcSyslog_LOCAL,
                                                                       b, tp,
                                                                       bluedot_json,
                                                                       bluedot_results,
                                                                       JSON_LOCAL->json_count );

                                                            /* If this is a "pass" signature,  we can stop processing now */

                                                            if ( rulestruct[b].rule_type == RULE_TYPE_PASS )
                                                                {
                                                                    break;
                                                                }

                                                        }
                                                    else
                                                        {

                                                            Dynamic_Rules(SaganProcSyslog_LOCAL, b, SaganProcSyslog_LOCAL->src_ip, SaganProcSyslog_LOCAL->dst_ip);

                                                        }

                                                }


                                        } /* Threshold / After */

                                } /* End of routing */

                        } /* End of pcre/content/etc match */

                    pre_match = false;  		      /* Reset match! */

                    SaganRouting->check_flow_return = true;
                    SaganRouting->position = 0;
                    SaganRouting->flexbit_count_return = 0;
                    SaganRouting->flexbit_return = 0;
                    SaganRouting->xbit_return = 0;
                    SaganRouting->event_id_return = 0;
                    SaganRouting->alert_time_trigger = 0;
                    SaganRouting->geoip2_isset = 0;
                    SaganRouting->blacklist_results = 0;
                    SaganRouting->zeekintel_results = 0;

#ifdef WITH_BLUEDOT

                    SaganRouting->bluedot_hash_flag = 0;
                    SaganRouting->bluedot_filename_flag = 0;
                    SaganRouting->bluedot_url_flag = 0;
                    SaganRouting->bluedot_ip_flag = 0;
                    SaganRouting->bluedot_ja3_flag = 0;

#endif

                    memset(lookup_cache, 0, sizeof(_Sagan_Lookup_Cache_Entry) * MAX_PARSE_IP);


                } /* If normal or dynamic rule */

            /* Clear data collected between signature passes.  Unlike other data,
             * "correlation" data isn't "static" (like IP addresses, normalization,
             * protocols, log data, etc).  We need to clear that out each pass
             * or a non-correlated signature will have "correlated" data that doesn't
             * make sense! */

#ifdef HAVE_LIBFASTJSON

            SaganProcSyslog_LOCAL->correlation_json[0] = '\0';
            SaganProcSyslog_LOCAL->json_normalize[0] = '\0';

            /* In case JSON mapping over wrote our original values,  we copy them back to their
               original states.  */

            if ( config->json_parse_data == true && JSON_LOCAL->json_count > 0 )
                {

                    if ( o_syslog_message_flag == true )
                        {
                            strlcpy( SaganProcSyslog_LOCAL->syslog_message, o_syslog_message, config->message_buffer_size);
                            o_syslog_message_flag = false;
                        }

                    if ( o_syslog_program_flag == true )
                        {
                            strlcpy( SaganProcSyslog_LOCAL->syslog_program, o_syslog_program, MAX_SYSLOG_PROGRAM);
                            o_syslog_program_flag = false;
                        }

                }

#endif

        } /* for(b=0; b < counters->rulecount; b++) */


#ifdef HAVE_LIBFASTJSON

    if ( config->eve_flag && config->eve_logs )
        {
            Log_JSON(SaganProcSyslog_LOCAL, tp);
        }

#endif

    free(lookup_cache);
    free(SaganRouting);
    free(syslog_append_orig_message);
    free(o_syslog_message);

#ifdef HAVE_LIBMAXMINDDB

    free(GeoIP_SRC);
    free(GeoIP_DEST);

#endif

    return;
}
