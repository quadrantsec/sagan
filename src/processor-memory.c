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

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>

#include "sagan-defs.h"
#include "sagan.h"

#include "processor-memory.h"

void Processor_Memory(  _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL )
{

    SaganProcSyslog_LOCAL->json_normalize = malloc( JSON_MAX_SIZE );

    if ( SaganProcSyslog_LOCAL->json_normalize == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __FILE__, __LINE__);
        }

    memset(SaganProcSyslog_LOCAL->json_normalize, 0, JSON_MAX_SIZE );

    SaganProcSyslog_LOCAL->json_original = malloc( JSON_MAX_SIZE );

    if ( SaganProcSyslog_LOCAL->json_original == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __FILE__, __LINE__);
        }

    memset(SaganProcSyslog_LOCAL->json_original, 0, JSON_MAX_SIZE );

    SaganProcSyslog_LOCAL->syslog_host = malloc( MAX_SYSLOG_HOST );

    if ( SaganProcSyslog_LOCAL->syslog_host == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __FILE__, __LINE__);
        }

    memset(SaganProcSyslog_LOCAL->syslog_host, 0, MAX_SYSLOG_HOST );

    SaganProcSyslog_LOCAL->syslog_facility = malloc( MAX_SYSLOG_FACILITY );

    if ( SaganProcSyslog_LOCAL->syslog_facility == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __FILE__, __LINE__);
        }

    memset(SaganProcSyslog_LOCAL->syslog_facility, 0, MAX_SYSLOG_FACILITY );

    SaganProcSyslog_LOCAL->syslog_priority = malloc( MAX_SYSLOG_PRIORITY );

    if ( SaganProcSyslog_LOCAL->syslog_priority == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __FILE__, __LINE__);
        }

    memset(SaganProcSyslog_LOCAL->syslog_priority, 0, MAX_SYSLOG_PRIORITY );

    SaganProcSyslog_LOCAL->syslog_level = malloc( MAX_SYSLOG_LEVEL );

    if ( SaganProcSyslog_LOCAL->syslog_level == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __FILE__, __LINE__);
        }

    memset(SaganProcSyslog_LOCAL->syslog_level, 0, MAX_SYSLOG_LEVEL );

    SaganProcSyslog_LOCAL->syslog_tag = malloc( MAX_SYSLOG_TAG );

    if ( SaganProcSyslog_LOCAL->syslog_tag == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __FILE__, __LINE__);
        }

    memset(SaganProcSyslog_LOCAL->syslog_tag, 0, MAX_SYSLOG_TAG );

    SaganProcSyslog_LOCAL->syslog_date = malloc( MAX_SYSLOG_DATE );

    if ( SaganProcSyslog_LOCAL->syslog_date == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __FILE__, __LINE__);
        }

    memset(SaganProcSyslog_LOCAL->syslog_date, 0, MAX_SYSLOG_DATE );

    SaganProcSyslog_LOCAL->syslog_time = malloc( MAX_SYSLOG_TIME );

    if ( SaganProcSyslog_LOCAL->syslog_time == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __FILE__, __LINE__);
        }

    memset(SaganProcSyslog_LOCAL->syslog_time, 0, MAX_SYSLOG_TIME );

    SaganProcSyslog_LOCAL->syslog_program = malloc( MAX_SYSLOG_PROGRAM );

    if ( SaganProcSyslog_LOCAL->syslog_program == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __FILE__, __LINE__);
        }

    memset(SaganProcSyslog_LOCAL->syslog_program, 0, MAX_SYSLOG_PROGRAM );

    SaganProcSyslog_LOCAL->syslog_message = malloc( MAX_SYSLOGMSG );

    if ( SaganProcSyslog_LOCAL->syslog_message == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __FILE__, __LINE__);
        }

    memset(SaganProcSyslog_LOCAL->syslog_message, 0, MAX_SYSLOGMSG );

    SaganProcSyslog_LOCAL->src_ip = malloc( MAXIP );

    if ( SaganProcSyslog_LOCAL->src_ip == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __FILE__, __LINE__);
        }

    memset(SaganProcSyslog_LOCAL->src_ip, 0, MAXIP );

    SaganProcSyslog_LOCAL->dst_ip = malloc( MAXIP );

    if ( SaganProcSyslog_LOCAL->dst_ip == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __FILE__, __LINE__);
        }

    memset(SaganProcSyslog_LOCAL->dst_ip, 0, MAXIP );

    SaganProcSyslog_LOCAL->src_host = malloc( MAXHOST );

    if ( SaganProcSyslog_LOCAL->src_host == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __FILE__, __LINE__);
        }

    memset(SaganProcSyslog_LOCAL->src_host, 0, MAXHOST );

    SaganProcSyslog_LOCAL->dst_host = malloc( MAXHOST );

    if ( SaganProcSyslog_LOCAL->dst_host == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __FILE__, __LINE__);
        }

    memset(SaganProcSyslog_LOCAL->dst_host, 0, MAXHOST );

    SaganProcSyslog_LOCAL->event_id = malloc( MAX_EVENTID );

    if ( SaganProcSyslog_LOCAL->event_id == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __FILE__, __LINE__);
        }

    memset(SaganProcSyslog_LOCAL->event_id, 0, MAX_EVENTID  );

    SaganProcSyslog_LOCAL->md5 = malloc( MD5_HASH_SIZE+1 );

    if ( SaganProcSyslog_LOCAL->md5 == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __FILE__, __LINE__);
        }

    memset(SaganProcSyslog_LOCAL->md5, 0, MD5_HASH_SIZE+1 );

    SaganProcSyslog_LOCAL->sha1 = malloc( SHA1_HASH_SIZE+1 );

    if ( SaganProcSyslog_LOCAL->sha1 == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __FILE__, __LINE__);
        }

    memset(SaganProcSyslog_LOCAL->sha1, 0, SHA1_HASH_SIZE+1 );

    SaganProcSyslog_LOCAL->sha256 = malloc( SHA256_HASH_SIZE+1 );

    if ( SaganProcSyslog_LOCAL->sha256 == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __FILE__, __LINE__);
        }

    memset(SaganProcSyslog_LOCAL->sha256, 0, SHA256_HASH_SIZE+1 );

    SaganProcSyslog_LOCAL->filename = malloc( MAX_FILENAME_SIZE+1 );

    if ( SaganProcSyslog_LOCAL->filename == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __FILE__, __LINE__);
        }

    memset(SaganProcSyslog_LOCAL->filename, 0, MAX_FILENAME_SIZE+1 );

    SaganProcSyslog_LOCAL->hostname = malloc( MAX_HOSTNAME_SIZE+1 );

    if ( SaganProcSyslog_LOCAL->hostname == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __FILE__, __LINE__);
        }

    memset(SaganProcSyslog_LOCAL->hostname, 0, MAX_HOSTNAME_SIZE+1 );

    SaganProcSyslog_LOCAL->url = malloc( MAX_URL_SIZE+1 );

    if ( SaganProcSyslog_LOCAL->url == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __FILE__, __LINE__);
        }

    memset(SaganProcSyslog_LOCAL->url, 0, MAX_URL_SIZE+1 );

    SaganProcSyslog_LOCAL->ja3 = malloc( MD5_HASH_SIZE+1 );

    if ( SaganProcSyslog_LOCAL->ja3 == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __FILE__, __LINE__);
        }

    memset(SaganProcSyslog_LOCAL->ja3, 0, MD5_HASH_SIZE+1 );

    SaganProcSyslog_LOCAL->username = malloc( MAX_USERNAME_SIZE+1 );

    if ( SaganProcSyslog_LOCAL->username == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __FILE__, __LINE__);
        }

    memset(SaganProcSyslog_LOCAL->username, 0, MAX_USERNAME_SIZE+1 );

#ifdef HAVE_LIBFASTJSON

    SaganProcSyslog_LOCAL->correlation_json = malloc( MAX_SYSLOGMSG );

    if ( SaganProcSyslog_LOCAL->correlation_json == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __FILE__, __LINE__);
        }

    memset(SaganProcSyslog_LOCAL->correlation_json, 0, MAX_SYSLOGMSG );

#endif

}
