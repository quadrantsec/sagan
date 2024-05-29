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

/* liblognormalize.c
 *
 * These functions deal with liblognorm / data normalization.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBLOGNORM

#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <liblognorm.h>
#include <json.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "liblognormalize.h"
#include "sagan-config.h"

extern struct _SaganConfig *config;
extern struct _SaganDebug *debug;

/************************************************************************
 * liblognorm GLOBALS
 ************************************************************************/

struct stat liblognorm_fileinfo;
struct liblognorm_toload_struct *liblognormtoloadstruct;
int liblognorm_count;

static ln_ctx ctx;

extern struct _SaganCounters *counters;

/************************************************************************
 * Liblognorm_Close
 *
 * Used to shutdown liblognorm
 ************************************************************************/

void Liblognorm_Close( void )
{
    (void)ln_exitCtx(ctx);			/* Seems to cause faults */
}

/************************************************************************
 * Liblognorm_Load
 *
 * Load in the normalization files into memory
 ************************************************************************/

void Liblognorm_Load(const char *infile)
{

    if((ctx = ln_initCtx()) == NULL)
        {
            Sagan_Log(ERROR, "[%s, line %d] Cannot initialize liblognorm context.", __FILE__, __LINE__);
        }

    Sagan_Log(NORMAL, "Loading %s for normalization.", infile);

    /* Remember - On reload,  file access will be by the "sagan" user! */

    if (stat(infile, &liblognorm_fileinfo))
        {
            Sagan_Log(ERROR, "[%s, line %d] Error accessing '%s'. Abort.", __FILE__, __LINE__, infile);
        }

    ln_loadSamples(ctx, infile);

}

/***********************************************************************
 * Normalize_Liblognorm
 *
 * Locates interesting log data via Rainer's liblognorm library
 ***********************************************************************/

void Normalize_Liblognorm( struct _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL )
{

    int rc_normalize = 0;
    const char *tmp = NULL;

    struct json_object *json_norm = NULL;
    struct json_object *string_obj = NULL;

    rc_normalize = ln_normalize(ctx, SaganProcSyslog_LOCAL->syslog_message, strlen(SaganProcSyslog_LOCAL->syslog_message), &json_norm);
    strlcpy(SaganProcSyslog_LOCAL->json_normalize, json_object_to_json_string_ext(json_norm, FJSON_TO_STRING_PLAIN), config->message_buffer_size );

    if ( debug->debugnormalize )
        {
            Sagan_Log(DEBUG, "[%s, line %d] Normalize: %s",__FILE__, __LINE__, SaganProcSyslog_LOCAL->syslog_message);
            Sagan_Log(DEBUG, "[%s, line %d] %s", __FILE__, __LINE__, SaganProcSyslog_LOCAL->json_normalize);
        }

    /* See liblognorm.h for error codes. -1000 == LN_WRONGPARSER, etc */

    if ( json_norm == NULL || rc_normalize != 0 )
        {
            json_object_put(json_norm);
            return;
        }

    /* Get source address information */

    json_object_object_get_ex(json_norm, "src-ip", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL)
        {

            if ( !Is_IP(tmp, IPv4) && !Is_IP(tmp, IPv6) )
                {

                    SaganProcSyslog_LOCAL->src_ip[0] = '\0';
                    SaganProcSyslog_LOCAL->ip_src_is_valid = false;
                    json_object_put(json_norm);
                    return;
                }

            strlcpy(SaganProcSyslog_LOCAL->src_ip, tmp, MAXIP);

            IP2Bit(SaganProcSyslog_LOCAL->src_ip, SaganProcSyslog_LOCAL->ip_src_bits);

            if ( is_notlocalhost( SaganProcSyslog_LOCAL->ip_src_bits ) )
                {
                    SaganProcSyslog_LOCAL->src_ip[0] = '\0';
                    SaganProcSyslog_LOCAL->ip_src_is_valid = false;
                }
            else
                {
                    SaganProcSyslog_LOCAL->ip_src_is_valid = true;
                }

        }


    json_object_object_get_ex(json_norm, "dst-ip", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {

            if ( !Is_IP(tmp, IPv4) && !Is_IP(tmp, IPv6) )
                {
                    SaganProcSyslog_LOCAL->ip_dst_is_valid = false;
                    SaganProcSyslog_LOCAL->dst_ip[0] = '\0';
                    json_object_put(json_norm);
                    return;
                }

            strlcpy(SaganProcSyslog_LOCAL->dst_ip, tmp, MAXIP);
            IP2Bit(SaganProcSyslog_LOCAL->dst_ip, SaganProcSyslog_LOCAL->ip_dst_bits);

            if ( is_notlocalhost( SaganProcSyslog_LOCAL->ip_dst_bits ) )
                {
                    SaganProcSyslog_LOCAL->dst_ip[0] = '\0';
                    SaganProcSyslog_LOCAL->ip_dst_is_valid = false;
                }
            else
                {
                    SaganProcSyslog_LOCAL->ip_dst_is_valid = true;
                }

        }

    /* Get username information - Will be used in the future */

    json_object_object_get_ex(json_norm, "username", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            strlcpy(SaganProcSyslog_LOCAL->username, tmp, MAX_USERNAME_SIZE);
        }

    /* Do DNS lookup for source hostname */

    json_object_object_get_ex(json_norm, "src-host", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            strlcpy(SaganProcSyslog_LOCAL->src_host, tmp, MAXHOST);
        }

    json_object_object_get_ex(json_norm, "dst-host", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            strlcpy(SaganProcSyslog_LOCAL->dst_host, tmp, MAXHOST);
        }

    json_object_object_get_ex(json_norm, "proto", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {

            if ( !strcasecmp(tmp, "tcp" ) )
                {
                    SaganProcSyslog_LOCAL->proto = 6;
                }

            else if ( !strcasecmp(tmp, "udp" ) )
                {
                    SaganProcSyslog_LOCAL->proto = 17;
                }

            else if ( !strcasecmp(tmp, "icmp" ) )
                {
                    SaganProcSyslog_LOCAL->proto = 1;
                }

        }


    /*
        json_object_object_get_ex(json_norm, "src-host", &string_obj);
        tmp = json_object_get_string(string_obj);

        if ( tmp != NULL )
            {
                strlcpy(NormalizeLiblognorm->src_host, tmp, MAXHOST);

                if ( NormalizeLiblognorm->ip_src[0] == '0' && config->syslog_src_lookup)
                    {

                        if (!DNS_Lookup(NormalizeLiblognorm->src_host, tmp_host, sizeof(tmp_host)))
                            {
                                strlcpy(NormalizeLiblognorm->ip_src, tmp_host, MAXIP);
                            }

                    }

            }

        json_object_object_get_ex(json_norm, "dst-host", &string_obj);
        tmp = json_object_get_string(string_obj);

        if ( tmp != NULL )
            {
                strlcpy(NormalizeLiblognorm->dst_host, tmp, MAXHOST);
                NormalizeLiblognorm->status = true;

                if ( NormalizeLiblognorm->ip_dst[0] == '0' && config->syslog_src_lookup)
                    {

                        if (!DNS_Lookup(NormalizeLiblognorm->dst_host, tmp_host, sizeof(tmp_host)))
                            {
                                strlcpy(NormalizeLiblognorm->ip_dst, tmp_host, MAXIP);
                            }
                    }
            }
    	*/

    /* Get port information */

    json_object_object_get_ex(json_norm, "src-port", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            SaganProcSyslog_LOCAL->src_port = atoi(tmp);
            SaganProcSyslog_LOCAL->port_src_is_valid = true;
        }

    json_object_object_get_ex(json_norm, "dst-port", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            SaganProcSyslog_LOCAL->dst_port = atoi(tmp);
            SaganProcSyslog_LOCAL->port_dst_is_valid = true;
        }


    json_object_object_get_ex(json_norm, "hash-md5", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            strlcpy(SaganProcSyslog_LOCAL->md5, tmp, MD5_HASH_SIZE+1);
        }


    json_object_object_get_ex(json_norm, "hash-sha1", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            strlcpy(SaganProcSyslog_LOCAL->sha1, tmp, SHA1_HASH_SIZE+1);
        }

    json_object_object_get_ex(json_norm, "hash-sha256", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            strlcpy(SaganProcSyslog_LOCAL->sha256, tmp, SHA256_HASH_SIZE+1);
        }

    json_object_object_get_ex(json_norm, "http_uri", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            strlcpy(SaganProcSyslog_LOCAL->url, tmp, MAX_URL_SIZE);
        }

    json_object_object_get_ex(json_norm, "http_hostname", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            strlcpy(SaganProcSyslog_LOCAL->hostname, tmp, MAX_HOSTNAME_SIZE);
        }

    json_object_object_get_ex(json_norm, "filename", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            strlcpy(SaganProcSyslog_LOCAL->filename, tmp, MAX_FILENAME_SIZE);
        }

    json_object_object_get_ex(json_norm, "ja3", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            strlcpy(SaganProcSyslog_LOCAL->ja3, tmp, MD5_HASH_SIZE+1);
        }

    json_object_object_get_ex(json_norm, "event_id", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            strlcpy(SaganProcSyslog_LOCAL->event_id, tmp, MAX_EVENT_ID_SIZE);
        }

    /*
    if ( debug->debugnormalize )
        {

            Sagan_Log(DEBUG, "---------------------------------------------------");
            Sagan_Log(DEBUG, "Log message to normalize: %s", SaganProcSyslog_LOCAL->syslog_message);
            Sagan_Log(DEBUG, "Parsed: %s", SaganProcSyslog_LOCAL->json_normalize);
            Sagan_Log(DEBUG, "Source IP: %s", SaganProcSyslog_LOCAL->src_ip);
            Sagan_Log(DEBUG, "Destination IP: %s", SaganProcSyslog_LOCAL->dst_ip);
            Sagan_Log(DEBUG, "Source Port: %d", SaganProcSyslog_LOCAL->src_port);
            Sagan_Log(DEBUG, "Destination Port: %d", SaganProcSyslog_LOCAL->dst_port);
            Sagan_Log(DEBUG, "Source Host: %s", SaganProcSyslog_LOCAL->src_host);
            Sagan_Log(DEBUG, "Destination Host: %s", SaganProcSyslog_LOCAL->dst_host);
            Sagan_Log(DEBUG, "Username: %s", SaganProcSyslog_LOCAL->username);
            Sagan_Log(DEBUG, "MD5 Hash: %s", SaganProcSyslog_LOCAL->md5);
            Sagan_Log(DEBUG, "SHA1 Hash: %s", SaganProcSyslog_LOCAL->sha1);
            Sagan_Log(DEBUG, "SHA265 Hash: %s", SaganProcSyslog_LOCAL->sha256);
            Sagan_Log(DEBUG, "HTTP URI: %s", SaganProcSyslog_LOCAL->url);
            Sagan_Log(DEBUG, "HTTP HOSTNAME: %s", SaganProcSyslog_LOCAL->hostname);
            Sagan_Log(DEBUG, "Filename: %s", SaganProcSyslog_LOCAL->filename);
            Sagan_Log(DEBUG, "JA3: %s",  SaganProcSyslog_LOCAL->ja3);
            Sagan_Log(DEBUG, "Event ID: %s",  SaganProcSyslog_LOCAL->event_id);

            Sagan_Log(DEBUG, "");
        }
    */

    json_object_put(json_norm);
}

void IPv4_as_6( char *ip )
{


}

#endif
