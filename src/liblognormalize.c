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

void Normalize_Liblognorm(const char *syslog_msg, struct _NormalizeLiblognorm *NormalizeLiblognorm)
{

    char buf[MAX_SYSLOGMSG] = { 0 };
    char tmp_host[254] = { 0 };

    int rc_normalize = 0;
    const char *tmp = NULL;

    struct json_object *json = NULL;
    struct json_object *string_obj = NULL;

    memset(NormalizeLiblognorm, 0, sizeof(_NormalizeLiblognorm));

//    NormalizeLiblognorm->status = false;

    NormalizeLiblognorm->ip_src[0] = '0';
    //NormalizeLiblognorm->ip_src[1] = '\0';
    NormalizeLiblognorm->ip_dst[0] = '0';
    //NormalizeLiblognorm->ip_dst[1] = '\0';

    /*
    NormalizeLiblognorm->username[0] = '\0';
    NormalizeLiblognorm->src_host[0] = '\0';
    NormalizeLiblognorm->dst_host[0] = '\0';

    NormalizeLiblognorm->hash_sha1[0] = '\0';
    NormalizeLiblognorm->hash_sha256[0] = '\0';
    NormalizeLiblognorm->hash_md5[0] = '\0';

    NormalizeLiblognorm->http_uri[0] = '\0';
    NormalizeLiblognorm->http_hostname[0] = '\0';

    NormalizeLiblognorm->ja3[0] = '\0';
    NormalizeLiblognorm->event_id[0] = '\0';

    NormalizeLiblognorm->src_port = 0;
    NormalizeLiblognorm->dst_port = 0;

    NormalizeLiblognorm->json_normalize[0] = '\0';
    */

//    snprintf(buf, sizeof(buf),"%s", syslog_msg);
    strlcpy(buf, syslog_msg, MAX_SYSLOGMSG);

    /* int ln_normalize(ln_ctx ctx, const char *str, size_t strLen, struct json_object **json_p); */

    rc_normalize = ln_normalize(ctx, buf, strlen(buf), &json);
//    rc_normalize = ln_normalize(ctx, syslog_msg, strlen(syslog_msg), &json);  

    if (json == NULL)
        {
            json_object_put(json);
            json_object_put(string_obj);
            return;
        }

    /* Get source address information */

    json_object_object_get_ex(json, "src-ip", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL)
        {
//            snprintf(NormalizeLiblognorm->ip_src, sizeof(NormalizeLiblognorm->ip_src), "%s", tmp);
	      strlcpy(NormalizeLiblognorm->ip_src, tmp, MAXIP);
	      NormalizeLiblognorm->status = true;
        }

    json_object_object_get_ex(json, "dst-ip", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
     //       snprintf(NormalizeLiblognorm->ip_dst, sizeof(NormalizeLiblognorm->ip_dst), "%s", tmp);
	    strlcpy(NormalizeLiblognorm->ip_dst, tmp, MAXIP);
            NormalizeLiblognorm->status = true;
        }

    /* Get username information - Will be used in the future */

    json_object_object_get_ex(json, "username", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
//            snprintf(NormalizeLiblognorm->username, sizeof(NormalizeLiblognorm->username), "%s", tmp);
	    strlcpy(NormalizeLiblognorm->username, tmp, MAX_USERNAME_SIZE);
            NormalizeLiblognorm->status = true;
        }


    /* Do DNS lookup for source hostname */

    json_object_object_get_ex(json, "src-host", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            strlcpy(NormalizeLiblognorm->src_host, tmp, MAXHOST);
            NormalizeLiblognorm->status = true;

            if ( NormalizeLiblognorm->ip_src[0] == '0' && config->syslog_src_lookup)
                {

                    if (!DNS_Lookup(NormalizeLiblognorm->src_host, tmp_host, sizeof(tmp_host)))
                        {
                            strlcpy(NormalizeLiblognorm->ip_src, tmp_host, MAXIP);
                        }

                }

        }

    json_object_object_get_ex(json, "dst-host", &string_obj);
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

    /* Get port information */

    json_object_object_get_ex(json, "src-port", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            NormalizeLiblognorm->src_port = atoi(tmp);
            NormalizeLiblognorm->status = true;
        }

    json_object_object_get_ex(json, "dst-port", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            NormalizeLiblognorm->dst_port = atoi(tmp);
            NormalizeLiblognorm->status = true;
        }


    json_object_object_get_ex(json, "hash-md5", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            strlcpy(NormalizeLiblognorm->hash_md5, tmp, MD5_HASH_SIZE+1);
            NormalizeLiblognorm->status = true;
        }


    json_object_object_get_ex(json, "hash-sha1", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            strlcpy(NormalizeLiblognorm->hash_sha1, tmp, SHA1_HASH_SIZE+1);
            NormalizeLiblognorm->status = true;
        }

    json_object_object_get_ex(json, "hash-sha256", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            strlcpy(NormalizeLiblognorm->hash_sha256, tmp, SHA256_HASH_SIZE+1);
            NormalizeLiblognorm->status = true;
        }


    json_object_object_get_ex(json, "http_uri", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            strlcpy(NormalizeLiblognorm->http_uri, tmp, MAX_URL_SIZE);
            NormalizeLiblognorm->status = true;
        }

    json_object_object_get_ex(json, "http_hostname", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            strlcpy(NormalizeLiblognorm->http_hostname, tmp, MAX_HOSTNAME_SIZE);
            NormalizeLiblognorm->status = true;
        }

    json_object_object_get_ex(json, "filename", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            strlcpy(NormalizeLiblognorm->filename, tmp, MAX_FILENAME_SIZE);
            NormalizeLiblognorm->status = true;
        }

    json_object_object_get_ex(json, "ja3", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            strlcpy(NormalizeLiblognorm->ja3, tmp, MD5_HASH_SIZE+1);
            NormalizeLiblognorm->status = true;
        }

    json_object_object_get_ex(json, "event_id", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            strlcpy(NormalizeLiblognorm->event_id, tmp, MAX_EVENT_ID_SIZE);
            NormalizeLiblognorm->status = true;
        }

    strlcpy(NormalizeLiblognorm->json_normalize, json_object_to_json_string_ext(json, FJSON_TO_STRING_PLAIN), sizeof(NormalizeLiblognorm->json_normalize) );

    if ( debug->debugnormalize )
        {

            Sagan_Log(DEBUG, "Liblognorm DEBUG output: %d", rc_normalize);
            Sagan_Log(DEBUG, "---------------------------------------------------");
            Sagan_Log(DEBUG, "Status: %s", NormalizeLiblognorm->status == true ? "true":"false");
            Sagan_Log(DEBUG, "Log message to normalize: %s", buf);
            Sagan_Log(DEBUG, "Parsed: %s", NormalizeLiblognorm->json_normalize);
            Sagan_Log(DEBUG, "Source IP: %s", NormalizeLiblognorm->ip_src);
            Sagan_Log(DEBUG, "Destination IP: %s", NormalizeLiblognorm->ip_dst);
            Sagan_Log(DEBUG, "Source Port: %d", NormalizeLiblognorm->src_port);
            Sagan_Log(DEBUG, "Destination Port: %d", NormalizeLiblognorm->dst_port);
            Sagan_Log(DEBUG, "Source Host: %s", NormalizeLiblognorm->src_host);
            Sagan_Log(DEBUG, "Destination Host: %s", NormalizeLiblognorm->dst_host);
            Sagan_Log(DEBUG, "Username: %s", NormalizeLiblognorm->username);
            Sagan_Log(DEBUG, "MD5 Hash: %s", NormalizeLiblognorm->hash_md5);
            Sagan_Log(DEBUG, "SHA1 Hash: %s", NormalizeLiblognorm->hash_sha1);
            Sagan_Log(DEBUG, "SHA265 Hash: %s", NormalizeLiblognorm->hash_sha256);
            Sagan_Log(DEBUG, "HTTP URI: %s", NormalizeLiblognorm->http_uri);
            Sagan_Log(DEBUG, "HTTP HOSTNAME: %s", NormalizeLiblognorm->http_hostname);
            Sagan_Log(DEBUG, "Filename: %s", NormalizeLiblognorm->filename);
            Sagan_Log(DEBUG, "JA3: %s",  NormalizeLiblognorm->ja3);
            Sagan_Log(DEBUG, "Event ID: %s",  NormalizeLiblognorm->event_id);

            Sagan_Log(DEBUG, "");
        }


    json_object_put(json);
    json_object_put(string_obj);
}

#endif
