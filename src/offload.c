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

/* This handles "offload" rule option */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef WITH_OFFLOAD

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <curl/curl.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"
#include "rules.h"
#include "offload.h"

#include "parsers/parsers.h"

extern struct _Rule_Struct *rulestruct;
extern struct _SaganConfig *config;
extern struct _SaganDebug *debug;

bool Offload( uint_fast32_t rule_position, const char *syslog_host, const char *syslog_facility, const char *syslog_priority, const char *syslog_level, const char *syslog_tag, const char *syslog_date, const char *syslog_time, const char *syslog_program, const char *syslog_message )
{

    CURL *curl;
    CURLcode res;

    char *response=NULL;
    struct curl_slist *headers = NULL;

    char buf[ MAX_SYSLOG_HOST + MAX_SYSLOG_FACILITY + MAX_SYSLOG_PRIORITY + MAX_SYSLOG_LEVEL + MAX_SYSLOG_TAG + MAX_SYSLOG_DATE + MAX_SYSLOG_TIME + MAX_SYSLOG_PROGRAM + MAX_SYSLOGMSG + 1 ] = { 0 };


    /* Build POST data to send */

    snprintf(buf, sizeof(buf), "%s|%s|%s|%s|%s|%s|%s|%s|%s", syslog_host, syslog_facility, syslog_priority, syslog_level, syslog_tag, syslog_date, syslog_time, syslog_program, syslog_message);

    if ( debug->debugoffload == true )
        {
            Sagan_Log(WARN, "Sending data to %s for signature id %" PRIuFAST64 " - Thread ID: %ld", rulestruct[rule_position].offload_location, rulestruct[rule_position].s_sid, pthread_self());
            Sagan_Log(WARN, "Data: %s", buf);
        }


    curl = curl_easy_init();

    if (curl)
        {


            if ( debug->debugoffload == true )
                {
                    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
                }

            curl_easy_setopt(curl, CURLOPT_NOBODY, 0);   /* Don't use HEAD! */
            curl_easy_setopt(curl, CURLOPT_URL, rulestruct[rule_position].offload_location );
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback_func);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
            curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);    /* Will send SIGALRM if not set */
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, buf);

            headers = NULL;
            headers = curl_slist_append (headers, USER_AGENT);

            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers );

            res = curl_easy_perform(curl);

            /* Verify that we actually made a clean connection to the backend */

            if ( res != CURLE_OK )
                {

                    Sagan_Log( NORMAL, "Offload failed: %s", curl_easy_strerror(res) );

		    curl_easy_cleanup(curl);

                    return(false);

                }

            /* Glad we made a connection,  did we get a valid response? */

            if ( response == NULL )
                {

                    Sagan_Log(WARN, "[%s, line %d] Offload program returned a empty \"response\".", __FILE__, __LINE__);

                    if ( debug->debugoffload == true )
                        {
                            Sagan_Log(DEBUG, "Empty response for Thread ID: %lu", pthread_self() );
                        }

		    curl_easy_cleanup(curl);

                    return(false);
                }

        }

    Remove_Return(response);

    if ( Sagan_stristr( response, "true", false) )
        {

            if ( debug->debugoffload == true )
                {
                    Sagan_Log(DEBUG, "%s returned \"true\" - Thread ID: %lu", rulestruct[rule_position].offload_location, pthread_self() );
                }

	    curl_easy_cleanup(curl);

            return( true );
        }


    if ( debug->debugoffload == true )
        {
            Sagan_Log(DEBUG, "%s returned \"false\" - Thread ID: %lu", rulestruct[rule_position].offload_location, pthread_self() );
        }

    curl_easy_cleanup(curl);

    return false;

}

/****************************************************************************
 * write_callback_func() - Callback for data received via libcurl
 ****************************************************************************/

size_t static write_callback_func(void *buffer, size_t size, size_t nmemb, void *userp)
{
    char **response_ptr =  (char**)userp;
    *response_ptr = strndup(buffer, (size_t)(size *nmemb));     /* Return the string */

    return size * nmemb;
}


#endif
