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

/* Read data from Sagan's traditional pipe delimited format */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"
#include "version.h"
#include "input-pipe.h"

extern struct _SaganCounters *counters;
extern struct _SaganDebug *debug;
extern struct _SaganConfig *config;
extern struct _SaganDNSCache *dnscache;

void SyslogInput_Pipe( char *syslog_string, struct _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL )
{

    bool dns_flag;

    char src_dns_lookup[20];

    uint_fast64_t i;
    int_fast8_t rc;

    char *ptr = NULL;

    ptr = syslog_string != NULL ? strsep(&syslog_string, "|") : NULL;

    if ( ptr != NULL )
        {

            /* If we're using DNS (and we shouldn't be!),  we start DNS checks and lookups
             * here.  We cache both good and bad lookups to not over load our DNS server(s).
             * The only way DNS cache can be cleared is to restart Sagan */

            if ( config->syslog_src_lookup == false )
                {

                    /* Check, make sure we have a valid IP for the syslog_host */

                    if ( Is_IP(ptr, IPv4) || Is_IP(ptr, IPv6) )
                        {
                            strlcpy(SaganProcSyslog_LOCAL->syslog_host, ptr, MAX_SYSLOG_HOST);
                        }
                    else
                        {

                            __atomic_add_fetch(&counters->malformed_host, 1, __ATOMIC_SEQ_CST);

                            strlcpy(SaganProcSyslog_LOCAL->syslog_host, config->sagan_host, MAX_SYSLOG_HOST);
                            if ( debug->debugmalformed )
                                {
                                    Sagan_Log(DEBUG, "Sagan received a malformed 'host': '%s' (replaced with %s)", SaganProcSyslog_LOCAL->syslog_host, config->sagan_host);
                                    Sagan_Log(DEBUG, "Raw malformed log: \"%s\"", syslog_string);
                                }
                        }

                }
            else
                {

                    /* Do a DNS lookup for the correct hostname */

                    dns_flag = false;

                    for(i=0; i <= counters->dns_cache_count ; i++)                      /* Check cache first */
                        {
                            if (!strcmp( dnscache[i].hostname, ptr))
                                {
                                    strlcpy(SaganProcSyslog_LOCAL->syslog_host, dnscache[i].src_ip, MAX_SYSLOG_HOST);
                                    dns_flag = true;
                                }
                        }


                    /* If entry was not found in cache,  look it up */

                    if ( dns_flag == false )
                        {

                            /* Do a DNS lookup */

                            rc = DNS_Lookup(ptr, src_dns_lookup, sizeof(src_dns_lookup));

                            /* Invalid lookups get the config->sagan_host value */

                            if ( rc == -1 )
                                {

                                    strlcpy(src_dns_lookup, config->sagan_host, sizeof(src_dns_lookup));
                                    counters->dns_miss_count++;

                                }

                            /* Add entry to DNS Cache */

                            dnscache = (_SaganDNSCache *) realloc(dnscache, (counters->dns_cache_count+1) * sizeof(_SaganDNSCache));

                            if ( dnscache == NULL )
                                {

                                    Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for dnscache. Abort!", __FILE__, __LINE__);

                                }

                            //memset(&dnscache[counters->dns_cache_count], 0, sizeof(_SaganDNSCache));

                            strlcpy(dnscache[counters->dns_cache_count].hostname, ptr, sizeof(dnscache[counters->dns_cache_count].hostname));
                            strlcpy(dnscache[counters->dns_cache_count].src_ip, src_dns_lookup, sizeof(dnscache[counters->dns_cache_count].src_ip));
                            counters->dns_cache_count++;
                            strlcpy(SaganProcSyslog_LOCAL->syslog_host, src_dns_lookup, sizeof(SaganProcSyslog_LOCAL->syslog_host));


                        } /* End of dns_flag == false */

                }  /* End of config->syslog_src_lookup == false */

        }
    else		/* ptr != NULL */
        {

            /* ptr was NULL,  throw error */

            __atomic_add_fetch(&counters->malformed_host, 1, __ATOMIC_SEQ_CST);

            strlcpy(SaganProcSyslog_LOCAL->syslog_host, config->sagan_host, MAX_SYSLOG_HOST);

            if ( debug->debugmalformed )
                {
                    Sagan_Log(DEBUG, "Sagan received a malformed NULL 'host' (replaced with %s)", config->sagan_host);
                    Sagan_Log(DEBUG, "Raw malformed log: \"%s\"", syslog_string);
                }
        }


    /* We now check the rest of the values */

    ptr = syslog_string != NULL ? strsep(&syslog_string, "|") : NULL;

    if ( ptr == NULL )
        {

            strlcpy(SaganProcSyslog_LOCAL->syslog_facility, "SAGAN: FACILITY ERROR", MAX_SYSLOG_FACILITY);

            __atomic_add_fetch(&counters->malformed_facility, 1, __ATOMIC_SEQ_CST);

            if ( debug->debugmalformed )
                {
                    Sagan_Log(DEBUG, "Sagan received a malformed 'facility' from %s.", SaganProcSyslog_LOCAL->syslog_host);
                    Sagan_Log(DEBUG, "Raw malformed log: \"%s\"", syslog_string);
                }
        }
    else
        {
            strlcpy(SaganProcSyslog_LOCAL->syslog_facility, ptr, MAX_SYSLOG_FACILITY);
        }

    ptr = syslog_string != NULL ? strsep(&syslog_string, "|") : NULL;

    if ( ptr == NULL )
        {

            strlcpy(SaganProcSyslog_LOCAL->syslog_priority, "SAGAN: PRIORITY ERROR", MAX_SYSLOG_PRIORITY);

            __atomic_add_fetch(&counters->malformed_priority, 1, __ATOMIC_SEQ_CST);

            if ( debug->debugmalformed )
                {
                    Sagan_Log(DEBUG, "Sagan received a malformed 'priority' from %s.", SaganProcSyslog_LOCAL->syslog_host);
                    Sagan_Log(DEBUG, "Raw malformed log: \"%s\"", syslog_string);
                }
        }
    else
        {

            strlcpy(SaganProcSyslog_LOCAL->syslog_priority, ptr, MAX_SYSLOG_PRIORITY);

        }

    ptr = syslog_string != NULL ? strsep(&syslog_string, "|") : NULL;

    if ( ptr == NULL )
        {

            strlcpy(SaganProcSyslog_LOCAL->syslog_level, "SAGAN: LEVEL ERROR", MAX_SYSLOG_LEVEL);

            __atomic_add_fetch(&counters->malformed_level, 1, __ATOMIC_SEQ_CST);

            if ( debug->debugmalformed )
                {
                    Sagan_Log(DEBUG, "Sagan received a malformed 'level' from %s.", SaganProcSyslog_LOCAL->syslog_host);
                    Sagan_Log(DEBUG, "Raw malformed log: \"%s\"", syslog_string);
                }
        }
    else
        {

            strlcpy(SaganProcSyslog_LOCAL->syslog_level, ptr, MAX_SYSLOG_LEVEL);

        }

    ptr = syslog_string != NULL ? strsep(&syslog_string, "|") : NULL;

    if ( ptr == NULL )
        {

            strlcpy(SaganProcSyslog_LOCAL->syslog_tag, "SAGAN: TAG ERROR", MAX_SYSLOG_LEVEL);

            __atomic_add_fetch(&counters->malformed_tag, 1, __ATOMIC_SEQ_CST);

            if ( debug->debugmalformed )
                {
                    Sagan_Log(DEBUG, "Sagan received a malformed 'tag' from %s.", SaganProcSyslog_LOCAL->syslog_host);
                    Sagan_Log(DEBUG, "Raw malformed log: \"%s\"", syslog_string);
                }
        }
    else
        {
            strlcpy(SaganProcSyslog_LOCAL->syslog_tag, ptr, MAX_SYSLOG_LEVEL);
        }

    ptr = syslog_string != NULL ? strsep(&syslog_string, "|") : NULL;

    if ( ptr == NULL )
        {

            strlcpy(SaganProcSyslog_LOCAL->syslog_date, "SAGAN: DATE ERROR", MAX_SYSLOG_DATE);

            __atomic_add_fetch(&counters->malformed_date, 1, __ATOMIC_SEQ_CST);

            if ( debug->debugmalformed )
                {
                    Sagan_Log(DEBUG, "Sagan received a malformed 'date' from %s.", SaganProcSyslog_LOCAL->syslog_host);
                    Sagan_Log(DEBUG, "Raw malformed log: \"%s\"", syslog_string);
                }
        }
    else
        {

            strlcpy(SaganProcSyslog_LOCAL->syslog_date, ptr, MAX_SYSLOG_DATE);
        }

    ptr = syslog_string != NULL ? strsep(&syslog_string, "|") : NULL;

    if ( ptr == NULL )
        {

            strlcpy( SaganProcSyslog_LOCAL->syslog_time, "SAGAN: TIME ERROR", MAX_SYSLOG_TIME );

            __atomic_add_fetch(&counters->malformed_time, 1, __ATOMIC_SEQ_CST);

            if ( debug->debugmalformed )
                {
                    Sagan_Log(DEBUG, "Sagan received a malformed 'time' from %s.", SaganProcSyslog_LOCAL->syslog_host);
                    Sagan_Log(DEBUG, "Raw malformed log: \"%s\"", syslog_string);
                }
        }
    else
        {

            strlcpy(SaganProcSyslog_LOCAL->syslog_time, ptr, MAX_SYSLOG_TIME );
        }

    ptr = syslog_string != NULL ? strsep(&syslog_string, "|") : NULL;

    if ( ptr == NULL )
        {

            strlcpy( SaganProcSyslog_LOCAL->syslog_program, "SAGAN: PROGRAM ERROR", MAX_SYSLOG_PROGRAM );

            __atomic_add_fetch(&counters->malformed_program, 1, __ATOMIC_SEQ_CST);

            if ( debug->debugmalformed )
                {
                    Sagan_Log(DEBUG, "Sagan received a malformed 'program' from %s.", SaganProcSyslog_LOCAL->syslog_host);
                    Sagan_Log(DEBUG, "Raw malformed log: \"%s\"", syslog_string);

                }
        }
    else
        {

            strlcpy( SaganProcSyslog_LOCAL->syslog_program, ptr, MAX_SYSLOG_PROGRAM );

        }

    ptr = syslog_string != NULL ? strsep(&syslog_string, "") : NULL; /* In case the message has | in it,  we delimit on "" */

    if ( ptr == NULL )
        {

            strlcpy( SaganProcSyslog_LOCAL->syslog_message, "SAGAN: MESSAGE ERROR", config->message_buffer_size );

            __atomic_add_fetch(&counters->malformed_message, 1, __ATOMIC_SEQ_CST);

            if ( debug->debugmalformed )
                {
                    Sagan_Log(DEBUG, "Sagan received a malformed 'message' from %s.", SaganProcSyslog_LOCAL->syslog_host);
                    Sagan_Log(DEBUG, "Raw malformed log: \"%s\"", syslog_string);
                }

            /* If the message is lost,  all is lost.  Typically,  you don't lose part of the message,
             * it's more likely to lose all  - Champ Clark III 11/17/2011 */

            __atomic_add_fetch(&counters->sagan_log_drop, 1, __ATOMIC_SEQ_CST);


        }
    else
        {

            strlcpy(SaganProcSyslog_LOCAL->syslog_message, ptr, config->message_buffer_size);

        }

    /* Strip any \n or \r from the syslog_message */

    if ( strcspn ( SaganProcSyslog_LOCAL->syslog_message, "\n" ) < strlen( SaganProcSyslog_LOCAL->syslog_message ) )
        {
            SaganProcSyslog_LOCAL->syslog_message[strcspn (  SaganProcSyslog_LOCAL->syslog_message, "\n" )] = '\0';
        }

}

