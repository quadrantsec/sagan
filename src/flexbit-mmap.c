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

/*
 * flexbit-mmap.c - Functions used for tracking events over multiple log
 * lines.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/mman.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "ipc.h"
#include "flexbit-mmap.h"
#include "rules.h"
#include "lockfile.h"
#include "sagan-config.h"
#include "util-base64.h"
#include "parsers/parsers.h"

extern struct _SaganCounters *counters;
extern struct _Rule_Struct *rulestruct;
extern struct _SaganDebug *debug;
extern struct _SaganConfig *config;

pthread_mutex_t Flexbit_Mutex=PTHREAD_MUTEX_INITIALIZER;

extern struct _Sagan_IPC_Counters *counters_ipc;
extern struct _Sagan_IPC_Flexbit *flexbit_ipc;

/*****************************************************************************
 * Flexbit_Condition - Used for testing "isset" & "isnotset".  Full
 * rule condition is tested here and returned.
 *****************************************************************************/

bool Flexbit_Condition_MMAP(uint_fast32_t rule_position, struct _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL )
{

    time_t t;
    struct tm *now;
    char  timet[20];

    int i;
    int a;

    int flexbit_total_match = 0;
    bool flexbit_match = 0;

    /* Flexbit do need a non-null username, otherwise a segmentation fault occurs */

//    char flexbit_username[MAX_USERNAME_SIZE] = {0};

    /*
    if ( username != NULL )
        {
            memcpy(flexbit_username, username, sizeof(flexbit_username));
        }
    */

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    Flexbit_Cleanup_MMAP();

    for (i = 0; i < rulestruct[rule_position].flexbit_count; i++)
        {

            /*******************
             *      ISSET      *
             *******************/

            if ( rulestruct[rule_position].flexbit_type[i] == 3 )
                {


                    if ( debug->debugflexbit )
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] Condition \"isset\" found in rule.", __FILE__, __LINE__);
                        }


                    for (a = 0; a < counters_ipc->flexbit_count; a++)
                        {

                            if ( !memcmp(rulestruct[rule_position].flexbit_name[i], flexbit_ipc[a].flexbit_name, sizeof(rulestruct[rule_position].flexbit_name[i])) &&
                                    flexbit_ipc[a].flexbit_state == true )
                                {

                                    /* direction: by_src - most common check */

                                    if ( rulestruct[rule_position].flexbit_direction[i] == 2 &&
                                            !memcmp(flexbit_ipc[a].ip_src, SaganProcSyslog_LOCAL->src_ip, sizeof(flexbit_ipc[a].ip_src)) )

                                        {

                                            if ( debug->debugflexbit )
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isset\" flexbit \"%s\" (direction: \"by_src\"). (%s -> any)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, flexbit_ipc[a].ip_src);
                                                }

                                            flexbit_total_match++;

                                        }

                                    /* direction: none */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 0 )

                                        {

                                            if ( debug->debugflexbit )
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isset\" flexbit \"%s\" (direction: \"none\"). (any -> any)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name);
                                                }

                                            flexbit_total_match++;

                                        }

                                    /* direction: both */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 1 &&
                                              !memcmp(flexbit_ipc[a].ip_src, SaganProcSyslog_LOCAL->src_ip, sizeof(flexbit_ipc[a].ip_src)) &&
                                              !memcmp(flexbit_ipc[a].ip_dst, SaganProcSyslog_LOCAL->dst_ip, sizeof(flexbit_ipc[a].ip_dst)) )

                                        {

                                            if ( debug->debugflexbit )
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isset\" flexbit \"%s\" (direction: \"both\"). (%s -> %s)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, SaganProcSyslog_LOCAL->src_ip, SaganProcSyslog_LOCAL->dst_ip);
                                                }

                                            flexbit_total_match++;

                                        }

                                    /* direction: by_dst */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 3 &&
                                              !memcmp(flexbit_ipc[a].ip_dst, SaganProcSyslog_LOCAL->dst_ip, sizeof(flexbit_ipc[a].ip_dst)) )

                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isset\" flexbit \"%s\" (direction: \"by_dst\"). (any -> %s)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, SaganProcSyslog_LOCAL->dst_ip);
                                                }

                                            flexbit_total_match++;

                                        }

                                    /* direction: reverse */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 4 &&
                                              !memcmp(flexbit_ipc[a].ip_src, SaganProcSyslog_LOCAL->dst_ip, sizeof(flexbit_ipc[a].ip_src)) &&
                                              !memcmp(flexbit_ipc[a].ip_dst, SaganProcSyslog_LOCAL->src_ip, sizeof(flexbit_ipc[a].ip_dst)) )

                                        {
                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isset\" flexbit \"%s\" (direction: \"reverse\"). (%s -> %s)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, SaganProcSyslog_LOCAL->dst_ip, SaganProcSyslog_LOCAL->src_ip);
                                                }

                                            flexbit_total_match++;

                                        }

                                    /* direction: src_xbitdst */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 5 &&
                                              !memcmp(flexbit_ipc[a].ip_dst, SaganProcSyslog_LOCAL->src_ip, sizeof(flexbit_ipc[a].ip_dst)) )

                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isset\" flexbit \"%s\" (direction: \"src_xbitdst\"). (%s -> any)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, SaganProcSyslog_LOCAL->src_ip);
                                                }

                                            flexbit_total_match++;

                                        }

                                    /* direction: dst_xbitsrc */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 6 &&
                                              !memcmp(flexbit_ipc[a].ip_src, SaganProcSyslog_LOCAL->dst_ip, sizeof(flexbit_ipc[a].ip_src)) )

                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isset\" flexbit \"%s\" (direction: \"dst_xbitsrc\"). (any -> %s)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, SaganProcSyslog_LOCAL->dst_ip);
                                                }

                                            flexbit_total_match++;

                                        }

                                    /* direction: both_p */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 7 &&
                                              !memcmp(flexbit_ipc[a].ip_src, SaganProcSyslog_LOCAL->src_ip, sizeof(flexbit_ipc[a].ip_src)) &&
                                              !memcmp(flexbit_ipc[a].ip_dst, SaganProcSyslog_LOCAL->dst_ip, sizeof(flexbit_ipc[a].ip_dst)) &&
                                              flexbit_ipc[a].src_port == SaganProcSyslog_LOCAL->src_port &&
                                              flexbit_ipc[a].dst_port == SaganProcSyslog_LOCAL->dst_port )

                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isset\" flexbit \"%s\" (direction: \"both_p\"). (%s -> %s)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, SaganProcSyslog_LOCAL->src_ip, SaganProcSyslog_LOCAL->dst_ip);
                                                }

                                            flexbit_total_match++;

                                        }

                                    /* direction: by_src_p */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 8 &&
                                              !memcmp(flexbit_ipc[a].ip_src, SaganProcSyslog_LOCAL->src_ip, sizeof(flexbit_ipc[a].ip_src)) &&
                                              flexbit_ipc[a].src_port == SaganProcSyslog_LOCAL->src_port )

                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isset\" flexbit \"%s\" (direction: \"by_src_p\"). (%s -> any)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, SaganProcSyslog_LOCAL->src_ip);
                                                }

                                            flexbit_total_match++;

                                        }

                                    /* direction: by_dst_p */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 9 &&
                                              !memcmp(flexbit_ipc[a].ip_dst, SaganProcSyslog_LOCAL->dst_ip, sizeof(flexbit_ipc[a].ip_dst))  &&
                                              flexbit_ipc[a].dst_port == SaganProcSyslog_LOCAL->dst_port )

                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isset\" flexbit \"%s\" (direction: \"by_dst_p\"). (any -> %s)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, SaganProcSyslog_LOCAL->dst_ip);
                                                }

                                            flexbit_total_match++;

                                        }

                                    /* direction: reverse_p */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 10 &&
                                              !memcmp(flexbit_ipc[a].ip_src, SaganProcSyslog_LOCAL->dst_ip, sizeof(flexbit_ipc[a].ip_src)) &&
                                              !memcmp(flexbit_ipc[a].ip_dst, SaganProcSyslog_LOCAL->src_ip, sizeof(flexbit_ipc[a].ip_dst)) &&
                                              flexbit_ipc[a].src_port == SaganProcSyslog_LOCAL->dst_port &&
                                              flexbit_ipc[a].dst_port == SaganProcSyslog_LOCAL->src_port )


                                        {
                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isset\" flexbit \"%s\" (direction: \"reverse_p\"). (%s -> %s)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, SaganProcSyslog_LOCAL->dst_ip, SaganProcSyslog_LOCAL->src_ip);
                                                }

                                            flexbit_total_match++;

                                        }

                                    /* direction: src_xbitdst_p */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 11 &&
                                              !memcmp(flexbit_ipc[a].ip_dst, SaganProcSyslog_LOCAL->src_ip, sizeof(flexbit_ipc[a].ip_dst)) &&
                                              flexbit_ipc[a].dst_port == SaganProcSyslog_LOCAL->src_port )

                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isset\" flexbit \"%s\" (direction: \"src_xbitdst_p\"). (%s -> any)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, SaganProcSyslog_LOCAL->src_ip);
                                                }

                                            flexbit_total_match++;

                                        }

                                    /* direction: dst_xbitsrc_p */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 12 &&
                                              !memcmp(flexbit_ipc[a].ip_src, SaganProcSyslog_LOCAL->dst_ip, sizeof(flexbit_ipc[a].ip_src)) &&
                                              flexbit_ipc[a].src_port == SaganProcSyslog_LOCAL->dst_port )

                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isset\" flexbit \"%s\" (direction: \"dst_xbitsrc_p\"). (any -> %s)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, SaganProcSyslog_LOCAL->dst_ip);
                                                }

                                            flexbit_total_match++;

                                        }
                                    /* direction: username */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 13 &&
                                              !memcmp(flexbit_ipc[a].username, SaganProcSyslog_LOCAL->username, sizeof(flexbit_ipc[a].username)))
                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isset\" flexbit \"%s\" (direction: \"username\"). (any -> %s)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, SaganProcSyslog_LOCAL->username);
                                                }

                                            flexbit_total_match++;

                                        }

                                } /* End of strcmp flexbit_name & flexbit_state = 1 */

                        } /* End of "for a" */

                } /* End "if" flexbit_type == 3 (ISSET) */

            /*******************
            *    ISNOTSET     *
            *******************/

            if ( rulestruct[rule_position].flexbit_type[i] == 4 )
                {


                    if ( debug->debugflexbit )
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] Condition \"isnotset\" found in rule.", __FILE__, __LINE__);
                        }

                    flexbit_match = false;

                    for (a = 0; a < counters_ipc->flexbit_count; a++)
                        {
                            if ( !memcmp(rulestruct[rule_position].flexbit_name[i], flexbit_ipc[a].flexbit_name, sizeof(rulestruct[rule_position].flexbit_name[i])) )
                                {

                                    /* direction: none */

                                    if ( rulestruct[rule_position].flexbit_direction[i] == 0 )
                                        {

                                            if ( flexbit_ipc[a].flexbit_state == true )
                                                {
                                                    if ( debug->debugflexbit )
                                                        {
                                                            Sagan_Log(DEBUG, "[%s, line %d] \"isnotset\" flexbit \"%s\" true (direction: \"none\"). (any -> any)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name);

                                                        }

                                                    flexbit_match = true;
                                                }
                                        }

                                    /* direction: both */

                                    if ( rulestruct[rule_position].flexbit_direction[i] == 1 )
                                        {

                                            if ( !memcmp(flexbit_ipc[a].ip_src, SaganProcSyslog_LOCAL->src_ip, sizeof(flexbit_ipc[a].ip_src)) &&
                                                    !memcmp(flexbit_ipc[a].ip_dst, SaganProcSyslog_LOCAL->dst_ip, sizeof(flexbit_ipc[a].ip_dst)) )
                                                {
                                                    if ( flexbit_ipc[a].flexbit_state == true )
                                                        {
                                                            if ( debug->debugflexbit )
                                                                {
                                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isnotset\" flexbit \"%s\" true (direction: \"by_src\"). (%s -> %s)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, SaganProcSyslog_LOCAL->src_ip, SaganProcSyslog_LOCAL->dst_ip);

                                                                }

                                                            flexbit_match = true;
                                                        }
                                                }
                                        }

                                    /* direction: by_src */

                                    if ( rulestruct[rule_position].flexbit_direction[i] == 2 )
                                        {

                                            if ( !memcmp(flexbit_ipc[a].ip_src, SaganProcSyslog_LOCAL->src_ip, sizeof(flexbit_ipc[a].ip_src)) )
                                                {
                                                    if ( flexbit_ipc[a].flexbit_state == true )
                                                        {
                                                            if ( debug->debugflexbit )
                                                                {
                                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isnotset\" flexbit \"%s\" true (direction: \"by_src\"). (%s -> any)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, SaganProcSyslog_LOCAL->src_ip);

                                                                }

                                                            flexbit_match = true;
                                                        }
                                                }
                                        }

                                    /* direction: by_dst */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 3 )
                                        {

                                            if ( !memcmp(flexbit_ipc[a].ip_dst, SaganProcSyslog_LOCAL->dst_ip, sizeof(flexbit_ipc[a].ip_dst)) )
                                                {
                                                    if ( flexbit_ipc[a].flexbit_state == true )
                                                        {
                                                            if ( debug->debugflexbit )
                                                                {
                                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isnotset\" flexbit \"%s\" true (direction: \"by_dst\"). (any -> %s)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, SaganProcSyslog_LOCAL->dst_ip);

                                                                }

                                                            flexbit_match = true;
                                                        }
                                                }
                                        }

                                    /* direction: reverse */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 4 )
                                        {

                                            if ( !memcmp(flexbit_ipc[a].ip_src, SaganProcSyslog_LOCAL->dst_ip, sizeof(flexbit_ipc[a].ip_src)) &&
                                                    !memcmp(flexbit_ipc[a].ip_dst, SaganProcSyslog_LOCAL->src_ip, sizeof(flexbit_ipc[a].ip_dst)) )
                                                {
                                                    if ( flexbit_ipc[a].flexbit_state == true )
                                                        {
                                                            if ( debug->debugflexbit )
                                                                {
                                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isnotset\" flexbit \"%s\" true (direction: \"reverse\"). (%s -> %s)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, SaganProcSyslog_LOCAL->dst_ip, SaganProcSyslog_LOCAL->src_ip);

                                                                }

                                                            flexbit_match = true;
                                                        }
                                                }
                                        }

                                    /* direciton: src_xbitdst */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 5 )
                                        {

                                            if ( !memcmp(flexbit_ipc[a].ip_dst, SaganProcSyslog_LOCAL->src_ip, sizeof(flexbit_ipc[a].ip_dst)) )
                                                {
                                                    if ( flexbit_ipc[a].flexbit_state == true )
                                                        {
                                                            if ( debug->debugflexbit )
                                                                {
                                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isnotset\" flexbit \"%s\" true (direction: \"src_xbitdst\"). (any -> %s)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, SaganProcSyslog_LOCAL->dst_ip);

                                                                }

                                                            flexbit_match = true;
                                                        }
                                                }
                                        }

                                    /* direction: dst_xbitsrc */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 6 )
                                        {

                                            if ( !memcmp(flexbit_ipc[a].ip_src, SaganProcSyslog_LOCAL->dst_ip, sizeof(flexbit_ipc[a].ip_src)) )
                                                {
                                                    if ( flexbit_ipc[a].flexbit_state == true )
                                                        {
                                                            if ( debug->debugflexbit )
                                                                {
                                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isnotset\" flexbit \"%s\" true (direction: \"src_xbitdst\"). (%s -> any)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, SaganProcSyslog_LOCAL->dst_ip);

                                                                }

                                                            flexbit_match = true;
                                                        }
                                                }
                                        }

                                    /* direction: both_p */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 7 )
                                        {

                                            if ( !memcmp(flexbit_ipc[a].ip_src, SaganProcSyslog_LOCAL->src_ip, sizeof(flexbit_ipc[a].ip_src)) &&
                                                    !memcmp(flexbit_ipc[a].ip_dst, SaganProcSyslog_LOCAL->dst_ip, sizeof(flexbit_ipc[a].ip_dst)) &&
                                                    flexbit_ipc[a].src_port == SaganProcSyslog_LOCAL->src_port &&
                                                    flexbit_ipc[a].dst_port == SaganProcSyslog_LOCAL->dst_port )

                                                {
                                                    if ( flexbit_ipc[a].flexbit_state == true )
                                                        {
                                                            if ( debug->debugflexbit )
                                                                {
                                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isnotset\" flexbit \"%s\" true (direction: \"src_xbitdst\"). (%s -> any)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, SaganProcSyslog_LOCAL->dst_ip);

                                                                }

                                                            flexbit_match = true;
                                                        }
                                                }
                                        }

                                    /* direction: by_src_p */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 8 )
                                        {

                                            if ( !memcmp(flexbit_ipc[a].ip_src, SaganProcSyslog_LOCAL->src_ip, sizeof(flexbit_ipc[a].ip_src)) &&
                                                    flexbit_ipc[a].src_port == SaganProcSyslog_LOCAL->src_port )

                                                {
                                                    if ( flexbit_ipc[a].flexbit_state == true )
                                                        {
                                                            if ( debug->debugflexbit )
                                                                {
                                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isnotset\" flexbit \"%s\" true (direction: \"by_src_p\"). (%s:%d -> any)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, SaganProcSyslog_LOCAL->src_ip, SaganProcSyslog_LOCAL->src_port);

                                                                }

                                                            flexbit_match = true;
                                                        }
                                                }
                                        }

                                    /* direction: by_dst_p */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 9 )
                                        {

                                            if ( !memcmp(flexbit_ipc[a].ip_dst, SaganProcSyslog_LOCAL->dst_ip, sizeof(flexbit_ipc[a].ip_dst)) &&
                                                    flexbit_ipc[a].dst_port == SaganProcSyslog_LOCAL->dst_port )

                                                {
                                                    if ( flexbit_ipc[a].flexbit_state == true )
                                                        {
                                                            if ( debug->debugflexbit )
                                                                {
                                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isnotset\" flexbit \"%s\" true (direction: \"by_dst_p\"). (any -> %s:%d)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, SaganProcSyslog_LOCAL->dst_ip, SaganProcSyslog_LOCAL->dst_port);

                                                                }

                                                            flexbit_match = true;
                                                        }
                                                }
                                        }

                                    /* direction: reverse_p */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 10 )
                                        {

                                            if ( !memcmp(flexbit_ipc[a].ip_src, SaganProcSyslog_LOCAL->dst_ip, sizeof(flexbit_ipc[a].ip_src)) &&
                                                    !memcmp(flexbit_ipc[a].ip_dst, SaganProcSyslog_LOCAL->src_ip, sizeof(flexbit_ipc[a].ip_dst)) &&
                                                    flexbit_ipc[a].src_port == SaganProcSyslog_LOCAL->dst_port &&
                                                    flexbit_ipc[a].dst_port == SaganProcSyslog_LOCAL->src_port)
                                                {
                                                    if ( flexbit_ipc[a].flexbit_state == true )
                                                        {
                                                            if ( debug->debugflexbit )
                                                                {
                                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isnotset\" flexbit \"%s\" true (direction: \"reverse_p\"). (%s:%d -> %s:%d)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, SaganProcSyslog_LOCAL->src_ip, SaganProcSyslog_LOCAL->dst_port, SaganProcSyslog_LOCAL->dst_ip, SaganProcSyslog_LOCAL->src_port);

                                                                }

                                                            flexbit_match = true;
                                                        }
                                                }
                                        }

                                    /* direction: src_xbitdst_p */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 11 )
                                        {

                                            if ( !memcmp(flexbit_ipc[a].ip_dst, SaganProcSyslog_LOCAL->src_ip, sizeof(flexbit_ipc[a].ip_dst)) &&
                                                    flexbit_ipc[a].dst_port == SaganProcSyslog_LOCAL->src_port )

                                                {
                                                    if ( flexbit_ipc[a].flexbit_state == true )
                                                        {
                                                            if ( debug->debugflexbit )
                                                                {
                                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isnotset\" flexbit \"%s\" true (direction: \"src_xbitdst_p\"). (any -> %s:%d)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, SaganProcSyslog_LOCAL->src_ip, SaganProcSyslog_LOCAL->src_port);

                                                                }

                                                            flexbit_match = true;
                                                        }
                                                }
                                        }

                                    /* direction: dst_xbitsrc_p */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 12 )
                                        {


                                            if ( !memcmp(flexbit_ipc[a].ip_src, SaganProcSyslog_LOCAL->dst_ip, sizeof(flexbit_ipc[a].ip_src)) &&
                                                    flexbit_ipc[a].src_port == SaganProcSyslog_LOCAL->dst_port )
                                                {
                                                    if ( flexbit_ipc[a].flexbit_state == true )
                                                        {
                                                            if ( debug->debugflexbit )
                                                                {
                                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isnotset\" flexbit \"%s\" true (direction: \"dst_xbitsrc_p\"). (%s:%d-> any)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, SaganProcSyslog_LOCAL->dst_ip, SaganProcSyslog_LOCAL->dst_port);

                                                                }

                                                            flexbit_match = true;
                                                        }
                                                }
                                        }

                                    /* direction: username */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 13 )
                                        {

                                            if ( !memcmp(flexbit_ipc[a].username, SaganProcSyslog_LOCAL->username, sizeof(flexbit_ipc[a].username)) )
                                                {
                                                    if ( flexbit_ipc[a].flexbit_state == true )
                                                        {
                                                            if ( debug->debugflexbit )
                                                                {
                                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isnotset\" flexbit \"%s\" true (direction: \"username\"). (any -> %s)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, SaganProcSyslog_LOCAL->username);

                                                                }

                                                            flexbit_match = true;
                                                        }
                                                }
                                        }

                                } /* if memcmp(rulestruct[rule_position].flexbit_name[i] */
                        } /* for a = 0 */

                    /* flexbit wasn't found for isnotset */

                    if ( flexbit_match == false )
                        {
                            flexbit_total_match++;
                        }

                } /* rulestruct[rule_position].flexbit_type[i] == 4 */

        } /* for (i = 0; i < rulestruct[rule_position].xbit_count; i++) */


    if ( flexbit_total_match == rulestruct[rule_position].flexbit_condition_count )
        {

            if ( debug->debugflexbit )
                {
                    Sagan_Log(DEBUG, "[%s, line %d] Got %d flexbits & needed %d. Got corrent number of flexbits, return true!", __FILE__, __LINE__, flexbit_total_match, rulestruct[rule_position].flexbit_condition_count );
                }

#ifdef HAVE_LIBFASTJSON

            struct json_object *jobj;
            char tmp_data[MAX_SYSLOGMSG*2] = { 0 };

            unsigned long b64_len = strlen(SaganProcSyslog_LOCAL->syslog_message) * 2;
            uint8_t b64_target[b64_len];

            char *proto = "UNKNOWN";

            jobj = json_object_new_object();

            json_object *jsensor = json_object_new_string(config->sagan_sensor_name);
            json_object_object_add(jobj,"sensor", jsensor);

            /*
                    json_object *jexpire = json_object_new_int(rulestruct[rule_position].xbit_expire[r]);
                    json_object_object_add(jobj,"expire", jexpire);
            */

            json_object *jsource_ip = json_object_new_string(SaganProcSyslog_LOCAL->syslog_host);
            json_object_object_add(jobj,"syslog_source", jsource_ip);

            json_object *jsrc_ip = json_object_new_string(SaganProcSyslog_LOCAL->src_ip);
            json_object_object_add(jobj,"src_ip", jsrc_ip );

            json_object *jdest_ip = json_object_new_string(SaganProcSyslog_LOCAL->dst_ip);
            json_object_object_add(jobj,"dest_ip", jdest_ip );

//        json_object *jusername = json_object_new_string(username);
//        json_object_object_add(jobj,"username", jusername );

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

            json_object *jrev = json_object_new_int(rulestruct[rule_position].s_rev);
            json_object_object_add(jobj,"rev", jrev);

            json_object *jtype = json_object_new_string("xbit");
            json_object_object_add(jobj,"type", jtype);

            json_object *jstorage = json_object_new_string("mmap");
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

            snprintf(tmp_data, sizeof(tmp_data), "%s", json_object_to_json_string(jobj));
            tmp_data[sizeof(tmp_data) - 1] = '\0';

            strlcpy( SaganProcSyslog_LOCAL->correlation_json, tmp_data, MAX_SYSLOGMSG);

            json_object_put(jobj);

            printf("%s\n",  SaganProcSyslog_LOCAL->correlation_json );

#endif


            return(true);

        }
    else
        {

            if ( debug->debugflexbit )
                {
                    Sagan_Log(DEBUG, "[%s, line %d] Got %d flexbits, needed %d", __FILE__, __LINE__, flexbit_total_match, rulestruct[rule_position].flexbit_condition_count );
                }

            return(false);

        }

    Sagan_Log(WARN, "Shouldn't make it this far in Xbit_Condition()!\n");

}  /* End of Xbit_Condition(); */


/*****************************************************************************
 * Flexbit_Count - Used to determine how many flexbits have been set based on a
 * source or destination address.  This is useful for identification of
 * distributed attacks.
 *****************************************************************************/

bool Flexbit_Count_MMAP( uint_fast32_t rule_position, const char *ip_src, const char *ip_dst )
{

    uint32_t a = 0;
    uint32_t i = 0;
    uint32_t counter = 0;

    for (i = 0; i < rulestruct[rule_position].flexbit_count_count; i++)
        {

            for (a = 0; a < counters_ipc->flexbit_count; a++)
                {

                    if ( rulestruct[rule_position].flexbit_direction[i] == 2 &&
                            !memcmp(flexbit_ipc[a].ip_src, ip_src, sizeof(flexbit_ipc[a].ip_src)) )
                        {

                            counter++;

                            if ( rulestruct[rule_position].flexbit_count_gt_lt[i] == 0 )
                                {

                                    if ( counter > rulestruct[rule_position].flexbit_count_counter[i] )
                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] Xbit count 'by_src' threshold reached for flexbit '%s'.", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name);
                                                }


                                            return(true);
                                        }
                                }
                        }

                    else if ( rulestruct[rule_position].flexbit_direction[i] == 3 &&
                              !memcmp(flexbit_ipc[a].ip_dst, ip_dst, sizeof(flexbit_ipc[a].ip_dst)) )
                        {

                            counter++;

                            if ( rulestruct[rule_position].flexbit_count_gt_lt[i] == 0 )
                                {

                                    if ( counter > rulestruct[rule_position].flexbit_count_counter[i] )
                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] Xbit count 'by_dst' threshold reached for flexbit '%s'.", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name);
                                                }

                                            return(true);
                                        }
                                }
                        }
                }
        }

    if ( debug->debugflexbit)
        {
            Sagan_Log(DEBUG, "[%s, line %d] Xbit count threshold NOT reached for flexbit.", __FILE__, __LINE__);
        }

    return(false);
}


/*****************************************************************************
 * Flexbit_Set - Used to "set" & "unset" flexbit.  All rule "set" and
 * "unset" happen here.
 *****************************************************************************/

void Flexbit_Set_MMAP(uint_fast32_t rule_position, const char *ip_src, const char *ip_dst, int src_port, int dst_port, const char *username, const char *syslog_message )
{

    uint_fast32_t i = 0;
    uint_fast32_t a = 0;

    time_t t;
    struct tm *now;
    char  timet[20];

    bool flexbit_match = false;
    bool flexbit_unset_match = 0;

    /* Flexbit do need a non-null username, otherwise a segmentation fault occurs */

    char flexbit_username[MAX_USERNAME_SIZE] = {0};

    if ( username != NULL )
        {
            memcpy(flexbit_username, username, sizeof(flexbit_username));
        }

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    struct _Sagan_Flexbit_Track *flexbit_track;

    flexbit_track = malloc(sizeof(_Sagan_Flexbit_Track));

    if ( flexbit_track  == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for flexbit_track. Abort!", __FILE__, __LINE__);
        }

    memset(flexbit_track, 0, sizeof(_Sagan_Flexbit_Track));

    int flexbit_track_count = 0;

    Flexbit_Cleanup_MMAP();

    for (i = 0; i < rulestruct[rule_position].flexbit_count; i++)
        {

            /*******************
             *      UNSET      *
             *******************/

            if ( rulestruct[rule_position].flexbit_type[i] == 2 )
                {

                    for (a = 0; a < counters_ipc->flexbit_count; a++)
                        {

                            if ( !strcmp(flexbit_ipc[a].flexbit_name, rulestruct[rule_position].flexbit_name[i] ))
                                {

                                    /* direction: none */

                                    if ( rulestruct[rule_position].flexbit_direction[i] == 0 )
                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"unset\" flexbit \"%s\" (direction: \"none\"). (any -> any)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name);
                                                }


                                            File_Lock(config->shm_flexbit);
                                            pthread_mutex_lock(&Flexbit_Mutex);

                                            flexbit_ipc[a].flexbit_state = false;

                                            pthread_mutex_unlock(&Flexbit_Mutex);
                                            File_Unlock(config->shm_flexbit);

                                            flexbit_unset_match = 1;

                                        }


                                    /* direction: both */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 1 &&
                                              !memcmp(flexbit_ipc[a].ip_src, ip_src, sizeof(flexbit_ipc[a].ip_src)) &&
                                              !memcmp(flexbit_ipc[a].ip_dst, ip_dst, sizeof(flexbit_ipc[a].ip_dst)) )
                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"unset\" flexbit \"%s\" (direction: \"both\"). (%s -> %s)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, ip_src, ip_dst);
                                                }

                                            File_Lock(config->shm_flexbit);
                                            pthread_mutex_lock(&Flexbit_Mutex);

                                            flexbit_ipc[a].flexbit_state = false;

                                            pthread_mutex_unlock(&Flexbit_Mutex);
                                            File_Unlock(config->shm_flexbit);

                                            flexbit_unset_match = 1;

                                        }

                                    /* direction: by_src */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 2 &&
                                              !memcmp(flexbit_ipc[a].ip_src, ip_src, sizeof(flexbit_ipc[a].ip_src)) )

                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"unset\" flexbit \"%s\" (direction: \"by_src\"). (%s -> any)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, ip_src);
                                                }

                                            File_Lock(config->shm_flexbit);
                                            pthread_mutex_lock(&Flexbit_Mutex);

                                            flexbit_ipc[a].flexbit_state = false;

                                            pthread_mutex_unlock(&Flexbit_Mutex);
                                            File_Unlock(config->shm_flexbit);

                                            flexbit_unset_match = 1;

                                        }


                                    /* direction: by_dst */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 3 &&
                                              !memcmp(flexbit_ipc[a].ip_dst, ip_dst, sizeof(flexbit_ipc[a].ip_dst)) )
                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"unset\" flexbit \"%s\" (direction: \"by_dst\"). (any -> %s)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, ip_dst);
                                                }

                                            File_Lock(config->shm_flexbit);
                                            pthread_mutex_lock(&Flexbit_Mutex);

                                            flexbit_ipc[a].flexbit_state = false;

                                            pthread_mutex_unlock(&Flexbit_Mutex);
                                            File_Unlock(config->shm_flexbit);

                                            flexbit_unset_match = 1;

                                        }

                                    /* direction: reverse */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 4 &&
                                              !memcmp(flexbit_ipc[a].ip_dst, ip_src, sizeof(flexbit_ipc[a].ip_dst)) &&
                                              !memcmp(flexbit_ipc[a].ip_src, ip_dst, sizeof(flexbit_ipc[a].ip_src)) )

                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"unset\" flexbit \"%s\" (direction: \"reverse\"). (%s -> %s)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, ip_dst, ip_src);
                                                }

                                            File_Lock(config->shm_flexbit);
                                            pthread_mutex_lock(&Flexbit_Mutex);

                                            flexbit_ipc[a].flexbit_state = false;

                                            pthread_mutex_unlock(&Flexbit_Mutex);
                                            File_Unlock(config->shm_flexbit);

                                            flexbit_unset_match = 1;

                                        }

                                    /* direction: src_xbitdst */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 5 &&
                                              !memcmp(flexbit_ipc[a].ip_dst, ip_src, sizeof(flexbit_ipc[a].ip_dst)) )
                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"unset\" flexbit \"%s\" (direction: \"src_xbitdst\"). (any -> %s)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, ip_src);
                                                }

                                            File_Lock(config->shm_flexbit);
                                            pthread_mutex_lock(&Flexbit_Mutex);

                                            flexbit_ipc[a].flexbit_state = 0;

                                            pthread_mutex_unlock(&Flexbit_Mutex);
                                            File_Unlock(config->shm_flexbit);

                                            flexbit_unset_match = 1;

                                        }

                                    /* direction: dst_xbitsrc */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 6 &&
                                              !memcmp(flexbit_ipc[a].ip_src, ip_dst, sizeof(flexbit_ipc[a].ip_src)) )
                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"unset\" flexbit \"%s\" (direction: \"dst_xbitsrc\"). (any -> %s)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, ip_dst);
                                                }

                                            File_Lock(config->shm_flexbit);
                                            pthread_mutex_lock(&Flexbit_Mutex);

                                            flexbit_ipc[a].flexbit_state = 0;

                                            pthread_mutex_unlock(&Flexbit_Mutex);
                                            File_Unlock(config->shm_flexbit);

                                            flexbit_unset_match = 1;

                                        }

                                    /* direction: both_p */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 7 &&
                                              !memcmp(flexbit_ipc[a].ip_src, ip_src, sizeof(flexbit_ipc[a].ip_src)) &&
                                              !memcmp(flexbit_ipc[a].ip_dst, ip_dst, sizeof(flexbit_ipc[a].ip_dst)) &&
                                              flexbit_ipc[a].src_port == src_port &&
                                              flexbit_ipc[a].dst_port == dst_port )
                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"unset\" flexbit \"%s\" (direction: \"both_p\"). (%s -> %s)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, ip_src, ip_dst);
                                                }

                                            File_Lock(config->shm_flexbit);
                                            pthread_mutex_lock(&Flexbit_Mutex);

                                            flexbit_ipc[a].flexbit_state = 0;

                                            pthread_mutex_unlock(&Flexbit_Mutex);
                                            File_Unlock(config->shm_flexbit);

                                            flexbit_unset_match = 1;

                                        }

                                    /* direction: by_src_p */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 8 &&
                                              !memcmp(flexbit_ipc[a].ip_src, ip_src, sizeof(flexbit_ipc[a].ip_src)) &&
                                              flexbit_ipc[a].src_port == src_port )

                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"unset\" flexbit \"%s\" (direction: \"by_src_p\"). (%s -> any)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, ip_src);
                                                }

                                            File_Lock(config->shm_flexbit);
                                            pthread_mutex_lock(&Flexbit_Mutex);

                                            flexbit_ipc[a].flexbit_state = 0;

                                            pthread_mutex_unlock(&Flexbit_Mutex);
                                            File_Unlock(config->shm_flexbit);

                                            flexbit_unset_match = 1;

                                        }


                                    /* direction: by_dst_p */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 9 &&
                                              !memcmp(flexbit_ipc[a].ip_dst, ip_dst, sizeof(flexbit_ipc[a].ip_dst)) &&
                                              flexbit_ipc[a].dst_port == dst_port )
                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"unset\" flexbit \"%s\" (direction: \"by_dst\"). (any -> %s)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, ip_dst);
                                                }

                                            File_Lock(config->shm_flexbit);
                                            pthread_mutex_lock(&Flexbit_Mutex);

                                            flexbit_ipc[a].flexbit_state = 0;

                                            pthread_mutex_unlock(&Flexbit_Mutex);
                                            File_Unlock(config->shm_flexbit);

                                            flexbit_unset_match = 1;

                                        }

                                    /* direction: reverse_p */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 10 &&
                                              !memcmp(flexbit_ipc[a].ip_dst, ip_src, sizeof(flexbit_ipc[a].ip_dst)) &&
                                              !memcmp(flexbit_ipc[a].ip_src, ip_dst, sizeof(flexbit_ipc[a].ip_src)) &&
                                              flexbit_ipc[a].src_port == dst_port &&
                                              flexbit_ipc[a].dst_port == src_port )

                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"unset\" flexbit \"%s\" (direction: \"reverse_p\"). (%s -> %s)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, ip_dst, ip_src);
                                                }

                                            File_Lock(config->shm_flexbit);
                                            pthread_mutex_lock(&Flexbit_Mutex);

                                            flexbit_ipc[a].flexbit_state = 0;

                                            pthread_mutex_unlock(&Flexbit_Mutex);
                                            File_Unlock(config->shm_flexbit);

                                            flexbit_unset_match = 1;

                                        }

                                    /* direction: src_xbitdst_p */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 11 &&
                                              !memcmp(flexbit_ipc[a].ip_dst, ip_src, sizeof(flexbit_ipc[a].ip_dst)) &&
                                              flexbit_ipc[a].dst_port == src_port )
                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"unset\" flexbit \"%s\" (direction: \"src_xbitdst_p\"). (any -> %s)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, ip_src);
                                                }

                                            File_Lock(config->shm_flexbit);
                                            pthread_mutex_lock(&Flexbit_Mutex);

                                            flexbit_ipc[a].flexbit_state = 0;

                                            pthread_mutex_unlock(&Flexbit_Mutex);
                                            File_Unlock(config->shm_flexbit);

                                            flexbit_unset_match = 1;

                                        }

                                    /* direction: dst_xbitsrc_p */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 12 &&
                                              !memcmp(flexbit_ipc[a].ip_src, ip_dst, sizeof(flexbit_ipc[a].ip_src)) &&
                                              flexbit_ipc[a].src_port == dst_port )
                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"unset\" flexbit \"%s\" (direction: \"dst_xbitsrc_p\"). (any -> %s)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, ip_dst);
                                                }

                                            File_Lock(config->shm_flexbit);
                                            pthread_mutex_lock(&Flexbit_Mutex);

                                            flexbit_ipc[a].flexbit_state = 0;

                                            pthread_mutex_unlock(&Flexbit_Mutex);
                                            File_Unlock(config->shm_flexbit);

                                            flexbit_unset_match = 1;

                                        }

                                    /* direction: username */

                                    else if ( rulestruct[rule_position].flexbit_direction[i] == 13 &&
                                              !memcmp(flexbit_ipc[a].username, flexbit_username, sizeof(flexbit_ipc[a].username)) )
                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"unset\" flexbit \"%s\" (direction: \"username\"). (any -> %s)", __FILE__, __LINE__, flexbit_ipc[a].flexbit_name, flexbit_username);
                                                }

                                            File_Lock(config->shm_flexbit);
                                            pthread_mutex_lock(&Flexbit_Mutex);

                                            flexbit_ipc[a].flexbit_state = false;

                                            pthread_mutex_unlock(&Flexbit_Mutex);
                                            File_Unlock(config->shm_flexbit);

                                            flexbit_unset_match = 1;

                                        }

                                }
                        }

                    if ( debug->debugflexbit && flexbit_unset_match == 0 )
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] No flexbit found to \"unset\" for %s.", __FILE__, __LINE__, rulestruct[rule_position].flexbit_name[i]);
                        }

                } /* if ( rulestruct[rule_position].flexbit_type[i] == 2 ) */

            /*******************
             *      SET        *
            *******************/

            else if ( rulestruct[rule_position].flexbit_type[i] == 1 )
                {

                    for (a = 0; a < counters_ipc->flexbit_count; a++)
                        {

                            /* Do we have the flexbit already in memory?  If so,  update the information */

                            if (!strcmp(flexbit_ipc[a].flexbit_name, rulestruct[rule_position].flexbit_name[i]) &&
                                    !memcmp(flexbit_ipc[a].ip_src, ip_src, sizeof(flexbit_ipc[a].ip_src)) &&
                                    !memcmp(flexbit_ipc[a].ip_dst, ip_dst, sizeof(flexbit_ipc[a].ip_dst)) &&
                                    !memcmp(flexbit_ipc[a].username, flexbit_username, sizeof(flexbit_ipc[a].username)) &&
                                    flexbit_ipc[a].src_port == config->sagan_port &&
                                    flexbit_ipc[a].dst_port == config->sagan_port )
                                {


                                    File_Lock(config->shm_flexbit);
                                    pthread_mutex_lock(&Flexbit_Mutex);

                                    flexbit_ipc[a].flexbit_date = atol(timet);
                                    flexbit_ipc[a].flexbit_expire = atol(timet) + rulestruct[rule_position].flexbit_timeout[i];
                                    flexbit_ipc[a].flexbit_state = true;
                                    strlcpy(flexbit_ipc[a].syslog_message, syslog_message, sizeof(flexbit_ipc[a].syslog_message));
                                    strlcpy(flexbit_ipc[a].username, flexbit_username, sizeof(flexbit_ipc[a].username));
                                    strlcpy(flexbit_ipc[a].signature_msg, rulestruct[rule_position].s_msg, sizeof(flexbit_ipc[a].signature_msg));
                                    flexbit_ipc[a].sid = rulestruct[rule_position].s_sid;


                                    if ( debug->debugflexbit)
                                        {

                                            Sagan_Log(DEBUG,"[%s, line %d] [%d] Updated via \"set\" for flexbit \"%s\". Next expire time is %d (%d) [ %s:%d -> %s:%d ]", __FILE__, __LINE__, a, rulestruct[rule_position].flexbit_name[i], flexbit_ipc[i].flexbit_expire, rulestruct[rule_position].flexbit_timeout[i], flexbit_ipc[a].ip_src, flexbit_ipc[a].src_port, flexbit_ipc[a].ip_dst, flexbit_ipc[a].dst_port);

                                        }

                                    pthread_mutex_unlock(&Flexbit_Mutex);
                                    File_Unlock(config->shm_flexbit);

                                    flexbit_match = true;
                                }

                        }


                    /* If the flexbit isn't in memory,  store it to be created later */

                    if ( flexbit_match == false )
                        {

                            flexbit_track = ( _Sagan_Flexbit_Track * ) realloc(flexbit_track, (flexbit_track_count+1) * sizeof(_Sagan_Flexbit_Track));

                            if ( flexbit_track == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for flexbit_track. Abort!", __FILE__, __LINE__);
                                }

                            memset(&flexbit_track[flexbit_track_count], 0, sizeof(_Sagan_Flexbit_Track));

                            strlcpy(flexbit_track[flexbit_track_count].flexbit_name, rulestruct[rule_position].flexbit_name[i], sizeof(flexbit_track[flexbit_track_count].flexbit_name));
                            strlcpy(flexbit_ipc[flexbit_track_count].syslog_message, syslog_message, sizeof(flexbit_ipc[flexbit_track_count].syslog_message));
                            strlcpy(flexbit_ipc[flexbit_track_count].signature_msg, rulestruct[rule_position].s_msg, sizeof(flexbit_ipc[flexbit_track_count].signature_msg));
                            flexbit_ipc[flexbit_track_count].sid = rulestruct[rule_position].s_sid;

                            flexbit_track[flexbit_track_count].flexbit_timeout = rulestruct[rule_position].flexbit_timeout[i];
                            flexbit_track[flexbit_track_count].flexbit_srcport = config->sagan_port;
                            flexbit_track[flexbit_track_count].flexbit_dstport = config->sagan_port;
                            flexbit_track_count++;

                        }

                } /* if flexbit_type == 1 */

            /***************************
             *      SET_SRCPORT        *
            ****************************/

            else if ( rulestruct[rule_position].flexbit_type[i] == 5 )
                {

                    flexbit_match = false;

                    for (a = 0; a < counters_ipc->flexbit_count; a++)
                        {

                            /* Do we have the flexbit already in memory?  If so,  update the information */

                            if (!strcmp(flexbit_ipc[a].flexbit_name, rulestruct[rule_position].flexbit_name[i]) &&
                                    !memcmp(flexbit_ipc[a].ip_src, ip_src, sizeof(flexbit_ipc[a].ip_src)) &&
                                    !memcmp(flexbit_ipc[a].ip_dst, ip_dst, sizeof(flexbit_ipc[a].ip_dst)) &&
                                    flexbit_ipc[a].src_port == src_port &&
                                    flexbit_ipc[a].dst_port == config->sagan_port )
                                {

                                    File_Lock(config->shm_flexbit);
                                    pthread_mutex_lock(&Flexbit_Mutex);

                                    flexbit_ipc[a].flexbit_date = atol(timet);
                                    flexbit_ipc[a].flexbit_expire = atol(timet) + rulestruct[rule_position].flexbit_timeout[i];
                                    flexbit_ipc[a].flexbit_state = true;
                                    strlcpy(flexbit_ipc[a].syslog_message, syslog_message, sizeof(flexbit_ipc[a].syslog_message));

                                    if ( debug->debugflexbit)
                                        {

                                            Sagan_Log(DEBUG,"[%s, line %d] [%d] Updated via \"set_srcport\" for flexbit \"%s\". Nex expire time is %d (%d) [ %s:%d -> %s:%d ]", __FILE__, __LINE__, a, rulestruct[rule_position].flexbit_name[i], flexbit_ipc[i].flexbit_expire, rulestruct[rule_position].flexbit_timeout[i], flexbit_ipc[a].ip_src, flexbit_ipc[a].src_port, flexbit_ipc[a].ip_dst, flexbit_ipc[a].dst_port);

                                        }

                                    pthread_mutex_unlock(&Flexbit_Mutex);
                                    File_Unlock(config->shm_flexbit);

                                    flexbit_match = true;
                                }

                        }


                    /* If the flexbit isn't in memory,  store it to be created later */

                    if ( flexbit_match == false )
                        {

                            flexbit_track = ( _Sagan_Flexbit_Track * ) realloc(flexbit_track, (flexbit_track_count+1) * sizeof(_Sagan_Flexbit_Track));

                            if ( flexbit_track == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for flexbit_track. Abort!", __FILE__, __LINE__);
                                }

                            memset(&flexbit_track[flexbit_track_count], 0, sizeof(_Sagan_Flexbit_Track));

                            strlcpy(flexbit_track[flexbit_track_count].flexbit_name, rulestruct[rule_position].flexbit_name[i], sizeof(flexbit_track[flexbit_track_count].flexbit_name));
                            strlcpy(flexbit_ipc[flexbit_track_count].syslog_message, syslog_message, sizeof(flexbit_ipc[flexbit_track_count].syslog_message));
                            flexbit_track[flexbit_track_count].flexbit_timeout = rulestruct[rule_position].flexbit_timeout[i];
                            flexbit_track[flexbit_track_count].flexbit_srcport = src_port;
                            flexbit_track[flexbit_track_count].flexbit_dstport = config->sagan_port;
                            flexbit_track_count++;

                        }

                } /* if flexbit_type == 5 */

            /***************************
             *      SET_DSTPORT        *
            ****************************/

            else if ( rulestruct[rule_position].flexbit_type[i] == 6 )
                {

                    flexbit_match = false;

                    for (a = 0; a < counters_ipc->flexbit_count; a++)
                        {

                            /* Do we have the flexbit already in memory?  If so,  update the information */

                            if (!strcmp(flexbit_ipc[a].flexbit_name, rulestruct[rule_position].flexbit_name[i]) &&
                                    !memcmp(flexbit_ipc[a].ip_src, ip_src, sizeof(flexbit_ipc[a].ip_src)) &&
                                    !memcmp(flexbit_ipc[a].ip_dst, ip_dst, sizeof(flexbit_ipc[a].ip_dst)) &&
                                    flexbit_ipc[a].src_port == config->sagan_port &&
                                    flexbit_ipc[a].dst_port == dst_port )
                                {

                                    File_Lock(config->shm_flexbit);
                                    pthread_mutex_lock(&Flexbit_Mutex);

                                    flexbit_ipc[a].flexbit_date = atol(timet);
                                    flexbit_ipc[a].flexbit_expire = atol(timet) + rulestruct[rule_position].flexbit_timeout[i];
                                    flexbit_ipc[a].flexbit_state = true;
                                    strlcpy(flexbit_ipc[a].syslog_message, syslog_message, sizeof(flexbit_ipc[a].syslog_message));

                                    if ( debug->debugflexbit)
                                        {

                                            Sagan_Log(DEBUG,"[%s, line %d] [%d] Updated via \"set_dstport\" for flexbit \"%s\". Nex expire time is %d (%d) [ %s:%d -> %s:%d ]", __FILE__, __LINE__, a, rulestruct[rule_position].flexbit_name[i], flexbit_ipc[i].flexbit_expire, rulestruct[rule_position].flexbit_timeout[i], flexbit_ipc[a].ip_src, flexbit_ipc[a].src_port, flexbit_ipc[a].ip_dst, flexbit_ipc[a].dst_port);

                                        }

                                    pthread_mutex_unlock(&Flexbit_Mutex);
                                    File_Unlock(config->shm_flexbit);

                                    flexbit_match = true;
                                }

                        }


                    /* If the flexbit isn't in memory,  store it to be created later */

                    if ( flexbit_match == false )
                        {

                            flexbit_track = ( _Sagan_Flexbit_Track * ) realloc(flexbit_track, (flexbit_track_count+1) * sizeof(_Sagan_Flexbit_Track));

                            if ( flexbit_track == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for flexbit_track. Abort!", __FILE__, __LINE__);
                                }

                            memset(&flexbit_track[flexbit_track_count], 0, sizeof(_Sagan_Flexbit_Track));

                            strlcpy(flexbit_track[flexbit_track_count].flexbit_name, rulestruct[rule_position].flexbit_name[i], sizeof(flexbit_track[flexbit_track_count].flexbit_name));
                            strlcpy(flexbit_ipc[flexbit_track_count].syslog_message, syslog_message, sizeof(flexbit_ipc[flexbit_track_count].syslog_message));
                            flexbit_track[flexbit_track_count].flexbit_timeout = rulestruct[rule_position].flexbit_timeout[i];
                            flexbit_track[flexbit_track_count].flexbit_srcport = config->sagan_port;
                            flexbit_track[flexbit_track_count].flexbit_dstport = dst_port;
                            flexbit_track_count++;

                        }

                } /* if flexbit_type == 6 */

            /*************************
             *      SET_PORTS        *
            **************************/

            else if ( rulestruct[rule_position].flexbit_type[i] == 7 )
                {

                    flexbit_match = false;

                    for (a = 0; a < counters_ipc->flexbit_count; a++)
                        {

                            /* Do we have the flexbit already in memory?  If so,  update the information */

                            if (!strcmp(flexbit_ipc[a].flexbit_name, rulestruct[rule_position].flexbit_name[i]) &&
                                    !memcmp(flexbit_ipc[a].ip_src, ip_src, sizeof(flexbit_ipc[a].ip_src)) &&
                                    !memcmp(flexbit_ipc[a].ip_dst, ip_dst, sizeof(flexbit_ipc[a].ip_dst)) &&
                                    flexbit_ipc[a].src_port == src_port &&
                                    flexbit_ipc[a].dst_port == dst_port )
                                {

                                    File_Lock(config->shm_flexbit);
                                    pthread_mutex_lock(&Flexbit_Mutex);

                                    flexbit_ipc[a].flexbit_date = atol(timet);
                                    flexbit_ipc[a].flexbit_expire = atol(timet) + rulestruct[rule_position].flexbit_timeout[i];
                                    flexbit_ipc[a].flexbit_state = true;
                                    strlcpy(flexbit_ipc[a].syslog_message, syslog_message, sizeof(flexbit_ipc[a].syslog_message));

                                    if ( debug->debugflexbit)
                                        {

                                            Sagan_Log(DEBUG,"[%s, line %d] [%d] Updated via \"set_ports\" for flexbit \"%s\". Nex expire time is %d (%d) [ %s:%d -> %s:%d ]", __FILE__, __LINE__, a, rulestruct[rule_position].flexbit_name[i], flexbit_ipc[i].flexbit_expire, rulestruct[rule_position].flexbit_timeout[i], flexbit_ipc[a].ip_src, flexbit_ipc[a].src_port, flexbit_ipc[a].ip_dst, flexbit_ipc[a].dst_port);

                                        }

                                    pthread_mutex_unlock(&Flexbit_Mutex);
                                    File_Unlock(config->shm_flexbit);

                                    flexbit_match = true;
                                }

                        }


                    /* If the flexbit isn't in memory,  store it to be created later */

                    if ( flexbit_match == false )
                        {

                            flexbit_track = ( _Sagan_Flexbit_Track * ) realloc(flexbit_track, (flexbit_track_count+1) * sizeof(_Sagan_Flexbit_Track));

                            if ( flexbit_track == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for flexbit_track. Abort!", __FILE__, __LINE__);
                                }

                            memset(&flexbit_track[flexbit_track_count], 0, sizeof(_Sagan_Flexbit_Track));

                            strlcpy(flexbit_track[flexbit_track_count].flexbit_name, rulestruct[rule_position].flexbit_name[i], sizeof(flexbit_track[flexbit_track_count].flexbit_name));
                            strlcpy(flexbit_ipc[flexbit_track_count].syslog_message, syslog_message, sizeof(flexbit_ipc[flexbit_track_count].syslog_message));
                            strlcpy(flexbit_ipc[flexbit_track_count].signature_msg, rulestruct[rule_position].s_msg, sizeof(flexbit_ipc[flexbit_track_count].signature_msg));
                            flexbit_ipc[flexbit_track_count].sid = rulestruct[rule_position].s_sid;

                            flexbit_track[flexbit_track_count].flexbit_timeout = rulestruct[rule_position].flexbit_timeout[i];
                            flexbit_track[flexbit_track_count].flexbit_srcport = src_port;
                            flexbit_track[flexbit_track_count].flexbit_dstport = dst_port;
                            flexbit_track_count++;

                        }

                } /* if flexbit_type == 7 */

        } /* Out of for i loop */

    /* Do we have any flexbits in memory that need to be created?  */

    if ( flexbit_track_count != 0 )
        {

            for (i = 0; i < flexbit_track_count; i++)
                {

                    if ( Clean_IPC_Object(FLEXBIT) == 0 )
                        {

                            if ( counters_ipc->flexbit_count >= config->max_flexbits )
                                {
                                    Remove_Lock_File();
                                    Sagan_Log(ERROR, "Storage for flexbits has been exhausted.  The current limit it for mmap-ipc -> flexbit is %d.  This needs to be increased and for the memory map (mmap) files be removed.  With that,  I have to abort processing data.  Sorry", config->max_flexbits );
                                }

                            File_Lock(config->shm_flexbit);
                            pthread_mutex_lock(&Flexbit_Mutex);

                            memcpy(flexbit_ipc[counters_ipc->flexbit_count].ip_src, ip_src, sizeof(flexbit_ipc[counters_ipc->flexbit_count].ip_src));
                            memcpy(flexbit_ipc[counters_ipc->flexbit_count].ip_dst, ip_dst, sizeof(flexbit_ipc[counters_ipc->flexbit_count].ip_dst));

                            flexbit_ipc[counters_ipc->flexbit_count].src_port = flexbit_track[i].flexbit_srcport;
                            flexbit_ipc[counters_ipc->flexbit_count].dst_port = flexbit_track[i].flexbit_dstport;
                            flexbit_ipc[counters_ipc->flexbit_count].flexbit_date = atol(timet);
                            flexbit_ipc[counters_ipc->flexbit_count].flexbit_expire = atol(timet) + flexbit_track[i].flexbit_timeout;
                            flexbit_ipc[counters_ipc->flexbit_count].flexbit_state = true;
                            flexbit_ipc[counters_ipc->flexbit_count].expire = flexbit_track[i].flexbit_timeout;

                            strlcpy(flexbit_ipc[counters_ipc->flexbit_count].flexbit_name, flexbit_track[i].flexbit_name, sizeof(flexbit_ipc[counters_ipc->flexbit_count].flexbit_name));
                            strlcpy(flexbit_ipc[counters_ipc->flexbit_count].signature_msg, rulestruct[rule_position].s_msg, sizeof(flexbit_ipc[counters_ipc->flexbit_count].signature_msg));
                            strlcpy(flexbit_ipc[counters_ipc->flexbit_count].syslog_message, syslog_message, sizeof(flexbit_ipc[counters_ipc->flexbit_count].syslog_message));
                            strlcpy(flexbit_ipc[counters_ipc->flexbit_count].username, flexbit_username, sizeof(flexbit_ipc[counters_ipc->flexbit_count].username));
                            flexbit_ipc[counters_ipc->flexbit_count].sid = rulestruct[rule_position].s_sid;


                            if ( debug->debugflexbit)
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] [%d] Created flexbit \"%s\" via \"set, set_srcport, set_dstport, or set_ports\" [%s:%d -> %s:%d]", __FILE__, __LINE__, counters_ipc->flexbit_count, flexbit_ipc[counters_ipc->flexbit_count].flexbit_name, ip_src, flexbit_track[i].flexbit_srcport, ip_dst, flexbit_track[i].flexbit_dstport);
                                }

                            File_Lock(config->shm_counters);

                            counters_ipc->flexbit_count++;

                            File_Unlock(config->shm_counters);
                            File_Unlock(config->shm_flexbit);

                            pthread_mutex_unlock(&Flexbit_Mutex);

                        }
                }
        }

    free(flexbit_track);

} /* End of Xbit_Set */

/*****************************************************************************
 * Xbit_Cleanup - Find "expired" flexbits and toggle the "state"
 * to "off"
 *****************************************************************************/

void Flexbit_Cleanup_MMAP(void)
{

    uint_fast32_t i = 0;

    time_t t;
    struct tm *now;
    char  timet[20];

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    for (i=0; i<counters_ipc->flexbit_count; i++)
        {

            if (  flexbit_ipc[i].flexbit_state == true && atol(timet) >= flexbit_ipc[i].flexbit_expire )
                {
                    if (debug->debugflexbit)
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] Setting flexbit %s to \"expired\" state.", __FILE__, __LINE__, flexbit_ipc[i].flexbit_name);
                        }
                    flexbit_ipc[i].flexbit_state = false;
                }
        }

}
