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

/* send-alert.c
 *
 * Sends alert information to the correct processor
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>

#include "sagan.h"
#include "sagan-config.h"
#include "version.h"
#include "liblognorm.h"
#include "geoip.h"

#include "send-alert.h"
#include "output.h"
#include "rules.h"

#include "routing.h"

extern struct _SaganConfig *config;
extern struct _Rule_Struct *rulestruct;

//void Send_Alert ( struct _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL, uint32_t rule_position, struct timeval tp, char *bluedot_json, unsigned char bluedot_results, struct _GeoIP *GeoIP_SRC, struct _GeoIP *GeoIP_DEST )

void Send_Alert ( struct _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL, uint32_t rule_position, struct timeval tp, char *bluedot_json, unsigned char bluedot_results, uint_fast16_t json_count )
{

    struct _Sagan_Event *SaganProcessorEvent = NULL;
    SaganProcessorEvent = malloc(sizeof(struct _Sagan_Event));

    if ( SaganProcessorEvent == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SaganProcessorEvent. Abort!", __FILE__, __LINE__);
        }

    memset(SaganProcessorEvent, 0, sizeof(_Sagan_Event));

    /* If the event is JSON,  we want to preserve it as part of the "message" */

    if ( ( config->json_parse_data == true && json_count > 0 )  || config->input_type == INPUT_JSON )
        {
            SaganProcessorEvent->message = SaganProcSyslog_LOCAL->json_original;
        }
    else
        {
            SaganProcessorEvent->message = SaganProcSyslog_LOCAL->syslog_message;
        }

    SaganProcessorEvent->f_msg           =       rulestruct[rule_position].s_msg;

    SaganProcessorEvent->program	 = 	 SaganProcSyslog_LOCAL->syslog_program;
    SaganProcessorEvent->level           =       SaganProcSyslog_LOCAL->syslog_level;

    SaganProcessorEvent->facility        =       SaganProcSyslog_LOCAL->syslog_facility;

    SaganProcessorEvent->priority        =       SaganProcSyslog_LOCAL->syslog_level;	/* Syslog priority */
    SaganProcessorEvent->pri             =       rulestruct[rule_position].s_pri;		/* Sagan priority */
    SaganProcessorEvent->class           =       rulestruct[rule_position].s_classtype;
    SaganProcessorEvent->tag             =       SaganProcSyslog_LOCAL->syslog_tag;
    SaganProcessorEvent->rev             =       rulestruct[rule_position].s_rev;

    SaganProcessorEvent->ip_src          =       SaganProcSyslog_LOCAL->src_ip;
    SaganProcessorEvent->ip_dst          =       SaganProcSyslog_LOCAL->dst_ip;

    SaganProcessorEvent->dst_port        =       SaganProcSyslog_LOCAL->dst_port;
    SaganProcessorEvent->src_port        =       SaganProcSyslog_LOCAL->src_port;

    SaganProcessorEvent->rule_position   =       rule_position;

    SaganProcessorEvent->normalize_http_uri	=	SaganProcSyslog_LOCAL->url;
    SaganProcessorEvent->normalize_http_hostname=	SaganProcSyslog_LOCAL->hostname;

    SaganProcessorEvent->sid             =       rulestruct[rule_position].s_sid;

    SaganProcessorEvent->host		 = 	 SaganProcSyslog_LOCAL->syslog_host;
    SaganProcessorEvent->time            =       SaganProcSyslog_LOCAL->syslog_time;
    SaganProcessorEvent->date            =       SaganProcSyslog_LOCAL->syslog_date;
    SaganProcessorEvent->ip_proto        =       SaganProcSyslog_LOCAL->proto;

    SaganProcessorEvent->event_time	 =       tp;

    SaganProcessorEvent->json_normalize     =    SaganProcSyslog_LOCAL->json_normalize;
    SaganProcessorEvent->bluedot_json       =    bluedot_json;
    SaganProcessorEvent->bluedot_results    =    bluedot_results;

    SaganProcessorEvent->flow_id	    =    SaganProcSyslog_LOCAL->flow_id;
    SaganProcessorEvent->correlation_json	 = SaganProcSyslog_LOCAL->correlation_json;


    Output ( SaganProcessorEvent );
    free(SaganProcessorEvent);

}

