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

/* Handles how if an alert needs to be triggered */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <pthread.h>
#include <errno.h>
#include <stdbool.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"
#include "routing.h"
#include "rules.h"

extern struct _Rule_Struct *rulestruct;
extern struct _SaganConfig *config;

bool Sagan_Check_Routing(  _Sagan_Routing *SaganRouting )
{

    /* Check Flow */

    if ( rulestruct[SaganRouting->position].has_flow == true && SaganRouting->check_flow_return == false )
        {
            return false;
        }

    /* Flexbit */

    if ( rulestruct[SaganRouting->position].flexbit_flag == false ||
            ( rulestruct[SaganRouting->position].flexbit_set_count && rulestruct[SaganRouting->position].flexbit_condition_count == 0 ) ||
            ( rulestruct[SaganRouting->position].flexbit_set_count && rulestruct[SaganRouting->position].flexbit_condition_count && SaganRouting->flexbit_return ) ||
            ( rulestruct[SaganRouting->position].flexbit_set_count == false && rulestruct[SaganRouting->position].flexbit_condition_count && SaganRouting->flexbit_return ))
        {
            /* pass */
        }
    else
        {
            return false;
        }

    if ( rulestruct[SaganRouting->position].flexbit_count_flag == true && SaganRouting->flexbit_count_return == false )
        {
            return false;
        }

    /* Xbit */

    if ( rulestruct[SaganRouting->position].xbit_flag == true &&
            ( rulestruct[SaganRouting->position].xbit_set_count != 0 || rulestruct[SaganRouting->position].xbit_unset_count != 0 )  )
        {
            /* pass */
        }
    else
        {

            if ( rulestruct[SaganRouting->position].xbit_flag == true && SaganRouting->xbit_return == false )
                {
                    return(false);
                }
        }


    /* Aetas */

    if ( rulestruct[SaganRouting->position].alert_time_flag == true && SaganRouting->alert_time_trigger == false )
        {
            return false;
        }

    /* Blacklist */

    if ( rulestruct[SaganRouting->position].blacklist_flag == true && SaganRouting->blacklist_results == false )
        {
            return false;
        }

    /* Zeek intel */

    if ( rulestruct[SaganRouting->position].zeekintel_flag == true && SaganRouting->zeekintel_results == false )
        {
            return false;
        }

    /* GeoIP */

#ifdef HAVE_LIBMAXMINDDB

    if ( rulestruct[SaganRouting->position].geoip2_flag == true && SaganRouting->geoip2_isset == false )
        {
            return false;
        }
#endif

#ifdef WITH_BLUEDOT

    if ( config->bluedot_flag == true )
        {

            if ( rulestruct[SaganRouting->position].bluedot_file_hash == true && SaganRouting->bluedot_hash_flag == false )
                {
                    return false;
                }

            if ( rulestruct[SaganRouting->position].bluedot_filename == true && SaganRouting->bluedot_filename_flag == false )
                {
                    return false;
                }

            if ( rulestruct[SaganRouting->position].bluedot_url == true && SaganRouting->bluedot_url_flag == false )
                {
                    return false;
                }

            if ( rulestruct[SaganRouting->position].bluedot_ja3 == true && SaganRouting->bluedot_ja3_flag == false )
                {
                    return false;
                }

            /* bluedot_ipaddr_type == 0 = disabled,  1 = src,  2 = dst,  3 = both,  4 = all  */

            if ( rulestruct[SaganRouting->position].bluedot_ipaddr_type != 0 && SaganRouting->bluedot_ip_flag == false )
                {
                    return false;
                }

        }

#endif

    return(true);

}
