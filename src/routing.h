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

typedef struct _Sagan_Routing _Sagan_Routing;
struct _Sagan_Routing
{
    uint_fast32_t position;
    bool check_flow_return;
    bool flexbit_count_return;
    bool flexbit_return;
    bool xbit_return;
    bool event_id_return;
    bool alert_time_trigger;
    bool geoip2_isset;
    bool blacklist_results;
    bool zeekintel_results;

#ifdef WITH_BLUEDOT

    bool bluedot_hash_flag;
    bool bluedot_filename_flag;
    bool bluedot_url_flag;
    bool bluedot_ip_flag;
    bool bluedot_ja3_flag;

#endif

};

bool Sagan_Check_Routing(  _Sagan_Routing *SaganRouting );

