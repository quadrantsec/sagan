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


//void Send_Alert ( struct _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL, uint32_t rule_position, struct timeval tp, char *bluedot_json, unsigned char bluedot_results, struct _GeoIP *GeoIP_SRC, struct _GeoIP *GeoIP_DEST );

void Send_Alert ( struct _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL, uint32_t rule_position, struct timeval tp, char *bluedot_json, unsigned char bluedot_results, uint_fast16_t json_count );



