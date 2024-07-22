/* $Id$ */
/*
** Copyright (C) 2009-2024 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2024 Champ Clark III <cclark@quadrantsec.com>
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


void Xbit_Set_MMAP(uint_fast32_t rule_position, const char *ip_src_char, const char *ip_dst_char, const char *syslog_message );
bool Xbit_Condition_MMAP( uint_fast32_t rule_position, struct _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL );
void Clean_Xbit_MMAP(void);

typedef struct _Sagan_IPC_Xbit _Sagan_IPC_Xbit;
struct _Sagan_IPC_Xbit
{
    char xbit_name[64];
    uint_fast32_t xbit_hash;
    uint_fast32_t xbit_name_hash;
    uint_fast64_t xbit_expire;
    uint_fast32_t expire;
    char syslog_message[0];
    uint_fast64_t sid;
    char signature_msg[MAX_SAGAN_MSG];

};
