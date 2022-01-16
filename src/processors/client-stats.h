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

void Client_Stats_Init( void );
void Client_Stats_Handler( void );
void Client_Stats_Add_Update_IP( const char *ip, const char *program, const char *message );
void Client_Stats_Close( void );

/* Client Stats strucure */

typedef struct _Client_Stats_Struct _Client_Stats_Struct;
struct _Client_Stats_Struct
{
    uint_fast32_t hash;
    char ip[64];
    uint_fast64_t epoch;
    uint_fast64_t old_epoch;
    char program[MAX_SYSLOG_PROGRAM];
    char message[MAX_SYSLOGMSG];
};
