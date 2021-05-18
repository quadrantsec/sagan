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

#include "parsers/strstr-asm/strstr-hook.h"

int Parse_IP( char *syslog_message, struct _Sagan_Lookup_Cache_Entry *lookup_cache );

uint_fast16_t Parse_Src_Port ( const char *msg );
uint_fast16_t Parse_Dst_Port ( const char *msg );

//int   Parse_Dst_Port( char * );
int   Parse_Proto( char * );
int   Parse_Proto_Program( char * );
void  Parse_Hash(char *syslog_message, uint_fast8_t type, char *str, size_t size);
void  Parse_Hash_Cleanup(char *, char *str, size_t size );

/* IP Lookup cache */


