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


#include <json.h>

#include "sagan-defs.h"

/* liblognorm struct */

typedef struct liblognorm_struct liblognorm_struct;
struct liblognorm_struct
{
    char type[50];
    char filepath[MAXPATH];
};

typedef struct liblognorm_toload_struct liblognorm_toload_struct;
struct liblognorm_toload_struct
{
    char type[50];
    char filepath[MAXPATH];
};

void Liblognorm_Load( const char *infile );
void Normalize_Liblognorm( struct _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL );
void Liblognorm_Close(void);


