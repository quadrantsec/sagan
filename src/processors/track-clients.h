/*
** Copyright (C) 2009-2023 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2023 Adam Hall <ahall@quadrantsec.com>
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

/* sagan-track-clients.h
*
* Simple pre-processors that keeps track of reporting syslog clients/agents.
* This is based off the IP address the clients,  not based on normalization.
* If a client/agent hasn't sent a syslog/event message in X minutes,  then
* generate an alert.
*
*/

void Track_Clients_Thread ( void );

#include "sagan-defs.h"

typedef struct _Sagan_Track_Clients_IPC _Sagan_Track_Clients_IPC;
struct _Sagan_Track_Clients_IPC
{
    unsigned char  hostbits[MAXIPBIT];
    long       	   utime;			/* need to be long for ctime() */
    uint_fast32_t     expire;
    bool    status;
};

typedef struct _Track_Clients_Networks _Track_Clients_Networks;
struct _Track_Clients_Networks
{

    struct
    {
        unsigned char ipbits[MAXIPBIT];
        unsigned char maskbits[MAXIPBIT];
    } range;

};

void Track_Clients ( const char *host );
