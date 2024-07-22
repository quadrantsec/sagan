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

/* zeek-intel.c
*
* This allows Sagan to read in Bro Intel files,  like those from Critical
* Stack (https://intel.criticalstack.com).
*
*/


#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

typedef struct _ZeekIntel_Intel_Addr _ZeekIntel_Intel_Addr;
struct _ZeekIntel_Intel_Addr
{
    unsigned char bits_ip[MAXIPBIT];
};

typedef struct _ZeekIntel_Intel_Domain _ZeekIntel_Intel_Domain;
struct _ZeekIntel_Intel_Domain
{
    char domain[255];
};

typedef struct _ZeekIntel_Intel_File_Hash _ZeekIntel_Intel_File_Hash;
struct _ZeekIntel_Intel_File_Hash
{
    char hash[64];
};

typedef struct _ZeekIntel_Intel_URL _ZeekIntel_Intel_URL;
struct _ZeekIntel_Intel_URL
{
    char url[10240];
};

typedef struct _ZeekIntel_Intel_Software _ZeekIntel_Intel_Software;
struct _ZeekIntel_Intel_Software
{
    char software[128];
};

typedef struct _ZeekIntel_Intel_Email _ZeekIntel_Intel_Email;
struct _ZeekIntel_Intel_Email
{
    char email[128];
};

typedef struct _ZeekIntel_Intel_User_Name _ZeekIntel_Intel_User_Name;
struct _ZeekIntel_Intel_User_Name
{
    char username[64];
};

typedef struct _ZeekIntel_Intel_File_Name _ZeekIntel_Intel_File_Name;
struct _ZeekIntel_Intel_File_Name
{
    char file_name[128];
};

typedef struct _ZeekIntel_Intel_Cert_Hash _ZeekIntel_Intel_Cert_Hash;
struct _ZeekIntel_Intel_Cert_Hash
{
    char cert_hash[64];
};


void ZeekIntel_Init(void);
void ZeekIntel_Load_File(void);

bool ZeekIntel_IPADDR ( unsigned char *ip, const char *ipaddr );
bool ZeekIntel_IPADDR_All ( const char *syslog_message, struct _Sagan_Lookup_Cache_Entry *lookup_cache, uint_fast8_t lookup_cache_size );

bool ZeekIntel_DOMAIN ( const char *syslog_message );
bool  ZeekIntel_FILE_HASH ( const char *syslog_message );
bool  ZeekIntel_URL ( const char *syslog_message );
bool  ZeekIntel_SOFTWARE( const char *syslog_message );
bool  ZeekIntel_EMAIL( const char *syslog_message );
bool  ZeekIntel_USER_NAME ( const char *syslog_message );
bool  ZeekIntel_FILE_NAME ( const char *syslog_message );
bool  ZeekIntel_CERT_HASH ( const char *syslog_message );

