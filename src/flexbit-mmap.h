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

//bool Flexbit_Condition_MMAP ( int, char *, char *, int, int, char *, _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL );
bool Flexbit_Condition_MMAP(int rule_position, const char *ip_src, const char *ip_dst, int src_port, int dst_port, struct _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL );

void Flexbit_Cleanup_MMAP( void );
void Flexbit_Set_MMAP(int rule_position, const char *ip_src, const char *ip_dst, int src_port, int dst_port, const char *username, const char *syslog_message );
bool Flexbit_Count_MMAP( int rule_position, const char *ip_src, const char *ip_dst );

typedef struct _Sagan_Flexbit_Track _Sagan_Flexbit_Track;
struct _Sagan_Flexbit_Track
{
    char	flexbit_name[64];
    uint_fast32_t	flexbit_timeout;
    uint_fast16_t	flexbit_srcport;
    uint_fast16_t	flexbit_dstport;
};

typedef struct _Sagan_IPC_Flexbit _Sagan_IPC_Flexbit;
struct _Sagan_IPC_Flexbit
{
    char flexbit_name[64];
    bool flexbit_state;
    unsigned char ip_src[MAXIPBIT];
    unsigned char ip_dst[MAXIPBIT];
    int src_port;
    int dst_port;
    char username[64];
    uint_fast64_t flexbit_date;
    uint_fast64_t flexbit_expire;
    uint_fast32_t expire;
    char syslog_message[MAX_SYSLOGMSG];
    uint_fast64_t sid;
    char signature_msg[MAX_SAGAN_MSG];

};


