/* $Id$ */
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

/* sagan.h
 *
 * Sagan prototypes and definitions.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <pcre.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <stdbool.h>

#include "sagan-defs.h"

#ifdef HAVE_LIBMAXMINDDB
#include <maxminddb.h>
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(char *, const char *, size_t );
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(char *, const char *, size_t );
#endif

/*
 * OS specific macro's for setting the thread name. "top" can display
 * this name. This was largely taken from Suricata.
 */

#if defined __FreeBSD__ /* FreeBSD */
/** \todo Add implementation for FreeBSD */
#define SetThreadName(n) ({ \
    char tname[16] = ""; \
    if (strlen(n) > 16) \
        Sagan_Log(WARN, "Thread name is too long, truncating it..."); \
    strlcpy(tname, n, 16); \
    pthread_set_name_np(pthread_self(), tname); \
    0; \
})
#elif defined __OpenBSD__ /* OpenBSD */
/** \todo Add implementation for OpenBSD */
#define SetThreadName(n) (0)
#elif defined OS_WIN32 /* Windows */
/** \todo Add implementation for Windows */
#define SetThreadName(n) (0)
#elif defined OS_DARWIN /* Mac OS X */
/** \todo Add implementation for MacOS */
#define SetThreadName(n) (0)
#elif defined HAVE_SYS_PRCTL_H /* PR_SET_NAME */
/**
 * \brief Set the threads name
 */
#define SetThreadName(n) ({ \
    char tname[THREAD_NAME_LEN + 1] = ""; \
    if (strlen(n) > THREAD_NAME_LEN) \
        Sagan_Log(WARN, "Thread name is too long, truncating it..."); \
    strlcpy(tname, n, THREAD_NAME_LEN); \
    int ret = 0; \
    if ((ret = prctl(PR_SET_NAME, tname, 0, 0, 0)) < 0) \
        Sagan_Log(WARN, "Error setting thread name \"%s\": %s", tname, strerror(errno)); \
    ret; \
})
#else
#define SetThreadName(n) (0)
#endif

bool	Is_Numeric (const char *str);
void	To_UpperC(char *const s);
void	To_LowerC(char *const s);
void    Usage( void );
void	Chroot(const char *chrootdir );
void	Remove_Spaces(char *s);
void	Remove_Return(char *s);
int	Classtype_Lookup( const char *classtype, char *str, size_t size );
void	Between_Quotes( const char *in_str, char *str, size_t size, const char *filename, uint32_t line_number );
double	CalcPct(uint64_t cnt, uint64_t total);
void	Replace_String(const char *in_str, char *orig, char *rep, char *str, size_t size);
uint64_t Value_To_Seconds(char *type, uint64_t number);
void    Sagan_Log (uint_fast8_t type, const char *format,... );
void	Droppriv( void );
int     DNS_Lookup( const char *host, char *str, size_t size );
void	Var_To_Value(const char *in_str, char *str, size_t size);
bool	IP2Bit(const char *ipaddr, unsigned char *out);
bool	Mask2Bit(int mask, unsigned char *out);
const char *Bit2IP(unsigned char *ipbits, char *str, size_t size);
bool 	Validate_HEX (const char *string);
void	Content_Pipe( const char *in_string, int linecount, const char *ruleset, char *str, size_t size );
bool    is_notroutable ( unsigned char *ip );
void    IPv6_Strip_FFFF( char *ip );
bool    is_notlocalhost ( unsigned char *ip );
bool    is_inrange ( unsigned char *ip, unsigned char *tests, int count);
void    Replace_Sagan( const char *in_str, char *replace, char *str, size_t size);
bool	Wildcard( char *first, char *second );
void	Open_Log_File( bool state, int type );
int	Check_Var(const char *string);
int	Netaddr_To_Range( char *ipstr, unsigned char *out );
void	Strip_Chars(const char *string, const char *chars, char *str);
bool	Is_IP (const char *ipaddr, int ver );
bool	File_Lock ( int fd );
bool    File_Unlock ( int fd );
bool    Check_Content_Not( const char *s );
uint_fast32_t Djb2_Hash(const char *str);
bool    Starts_With(const char *str, const char *prefix);
bool	Is_IP_Range (char *str);
bool    ValidateMessage( const char *message );

#if defined(F_GETPIPE_SZ) && defined(F_SETPIPE_SZ)
void      Set_Pipe_Size( FILE * );
#endif


#ifdef __OpenBSD__
/* OpenBSD won't allow for this test:
 * "suricata(...): mprotect W^X violation" */
#ifndef PageSupportsRWX()
#define PageSupportsRWX() 0
#endif
#else
#ifndef HAVE_SYS_MMAN_H
#define PageSupportsRWX() 1
#else
int       PageSupportsRWX(void);
#endif /* HAVE_SYS_MMAN_H */
#endif

typedef struct _SaganDNSCache _SaganDNSCache;
struct _SaganDNSCache
{

    char hostname[64];
    char src_ip[20];
};

typedef struct _Sagan_IPC_Counters _Sagan_IPC_Counters;
struct _Sagan_IPC_Counters
{

    double version;

    uint_fast32_t flexbit_count;
    uint_fast32_t xbit_count;

    uint_fast32_t thresh2_count;
    uint_fast32_t after2_count;

    uint_fast32_t track_client_count;
    uint_fast32_t track_clients_client_count;
    uint_fast32_t track_clients_down;

};

typedef struct _SaganCounters _SaganCounters;
struct _SaganCounters
{

    uint_fast64_t threshold_total;
    uint_fast64_t after_total;
    uint_fast64_t events_received;
    uint_fast64_t events_processed;
    uint_fast64_t saganfound;
    uint_fast64_t sagan_output_drop;
    uint_fast64_t sagan_processor_drop;
    uint_fast64_t sagan_log_drop;
    uint_fast64_t dns_cache_count;
    uint_fast64_t dns_miss_count;
    uint_fast64_t ignore_count;
    uint_fast64_t blacklist_count;
    uint_fast64_t bytes_total;
    uint_fast64_t max_bytes_length;
    uint_fast64_t max_bytes_over;
    uint_fast64_t bytes_ignored;
    uint_fast64_t null_message;

    uint_fast64_t alert_total;

    uint_fast64_t malformed_host;
    uint_fast64_t malformed_facility;
    uint_fast64_t malformed_priority;
    uint_fast64_t malformed_level;
    uint_fast64_t malformed_tag;
    uint_fast64_t malformed_date;
    uint_fast64_t malformed_time;
    uint_fast64_t malformed_program;
    uint_fast64_t malformed_message;

    uint_fast64_t worker_thread_exhaustion;
    uint_fast16_t max_threads_used;

    uint_fast32_t ruleset_track_count;

    uint_fast64_t blacklist_hit_count;
    uint_fast64_t blacklist_lookup_count;

    uint_fast32_t client_stats_count;

    uint_fast32_t	     flexbit_total_counter;
    uint_fast32_t	     xbit_total_counter;
    uint_fast32_t 	     var_count;
    uint_fast32_t     	     dynamic_rule_count;
    uint_fast16_t	     classcount;
    uint_fast32_t  	     rulecount;
    uint_fast16_t	     refcount;
    uint_fast32_t	     ruletotal;
    uint_fast16_t	     genmapcount;

    uint_fast16_t      mapcount_message;
    uint_fast16_t      mapcount_program;

    uint_fast32_t     droplist_count;

    uint_fast32_t      zeekintel_addr_count;
    uint_fast32_t      zeekintel_domain_count;
    uint_fast32_t      zeekintel_file_hash_count;
    uint_fast32_t      zeekintel_url_count;
    uint_fast32_t      zeekintel_software_count;
    uint_fast32_t      zeekintel_email_count;
    uint_fast32_t      zeekintel_user_name_count;
    uint_fast32_t      zeekintel_file_name_count;
    uint_fast32_t      zeekintel_cert_hash_count;
    uint_fast32_t      zeekintel_dups;

    uint_fast32_t	      rules_loaded_count;

    uint_fast64_t follow_flow_total;	 /* This will only be needed if follow_flow is an option */
    uint_fast64_t follow_flow_drop;   /* Amount of flows that did not match and were dropped */

    uint_fast64_t track_clients_count;

#ifdef HAVE_LIBMAXMINDDB
    uint_fast64_t geoip2_hit;				/* GeoIP hit count */
    uint_fast64_t geoip2_lookup;				/* Total lookups */
    uint_fast64_t geoip2_error;				/* Lookup Errors */
    uint_fast64_t geoip_skip_count;
#endif

#ifdef WITH_BLUEDOT
    uint_fast64_t bluedot_ip_cache_count;                      /* Bluedot cache processor */
    uint_fast64_t bluedot_ip_cache_hit;                        /* Bluedot hit's from Cache */
    uint_fast64_t bluedot_ip_positive_hit;
    uint_fast64_t bluedot_ip_total;

    uint_fast64_t  bluedot_skip_count;

    uint_fast16_t bluedot_ip_queue_current;
    uint_fast16_t bluedot_hash_queue_current;
    uint_fast16_t bluedot_url_queue_current;
    uint_fast16_t bluedot_filename_queue_current;
    uint_fast16_t bluedot_ja3_queue_current;

    uint_fast64_t bluedot_mdate;					   /* Hits , but where over a modification date */
    uint_fast64_t bluedot_cdate;            	                   /* Hits , but where over a creation date */
    uint_fast64_t bluedot_mdate_cache;                                 /* Hits from cache , but where over a modification date */
    uint_fast64_t bluedot_cdate_cache;      			   /* Hits from cache , but where over a create date */
    uint_fast64_t bluedot_error_count;

    uint_fast64_t bluedot_hash_cache_count;
    uint_fast64_t bluedot_hash_cache_hit;
    uint_fast64_t bluedot_hash_positive_hit;
    uint_fast64_t bluedot_hash_total;

    uint_fast64_t bluedot_url_cache_count;
    uint_fast64_t bluedot_url_cache_hit;
    uint_fast64_t bluedot_url_positive_hit;
    uint_fast64_t bluedot_url_total;

    uint_fast64_t bluedot_filename_cache_count;
    uint_fast64_t bluedot_filename_cache_hit;
    uint_fast64_t bluedot_filename_positive_hit;
    uint_fast64_t bluedot_filename_total;

    uint_fast64_t bluedot_ja3_cache_count;
    uint_fast64_t bluedot_ja3_cache_hit;
    uint_fast64_t bluedot_ja3_positive_hit;
    uint_fast64_t bluedot_ja3_total;

    uint_fast16_t bluedot_cat_count;

#endif


#ifdef HAVE_LIBESMTP
    uint_fast64_t esmtp_count_success;
    uint_fast64_t esmtp_count_failed;
#endif

#ifdef HAVE_LIBHIREDIS
    uint_fast64_t redis_writer_threads_drop;
#endif

#ifdef HAVE_LIBFASTJSON

    uint_fast64_t malformed_json_input_count;

    uint_fast64_t json_mp_count;
    uint_fast64_t malformed_json_mp_count;

#endif


};

typedef struct _SaganDebug _SaganDebug;
struct _SaganDebug
{

    bool debugsyslog;
    bool debugload;
    bool debugexternal;
    bool debugthreads;
    bool debugflexbit;
    bool debugxbit;
    bool debugengine;
    bool debugbrointel;
    bool debugmalformed;
    bool debuglimits;
    bool debugipc;
    bool debugjson;
    bool debugparse_ip;
    bool debugclient_stats;
    bool debugtrack_clients;

#ifdef HAVE_LIBMAXMINDDB
    bool debuggeoip2;
#endif

#ifdef HAVE_LIBLOGNORM
    bool debugnormalize;
#endif

#ifdef HAVE_LIBESMTP
    bool debugesmtp;
#endif

#ifdef HAVE_LIBPCAP
    bool debugplog;
#endif

#ifdef WITH_BLUEDOT
    bool debugbluedot;
#endif

#ifdef HAVE_LIBHIREDIS
    bool debugredis;
#endif

};

typedef struct _Sagan_Proc_Syslog _Sagan_Proc_Syslog;
struct _Sagan_Proc_Syslog
{

    char *syslog_host;
    char *syslog_facility;
    char *syslog_priority;
    char *syslog_level;
    char *syslog_tag;
    char *syslog_date;
    char *syslog_time;
    char *syslog_program;
    char *syslog_message;

    char *src_ip;
    char *dst_ip;

    char *src_host;
    char *dst_host;

    bool ip_src_is_valid;
    bool ip_dst_is_valid;

    bool port_src_is_valid;
    bool port_dst_is_valid;

    unsigned char ip_src_bits[MAXIPBIT];
    unsigned char ip_dst_bits[MAXIPBIT];
    unsigned char syslog_bits[MAXIPBIT];

    uint_fast16_t src_port;
    uint_fast16_t dst_port;
    uint_fast8_t proto;

    uint_fast64_t flow_id;

    char *event_id;

    char *md5;
    char *sha1;
    char *sha256;
    char *filename;
    char *hostname;
    char *url;
    char *ja3;
    char *username;

    char *json_normalize;
    char *json_original;

#ifdef HAVE_LIBFASTJSON
    char *correlation_json;
#endif

};

/* Don't #ifdef,  because we still need placeholders even when
 * JSON isn't enabled */

typedef struct _Sagan_JSON _Sagan_JSON;
struct _Sagan_JSON
{

    uint_fast16_t json_count;
    char *json_key[JSON_MAX_OBJECTS];
    char *json_value[JSON_MAX_OBJECTS];

};

typedef struct _Sagan_Pass_Syslog _Sagan_Pass_Syslog;
struct _Sagan_Pass_Syslog
{
    char *batch[MAX_SYSLOG_BATCH];
};

#ifdef HAVE_LIBFASTJSON

typedef struct _Syslog_JSON_Map _Syslog_JSON_Map;
struct _Syslog_JSON_Map
{

    char syslog_map_host[JSON_INPUT_S_SOURCE_MAX_COUNT][JSON_INPUT_S_SOURCE_MAX_SIZE];
    uint_fast8_t syslog_map_host_count;

    char syslog_map_facility[JSON_INPUT_FACILITY_MAX_COUNT][JSON_INPUT_FACILITY_MAX_SIZE];
    uint_fast8_t syslog_map_facility_count;

    char syslog_map_level[JSON_INPUT_LEVEL_MAX_COUNT][JSON_INPUT_LEVEL_MAX_SIZE];
    uint_fast8_t syslog_map_level_count;

    char syslog_map_priority[JSON_INPUT_PRIORITY_MAX_COUNT][JSON_INPUT_PRIORITY_MAX_SIZE];
    uint_fast8_t syslog_map_priority_count;

    char syslog_map_tag[JSON_INPUT_TAG_MAX_COUNT][JSON_INPUT_TAG_MAX_SIZE];
    uint_fast8_t syslog_map_tag_count;

    char syslog_map_program[JSON_INPUT_PROGRAM_MAX_COUNT][JSON_INPUT_PROGRAM_MAX_SIZE];
    uint_fast8_t syslog_map_program_count;

    char syslog_map_message[JSON_INPUT_MESSAGE_MAX_COUNT][JSON_INPUT_MESSAGE_MAX_SIZE];
    uint_fast8_t syslog_map_message_count;

    char syslog_map_time[JSON_INPUT_TIME_MAX_COUNT][JSON_INPUT_TIME_MAX_SIZE];
    uint_fast8_t syslog_map_time_count;

    char syslog_map_date[JSON_INPUT_DATE_MAX_COUNT][JSON_INPUT_DATE_MAX_SIZE];
    uint_fast8_t syslog_map_date_count;

    /* non-syslog maps */

    char username[JSON_INPUT_USERNAME_MAX_COUNT][JSON_INPUT_USERNAME_MAX_SIZE];
    uint_fast8_t username_count;

    char src_ip[JSON_INPUT_SRCIP_MAX_COUNT][JSON_INPUT_SRCIP_MAX_SIZE];
    uint_fast8_t src_ip_count;

    char dst_ip[JSON_INPUT_DSTIP_MAX_COUNT][JSON_INPUT_DSTIP_MAX_SIZE];
    uint_fast8_t dst_ip_count;

    char src_port[JSON_INPUT_SRCPORT_MAX_COUNT][JSON_INPUT_SRCPORT_MAX_SIZE];
    uint_fast8_t src_port_count;

    char dst_port[JSON_INPUT_DSTPORT_MAX_COUNT][JSON_INPUT_DSTPORT_MAX_SIZE];
    uint_fast8_t dst_port_count;

    char md5[JSON_INPUT_MD5_MAX_COUNT][JSON_INPUT_MD5_MAX_SIZE];
    uint_fast8_t md5_count;

    char sha1[JSON_INPUT_SHA1_MAX_COUNT][JSON_INPUT_SHA1_MAX_SIZE];
    uint_fast8_t sha1_count;

    char sha256[JSON_INPUT_SHA256_MAX_COUNT][JSON_INPUT_SHA256_MAX_SIZE];
    uint_fast8_t sha256_count;

    char filename[JSON_INPUT_FILENAME_MAX_COUNT][JSON_INPUT_FILENAME_MAX_SIZE];
    uint_fast8_t filename_count;

    char hostname[JSON_INPUT_HOSTNAME_MAX_COUNT][JSON_INPUT_HOSTNAME_MAX_SIZE];
    uint_fast8_t hostname_count;

    char url[JSON_INPUT_URL_MAX_COUNT][JSON_INPUT_URL_MAX_SIZE];
    uint_fast8_t url_count;

    char ja3[JSON_INPUT_JA3_MAX_COUNT][JSON_INPUT_JA3_MAX_SIZE];
    uint_fast8_t ja3_count;

    char flow_id[JSON_INPUT_FLOW_ID_MAX_COUNT][JSON_INPUT_FLOW_ID_MAX_SIZE];
    uint_fast8_t flow_id_count;

    char event_id[JSON_INPUT_EVENT_ID_MAX_COUNT][JSON_INPUT_EVENT_ID_MAX_SIZE];
    uint_fast8_t event_id_count;

    char proto[JSON_INPUT_PROTO_MAX_COUNT][JSON_INPUT_PROTO_MAX_SIZE];
    uint_fast8_t proto_count;

};

#endif

typedef struct _Sagan_Event _Sagan_Event;
struct _Sagan_Event
{

    char *ip_src;
    char *ip_dst;
    uint_fast16_t dst_port;
    uint_fast16_t src_port;

    struct timeval event_time;

    uint_fast32_t rule_position;

    char *fpri;             /* *priority */

    bool endian;
    bool drop;

    char *f_msg;

    /* message information */

    char *time;
    char *date;

    char *priority;         /* Syslog priority */
    char *host;
    char *facility;
    char *level;
    char *tag;
    char *program;
    char *message;

    char *bluedot_json;
    uint_fast8_t bluedot_results;

    uint_fast64_t sid;
    uint_fast32_t rev;

    char *class;
    int pri;
    uint_fast8_t ip_proto;

    char *normalize_http_uri;
    char *normalize_http_hostname;

    uint_fast64_t alertid;

    uint_fast64_t flow_id;

#ifdef HAVE_LIBLOGNORM

    char *json_normalize;

#endif

#ifdef HAVE_LIBFASTJSON

    char *correlation_json;

#endif


};

typedef struct _Threshold2_IPC _Threshold2_IPC;
struct _Threshold2_IPC
{

    uint_fast32_t hash;

    bool threshold2_method_src;
    bool threshold2_method_dst;
    bool threshold2_method_username;
    bool threshold2_method_srcport;
    bool threshold2_method_dstport;

    char ip_src[MAXIP];
    char ip_dst[MAXIP];

    uint_fast16_t src_port;
    uint_fast16_t dst_port;
    char username[MAX_USERNAME_SIZE];

    uint_fast64_t count;
    uint_fast64_t target_count;

    uint_fast64_t utime;
    uint_fast64_t sid;
    uint_fast32_t expire;
    char syslog_message[0];
    char signature_msg[MAX_SAGAN_MSG];
};


typedef struct _After2_IPC _After2_IPC;
struct _After2_IPC
{

    uint_fast32_t hash;

    bool after2_method_src;
    bool after2_method_dst;
    bool after2_method_username;
    bool after2_method_srcport;
    bool after2_method_dstport;

    char ip_src[MAXIP];
    char ip_dst[MAXIP];

    uint_fast16_t src_port;
    uint_fast16_t dst_port;
    char username[MAX_USERNAME_SIZE];

    uint_fast64_t count;
    uint_fast64_t target_count;

    uint_fast64_t utime;
    uint_fast64_t sid;
    uint_fast32_t rev;

    uint_fast32_t expire;
    char syslog_message[0];
    char signature_msg[MAX_SAGAN_MSG];
};

typedef struct _SaganVar _SaganVar;
struct _SaganVar
{
    char var_name[MAX_VAR_NAME_SIZE];
    char var_value[MAX_VAR_VALUE_SIZE];
};

/* IP Lookup cache */

typedef struct _Sagan_Lookup_Cache_Entry _Sagan_Lookup_Cache_Entry;
struct _Sagan_Lookup_Cache_Entry
{
    char ip[MAXIP];
    unsigned char ip_bits[MAXIPBIT];
    uint_fast16_t port;
    uint_fast8_t proto;
    bool status;
};

typedef struct _Sagan_Lookup_Cache_Entry _Sagan_Lookup_Cache_Other;
struct _Sagan_Lookup_Cache_Other
{
    uint_fast8_t proto;
};

/* Function that require the above arrays */

int_fast64_t FlowGetId( struct timeval tp );

