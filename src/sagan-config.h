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

#ifdef HAVE_LIBHIREDIS
#include <hiredis/hiredis.h>
#endif

/* Sagan configuration struct (global) */

typedef struct _SaganConfig _SaganConfig;
struct _SaganConfig
{

    /* Non-dependent var's */

    bool 	 sagan_reload;
    bool	 daemonize;
    bool	 quiet;

    unsigned char	input_type;

#ifdef HAVE_LIBFASTJSON

    char	 json_input_map_file[MAXPATH];
    char	 json_input_software[64];
    bool	 json_parse_data;

#endif

    bool	 liblognorm_load;

    const char	 *sagan_runas;
    char         sagan_config[MAXPATH];                 /* Master Sagan configuration file */

    bool	 alert_flag;

    bool	 	eve_flag; 			/* 0 = file */
    uint_fast8_t 	eve_type;
    char		eve_interface[32];
    char 		eve_filename[MAXPATH];

    bool		eve_alerts;
    bool		eve_alerts_base64;
    bool		eve_logs;

    bool	rules_from_file_flag;
    char	rules_from_file[MAXPATH];

    char         sagan_alert_filepath[MAXPATH];

    char	 sagan_sensor_name[64];
    char	 sagan_cluster_name[64];
    char         sagan_interface[50];

    char         sagan_log_filepath[MAXPATH];

    FILE         *sagan_log_stream;
    int		 sagan_log_stream_int;

    char         sagan_lockfile_full[MAXPATH];
    char	 sagan_lockfile[MAXPATH];
    char	 sagan_lockpath[MAXPATH];

    bool	 chown_fifo;
    bool	 sagan_log_syslog;

    char         sagan_fifo[MAXPATH];
    bool         sagan_is_file;                       /* FIFO or FILE */
    char         sagan_log_path[MAXPATH];
    char         sagan_rule_path[MAXPATH];
    char         sagan_host[MAXHOST];
    char         sagan_startutime[20];                  /* Records utime at startup */
    char         home_net[MAXPATH];
    char         external_net[MAXPATH];

    bool 	 xbit_storage;				/* 0 == mmap, 1 == redis */

    uint32_t     message_buffer_size;


    char         sagan_droplistfile[MAXPATH];           /* Log lines to "ignore" */
    bool         sagan_droplist_flag;

    bool         output_thread_flag;

    uint_fast16_t	max_processor_threads;
    uint_fast8_t	 max_batch;

    uint_fast16_t     sagan_port;
    bool         disable_dns_warnings;
    bool         syslog_src_lookup;
    uint_fast16_t          sagan_proto;
    char 	 *sagan_proto_string;

    bool	 pcre_jit; 				/* For PCRE JIT support testing */

    bool         endian;

    bool 	 fast_flag;
    char         fast_filename[MAXPATH];

//    bool	 parse_ip_ipv6;
//    bool	 parse_ip_ipv4_mapped_ipv6;

#ifdef WITH_SYSLOG

    bool	 rule_tracking_flag;
    bool	 rule_tracking_console;
    bool         rule_tracking_syslog;
    uint_fast32_t rule_tracking_time;

#endif

    /* Processors */

    uint_fast32_t        pp_sagan_track_clients;
    bool       sagan_track_clients_flag;

    bool        blacklist_flag;
    char        blacklist_files[2048];

    bool        client_stats_flag;
    bool	client_stats_type;
    bool	client_stats_private_only;
    char 	client_stats_file_name[MAXPATH];
    uint_fast32_t 	client_stats_time;
    uint_fast16_t	client_stats_interval;
    uint_fast32_t 	client_stats_max;

    bool        client_stats_file_stream_status;
    FILE	*client_stats_file_stream;
    int		client_stats_file_stream_int;

    bool	stats_json_sub_old_values;
    bool	stats_json_flag;
    bool	stats_json_file_stream_status;
    FILE	*stats_json_file_stream;
    int		stats_json_file_stream_int;
    char	stats_json_filename[MAXPATH];
    uint_fast32_t	stats_json_time;

    /* Dynamic rule loading and reporting */

    bool		dynamic_load_flag;
    uint_fast16_t	dynamic_load_sample_rate;
    uint_fast8_t	dynamic_load_type;

    /* Syslog output */

    bool	sagan_syslog_flag;
    int		sagan_syslog_facility;
    int		sagan_syslog_priority;
    int		sagan_syslog_options;

    int		shm_counters;
    bool	shm_counters_status;

    int		shm_flexbit;
    bool	shm_flexbit_status;

    int		shm_xbit;
    bool        shm_xbit_status;

    int		shm_thresh2;
    bool	shm_thresh2_status;

    int	 	shm_after2;
    bool	shm_after2_status;

    int		shm_track_clients;
    bool	shm_track_clients_status;

    /* IPC sizes for threshold, after, etc */

    char	ipc_directory[MAXPATH];

    uint_fast32_t	max_flexbits;
    uint_fast32_t	max_xbits;
    uint_fast32_t	max_threshold2;
    uint_fast32_t	max_after2;
    uint_fast32_t	max_track_clients;

#ifdef HAVE_LIBPCAP
    char        plog_interface[50];
    char        plog_logdev[50];
    char        plog_filter[256];
    bool        plog_flag;
    bool        plog_promiscuous;
#endif

    /* Redis/hiredis support */

#ifdef HAVE_LIBHIREDIS

    redisContext *c_reader_redis;

    bool 	redis_flag;
    char	redis_server[255];
    uint_fast16_t		redis_port;
    char	redis_password[255];

    uint_fast8_t redis_max_writer_threads;

#endif

    /* libesmtp/SMTP support */

#ifdef HAVE_LIBESMTP
    bool       sagan_sendto_flag;
    char        sagan_esmtp_from[255];
    char        sagan_esmtp_server[255];
    bool       sagan_esmtp_flag;
    char        sagan_email_subject[64];
#endif

    /* Bluedot */

#ifdef WITH_BLUEDOT
    bool        bluedot_flag;
    char         bluedot_device_id[64];
    char	 bluedot_host[128];
    char	 bluedot_ip[64];
    uint_fast32_t		 bluedot_dns_ttl;
    uint_fast64_t	 bluedot_dns_last_lookup;
    char         bluedot_uri[256];
    char         bluedot_auth[64];
    char         bluedot_cat[MAXPATH];
    uint_fast32_t         bluedot_timeout;
    uint_fast32_t         bluedot_ip_max_cache;
    uint_fast32_t	  bluedot_hash_max_cache;
    uint_fast32_t	  bluedot_url_max_cache;
    uint_fast32_t 	  bluedot_filename_max_cache;
    uint_fast32_t	  bluedot_ja3_max_cache;
    uint_fast32_t         bluedot_last_time;                    /* For cache cleaning */

    uint_fast16_t		 bluedot_ip_queue;
    uint_fast16_t		 bluedot_hash_queue;
    uint_fast16_t		 bluedot_url_queue;
    uint_fast16_t		 bluedot_filename_queue;
    uint_fast16_t		 bluedot_ja3_queue;

#endif


    /* Zeek Intel Framework Support */

    bool	 zeekintel_flag;
    char	 zeekintel_files[2048];

    /* For Maxmind GeoIP2 address lookup */

#ifdef HAVE_LIBMAXMINDDB

    MMDB_s 	geoip2;
    char        geoip2_country_file[MAXPATH];
    bool 	have_geoip2;

#endif

    /* Used for altering pipe size (if supported) */

#if defined(HAVE_GETPIPE_SZ) && defined(HAVE_SETPIPE_SZ)
    uint_fast32_t          sagan_fifo_size;
#endif

};


