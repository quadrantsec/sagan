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

#ifdef WITH_BLUEDOT
#define BLUEDOT_MAX_CAT        10
#endif

#define		VALID_RULE_OPTIONS "parse_port,parse_proto,parse_proto_program,flexbits_upause,xbits_upause,flexbits_pause,xbits_pause,default_proto,default_src_port,default_dst_port,parse_src_ip,parse_dst_ip,parse_hash,xbits,flexbits,dynamic_load,country_code,meta_content,meta_nocase,rev,classtype,program,event_type,reference,sid,syslog_tag,syslog_facility,syslog_level,syslog_priority,pri,priority,email,normalize,msg,content,nocase,offset,meta_offset,depth,meta_depth,distance,meta_distance,within,meta_within,pcre,alert_time,threshold,after,blacklist,bro-intel,zeek-intel,external,bluedot,metadata,event_id,json_content,json_nocase,json_pcre,json_meta_content,json_meta_nocase,json_strstr,json_meta_strstr,append_program,json_contains,json_map,json_decode_base64,json_meta_contains,json_decode_base64_pcre,json_decode_base64_meta"

/* JSON Mapping in rules */

#define		JSON_MAP_SRC_IP		1
#define         JSON_MAP_DEST_IP        2
#define		JSON_MAP_SRC_PORT	3
#define         JSON_MAP_DEST_PORT      4
#define		JSON_MAP_USERNAME	5
#define		JSON_MAP_MESSAGE	6
#define		JSON_MAP_PROGRAM	7
#define         JSON_MAP_EVENT_ID       8
#define		JSON_MAP_FLOW_ID	9
#define         JSON_MAP_MD5	        10
#define         JSON_MAP_SHA1           11
#define         JSON_MAP_SHA256         12
#define         JSON_MAP_FILENAME	13
#define         JSON_MAP_HOSTNAME       14
#define         JSON_MAP_URL		15
#define         JSON_MAP_JA3            16
#define		JSON_MAP_PROTO		17

typedef struct _Rules_Loaded _Rules_Loaded;
struct _Rules_Loaded
{
    char ruleset[MAXPATH];
};

typedef struct arr_flow_1 arr_flow_1;
struct arr_flow_1
{
    struct
    {
        unsigned char ipbits[MAXIPBIT];
        unsigned char maskbits[MAXIPBIT];
    } range;
};

typedef struct arr_flow_2 arr_flow_2;
struct arr_flow_2
{
    struct
    {
        unsigned char ipbits[MAXIPBIT];
        unsigned char maskbits[MAXIPBIT];
    } range;
};

typedef struct arr_port_1 arr_port_1;
struct arr_port_1
{
    uint_fast32_t lo;
    uint_fast32_t hi;
};

typedef struct arr_port_2 arr_port_2;
struct arr_port_2
{
    uint_fast32_t lo;
    uint_fast32_t hi;
};

typedef struct meta_content_conversion meta_content_conversion;
struct meta_content_conversion
{
    char meta_content_converted[MAX_META_CONTENT_ITEMS][256];
    uint_fast16_t  meta_counter;
};

typedef struct json_meta_content_conversion json_meta_content_conversion;
struct json_meta_content_conversion
{
    char json_meta_content_converted[MAX_JSON_META_CONTENT_ITEMS][256];
    uint_fast16_t json_meta_counter;
};


typedef struct _Rule_Struct _Rule_Struct;
struct _Rule_Struct
{

    char signature_copy[RULEBUF];

    char s_msg[MAX_SAGAN_MSG];

    uint_fast32_t ruleset_id;

    pcre *re_pcre[MAX_PCRE];
    pcre_extra *pcre_extra[MAX_PCRE];

    uint_fast8_t       json_map_type[MAX_JSON_MAP];
    char               json_map_key[MAX_JSON_MAP][JSON_MAX_KEY_SIZE];
    uint_fast8_t       json_map_count;

    uint_fast8_t	rule_type;

    char content[MAX_CONTENT][256];
    char s_reference[MAX_REFERENCE][256];
    char s_classtype[32];
    uint_fast64_t s_sid;
    uint_fast32_t s_rev;
    uint_fast8_t s_pri;
    char s_program[256];
    char s_facility[50];
    char s_syspri[25];
    char s_level[25];
    char s_tag[MAX_SYSLOG_TAG_SIZE];

    char event_id[MAX_EVENT_ID][32];

    char email[255];
    bool email_flag;

    bool type;				/* 0 == normal,  1 == dynamic */
    char  dynamic_ruleset[MAXPATH];

    /* Check Flow */
    struct arr_flow_1 flow_1[MAX_CHECK_FLOWS];
    struct arr_flow_2 flow_2[MAX_CHECK_FLOWS];

    struct arr_port_1 port_1[MAX_CHECK_FLOWS];
    struct arr_port_2 port_2[MAX_CHECK_FLOWS];

    struct meta_content_conversion meta_content_containers[MAX_META_CONTENT];
    struct json_meta_content_conversion json_meta_content_containers[MAX_JSON_META_CONTENT];

    uint_fast8_t direction;

    bool flow_1_var;
    bool flow_2_var;
    bool port_1_var;
    bool port_2_var;

    bool has_flow;

    uint_fast8_t flow_1_type[MAX_CHECK_FLOWS];
    uint_fast8_t flow_2_type[MAX_CHECK_FLOWS];
    uint_fast8_t flow_1_counter;
    uint_fast32_t flow_2_counter;

    uint_fast8_t port_1_type[MAX_CHECK_FLOWS];
    uint_fast8_t port_2_type[MAX_CHECK_FLOWS];
    uint_fast8_t port_1_counter;
    uint_fast32_t port_2_counter;

    bool content_case[MAX_CONTENT];
    uint_fast32_t s_offset[MAX_CONTENT];
    uint_fast32_t s_depth[MAX_CONTENT];
    uint_fast32_t s_distance[MAX_CONTENT];
    uint_fast32_t s_within[MAX_CONTENT];

    bool meta_nocase[MAX_META_CONTENT];
    uint_fast32_t meta_offset[MAX_META_CONTENT];
    uint_fast32_t meta_depth[MAX_META_CONTENT];
    uint_fast32_t meta_distance[MAX_META_CONTENT];
    uint_fast32_t meta_within[MAX_META_CONTENT];

    uint_fast8_t pcre_count;
    uint_fast8_t content_count;
    uint_fast8_t event_id_count;
    uint_fast32_t meta_content_count;
    uint_fast16_t meta_content_converted_count;


    /* Flexbit */

    uint_fast8_t flexbit_count;				/* Number of flexbits in memory */
    uint_fast32_t flexbit_upause_time;		/* Delay to let flexbits settle */
    uint_fast16_t flexbit_pause_time;
    uint_fast8_t flexbit_condition_count;		/* Number of isset/isnot within a rule */
    uint_fast8_t flexbit_set_count;			/* Number of set/unset within a rule */
    uint_fast8_t flexbit_count_count;		/* Number of count within a rule */

    bool flexbit_flag;              	        /* Does the rule contain a flexbit? */
    bool flexbit_noalert;                       /* Do we want to suppress "alerts" from flexbits in ALL output plugins? */
    bool flexbit_noeve;				/* Do we want to suppress "eve" from flexbits */

    uint_fast8_t flexbit_type[MAX_FLEXBITS];         /* 1 == set, 2 == unset, 3 == isset, 4 == isnotset, 5 == set_srcport,
						         6 == set_dstport, 7 == set_ports, 8 == count */

    uint_fast8_t flexbit_direction[MAX_FLEXBITS];    /* 0 == none, 1 == both, 2 == by_src, 3 == by_dst */
    uint_fast32_t flexbit_timeout[MAX_FLEXBITS];                /* How long a flexbit is to stay alive (seconds) */
    char flexbit_name[MAX_FLEXBITS][64];              /* Name of the flexbit */

    uint_fast8_t flexbit_count_gt_lt[MAX_FLEXBITS];  	/* 0 == Greater, 1 == Less than, 2 == Equals. */
    uint_fast32_t flexbit_count_counter[MAX_FLEXBITS];        /* The amount the user is looking for */
    bool flexbit_count_flag;

    /* Xbit */

    uint_fast8_t xbit_count;

    bool xbit_flag;
    bool xbit_noalert;
    bool xbit_noeve;
    unsigned char xbit_direction[MAX_XBITS];	      /* 1 == ip_src, 2 == ip_dst,  3 == ip_par */

    uint_fast8_t xbit_set_count;            /* Number of set within a rule */
    uint_fast8_t xbit_unset_count;
    uint_fast8_t xbit_isset_count;
    uint_fast8_t xbit_isnotset_count;
    uint_fast8_t xbit_condition_count;
    uint_fast8_t xbit_type[MAX_XBITS];         /* 1 == set, 2 == unset, 3 == isset, 4 == isnotset, 5 == set_srcport,
                                                   6 == set_dstport, 7 == set_ports, 8 == count */

    uint_fast32_t xbit_upause_time;
    uint_fast32_t xbit_pause_time;

    char xbit_name[MAX_XBITS][64];
    uint_fast32_t xbit_name_hash[MAX_XBITS];
    uint_fast32_t xbit_expire[MAX_XBITS];

    uint_fast8_t ref_count;
    uint_fast8_t ip_proto;                               /*protocol to match against events*/

    uint_fast16_t default_dst_port;                       /*default dst port to set*/
    uint_fast16_t default_src_port;                       /*default src port to set*/
    uint_fast8_t default_proto;                          /*default protocol to set*/

    bool s_find_port;
    bool s_find_proto;
    bool s_find_proto_program;

    bool s_find_src_ip;
    uint_fast8_t s_find_src_pos;

    bool s_find_dst_ip;
    uint_fast8_t  s_find_dst_pos;

    uint_fast8_t  s_find_hash_type;

    bool normalize;
    bool content_not[MAX_CONTENT];             /* content: ! "something" */
    bool append_program;

    bool drop;                                   /* inline DROP for ext. */

#define THRESHOLD_LIMIT 1
#define THRESHOLD_SUPPRESS 2

    uint_fast8_t threshold2_type;               /* 1 = limit,  2 = threshold */
    uint_fast8_t threshold2_method;             /* 1 ==  src,  2 == dst,  3 == username, 4 == srcport, 5 == dstport */
    uint_fast32_t threshold2_count;
    uint_fast32_t threshold2_seconds;

    bool threshold2_method_src;
    bool threshold2_method_dst;
    bool threshold2_method_username;
    bool threshold2_method_srcport;
    bool threshold2_method_dstport;

    bool after2;

    bool after2_method_src;
    bool after2_method_dst;
    bool after2_method_username;
    bool after2_method_srcport;
    bool after2_method_dstport;

    uint_fast32_t after2_count;
    uint_fast32_t after2_seconds;

    bool meta_content_flag;
    bool meta_content_case[MAX_META_CONTENT];
    bool meta_content_not[MAX_META_CONTENT];

    char meta_content_help[MAX_META_CONTENT][CONFBUF];

    bool json_decode_base64[MAX_JSON_DECODE_BASE64];
    bool json_decode_base64_pcre[MAX_JSON_DECODE_BASE64];
    bool json_decode_base64_meta[MAX_JSON_DECODE_BASE64];

    bool json_content_not[MAX_JSON_CONTENT];
    char json_content_key[MAX_JSON_CONTENT][128];
    char json_content_content[MAX_JSON_CONTENT][1024];
    uint_fast32_t  json_content_count;
    bool json_content_case[MAX_JSON_CONTENT];
    bool json_content_strstr[MAX_JSON_CONTENT];

    pcre *json_re_pcre[MAX_JSON_PCRE];
    pcre_extra *json_pcre_extra[MAX_JSON_PCRE];
    uint_fast32_t  json_pcre_count;
    char json_pcre_key[MAX_JSON_PCRE][128];

    uint_fast8_t json_decode_base64_count;
    uint_fast8_t json_decode_base64_pcre_count;
    uint_fast8_t json_decode_base64_meta_count;

    bool json_meta_content_case[MAX_JSON_META_CONTENT];
    bool json_meta_content_not[MAX_JSON_META_CONTENT];
    bool json_meta_strstr[MAX_JSON_META_CONTENT];
    char json_meta_content_key[MAX_JSON_META_CONTENT][128];
    uint_fast32_t  json_meta_content_count;
    uint_fast16_t json_meta_content_converted_count;

    bool alert_time_flag;
    uint_fast8_t alert_days;
    bool aetas_next_day;

    uint_fast32_t	 aetas_start;
    uint_fast32_t     aetas_end;

    bool external_flag;
    char  external_program[MAXPATH];

    /* Bro Intel */

    bool zeekintel_flag;

    bool zeekintel_ipaddr_src;
    bool zeekintel_ipaddr_dst;
    bool zeekintel_ipaddr_both;
    bool zeekintel_ipaddr_all;

    bool zeekintel_domain;
    bool zeekintel_file_hash;
    bool zeekintel_url;
    bool zeekintel_software;
    bool zeekintel_email;
    bool zeekintel_user_name;
    bool zeekintel_file_name;
    bool zeekintel_cert_hash;

    /* Blacklist */

    bool blacklist_flag;

    bool blacklist_ipaddr_src;
    bool blacklist_ipaddr_dst;
    bool blacklist_ipaddr_both;
    bool blacklist_ipaddr_all;

#ifdef WITH_BLUEDOT

    uint_fast8_t  bluedot_ipaddr_type;                 /* 1 == src,  2 == dst,  3 == both,  4 == all */

    uint_fast16_t   bluedot_ip_cats[BLUEDOT_MAX_CAT];
    uint_fast16_t   bluedot_ip_cat_count;

    uint_fast64_t bluedot_mdate_effective_period;
    uint_fast64_t bluedot_cdate_effective_period;

    uint_fast16_t   bluedot_hash_cats[BLUEDOT_MAX_CAT];
    uint_fast16_t   bluedot_hash_cat_count;

    uint_fast16_t   bluedot_url_cats[BLUEDOT_MAX_CAT];
    uint_fast16_t   bluedot_url_cat_count;

    uint_fast16_t   bluedot_filename_cats[BLUEDOT_MAX_CAT];
    uint_fast16_t   bluedot_filename_cat_count;

    uint_fast16_t   bluedot_ja3_cats[BLUEDOT_MAX_CAT];
    uint_fast16_t   bluedot_ja3_cat_count;

    bool bluedot_file_hash;
    bool bluedot_url;
    bool bluedot_filename;
    bool bluedot_ja3;

#endif


#ifdef HAVE_LIBMAXMINDDB

    bool geoip2_flag;
    uint_fast8_t geoip2_type;           /* 1 == isnot, 2 == is */
    char  geoip2_country_codes[256];
    uint_fast8_t  geoip2_src_or_dst;             /* 1 == src, 2 == dst */

#endif

#ifdef HAVE_LIBFASTJSON
    char metadata_json[1024];
#endif

};

typedef struct _Sagan_Ruleset_Track _Sagan_Ruleset_Track;
struct _Sagan_Ruleset_Track
{
    char ruleset[MAXPATH];
    bool trigger;
};


void Load_Rules ( const char * );
