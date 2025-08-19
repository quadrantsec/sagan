/*
** Copyright (C) 2009-2025 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2025 Champ Clark III <cclark@quadrantsec.com>
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

/* rules.c
 *
 * Loads and parses the rule files into memory
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include <pcre.h>

#include "version.h"

#include "sagan.h"
#include "sagan-defs.h"

#include "flexbit.h"
#include "flexbit-mmap.h"
#include "lockfile.h"
#include "classifications.h"
#include "util-base64.h"
#include "rules.h"
#include "sagan-config.h"
#include "parsers/parsers.h"

#ifdef WITH_BLUEDOT
#include "processors/bluedot.h"
#endif

#ifdef HAVE_LIBFASTJSON
#include <json.h>
#endif

#ifdef WITH_OFFLOAD
bool offload_flag = false;
#endif

extern struct _SaganCounters *counters;
extern struct _SaganDebug *debug;
extern struct _SaganConfig *config;

#ifdef WITH_BLUEDOT
extern struct _Sagan_Bluedot_Cat_List *SaganBluedotCatList;

char *bluedot_time = NULL;
char *bluedot_type = NULL;

uint64_t bluedot_time_u32 = 0;
#endif

#ifdef HAVE_LIBLOGNORM
#include "liblognormalize.h"
extern struct liblognorm_struct *liblognormstruct;
extern struct liblognorm_toload_struct *liblognormtoloadstruct;
extern int liblognorm_count;
#endif

/* For pre-8.20 PCRE compatibility */

#ifndef PCRE_STUDY_JIT_COMPILE
#define PCRE_STUDY_JIT_COMPILE 0
#endif

struct _Rule_Struct *rulestruct = NULL;
struct _Class_Struct *classstruct = NULL;
struct _Sagan_Ruleset_Track *Ruleset_Track = NULL;

void Load_Rules( const char *ruleset )
{

    struct stat filecheck;

    /* This is done for stanity check */

    char valid_rules[2048] = { 0 };
    bool is_valid = false;
    uint8_t valid = 0;

    bool found = 0;

    const char *error;
    int erroffset;

    FILE *rulesfile;
    char ruleset_fullname[MAXPATH] = { 0 };

    char *rulestring;
    char *netstring;

    char nettmp[64] = { 0 };

    char *tokenrule;
    char *tokennet;
    char *rulesplit;
    char *arg;
    char *saveptrnet;
    char *saveptrrule1;
    char *saveptrrule2;
    char *saveptrrule3=NULL;
    char *saveptrflow;
    char *saveptrport;
    char *saveptrportrange;
    char *saveptrcheck;
    char *tmptoken;

    char *tok_tmp;
    char *tmptok_tmp;
    char *ptmp=NULL;
    char *tok = NULL;

    char *after_value1;
    char *after_value2;
    char *after_value3;

    char tmp_help[CONFBUF] = { 0 };
    char tok_help[64] = { 0 };
    char tok_help2[64] = { 0 };

    char netstr[RULEBUF] = { 0 };
    char rulestr[RULEBUF] = { 0 };
    char rulebuf[RULEBUF] = { 0 };

    char pcrerule[MAX_PCRE_SIZE] = { 0 };

    char tmp4[MAX_CHECK_FLOWS * 10] = { 0 };
    char tmp3[MAX_CHECK_FLOWS * 21] = { 0 };
    char tmp2[MAX_VAR_VALUE_SIZE] = { 0 };
    char tmp[2] = { 0 };
    char tmp1[CONFBUF] = { 0 };

    char rule_tmp[MAX_VAR_VALUE_SIZE] = { 0 };

    char final_content[512] = { 0 };

    char flow_a[MAX_VAR_VALUE_SIZE] = { 0 };
    char flow_b[MAX_VAR_VALUE_SIZE] = { 0 };

    char alert_time_tmp[10] = { 0 };
    char alert_tmp_minute[3] = { 0 };
    char alert_tmp_hour[3] = { 0 };
    char alert_time_all[5] = { 0 } ;

    uint32_t linecount=0;
    uint8_t netcount=0;
    uint8_t ref_count=0;

    uint8_t content_count=0;
    uint8_t json_content_count=0;

    uint16_t json_map_count=0;
    uint32_t meta_content_count=0;

#ifdef HAVE_LIBFASTJSON
    uint16_t json_decode_base64_count=0;		/* For json_content */
    uint16_t json_decode_base64_pcre_count=0;		/* For json_pcre */
    uint16_t json_decode_base64_meta_count=0;           /* For json_meta_content */
#endif

    uint16_t meta_content_converted_count=0;
    uint16_t json_meta_content_converted_count=0;
    uint8_t json_pcre_count=0;
    uint32_t json_meta_content_count=0;
    uint8_t pcre_count=0;
    uint8_t event_id_count;

    uint8_t flexbit_count;
    uint8_t xbit_count;

    uint32_t flow_1_count=0;
    uint32_t flow_2_count=0;
    uint32_t port_1_count=0;
    uint32_t port_2_count=0;

    bool pcreflag = false;

    int pcreoptions=0;

    uint32_t i=0;
    uint8_t d=0;

    int rc=0;

    uint_fast8_t z = 0;

    uint32_t forward=0;
    uint32_t reverse=0;

    int is_masked = 0;

    uint32_t ruleset_track_id = 0;

#ifdef HAVE_LIBFASTJSON

    bool meta_bool = false;
    char *saveptrmeta = NULL;
    char meta_key[32] = { 0 };
    unsigned char metadata_array_count = 0;

    json_object *metadata_jobj = json_object_new_object();
    json_object *metadata_jstring;
    json_object *metadata_jarray[MAX_METADATA];

#endif

    /* Store rule set names/path in memory for later usage dynamic loading, etc */

    strlcpy(ruleset_fullname, ruleset, sizeof(ruleset_fullname));

    if (( rulesfile = fopen(ruleset_fullname, "r" )) == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Cannot open rule file (%s - %s)", __FILE__, __LINE__, ruleset_fullname, strerror(errno));
        }

    Ruleset_Track = (_Sagan_Ruleset_Track *) realloc(Ruleset_Track, (counters->ruleset_track_count+1) * sizeof(_Sagan_Ruleset_Track));

    if ( Ruleset_Track == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for _Sagan_Ruleset_Track. Abort!", __FILE__, __LINE__);
        }

    memset(&Ruleset_Track[counters->ruleset_track_count], 0, sizeof(struct _Sagan_Ruleset_Track));

    strlcpy(Ruleset_Track[counters->ruleset_track_count].ruleset, ruleset_fullname, sizeof(Ruleset_Track[counters->ruleset_track_count].ruleset));

    ruleset_track_id = counters->ruleset_track_count;

    __atomic_add_fetch(&counters->ruleset_track_count, 1, __ATOMIC_SEQ_CST);

    Sagan_Log(NORMAL, "Loading %s rule file.", ruleset_fullname);

    while ( fgets(rulebuf, sizeof(rulebuf), rulesfile) != NULL )
        {
            /* Reset for next rule */

            pcre_count=0;
            json_pcre_count=0;
            json_meta_content_count=0;
	    json_meta_content_converted_count=0;
            content_count=0;
            json_content_count=0;
            json_map_count=0;
            meta_content_count=0;
            meta_content_converted_count=0;
            flexbit_count=0;
            xbit_count=0;
            netcount=0;
            ref_count=0;
            flow_1_count=0;
            flow_2_count=0;
            port_1_count=0;
            port_2_count=0;

            memset(netstr, 0, sizeof(netstr));
            memset(rulestr, 0, sizeof(rulestr));

            int f1=0; /* Need for flow_direction, must reset every rule, not every group */
            int f2=0; /* Need for flow_direction, must reset every rule, not every group */
            int g1=0; /* Need for port_direction, must reset every rule, not every group */
            int g2=0; /* Need for port_direction, must reset every rule, not every group */

            linecount++;

            if (rulebuf[0] == '#' || rulebuf[0] == 10 || rulebuf[0] == ';' || rulebuf[0] == 32)
                {

                    continue;

                }
            else
                {

                    /* Allocate memory for rules, but not comments */

                    rulestruct = (_Rule_Struct *) realloc(rulestruct, (counters->rulecount+1) * sizeof(_Rule_Struct));

                    if ( rulestruct == NULL )
                        {
                            Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for rulestruct. Abort!", __FILE__, __LINE__);
                        }

                    /* Init some memory segments */

                    rulestruct[counters->rulecount].s_classtype[0] = '\0';
                    rulestruct[counters->rulecount].s_program[0] = '\0';
                    rulestruct[counters->rulecount].s_facility[0] = '\0';
                    rulestruct[counters->rulecount].s_level[0] = '\0';
                    rulestruct[counters->rulecount].s_tag[0] = '\0';
                    rulestruct[counters->rulecount].s_syspri[0] = '\0';
                    rulestruct[counters->rulecount].email[0] = '\0';
                    rulestruct[counters->rulecount].dynamic_ruleset[0] = '\0';

                    rulestruct[counters->rulecount].pcre_count = 0;
                    rulestruct[counters->rulecount].content_count = 0;
                    rulestruct[counters->rulecount].event_id_count = 0;
                    rulestruct[counters->rulecount].meta_content_converted_count = 0;

                    rulestruct[counters->rulecount].flexbit_count = 0;
                    rulestruct[counters->rulecount].xbit_count = 0;

                    rulestruct[counters->rulecount].ref_count = 0;
                    rulestruct[counters->rulecount].ip_proto = 0;
                    rulestruct[counters->rulecount].default_dst_port = 0;
                    rulestruct[counters->rulecount].default_src_port = 0;

                    rulestruct[counters->rulecount].alert_time_flag = 0;
                    rulestruct[counters->rulecount].external_flag = 0;

                    rulestruct[counters->rulecount].zeekintel_flag = 0;
                    rulestruct[counters->rulecount].blacklist_flag = 0;

#ifdef WITH_BLUEDOT
                    rulestruct[counters->rulecount].bluedot_ipaddr_type = 0;
#endif

#ifdef HAVE_LIBMAXMINDDB
                    rulestruct[counters->rulecount].geoip2_flag = 0;
#endif

#ifdef HAVE_LIBFASTJSON
                    rulestruct[counters->rulecount].metadata_json[0] = '\0';
#endif

                }

            Remove_Return(rulebuf);


            /* Store a copy of the rule */

            strlcpy(rulestruct[counters->rulecount].signature_copy, rulebuf, RULEBUF );

            /****************************************/
            /* Some really basic rule sanity checks */
            /****************************************/

            if (!strchr(rulebuf, ';') || !strchr(rulebuf, ':') ||
                    !strchr(rulebuf, '(') || !strchr(rulebuf, ')'))
                {
                    Sagan_Log(ERROR, "[%s, line %d]  %s on line %d appears to be incorrect, Abort.", __FILE__, __LINE__, ruleset_fullname, linecount);
                }

            if (!Sagan_strstr(rulebuf, "sid:"))
                {
                    Sagan_Log(ERROR, "[%s, line %d] %s on line %d appears to not have a 'sid', Abort", __FILE__, __LINE__, ruleset_fullname, linecount);
                }

            if (!Sagan_strstr(rulebuf, "rev:"))
                {
                    Sagan_Log(ERROR, "[%s, line %d] %s on line %d appears to not have a 'rev', Abort", __FILE__, __LINE__, ruleset_fullname, linecount);
                }

            if (!Sagan_strstr(rulebuf, "msg:"))
                {
                    Sagan_Log(ERROR, "[%s, line %d] %s on line %d appears to not have a 'msg', Abort", __FILE__, __LINE__, ruleset_fullname, linecount);
                }


//            rc=0;

            if ( rulebuf[0] == 'a' && rulebuf[1] == 'l' && rulebuf[2] == 'e' && rulebuf[3] == 'r' && rulebuf[4] == 't' )
                {
                    rulestruct[counters->rulecount].rule_type = RULE_TYPE_ALERT;
                }

            else if ( rulebuf[0] == 'd' && rulebuf[1] == 'r' && rulebuf[2] == 'o' && rulebuf[3] == 'p' )
                {
                    rulestruct[counters->rulecount].rule_type = RULE_TYPE_DROP;
                }

            else if ( rulebuf[0] == 'p' && rulebuf[1] == 'a' && rulebuf[2] == 's' && rulebuf[3] == 's' )
                {
                    rulestruct[counters->rulecount].rule_type = RULE_TYPE_PASS;
                }

            if ( rulestruct[counters->rulecount].rule_type == 0 )
                {
                    Sagan_Log(ERROR, "[%s, line %d] %s on line %d appears to not have a 'alert', 'drop' or 'pass', Abort.", __FILE__, __LINE__, ruleset_fullname, linecount, rulestruct[counters->rulecount].rule_type);
                }

            /* Sanity check alert any, alert icmp, alert tcp, alert udp */

            rc = false;

            uint8_t cs = 4;	/* This is for pass or drop */

            if ( rulestruct[counters->rulecount].rule_type == RULE_TYPE_ALERT )
                {
                    cs = 5;
                }

            /* any */

            if ( rulebuf[cs] == ' ' && rulebuf[cs+1] == 'a' && rulebuf[cs+2] == 'n' && rulebuf[cs+3] == 'y' && rulebuf[cs+4] == ' ' )
                {
                    rc = true;
                }

            /* tcp */

            else if ( rulebuf[cs] == ' ' && rulebuf[cs+1] == 't' && rulebuf[cs+2] == 'c' && rulebuf[cs+3] == 'p' && rulebuf[cs+4] == ' ' )
                {
                    rc = true;
                }

            /* udp */

            else if ( rulebuf[cs] == ' ' && rulebuf[cs+1] == 'u' && rulebuf[cs+2] == 'd' && rulebuf[cs+3] == 'p' && rulebuf[cs+4] == ' ' )
                {
                    rc = true;
                }

            /* icmp */

            else if ( rulebuf[cs] == ' ' && rulebuf[cs+1] == 'i' && rulebuf[cs+2] == 'c' && rulebuf[cs+3] == 'm' &&
                      rulebuf[cs+4] == 'p' && rulebuf[cs+5] == ' ' )
                {
                    rc = true;
                }

            /* syslog */

            else if ( rulebuf[cs] == ' ' && rulebuf[cs+1] == 's' && rulebuf[cs+2] == 'y' && rulebuf[cs+3] == 's' &&
                      rulebuf[cs+4] == 'l' && rulebuf[cs+5] == 'o' && rulebuf[cs+6] == 'g' && rulebuf[cs+7] == ' ' )
                {
                    rc = true;
                }


            if ( rc == false )
                {
                    Sagan_Log(ERROR, "[%s, line %d] %s on line %d appears to not have a protocol type (any/tcp/udp/icmp/syslog), Abort", __FILE__, __LINE__, ruleset_fullname, linecount);
                }

            /* Parse forward for the first '(' */

            for (i=0; i<strlen(rulebuf); i++)
                {
                    if ( rulebuf[i] == '(' )
                        {
                            forward=i;
                            break;
                        }
                }

            /* Parse reverse for the first ')' */

            for (i=strlen(rulebuf); i>0; i--)
                {
                    if ( rulebuf[i] == ')' )
                        {
                            reverse=i;
                            break;
                        }
                }

            /* Get rule structure,  minus the ( ) */

            for (i=forward+1; i<reverse; i++)
                {
                    snprintf(tmp, sizeof(tmp), "%c", rulebuf[i]);
                    strlcat(rulestr, tmp, sizeof(rulestr));
                }

            /* Get the network information, before the rule */

            for (i=0; i<forward; i++)
                {
                    snprintf(tmp, sizeof(tmp), "%c", rulebuf[i]);
                    strlcat(netstr, tmp, sizeof(netstr));
                }

            /* Assign pointer's to values */

            netstring = netstr;
            rulestring = rulestr;

            /* Assigned ruleset "id" to track when rules "fire" */

            rulestruct[counters->rulecount].ruleset_id = ruleset_track_id;


            /****************************************************************************/
            /* Parse the section _before_ the rule set.  This is stuff like $HOME_NET,  */
            /* $EXTERNAL_NET, etc                                                       */
            /****************************************************************************/

            tokennet = strtok_r(netstring, " ", &saveptrnet);

            while ( tokennet != NULL )
                {

                    Remove_Spaces(tokennet);

                    if ( netcount == 0 )
                        {

                            if (!strcmp(tokennet, "drop" ))
                                {

                                    rulestruct[counters->rulecount].drop = true;

                                }
                            else
                                {

                                    rulestruct[counters->rulecount].drop = false;

                                }
                        }

                    /* Protocol */

                    if ( netcount == 1 )
                        {
                            if (!strcmp(tokennet, "any" ))
                                {
                                    rulestruct[counters->rulecount].ip_proto = 0;
                                }

                            else if (!strcmp(tokennet, "ip" ))
                                {
                                    rulestruct[counters->rulecount].ip_proto = 0;
                                }

                            else if (!strcmp(tokennet, "icmp" ))
                                {
                                    rulestruct[counters->rulecount].ip_proto = 1;
                                }

                            else if (!strcmp(tokennet, "tcp"  ))
                                {
                                    rulestruct[counters->rulecount].ip_proto = 6;
                                }

                            else if (!strcmp(tokennet, "udp"  ))
                                {
                                    rulestruct[counters->rulecount].ip_proto = 17;
                                }

                            else if (!strcmp(tokennet, "syslog"  ))
                                {
                                    rulestruct[counters->rulecount].ip_proto = config->sagan_proto;
                                }
                        }

                    /* First flow */

                    if ( netcount == 2 )
                        {


                            Var_To_Value(tokennet, flow_a, sizeof(flow_a));

                            Remove_Spaces(flow_a);

                            /* Quick sanity check for [] (if used) */

                            if ( ( flow_a[0] == '['  &&  flow_a[strlen(flow_a)-1] != ']') ||
                                    ( ( flow_a[strlen(flow_a)-1] == ']'  &&  flow_a[0] != '[' )) )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Unbalanced flow_a set in '%s' line %d. Abort", __FILE__, __LINE__, ruleset_fullname, linecount);
                                }

                            if (!strcmp(flow_a, "any")) //  || !strcmp(flow_a, tokennet))
                                {
                                    rulestruct[counters->rulecount].flow_1_var = 0;	  /* 0 = any */

                                }
                            else
                                {

                                    strlcpy(tmp3, flow_a, sizeof(tmp3));

                                    /* Nuke [] */

                                    if ( flow_a[0] == '[' && flow_a[ strlen(flow_a) - 1 ] == ']' )
                                        {
                                            for ( i = 1; i < strlen(flow_a)-1; i++ )
                                                {
                                                    tmp3[i-1] = flow_a[i];
                                                    tmp3[i] = '\0';
                                                }
                                        }


                                    for(tmptoken = strtok_r(tmp3, ",", &saveptrflow); tmptoken; tmptoken = strtok_r(NULL, ",", &saveptrflow))
                                        {

                                            Strip_Chars(tmptoken, "not!", tok_help);

                                            if ( !Is_IP_Range(tok_help) )
                                                {
                                                    Sagan_Log(ERROR,"[%s, line %d] Value is not a valid IPv4/IPv6 '%s'. Abort", __FILE__, __LINE__, tok_help);
                                                }

                                            f1++;

                                            is_masked = Netaddr_To_Range(tok_help, (unsigned char *)&rulestruct[counters->rulecount].flow_1[flow_1_count].range);

                                            if(strchr(tmptoken, '/'))
                                                {

                                                    if( !strncmp(tmptoken, "!", 1) || !strncmp("not", tmptoken, 3))
                                                        {

                                                            rulestruct[counters->rulecount].flow_1_type[f1] = is_masked ? 0 : 2; /* 0 = not in group, 2 == IP not range */
                                                        }
                                                    else
                                                        {

                                                            rulestruct[counters->rulecount].flow_1_type[f1] = is_masked ? 1 : 3; /* 1 = in group, 3 == IP not range */
                                                        }
                                                }
                                            else if( !strncmp(tmptoken, "!", 1) || !strncmp("not", tmptoken, 3))
                                                {

                                                    rulestruct[counters->rulecount].flow_1_type[f1] = 2; /* 2 = not match ip */
                                                }
                                            else
                                                {

                                                    rulestruct[counters->rulecount].flow_1_type[f1] = 3; /* 3 = match ip */
                                                }

                                            flow_1_count++;

                                            if( flow_1_count > MAX_CHECK_FLOWS )
                                                {
                                                    Sagan_Log(ERROR,"[%s, line %d] You have exceeded the amount of IP's for flow_1 '%d', Abort.", __FILE__, __LINE__, MAX_CHECK_FLOWS);
                                                }
                                        }

                                    rulestruct[counters->rulecount].flow_1_var = 1;   /* 1 = var */
                                    rulestruct[counters->rulecount].flow_1_counter = flow_1_count;
                                }
                        }

                    /* Source Port */

                    if ( netcount == 3 )
                        {
                            if (!strcmp(nettmp, "any"))
                                {
                                    rulestruct[counters->rulecount].port_1_var = 0;	  /* 0 = any */
                                }
                            else
                                {
                                    rulestruct[counters->rulecount].port_1_var = 1;	  /* 1 = var */
                                    strlcpy(tmp4, nettmp, sizeof(tmp4));

                                    for (tmptoken = strtok_r(tmp4, ",", &saveptrport); tmptoken; tmptoken = strtok_r(NULL, ",", &saveptrport))
                                        {
                                            Strip_Chars(tmptoken, "not!", tok_help2);
                                            g1++;
                                            if (Is_Numeric(nettmp))
                                                {
                                                    rulestruct[counters->rulecount].port_1[port_1_count].lo = atoi(nettmp);          /* If it's a number (see Var_To_Value),  then set to that */
                                                }

                                            if (!strncmp(tmptoken,"!", 1) || !strncmp("not", tmptoken, 3))
                                                {
                                                    if(strchr(tok_help2,':'))
                                                        {

                                                            rulestruct[counters->rulecount].port_1[port_1_count].lo = atoi(strtok_r(tok_help2, ":", &saveptrportrange));
                                                            rulestruct[counters->rulecount].port_1[port_1_count].hi = atoi(strtok_r(NULL, ":", &saveptrportrange));
                                                            rulestruct[counters->rulecount].port_1_type[g1] = 0; /* 0 = not in group */

                                                        }
                                                    else
                                                        {

                                                            rulestruct[counters->rulecount].port_1[port_1_count].lo = atoi(tok_help2);
                                                            rulestruct[counters->rulecount].port_1_type[g1] = 2; /* This was a single port, not a range */

                                                        }
                                                }
                                            else
                                                {
                                                    if(strchr(tok_help2, ':'))
                                                        {

                                                            rulestruct[counters->rulecount].port_1[port_1_count].lo = atoi(strtok_r(tok_help2, ":", &saveptrportrange));
                                                            rulestruct[counters->rulecount].port_1[port_1_count].hi = atoi(strtok_r(NULL, ":", &saveptrportrange));
                                                            rulestruct[counters->rulecount].port_1_type[g1] = 1; /* 1 = in group */

                                                        }
                                                    else
                                                        {

                                                            rulestruct[counters->rulecount].port_1[port_1_count].lo = atoi(tok_help2);
                                                            rulestruct[counters->rulecount].port_1_type[g1] = 3; /* This was a single port, not a range */

                                                        }

                                                }
                                            port_1_count++;

                                            if( port_1_count > MAX_CHECK_FLOWS )
                                                {
                                                    Sagan_Log(ERROR,"[%s, line %d] You have exceeded the amount of Ports for port_1 '%d', Abort", __FILE__, __LINE__, MAX_CHECK_FLOWS);
                                                }

                                        }
                                    rulestruct[counters->rulecount].port_1_counter = port_1_count;
                                }

                        }


                    /* Direction */

                    if ( netcount == 4 )
                        {

                            if ( !strcmp(tokennet, "->") )
                                {
                                    d = 1;  /* 1 = right */
                                }
                            else if( !strcmp(tokennet, "<>") || !strcmp(tokennet, "any") || !strcmp(tokennet, "<->") )
                                {
                                    d = 0;  /* 0 = any */
                                }
                            else if( !strcmp(tokennet, "<-") )
                                {
                                    d = 2;  /* 2 = left */
                                }
                            else
                                {
                                    d = 0;  /* 0 = any */
                                }
                            rulestruct[counters->rulecount].direction = d;
                        }

                    /* Second flow */

                    if ( netcount == 5 )
                        {

                            Var_To_Value(tokennet, flow_b, sizeof(flow_b));

                            Remove_Spaces(flow_b);

                            if ( ( flow_b[0] == '['  &&  flow_b[strlen(flow_b)-1] != ']') ||
                                    ( ( flow_b[strlen(flow_b)-1] == ']'  &&  flow_b[0] != '[' )) )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Unbalanced flow_b set in '%s' line %d. Abort", __FILE__, __LINE__, ruleset_fullname, linecount);
                                }

                            if (!strcmp(flow_b, "any")) //  || !strcmp(flow_b, tokennet))
                                {
                                    rulestruct[counters->rulecount].flow_2_var = 0;     /* 0 = any */

                                }
                            else
                                {

                                    strlcpy(tmp3, flow_b, sizeof(tmp3));

                                    /* Nuke [] */

                                    if ( flow_b[0] == '[' && flow_b[ strlen(flow_b) - 1 ] == ']' )
                                        {
                                            for ( i = 1; i < strlen(flow_b)-1; i++ )
                                                {
                                                    tmp3[i-1] = flow_b[i];
                                                    tmp3[i] = '\0';
                                                }
                                        }


                                    for(tmptoken = strtok_r(tmp3, ",", &saveptrflow); tmptoken; tmptoken = strtok_r(NULL, ",", &saveptrflow))
                                        {

                                            Strip_Chars(tmptoken, "not!", tok_help);

                                            if ( !Is_IP_Range(tok_help) )
                                                {
                                                    Sagan_Log(ERROR,"[%s, line %d] Value is not a valid IPv4/IPv6 '%s'. Abort", __FILE__, __LINE__, tok_help);
                                                }

                                            f2++;

                                            is_masked = Netaddr_To_Range(tok_help, (unsigned char *)&rulestruct[counters->rulecount].flow_2[flow_2_count].range);

                                            if(strchr(tmptoken, '/'))
                                                {
                                                    if( !strncmp(tmptoken, "!", 1) || !strncmp("not", tmptoken, 3))
                                                        {
                                                            rulestruct[counters->rulecount].flow_2_type[f2] = is_masked ? 0 : 2; /* 0 = not in group, 2 == IP not range */
                                                        }
                                                    else
                                                        {
                                                            rulestruct[counters->rulecount].flow_2_type[f2] = is_masked ? 1 : 3; /* 1 = in group, 3 == IP not range */
                                                        }
                                                }
                                            else if( !strncmp(tmptoken, "!", 1) || !strncmp("not", tmptoken, 3))
                                                {
                                                    rulestruct[counters->rulecount].flow_2_type[f2] = 2; /* 2 = not match ip */
                                                }
                                            else
                                                {
                                                    rulestruct[counters->rulecount].flow_2_type[f2] = 3; /* 3 = match ip */
                                                }

                                            flow_2_count++;

                                            if( flow_2_count > MAX_CHECK_FLOWS )
                                                {
                                                    Sagan_Log(ERROR,"[%s, line %d] You have exceeded the amount of entries for follow_flow_2 '50', Abort.", __FILE__, __LINE__);
                                                }
                                        }

                                    rulestruct[counters->rulecount].flow_2_var = 1;   /* 1 = var */
                                    rulestruct[counters->rulecount].flow_2_counter = flow_2_count;
                                }
                        }

                    /* Destination Port */

                    if ( netcount == 6 )
                        {
                            if (!strcmp(nettmp, "any"))
                                {
                                    rulestruct[counters->rulecount].port_2_var = 0;	  /* 0 = any */
                                }
                            else
                                {
                                    rulestruct[counters->rulecount].port_2_var = 1;	  /* 1 = var */
                                    strlcpy(tmp4, nettmp, sizeof(tmp4));

                                    for (tmptoken = strtok_r(tmp4, ",", &saveptrport); tmptoken; tmptoken = strtok_r(NULL, ",", &saveptrport))
                                        {
                                            Strip_Chars(tmptoken, "not!", tok_help2);
                                            g2++;
                                            if (Is_Numeric(nettmp))
                                                {
                                                    rulestruct[counters->rulecount].port_2[port_2_count].lo = atoi(nettmp);          /* If it's a number (see Var_To_Value),  then set to that */
                                                }

                                            if (!strncmp(tmptoken,"!", 1) || !strncmp("not", tmptoken, 3))
                                                {
                                                    if(strchr(tok_help2,':'))
                                                        {

                                                            rulestruct[counters->rulecount].port_2[port_2_count].lo = atoi(strtok_r(tok_help2, ":", &saveptrportrange));
                                                            rulestruct[counters->rulecount].port_2[port_2_count].hi = atoi(strtok_r(NULL, ":", &saveptrportrange));
                                                            rulestruct[counters->rulecount].port_2_type[g2] = 0; /* 0 = not in group */

                                                        }
                                                    else
                                                        {

                                                            rulestruct[counters->rulecount].port_2[port_2_count].lo = atoi(tok_help2);
                                                            rulestruct[counters->rulecount].port_2_type[g2] = 2; /* This was a single port, not a range */

                                                        }
                                                }
                                            else
                                                {
                                                    if(strchr(tok_help2, ':'))
                                                        {

                                                            rulestruct[counters->rulecount].port_2[port_2_count].lo = atoi(strtok_r(tok_help2, ":", &saveptrportrange));
                                                            rulestruct[counters->rulecount].port_2[port_2_count].hi = atoi(strtok_r(NULL, ":", &saveptrportrange));
                                                            rulestruct[counters->rulecount].port_2_type[g2] = 1; /* 1 = in group */

                                                        }
                                                    else
                                                        {

                                                            rulestruct[counters->rulecount].port_2[port_2_count].lo = atoi(tok_help2);
                                                            rulestruct[counters->rulecount].port_2_type[g2] = 3; /* This was a single port, not a range */

                                                        }

                                                }
                                            port_2_count++;

                                            if( port_2_count > MAX_CHECK_FLOWS )
                                                {
                                                    Sagan_Log(ERROR,"[%s, line %d] You have exceeded the amount of Ports for port_2 '%d', Abort.", __FILE__, __LINE__, MAX_CHECK_FLOWS);
                                                }

                                        }
                                    rulestruct[counters->rulecount].port_2_counter = port_2_count;
                                }

                        }

                    /* Used later for a single check to determine if a rule has a flow or not
                        - Champ Clark III (06/12/2016) */

                    if ( rulestruct[counters->rulecount].ip_proto != 0 || rulestruct[counters->rulecount].flow_1_var != 0 || rulestruct[counters->rulecount].port_1_var != 0 || rulestruct[counters->rulecount].flow_2_var != 0 || rulestruct[counters->rulecount].port_2_var != 0 )
                        {
                            rulestruct[counters->rulecount].has_flow = 1;
                        }

                    tokennet = strtok_r(NULL, " ", &saveptrnet);
                    Var_To_Value(tokennet, nettmp, sizeof(nettmp));
                    Remove_Spaces(nettmp);

                    netcount++;
                }

            /*****************************************************************************/
            /* Parse the rule set!                                                       */
            /*****************************************************************************/

            /* Set some defaults outside the option parsing */

            rulestruct[counters->rulecount].default_proto = config->sagan_proto;
            rulestruct[counters->rulecount].default_src_port = config->sagan_port;
            rulestruct[counters->rulecount].default_dst_port = config->sagan_port;

            tokenrule = strtok_r(rulestring, ";", &saveptrrule1);

            while ( tokenrule != NULL )
                {

                    rulesplit = strtok_r(tokenrule, ":", &saveptrrule2);
                    Remove_Spaces(rulesplit);

                    /* single flag options.  (nocase, parse_port, etc) */

                    if (!strcmp(rulesplit, "parse_port"))
                        {
                            strtok_r(NULL, ":", &saveptrrule2);
                            rulestruct[counters->rulecount].s_find_port = true;
                        }

                    if (!strcmp(rulesplit, "parse_proto"))
                        {
                            strtok_r(NULL, ":", &saveptrrule2);
                            rulestruct[counters->rulecount].s_find_proto = true;
                        }

                    if (!strcmp(rulesplit, "parse_proto_program"))
                        {
                            strtok_r(NULL, ":", &saveptrrule2);
                            rulestruct[counters->rulecount].s_find_proto_program = true;
                        }

                    if (!strcmp(rulesplit, "append_program"))
                        {
                            strtok_r(NULL, ":", &saveptrrule2);
                            rulestruct[counters->rulecount].append_program = true;
                        }

                    if (!strcmp(rulesplit, "flexbits_upause"))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if ( arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The \"flexbit_upause\" option appears to be incomplete at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            rulestruct[counters->rulecount].flexbit_upause_time = atoi(arg);
                        }

                    if (!strcmp(rulesplit, "xbits_upause"))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if ( arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The \"xbit_upause\" option appears to be incomplete at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            rulestruct[counters->rulecount].xbit_upause_time = atoi(arg);
                        }

                    if (!strcmp(rulesplit, "flexbits_pause"))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if ( arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The \"flexbits_pause\" option appears to be incomplete at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            rulestruct[counters->rulecount].flexbit_pause_time = atoi(arg);
                        }

                    if (!strcmp(rulesplit, "xbits_pause"))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if ( arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The \"xbit_pause\" option appears to be incomplete at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            rulestruct[counters->rulecount].xbit_pause_time = atoi(arg);
                        }


                    if (!strcmp(rulesplit, "default_proto"))
                        {

                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if ( arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The \"default_proto\" option appears to be incomplete at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            Var_To_Value(arg, tmp1, sizeof(tmp1));
                            Remove_Spaces(tmp1);

                            if (!strcmp(tmp1, "icmp") || !strcmp(tmp1, "1"))
                                {
                                    rulestruct[counters->rulecount].default_proto = 1;
                                }

                            else if (!strcmp(tmp1, "tcp" ) || !strcmp(tmp1, "6" ))
                                {
                                    rulestruct[counters->rulecount].default_proto = 6;
                                }

                            else if (!strcmp(tmp1, "udp" ) || !strcmp(tmp1, "17" ))
                                {
                                    rulestruct[counters->rulecount].default_proto = 17;
                                }

                        }

                    if (!strcmp(rulesplit, "default_src_port"))
                        {

                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if ( arg == NULL )
                                {
                                    Sagan_Log(ERROR,"[%s, line %d] The \"default_src_port\" option appears to be incomplete at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            Var_To_Value(arg, tmp1, sizeof(tmp1));
                            Remove_Spaces(tmp1);

                            rulestruct[counters->rulecount].default_src_port = atoi(tmp1);

                        }

                    if (!strcmp(rulesplit, "default_dst_port"))
                        {

                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if ( arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The \"default_dst_port\" option appears to be incomplete at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            Var_To_Value(arg, tmp1, sizeof(tmp1));
                            Remove_Spaces(tmp1);


                            rulestruct[counters->rulecount].default_dst_port = atoi(tmp1);

                        }

                    if (!strcmp(rulesplit, "parse_src_ip"))
                        {

                            arg = strtok_r(NULL, ":", &saveptrrule2);
                            rulestruct[counters->rulecount].s_find_src_ip = true;

                            if ( arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The \"parse_src_ip\" option appears to be incomplete at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            rulestruct[counters->rulecount].s_find_src_pos = atoi(arg);
                        }

                    if (!strcmp(rulesplit, "parse_dst_ip"))
                        {

                            arg = strtok_r(NULL, ":", &saveptrrule2);
                            rulestruct[counters->rulecount].s_find_dst_ip = 1;

                            if ( arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The \"parse_dst_ip\" option appears to be incomplete at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            rulestruct[counters->rulecount].s_find_dst_pos = atoi(arg);
                        }

                    if (!strcmp(rulesplit, "parse_hash"))
                        {

                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if ( arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The \"parse_hash\" option appears to be incomplete at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            Remove_Spaces(arg);

                            if (!strcmp(arg, "md5"))
                                {
                                    rulestruct[counters->rulecount].s_find_hash_type = PARSE_HASH_MD5;
                                }

                            else if (!strcmp(arg, "sha1"))
                                {
                                    rulestruct[counters->rulecount].s_find_hash_type = PARSE_HASH_SHA1;
                                }

                            else if (!strcmp(arg, "sha256"))
                                {
                                    rulestruct[counters->rulecount].s_find_hash_type = PARSE_HASH_SHA256;
                                }
                            /*
                                                        else if (!strcmp(arg, "all"))
                                                            {
                                                                rulestruct[counters->rulecount].s_find_hash_type = PARSE_HASH_ALL;
                                                            }
                            */

                            if ( rulestruct[counters->rulecount].s_find_hash_type == 0 )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The \"parse_hash\" option appears to be invalid at line %d in %s. Valid values are 'md5', 'sha1' and 'sha256', Abort.", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }


                        }

                    /************************************************/
                    /* Non-quoted information (sid, reference, etc) */
                    /************************************************/

                    /* Suricata style "xbits" */

                    if ( !strcmp(rulesplit, "xbits" ) )
                        {

                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            Remove_Spaces(arg);

                            /* This handles "sbits: noeve;", etc */

                            bool xbit_single = false; 	/* So we don't have to check multiple flags */

                            if ( !strcmp(arg, "noeve") )
                                {
                                    rulestruct[counters->rulecount].xbit_noeve=true;
                                    xbit_single = true;
                                }

                            if ( !strcmp(arg, "noalert") )
                                {
                                    rulestruct[counters->rulecount].xbit_noalert=true;
                                    xbit_single = true;
                                }


                            /* xbits things like "set", "unset", which have multiple options */

                            if ( xbit_single == false )
                                {

                                    tmptoken = strtok_r(arg, ",", &saveptrrule2);

                                    if ( tmptoken == NULL )
                                        {
                                            Sagan_Log(ERROR, "[%s, line %d] Incomplete 'xbits' option at %d in '%s', Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                        }

                                    Remove_Spaces(tmptoken);

                                    if ( strcmp(tmptoken, "set") && strcmp(tmptoken, "unset") && strcmp(tmptoken, "isset") &&
                                            strcmp(tmptoken, "isnotset") && strcmp(tmptoken, "toggle") )
                                        {
                                            Sagan_Log(ERROR, "[%s, line %d] Expected 'set', 'unset', 'isset', 'isnotset', 'toggle', 'noalert', or 'noeve' but got '%s' at line %d in %s, Abort", __FILE__, __LINE__, tmptoken, linecount, ruleset);

                                        }


                                    rulestruct[counters->rulecount].xbit_flag = true;

                                    if (!strcmp(tmptoken, "set") )
                                        {

                                            rulestruct[counters->rulecount].xbit_type[xbit_count]  = 1;   /* set */
                                            rulestruct[counters->rulecount].xbit_set_count++;
                                            __atomic_add_fetch(&counters->xbit_total_counter, 1, __ATOMIC_SEQ_CST);
                                        }

                                    else if (!strcmp(tmptoken, "unset") )
                                        {
                                            rulestruct[counters->rulecount].xbit_type[xbit_count]  = 2;   /* unset */
                                            rulestruct[counters->rulecount].xbit_unset_count++;
                                        }

                                    else if (!strcmp(tmptoken, "isset") )
                                        {
                                            rulestruct[counters->rulecount].xbit_type[xbit_count]  = 3;   /* isset */
                                            rulestruct[counters->rulecount].xbit_isset_count++;
                                        }

                                    else if (!strcmp(tmptoken, "isnotset") )
                                        {
                                            rulestruct[counters->rulecount].xbit_type[xbit_count]  = 4;   /* isnotset */
                                            rulestruct[counters->rulecount].xbit_isnotset_count++;
                                        }


                                    /*

                                    			            Toggle presents some issues & I'm not sure of a decent use case.  For one,
                                                                        if the xbit is present (in memory), toggling isn't an issue because the expire
                                                                        time is already in memory.  If it's _never_ been set,  we would have to locate
                                                                        the expire time in memory and store it.  With Redis storage,  it's worse.  We
                                                                        let Redis handle the xbit expiring (via "DEL" command).  Again, we would need
                                                                        to locate an xbit "set" to determine the expire time to set that on "toggle" :(

                                    				    2019/03/19 - Champ Clark III

                                                                        else if (!strcmp(tmptoken, "toggle") )
                                                                            {
                                                                                rulestruct[counters->rulecount].xbit_type[xbit_count]  = 5;
                                    					    rulestruct[counters->rulecount].xbit_toggle_count++;

                                                                            }
                                    */

                                    if ( rulestruct[counters->rulecount].xbit_type[xbit_count] == 0 )
                                        {
                                            Sagan_Log(ERROR, "[%s, line %d] Xbit is not 'set', 'unset', 'isset', 'isnotset' or 'toggle'. Abort at line %d in %s", __FILE__, __LINE__, linecount, ruleset);
                                        }

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                    if ( tmptoken == NULL )
                                        {
                                            Sagan_Log(ERROR, "[%s, line %d] Missing xbit 'name'. Abort at %d in %s. Abort", __FILE__, __LINE__, linecount, ruleset);
                                        }

                                    Remove_Spaces(tmptoken);

                                    strlcpy(rulestruct[counters->rulecount].xbit_name[xbit_count], tmptoken, sizeof(rulestruct[counters->rulecount].xbit_name[xbit_count]));

                                    rulestruct[counters->rulecount].xbit_name_hash[xbit_count] = Djb2_Hash(tmptoken);

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                    if ( tmptoken == NULL )
                                        {
                                            Sagan_Log(ERROR, "[%s, line %d] Incomplete xbit at line %d in file %s. Abort.", __FILE__, __LINE__, linecount, ruleset);

                                        }

                                    Remove_Spaces(tmptoken);

                                    if ( strlen(tmptoken) < 6 || tmptoken[0] != 't' || tmptoken[1] != 'r' || tmptoken[2] != 'a' || tmptoken[3] != 'c' || tmptoken[4] != 'k' )
                                        {
                                            Sagan_Log(ERROR, "[%s, line %d] Expected 'track' for xbit at line %d in file %s. Abort.", __FILE__, __LINE__, linecount, ruleset);
                                        }


                                    if ( strlen(tmptoken) == 11 && tmptoken[5] == 'i' && tmptoken[6] == 'p' && tmptoken[7] == '_' &&
                                            tmptoken[8] == 's' && tmptoken[9] == 'r' && tmptoken[10] == 'c' )
                                        {

                                            rulestruct[counters->rulecount].xbit_direction[xbit_count] = 1; /* ip_src */
                                        }

                                    else if ( strlen(tmptoken) == 11 && tmptoken[5] == 'i' && tmptoken[6] == 'p' && tmptoken[7] == '_' &&
                                              tmptoken[8] == 'd' && tmptoken[9] == 's' && tmptoken[10] == 't' )
                                        {

                                            rulestruct[counters->rulecount].xbit_direction[xbit_count] = 2; /* ip_dst */
                                        }

                                    else if ( strlen(tmptoken) == 12 && tmptoken[5] == 'i' && tmptoken[6] == 'p' && tmptoken[7] == '_' &&
                                              tmptoken[8] == 'p' && tmptoken[9] == 'a' && tmptoken[10] == 'i' && tmptoken[11] == 'r' )
                                        {

                                            rulestruct[counters->rulecount].xbit_direction[xbit_count] = 3; /* ip_pair */
                                        }

                                    if ( rulestruct[counters->rulecount].xbit_direction[xbit_count] == 0 )
                                        {
                                            Sagan_Log(ERROR, "[%s, line %d] Expected track by 'ip_src', 'ip_dst', or 'ip_pair'. Aborting at line %d in file %s.", __FILE__, __LINE__, linecount, ruleset);
                                        }


                                    /* If we're in a 'set', we'll need expire time */

                                    if ( rulestruct[counters->rulecount].xbit_type[xbit_count] == 1 )
                                        {

                                            tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                            if ( tmptoken == NULL )
                                                {
                                                    Sagan_Log(ERROR, "[%s, line %d] Incomplete xbit at line %d in file %s. Abort", __FILE__, __LINE__, linecount, ruleset);

                                                }

                                            Remove_Spaces(tmptoken);

                                            if ( tmptoken[0] != 'e' || tmptoken[1] != 'x' || tmptoken[2] != 'p' || tmptoken[3] != 'i' ||
                                                    tmptoken[4] != 'r' || tmptoken[5] != 'e' )

                                                {

                                                    Sagan_Log(ERROR, "[%s, line %d] Incomplete 'set' xbit at line %d in file %s.  Expected a 'expire' time. Abort", __FILE__, __LINE__, linecount, ruleset);

                                                }

                                            /* Zero tmp space */

                                            tmp2[0] = '\0';

                                            /* Get 'expire' time from the rule */

                                            for ( i = 6; i < strlen(tmptoken); i++ )
                                                {
                                                    snprintf(tmp, sizeof(tmp), "%c", tmptoken[i]);
                                                    strlcat(tmp2, tmp, sizeof(tmp2));
                                                }

                                            rulestruct[counters->rulecount].xbit_expire[xbit_count] = atol(tmp2);

                                            if ( rulestruct[counters->rulecount].xbit_direction[xbit_count] == 0 )
                                                {
                                                    Sagan_Log(ERROR, "[%s, line %d] xbit expire time is invalid at %d in file %s. Abort", __FILE__, __LINE__, linecount, ruleset);
                                                }


                                        }

                                    xbit_count++;
                                    rulestruct[counters->rulecount].xbit_count = xbit_count;
                                }

                        }

                    /* Flexbits */

                    if ( !strcmp(rulesplit, "flexbits") )
                        {

                            arg = strtok_r(NULL, ":", &saveptrrule2);
                            tmptoken = strtok_r(arg, ",", &saveptrrule2);

                            if ( tmptoken == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Incomplete 'flexbit' option at %d in '%s', Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            Remove_Spaces(tmptoken);


                            if ( strcmp(tmptoken, "noalert") && strcmp(tmptoken, "set") &&
                                    strcmp(tmptoken, "unset") && strcmp(tmptoken, "isset") && strcmp(tmptoken, "isnotset") &&
                                    strcmp(tmptoken, "set_srcport") && strcmp(tmptoken, "set_dstport") && strcmp(tmptoken, "set_ports") &&
                                    strcmp(tmptoken, "count") && strcmp(tmptoken, "noeve" ) )
                                {


                                    Sagan_Log(ERROR, "[%s, line %d] Expected 'noalert', 'set', 'unset', 'isnotset', 'isset', 'noeve'  or 'count' but got '%s' at line %d in %s, Abort", __FILE__, __LINE__, tmptoken, linecount, ruleset);

                                }

                            if (!strcmp(tmptoken, "noalert"))
                                {
                                    rulestruct[counters->rulecount].flexbit_noalert=true;
                                }

                            if (!strcmp(tmptoken, "noeve"))
                                {
                                    rulestruct[counters->rulecount].flexbit_noeve=true;
                                }


                            /* SET */

                            if (!strcmp(tmptoken, "set"))
                                {

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                    if ( tmptoken == NULL )
                                        {
                                            Sagan_Log(ERROR, "[%s, line %d] Expected flexbit name at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                        }

                                    Remove_Spaces(tmptoken);

                                    rulestruct[counters->rulecount].flexbit_flag = 1; 				/* We have flexbit in the rule! */
                                    rulestruct[counters->rulecount].flexbit_set_count++;
                                    rulestruct[counters->rulecount].flexbit_type[flexbit_count]  = 1;		/* set */

                                    strlcpy(rulestruct[counters->rulecount].flexbit_name[flexbit_count], tmptoken, sizeof(rulestruct[counters->rulecount].flexbit_name[flexbit_count]));

                                    rulestruct[counters->rulecount].flexbit_timeout[flexbit_count] = atoi(strtok_r(NULL, ",", &saveptrrule2));

                                    if ( rulestruct[counters->rulecount].flexbit_timeout[flexbit_count] == 0 )
                                        {
                                            Sagan_Log(ERROR, "[%s, line %d] Expected flexbit valid expire time for \"set\" at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                        }

                                    flexbit_count++;
                                    __atomic_add_fetch(&counters->flexbit_total_counter, 1, __ATOMIC_SEQ_CST);

                                }

                            /* UNSET */

                            else if (!strcmp(tmptoken, "unset"))
                                {

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                    if ( tmptoken == NULL )
                                        {
                                            Sagan_Log(ERROR, "[%s, line %d] Expected \"direction\" at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                        }

                                    Remove_Spaces(tmptoken);

                                    rulestruct[counters->rulecount].flexbit_direction[flexbit_count] = Flexbit_Type(tmptoken, linecount, ruleset_fullname);

                                    rulestruct[counters->rulecount].flexbit_flag = 1;               			/* We have flexbit in the rule! */
                                    rulestruct[counters->rulecount].flexbit_set_count++;
                                    rulestruct[counters->rulecount].flexbit_type[flexbit_count]  = 2;                	/* unset */

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                    if ( tmptoken == NULL )
                                        {
                                            Sagan_Log(ERROR, "[%s, line %d] Expected flexbit name at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                        }

                                    Remove_Spaces(tmptoken);

                                    strlcpy(rulestruct[counters->rulecount].flexbit_name[flexbit_count], tmptoken, sizeof(rulestruct[counters->rulecount].flexbit_name[flexbit_count]));

                                    flexbit_count++;

                                }

                            /* ISSET */

                            else if (!strcmp(tmptoken, "isset"))
                                {

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                    if ( tmptoken == NULL )
                                        {
                                            Sagan_Log(ERROR, "[%s, line %d] Expected flexbit name at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                        }

                                    Remove_Spaces(tmptoken);

                                    rulestruct[counters->rulecount].flexbit_direction[flexbit_count] = Flexbit_Type(tmptoken, linecount, ruleset_fullname);

                                    rulestruct[counters->rulecount].flexbit_flag = 1;               			/* We have flexbit in the rule! */
                                    rulestruct[counters->rulecount].flexbit_type[flexbit_count]  = 3;               	/* isset */

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                    if ( tmptoken == NULL )
                                        {
                                            Sagan_Log(ERROR, "[%s, line %d] Expected flexbit name at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                        }

                                    Remove_Spaces(tmptoken);

                                    strlcpy(rulestruct[counters->rulecount].flexbit_name[flexbit_count], tmptoken, sizeof(rulestruct[counters->rulecount].flexbit_name[flexbit_count]));

                                    rulestruct[counters->rulecount].flexbit_condition_count++;
                                    flexbit_count++;

                                }

                            /* ISNOTSET */

                            else if (!strcmp(tmptoken, "isnotset"))
                                {

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                    if ( tmptoken == NULL )
                                        {
                                            Sagan_Log(ERROR, "[%s, line %d] Expected flexbit name at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                        }

                                    Remove_Spaces(tmptoken);

                                    rulestruct[counters->rulecount].flexbit_direction[flexbit_count] = Flexbit_Type(tmptoken, linecount, ruleset_fullname);

                                    rulestruct[counters->rulecount].flexbit_flag = 1;                               	/* We have flexbit in the rule! */
                                    rulestruct[counters->rulecount].flexbit_type[flexbit_count]  = 4;               	/* isnotset */

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                    if ( tmptoken == NULL )
                                        {
                                            Sagan_Log(ERROR, "[%s, line %d] Expected flexbit name at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                        }

                                    Remove_Spaces(tmptoken);

                                    strlcpy(rulestruct[counters->rulecount].flexbit_name[flexbit_count], tmptoken, sizeof(rulestruct[counters->rulecount].flexbit_name[flexbit_count]));

                                    rulestruct[counters->rulecount].flexbit_condition_count++;
                                    flexbit_count++;

                                }

                            /* SET_SRCPORT */

                            else if (!strcmp(tmptoken, "set_srcport"))
                                {

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                    if ( tmptoken == NULL )
                                        {
                                            Sagan_Log(ERROR, "[%s, line %d] Expected flexbit name at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                        }

                                    Remove_Spaces(tmptoken);

                                    rulestruct[counters->rulecount].flexbit_flag = 1; 				/* We have flexbit in the rule! */
                                    rulestruct[counters->rulecount].flexbit_set_count++;
                                    rulestruct[counters->rulecount].flexbit_type[flexbit_count]  = 5;		/* set_srcport */

                                    strlcpy(rulestruct[counters->rulecount].flexbit_name[flexbit_count], tmptoken, sizeof(rulestruct[counters->rulecount].flexbit_name[flexbit_count]));

                                    rulestruct[counters->rulecount].flexbit_timeout[flexbit_count] = atoi(strtok_r(NULL, ",", &saveptrrule2));

                                    if ( rulestruct[counters->rulecount].flexbit_timeout[flexbit_count] == 0 )
                                        {
                                            Sagan_Log(ERROR, "[%s, line %d] Expected flexbit valid expire time for \"set\" at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                        }

                                    flexbit_count++;
                                    __atomic_add_fetch(&counters->flexbit_total_counter, 1, __ATOMIC_SEQ_CST);

                                }

                            /* SET_DSTPORT */

                            else if (!strcmp(tmptoken, "set_dstport"))
                                {

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                    if ( tmptoken == NULL )
                                        {
                                            Sagan_Log(ERROR, "[%s, line %d] Expected flexbit name at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset);
                                        }

                                    Remove_Spaces(tmptoken);

                                    rulestruct[counters->rulecount].flexbit_flag = 1; 				/* We have flexbit in the rule! */
                                    rulestruct[counters->rulecount].flexbit_set_count++;
                                    rulestruct[counters->rulecount].flexbit_type[flexbit_count]  = 6;		/* set_dstport */

                                    strlcpy(rulestruct[counters->rulecount].flexbit_name[flexbit_count], tmptoken, sizeof(rulestruct[counters->rulecount].flexbit_name[flexbit_count]));

                                    rulestruct[counters->rulecount].flexbit_timeout[flexbit_count] = atoi(strtok_r(NULL, ",", &saveptrrule2));

                                    if ( rulestruct[counters->rulecount].flexbit_timeout[flexbit_count] == 0 )
                                        {
                                            Sagan_Log(ERROR, "[%s, line %d] Expected flexbit valid expire time for \"set\" at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset);
                                        }

                                    flexbit_count++;
                                    __atomic_add_fetch(&counters->flexbit_total_counter, 1, __ATOMIC_SEQ_CST);

                                }

                            /* SET_PORTS */

                            else if (!strcmp(tmptoken, "set_ports"))
                                {

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                    if ( tmptoken == NULL )
                                        {
                                            Sagan_Log(ERROR, "[%s, line %d] Expected flexbit name at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset);
                                        }

                                    Remove_Spaces(tmptoken);

                                    rulestruct[counters->rulecount].flexbit_flag = 1; 				/* We have flexbit in the rule! */
                                    rulestruct[counters->rulecount].flexbit_set_count++;
                                    rulestruct[counters->rulecount].flexbit_type[flexbit_count]  = 7;		/* set_ports */

                                    strlcpy(rulestruct[counters->rulecount].flexbit_name[flexbit_count], tmptoken, sizeof(rulestruct[counters->rulecount].flexbit_name[flexbit_count]));

                                    rulestruct[counters->rulecount].flexbit_timeout[flexbit_count] = atoi(strtok_r(NULL, ",", &saveptrrule2));

                                    if ( rulestruct[counters->rulecount].flexbit_timeout[flexbit_count] == 0 )
                                        {
                                            Sagan_Log(ERROR, "[%s, line %d] Expected flexbit valid expire time for \"set\" at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset);
                                        }

                                    flexbit_count++;
                                    __atomic_add_fetch(&counters->flexbit_total_counter, 1, __ATOMIC_SEQ_CST);

                                }

                            /* COUNTER */

                            else if (!strcmp(tmptoken, "count"))
                                {

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                    if ( tmptoken == NULL )
                                        {
                                            Sagan_Log(ERROR, "[%s, line %d] Expected flexbit name at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset);
                                        }

                                    Remove_Spaces(tmptoken);

                                    if ( strcmp(tmptoken, "by_src") && strcmp(tmptoken, "by_dst") )
                                        {

                                            Sagan_Log(ERROR, "[%s, line %d] Expected count 'by_src' or 'by_dst'.  Got '%s' instead at line %d in %s, Abort", __FILE__, __LINE__, tmptoken, linecount, ruleset);

                                        }

                                    if ( !strcmp(tmptoken, "by_src") )
                                        {

                                            rulestruct[counters->rulecount].flexbit_direction[flexbit_count] = 2;

                                        }
                                    else
                                        {

                                            rulestruct[counters->rulecount].flexbit_direction[flexbit_count] = 3;

                                        }

                                    rulestruct[counters->rulecount].flexbit_flag = 1;
                                    rulestruct[counters->rulecount].flexbit_set_count++;
                                    rulestruct[counters->rulecount].flexbit_type[flexbit_count]  = 8;         /* count */

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                    if ( tmptoken == NULL )
                                        {
                                            Sagan_Log(ERROR, "[%s, line %d] Expected flexbit name to count at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset);
                                        }

                                    Remove_Spaces(tmptoken);
                                    strlcpy(rulestruct[counters->rulecount].flexbit_name[flexbit_count], tmptoken, sizeof(rulestruct[counters->rulecount].flexbit_name[flexbit_count]));

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                    if ( tmptoken == NULL )
                                        {
                                            Sagan_Log(ERROR, "[%s, line %d] Expected flexbit value to count at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset);
                                        }

                                    strlcpy(tmp1, tmptoken, sizeof(tmp1));
                                    Remove_Spaces(tmp1);

                                    if ( tmp1[0] != '>' && tmp1[0] != '<' && tmp1[0] != '=' )
                                        {
                                            Sagan_Log(ERROR, "[%s, line %d] Expected '>', '<' or '=' operator in flexbit count at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset);

                                        }

                                    /* Determine the flexbit counter operator */

                                    if ( tmp1[0] == '>' )
                                        {
                                            rulestruct[counters->rulecount].flexbit_count_gt_lt[flexbit_count] = 0;
                                            tmptoken = strtok_r(tmp1, ">", &saveptrrule3);
                                        }

                                    else if ( tmp1[0] == '<' )
                                        {
                                            rulestruct[counters->rulecount].flexbit_count_gt_lt[flexbit_count] = 1;
                                            tmptoken = strtok_r(tmp1, "<", &saveptrrule3);
                                        }

                                    else if ( tmp1[0] == '=' )
                                        {
                                            rulestruct[counters->rulecount].flexbit_count_gt_lt[flexbit_count] = 2;
                                            tmptoken = strtok_r(tmp1, "=", &saveptrrule3);
                                        }

                                    if ( tmptoken == NULL )
                                        {
                                            Sagan_Log(ERROR, "[%s, line %d] Expected value to look for in flexbit count at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset);
                                        }

                                    Remove_Spaces(tmptoken);
                                    rulestruct[counters->rulecount].flexbit_count_counter[flexbit_count] = atoi(tmptoken);
                                    rulestruct[counters->rulecount].flexbit_count_flag = true;

                                    flexbit_count++;
                                    __atomic_add_fetch(&counters->flexbit_total_counter, 1, __ATOMIC_SEQ_CST);
                                    rulestruct[counters->rulecount].flexbit_count_count++;
                                }

                            rulestruct[counters->rulecount].flexbit_count = flexbit_count;

                        }

                    /* "Dynamic" rule loading.  This allows Sagan to load rules when it "detects" new types */

                    if (!strcmp(rulesplit, "dynamic_load"))
                        {

                            if ( config->dynamic_load_sample_rate == 0 )
                                {

                                    Sagan_Log(ERROR, "[%s, line %d] Attempting to load a dynamic rule but the 'dynamic_load' processor hasn't been configured, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);

                                }

                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if ( arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] 'dynamic_load' specified but not complete at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            Var_To_Value(arg, tmp1, sizeof(tmp1));
                            Remove_Spaces(tmp1);

                            strlcpy(rulestruct[counters->rulecount].dynamic_ruleset, tmp1, sizeof(rulestruct[counters->rulecount].dynamic_ruleset));
                            rulestruct[counters->rulecount].type = DYNAMIC_RULE;
                            __atomic_add_fetch(&counters->dynamic_rule_count, 1, __ATOMIC_SEQ_CST);

                        }

#ifdef HAVE_LIBMAXMINDDB

                    if (!strcmp(rulesplit, "country_code"))
                        {

                            /* Have the requirements for GeoIP2 been loaded (Maxmind DB, etc) */

                            if (!config->have_geoip2)
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Rule %s at line %d has GeoIP option,  but Sagan configuration lacks GeoIP - Abort", __FILE__, __LINE__, ruleset_fullname, linecount);
                                }

                            arg = strtok_r(NULL, ":", &saveptrrule2);
                            tmptoken = strtok_r(arg, " ", &saveptrrule2);

                            if (strcmp(tmptoken, "track"))
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Expected 'track' in 'country_code' option at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                            if ( tmptoken == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Incomplete country_code option at %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            Remove_Spaces(tmptoken);

                            if (strcmp(tmptoken, "by_src") && strcmp(tmptoken, "by_dst"))
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Expected 'by_src' or 'by_dst' in 'country_code' option at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            if (!strcmp(tmptoken, "by_src"))
                                {
                                    rulestruct[counters->rulecount].geoip2_src_or_dst = 1;
                                }

                            if (!strcmp(tmptoken, "by_dst"))
                                {
                                    rulestruct[counters->rulecount].geoip2_src_or_dst = 2;
                                }

                            tmptoken = strtok_r(NULL, " ", &saveptrrule2);

                            if ( tmptoken == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Incomplete country_code option at %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            Remove_Spaces(tmptoken);

                            if (strcmp(tmptoken, "is") && strcmp(tmptoken, "isnot"))
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Expected 'is' or 'isnot' in 'country_code' option at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            if (!strcmp(tmptoken, "isnot"))
                                {
                                    rulestruct[counters->rulecount].geoip2_type = 1;
                                }

                            if (!strcmp(tmptoken, "is" ))
                                {
                                    rulestruct[counters->rulecount].geoip2_type = 2;
                                }

                            tmptoken = strtok_r(NULL, ";", &saveptrrule2);           /* Grab country codes */

                            Var_To_Value(tmptoken, tmp1, sizeof(tmp1));
                            Remove_Spaces(tmp1);

                            strlcpy(rulestruct[counters->rulecount].geoip2_country_codes, tmp1, sizeof(rulestruct[counters->rulecount].geoip2_country_codes));

                            rulestruct[counters->rulecount].geoip2_flag = 1;

                        }
#endif

#ifndef HAVE_LIBMAXMINDDB
                    if (!strcmp(rulesplit, "country_code"))
                        {
                            Sagan_Log(ERROR, "** Error: Rule %d of %s has \"country_code:\" tracking but Sagan lacks GeoIP support! Rebuild Sagan with \"--enable-geoip\" or disable this rule!", linecount, ruleset_fullname);
                        }
#endif


                    if (!strcmp(rulesplit, "event_id" ))
                        {

                            /* Is it over the MAX */

                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if ( arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] 'event_id' is not valid at line %d in %s. ABort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            tmptoken = strtok_r(arg, ",", &saveptrrule2);

                            if ( tmptoken == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Invalid value for 'event_id at line %d in %s. Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            event_id_count = 0;

                            while ( tmptoken != NULL )
                                {

                                    if ( event_id_count > MAX_EVENT_ID )
                                        {
                                            Sagan_Log(ERROR, "[%s, line %d] There is to many event ids in 'event_id' types in the rule at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                        }

                                    Remove_Spaces(tmptoken);

                                    /* We copy it as a string in case we have event id's that lead with a zero */

                                    strlcpy(rulestruct[counters->rulecount].event_id[event_id_count], tmptoken, sizeof(rulestruct[counters->rulecount].event_id[event_id_count]));

                                    event_id_count++;
                                    rulestruct[counters->rulecount].event_id_count = event_id_count;

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                }
                        }

                    if (!strcmp(rulesplit, "meta_content"))
                        {

                            if ( meta_content_count > MAX_META_CONTENT )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] There is to many \"meta_content\" types in the rule at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if ( Check_Content_Not(arg) == true )
                                {
                                    rulestruct[counters->rulecount].meta_content_not[meta_content_count] = true;
                                }

                            tmptoken = strtok_r(arg, ",", &saveptrrule2);

                            if ( tmptoken == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Expected a meta_content 'helper',  but none was found at line %d in %s - Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            Between_Quotes(tmptoken, tmp2, sizeof(tmp2), ruleset_fullname, linecount, true);

                            Content_Pipe(tmp2, linecount, ruleset_fullname, rule_tmp, sizeof(rule_tmp));

                            if ( !Sagan_strstr(tmp2, "%sagan%" ) )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Line %d in %s lacks the meta_content 'helper' (%%sagan%%).", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            strlcpy(rulestruct[counters->rulecount].meta_content_help[meta_content_count], rule_tmp, sizeof(rulestruct[counters->rulecount].meta_content_help[meta_content_count]));

                            tmptoken = strtok_r(NULL, ";", &saveptrrule2);           /* Grab Search data */

                            if ( tmptoken == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Expected some sort of meta_content,  but none was found at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            Var_To_Value(tmptoken, tmp1, sizeof(tmp1));

                            Remove_Spaces(rule_tmp);

                            Content_Pipe(tmp1, linecount, ruleset_fullname, rule_tmp, sizeof(rule_tmp));
                            strlcpy(tmp2, rule_tmp, sizeof(tmp2));

                            ptmp = strtok_r(tmp2, ",", &tok);
                            meta_content_converted_count = 0;

                            while (ptmp != NULL)
                                {

                                    Replace_Sagan(rulestruct[counters->rulecount].meta_content_help[meta_content_count], ptmp, tmp_help, sizeof(tmp_help));

                                    strlcpy(rulestruct[counters->rulecount].meta_content_containers[meta_content_count].meta_content_converted[meta_content_converted_count], tmp_help, sizeof(rulestruct[counters->rulecount].meta_content_containers[meta_content_count].meta_content_converted[meta_content_converted_count]));

                                    meta_content_converted_count++;

                                    if ( meta_content_converted_count > MAX_META_ITEM_SIZE )
                                        {

                                            Sagan_Log(ERROR, "[%s, line %d] To many meta_content string values at %d in %s.  Max is %d", __FILE__, __LINE__, linecount, ruleset_fullname, MAX_META_ITEM_SIZE);

                                        }

                                    ptmp = strtok_r(NULL, ",", &tok);
                                }

                            rulestruct[counters->rulecount].meta_content_containers[meta_content_count].meta_counter = meta_content_converted_count;

                            rulestruct[counters->rulecount].meta_content_flag = true;

                            tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                            meta_content_count++;
                            rulestruct[counters->rulecount].meta_content_count=meta_content_count;

                        }

                    /* Like "nocase" for content,  but for "meta_nocase".  This is a "single option" but works better here */

                    if (!strcmp(rulesplit, "meta_nocase"))
                        {

                            if ( meta_content_count >= 1 )
                                {
                                    strtok_r(NULL, ":", &saveptrrule2);
                                    rulestruct[counters->rulecount].meta_content_case[meta_content_count-1] = 1;
                                }
                            else
                                {
                                    Sagan_Log(ERROR, "There is no 'meta_content' to apply a 'meta_nocase' to in %s at line %d!", ruleset_fullname, linecount );
                                }
                        }


#ifdef HAVE_LIBFASTJSON

                    /* JSON "mapping" */

                    if (!strcmp(rulesplit, "json_map"))
                        {

                            if ( json_map_count > MAX_JSON_MAP )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] There is to many \"json_map\" objects in the rule at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if ( arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] To few arguments for rule options \"json_map\" at line %d in %s - Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            tmptoken = strtok_r(arg, ",", &saveptrrule2);

                            if ( tmptoken == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Expected a json_map type,  but none was found at line %d in %s - Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            char json_map_type[32] = { 0 };

                            Between_Quotes(tmptoken, json_map_type, sizeof(json_map_type), ruleset_fullname, linecount, true);

                            if ( !strcmp(json_map_type, "src_ip" ) )
                                {
                                    rulestruct[counters->rulecount].json_map_type[json_map_count] = JSON_MAP_SRC_IP;
                                }

                            else if ( !strcmp(json_map_type, "dest_ip" ) )
                                {
                                    rulestruct[counters->rulecount].json_map_type[json_map_count] = JSON_MAP_DEST_IP;
                                }

                            else if ( !strcmp(json_map_type, "src_port" ) )
                                {
                                    rulestruct[counters->rulecount].json_map_type[json_map_count] = JSON_MAP_SRC_PORT;
                                }

                            else if ( !strcmp(json_map_type, "dest_port" ) )
                                {
                                    rulestruct[counters->rulecount].json_map_type[json_map_count] = JSON_MAP_DEST_PORT;
                                }

                            else if ( !strcmp(json_map_type, "username" ) )
                                {
                                    rulestruct[counters->rulecount].json_map_type[json_map_count] = JSON_MAP_USERNAME;
                                }

                            else if ( !strcmp(json_map_type, "message" ) )
                                {
                                    rulestruct[counters->rulecount].json_map_type[json_map_count] = JSON_MAP_MESSAGE;
                                }

                            else if ( !strcmp(json_map_type, "program" ) || !strcmp(json_map_type, "event_type" ) )
                                {
                                    rulestruct[counters->rulecount].json_map_type[json_map_count] = JSON_MAP_PROGRAM;
                                }

                            else if ( !strcmp(json_map_type, "event_id" ) )
                                {
                                    rulestruct[counters->rulecount].json_map_type[json_map_count] = JSON_MAP_EVENT_ID;
                                }

                            else if ( !strcmp(json_map_type, "flow_id" ) )
                                {
                                    rulestruct[counters->rulecount].json_map_type[json_map_count] = JSON_MAP_FLOW_ID;
                                }

                            else if ( !strcmp(json_map_type, "md5" ) )
                                {
                                    rulestruct[counters->rulecount].json_map_type[json_map_count] = JSON_MAP_MD5;
                                }

                            else if ( !strcmp(json_map_type, "sha1" ) )
                                {
                                    rulestruct[counters->rulecount].json_map_type[json_map_count] = JSON_MAP_SHA1;
                                }

                            else if ( !strcmp(json_map_type, "sha256" ) )
                                {
                                    rulestruct[counters->rulecount].json_map_type[json_map_count] = JSON_MAP_SHA256;
                                }

                            else if ( !strcmp(json_map_type, "filename" ) )
                                {
                                    rulestruct[counters->rulecount].json_map_type[json_map_count] = JSON_MAP_FILENAME;
                                }

                            else if ( !strcmp(json_map_type, "hostname" ) )
                                {
                                    rulestruct[counters->rulecount].json_map_type[json_map_count] = JSON_MAP_HOSTNAME;
                                }

                            else if ( !strcmp(json_map_type, "url" ) )
                                {
                                    rulestruct[counters->rulecount].json_map_type[json_map_count] = JSON_MAP_URL;
                                }

                            else if ( !strcmp(json_map_type, "ja3" ) )
                                {
                                    rulestruct[counters->rulecount].json_map_type[json_map_count] = JSON_MAP_JA3;
                                }

                            else if ( !strcmp(json_map_type, "proto" ) )
                                {
                                    rulestruct[counters->rulecount].json_map_type[json_map_count] = JSON_MAP_PROTO;
                                }

                            /* Not valid map specified */

                            if ( rulestruct[counters->rulecount].json_map_type[json_map_count] == 0 )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] json_map type '%s' is invalid at line %d in %s - Abort", __FILE__, __LINE__, json_map_type, linecount, ruleset_fullname);
                                }

                            tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                            if ( tmptoken == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Expected a json_map key,  but none was found at line %d in %s - Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            Between_Quotes(tmptoken, rulestruct[counters->rulecount].json_map_key[json_map_count], sizeof(rulestruct[counters->rulecount].json_map_key[json_map_count]), ruleset_fullname, linecount, true);

                            json_map_count++;
                            rulestruct[counters->rulecount].json_map_count = json_map_count;

                        }

                    /* "json_content" works like "content" but on JSON key/values */

                    if (!strcmp(rulesplit, "json_content") )
                        {

                            if ( config->input_type != INPUT_JSON && config->json_parse_data == false )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Signature in %s at line %d contains 'json_content', but the Sagan 'input-type' isn't JSON and 'json-parse-data' is not enabled.  Abort.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                }

                            if ( json_content_count > MAX_JSON_CONTENT )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] There is to many \"json_content\" types in the rule at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if ( arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] To few arguments for rule options \"json_content\" at line %d in %s - Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            if ( Check_Content_Not(arg) == true )
                                {
                                    rulestruct[counters->rulecount].json_content_not[json_content_count] = true;
                                }

                            tmptoken = strtok_r(arg, ",", &saveptrrule2);

                            if ( tmptoken == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Expected a json_content key,  but none was found at line %d in %s - Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            Between_Quotes(tmptoken, rulestruct[counters->rulecount].json_content_key[json_content_count], sizeof(rulestruct[counters->rulecount].json_content_key[json_content_count]), ruleset_fullname, linecount, true);

                            if ( rulestruct[counters->rulecount].json_content_key[json_content_count][0] != '.' )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Invalid key for 'json_content' at line %d in %s. A '.' should prepend the key.", __FILE__, __LINE__, linecount, ruleset_fullname);

                                }

                            tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                            if ( tmptoken == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Expected a json_content \"content\",  but none was found at line %d in %s - Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            /* Convert |3a| type of content */

                            Content_Pipe(tmptoken, linecount, ruleset_fullname, rule_tmp, sizeof(rule_tmp));

                            Between_Quotes(rule_tmp, rulestruct[counters->rulecount].json_content_content[json_content_count], sizeof(rulestruct[counters->rulecount].json_content_content[json_content_count]), ruleset_fullname, linecount, true);

                            json_content_count++;
                            rulestruct[counters->rulecount].json_content_count=json_content_count;

                        }

                    /* Set the previous "json_content" to case insensitive */

                    if (!strcmp(rulesplit, "json_nocase"))
                        {

                            if ( config->input_type != INPUT_JSON && config->json_parse_data == false )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Signature in %s at line %d contains 'json_nocase', but the Sagan 'input-type' isn't JSON and 'json-parse-data' is not enabled.  Abort.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                }

                            strtok_r(NULL, ":", &saveptrrule2);
                            rulestruct[counters->rulecount].json_content_case[json_content_count-1] = 1;
                        }

                    /* Set the previous "json_strstr" to use strstr instead of strcmp */

                    if ( !strcmp(rulesplit, "json_contains") )
                        {

                            if ( config->input_type != INPUT_JSON && config->json_parse_data == false )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Signature in %s at line %d contains 'json_contains', but the Sagan 'input-type' isn't JSON and 'json-parse-data' is not enabled.  Abort.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                }

                            strtok_r(NULL, ":", &saveptrrule2);
                            rulestruct[counters->rulecount].json_content_strstr[json_content_count-1] = 1;
                        }

                    /* For json_content */

                    if (!strcmp(rulesplit, "json_decode_base64"))
                        {

                            if ( config->input_type != INPUT_JSON && config->json_parse_data == false )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Signature in %s at line %d contains 'json_decode_base64', but the Sagan 'input-type' isn't JSON and 'json-parse-data' is not enabled.  Abort.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                }

                            strtok_r(NULL, ":", &saveptrrule2);
                            rulestruct[counters->rulecount].json_decode_base64[json_decode_base64_count] = true;

                            json_decode_base64_count++;
                        }

                    /* For json_pcre */

                    if (!strcmp(rulesplit, "json_decode_base64_pcre"))
                        {

                            if ( config->input_type != INPUT_JSON && config->json_parse_data == false )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Signature in %s at line %d contains 'json_decode_base64_pcre', but the Sagan 'input-type' isn't JSON and 'json-parse-data' is not enabled.  Abort.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                }

                            strtok_r(NULL, ":", &saveptrrule2);
                            rulestruct[counters->rulecount].json_decode_base64_pcre[json_decode_base64_pcre_count] = true;

                            json_decode_base64_pcre_count++;
                        }

                    /* For json_meta_content */

                    if (!strcmp(rulesplit, "json_decode_base64_meta"))
                        {

                            if ( config->input_type != INPUT_JSON && config->json_parse_data == false )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Signature in %s at line %d contains 'json_decode_base64_meta', but the Sagan 'input-type' isn't JSON and 'json-parse-data' is not enabled.  Abort.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                }

                            strtok_r(NULL, ":", &saveptrrule2);
                            rulestruct[counters->rulecount].json_decode_base64_meta[json_decode_base64_meta_count] = true;

                            json_decode_base64_meta_count++;
                        }


                    /* Set the previous "json_meta_content" to use strstr instead of strcmp */

                    if ( !strcmp(rulesplit, "json_meta_contains" ) )
                        {

                            if ( config->input_type != INPUT_JSON && config->json_parse_data == false )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Signature in %s at line %d contains 'json_meta_contains', but the Sagan 'input-type' isn't JSON and 'json-parse-data' is not enabled.  Abort.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                }

                            strtok_r(NULL, ":", &saveptrrule2);
                            rulestruct[counters->rulecount].json_meta_strstr[json_meta_content_count-1] = 1;
                        }


                    /* Search JSON via PCRE */

                    if (!strcmp(rulesplit, "json_pcre"))
                        {

                            if ( config->input_type != INPUT_JSON && config->json_parse_data == false )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Signature in %s at line %d contains 'json_pcre', but the Sagan 'input-type' isn't JSON and 'json-parse-data' is not enabled.  Abort.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                }

                            if ( json_pcre_count > MAX_JSON_PCRE )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] There is to many \"json_pcre\" types in the rule at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if ( arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] To few arguments for rule options \"json_pcre\" at line %d in %s - Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            tmptoken = strtok_r(arg, ",", &saveptrrule2);

                            if ( tmptoken == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Expected a json_pcre key,  but none was found at line %d in %s - Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }


                            Between_Quotes(tmptoken, rulestruct[counters->rulecount].json_pcre_key[json_pcre_count], sizeof(rulestruct[counters->rulecount].json_pcre_key[json_pcre_count]), ruleset_fullname, linecount, true);

                            if ( rulestruct[counters->rulecount].json_pcre_key[json_pcre_count][0] != '.' )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Invalid key for 'json_pcre' at line %d in %s. A '.' should prepend the key.", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }


                            /* DEBUG: This isn't great.  If the pcre has a semicolon, it will break things :(
                               I need to re-write this section (?) */

                            tmptoken = strtok_r(NULL, ";", &saveptrrule2);	/* strtok on the ; */

                            if ( tmptoken == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Expected a json_pcre \"pcre\" statement,  but none was found at line %d in %s - Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            Between_Quotes(tmptoken, tmp2, sizeof(tmp2), ruleset_fullname, linecount, false);

                            pcreflag=false;

                            memset(pcrerule, 0, sizeof(pcrerule));

                            for ( i = 1; i < strlen(tmp2); i++)
                                {

                                    if ( tmp2[i] == '/' && tmp2[i-1] != '\\' )
                                        {
                                            pcreflag = true;
                                        }

                                    if ( pcreflag == false )
                                        {
                                            snprintf(tmp, sizeof(tmp), "%c", tmp2[i]);
                                            strlcat(pcrerule, tmp, sizeof(pcrerule));
                                        }

                                    /* are we /past/ and at the args? */

                                    if ( pcreflag == true )
                                        {

                                            switch(tmp2[i])
                                                {

                                                case 'i':
                                                    if ( pcreflag == true ) pcreoptions |= PCRE_CASELESS;
                                                    break;
                                                case 's':
                                                    if ( pcreflag == true ) pcreoptions |= PCRE_DOTALL;
                                                    break;
                                                case 'm':
                                                    if ( pcreflag == true ) pcreoptions |= PCRE_MULTILINE;
                                                    break;
                                                case 'x':
                                                    if ( pcreflag == true ) pcreoptions |= PCRE_EXTENDED;
                                                    break;
                                                case 'A':
                                                    if ( pcreflag == true ) pcreoptions |= PCRE_ANCHORED;
                                                    break;
                                                case 'E':
                                                    if ( pcreflag == true ) pcreoptions |= PCRE_DOLLAR_ENDONLY;
                                                    break;
                                                case 'G':
                                                    if ( pcreflag == true ) pcreoptions |= PCRE_UNGREEDY;
                                                    break;

                                                }
                                        }
                                }


                            if ( pcreflag == false )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Missing last '/' in json_pcre: %s at line %d, Abort", __FILE__, __LINE__, ruleset_fullname, linecount);
                                }

                            /* We store the compiled/study results. */

                            rulestruct[counters->rulecount].json_re_pcre[json_pcre_count] =  pcre_compile( pcrerule, pcreoptions, &error, &erroffset, NULL );


#ifdef PCRE_HAVE_JIT

                            if ( config->pcre_jit == true )
                                {
                                    pcreoptions |= PCRE_STUDY_JIT_COMPILE;
                                }
#endif

                            rulestruct[counters->rulecount].json_pcre_extra[json_pcre_count] = pcre_study( rulestruct[counters->rulecount].json_re_pcre[json_pcre_count], pcreoptions, &error);

#ifdef PCRE_HAVE_JIT

                            if ( config->pcre_jit == true )
                                {
                                    int jit = 0;
                                    rc = 0;

                                    rc = pcre_fullinfo(rulestruct[counters->rulecount].json_re_pcre[json_pcre_count], rulestruct[counters->rulecount].json_pcre_extra[json_pcre_count], PCRE_INFO_JIT, &jit);

                                    if (rc != 0 || jit != 1)
                                        {
                                            Sagan_Log(WARN, "[%s, line %d] PCRE JIT does not support regexp in %s at line %d. Continuing without PCRE JIT enabled for this rule.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                        }
                                }

#endif

                            if (  rulestruct[counters->rulecount].json_re_pcre[json_pcre_count]  == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] PCRE failure in %s at %d [%d: %s], Abort", __FILE__, __LINE__, ruleset_fullname, linecount, erroffset, error);
                                }


                            json_pcre_count++;
                            rulestruct[counters->rulecount].json_pcre_count=json_pcre_count;

                        }

                    if (!strcmp(rulesplit, "json_meta_content"))
                        {

                            if ( config->input_type != INPUT_JSON && config->json_parse_data == false )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Signature in %s at line %d contains 'json_meta_content', but the Sagan 'input-type' isn't JSON and 'json-parse-data' is not enabled.  Abort.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                }

                            if ( json_meta_content_count > MAX_JSON_META_CONTENT )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] There is to many \"json_meta_content\" types in the rule at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if ( Check_Content_Not(arg) == true )
                                {
                                    rulestruct[counters->rulecount].json_meta_content_not[json_meta_content_count] = true;
                                }

                            tmptoken = strtok_r(arg, ",", &saveptrrule2);

                            if ( tmptoken == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Expected a json_meta_content key but none was found at line %d in %s - Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            Between_Quotes(tmptoken, rulestruct[counters->rulecount].json_meta_content_key[json_meta_content_count],sizeof(rulestruct[counters->rulecount].json_meta_content_key[json_meta_content_count]), ruleset_fullname, linecount, true);

                            if ( rulestruct[counters->rulecount].json_meta_content_key[json_meta_content_count][0] != '.' )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Invalid key for 'json_meta_content' at line %d in %s. A '.' should prepend the key.", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }


                            tmptoken = strtok_r(NULL, ";", &saveptrrule2);           /* Grab Search data */

                            if ( tmptoken == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Expected some sort of json_meta_content,  but none was found at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            Var_To_Value(tmptoken, tmp1, sizeof(tmp1));

                            Remove_Spaces(rule_tmp);

                            Content_Pipe(tmp1, linecount, ruleset_fullname, rule_tmp, sizeof(rule_tmp));
                            strlcpy(tmp2, rule_tmp, sizeof(tmp2));

                            ptmp = strtok_r(tmp2, ",", &tok);

                            while ( ptmp != NULL )
                                {

                                    strlcpy(rulestruct[counters->rulecount].json_meta_content_containers[json_meta_content_count].json_meta_content_converted[json_meta_content_converted_count], ptmp, sizeof(rulestruct[counters->rulecount].json_meta_content_containers[json_meta_content_count].json_meta_content_converted[json_meta_content_converted_count]));

                                    json_meta_content_converted_count++;

                                    if ( json_meta_content_converted_count > MAX_JSON_META_ITEM_SIZE )
                                        {

                                            Sagan_Log(ERROR, "[%s, line %d] To many json_meta_content string values at %d in %s.  Max is %d", __FILE__, __LINE__, linecount, ruleset_fullname, MAX_JSON_META_ITEM_SIZE);

                                        }

                                    ptmp = strtok_r(NULL, ",", &tok);

                                }

                            rulestruct[counters->rulecount].json_meta_content_containers[json_meta_content_count].json_meta_counter = json_meta_content_converted_count;


                            json_meta_content_count++;
                            rulestruct[counters->rulecount].json_meta_content_count=json_meta_content_count;

                        }

                    if (!strcmp(rulesplit, "json_meta_nocase"))
                        {

                            if ( config->input_type != INPUT_JSON && config->json_parse_data == false )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Signature in %s at line %d contains 'json_meta_nocase', but the Sagan 'input-type' isn't JSON and 'json-parse-data' is not enabled.  Abort.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                }

                            if ( json_meta_content_count >= 1 )
                                {

                                    strtok_r(NULL, ":", &saveptrrule2);
                                    rulestruct[counters->rulecount].json_meta_content_case[json_meta_content_count-1] = true;
                                }
                            else
                                {
                                    Sagan_Log(ERROR, "There is no 'json_meta_content' to apply a 'json_meta_nocase' to in %s at line %d!", ruleset_fullname, linecount );
                                }

                        }

#endif

                    /* Rule revision */

                    if (!strcmp(rulesplit, "rev" ))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The \"rev\" appears to be incomplete at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            Remove_Spaces(arg);

                            rulestruct[counters->rulecount].s_rev = atoi(arg);
                        }

                    if (!strcmp(rulesplit, "classtype" ))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The \"classtype\" appears to be incomplete at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            Remove_Spaces(arg);
                            strlcpy(rulestruct[counters->rulecount].s_classtype, arg, sizeof(rulestruct[counters->rulecount].s_classtype));

                            found = 0;

                            for(i=0; i < counters->classcount; i++)
                                {
                                    if (!strcmp(classstruct[i].s_shortname, rulestruct[counters->rulecount].s_classtype))
                                        {
                                            rulestruct[counters->rulecount].s_pri = classstruct[i].s_priority;
                                            found = 1;
                                        }
                                }

                            if ( found == 0 )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The classtype \"%s\" was not found on line %d in %s! "
                                              "Are you attempting loading a rule set before loading the classification.config? - Abort", __FILE__, __LINE__, rulestruct[counters->rulecount].s_classtype, linecount, ruleset_fullname);
                                }

                        }

                    if (!strcmp(rulesplit, "program" ) || !strcmp(rulesplit, "event_type" ))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The \"program\" or \"event_type\" appears to be incomplete at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            Var_To_Value(arg, tmp1, sizeof(tmp1));
                            Remove_Spaces(tmp1);

                            strlcpy(rulestruct[counters->rulecount].s_program, tmp1, sizeof(rulestruct[counters->rulecount].s_program));

                        }

                    if (!strcmp(rulesplit, "reference" ))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The \"reference\" appears to be incomplete at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            Remove_Spaces(arg);

                            /* references are , delimited.  For exmaple: "url,www.example.com".  I've seen people put
                               "reference: Sharepoint;" which isn't valid.  Check the reference before passing. */

                            if ( !Sagan_strstr(arg, "," ) )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The \"reference\" \"%s\" is invalid at line %d in %s. It need to be comma delimited (ie = \"url,example.com\", \"cve,1234\")", __FILE__, __LINE__, arg, linecount, ruleset_fullname);
                                }

                            strlcpy(rulestruct[counters->rulecount].s_reference[ref_count], arg, sizeof(rulestruct[counters->rulecount].s_reference[ref_count]));

                            rulestruct[counters->rulecount].ref_count=ref_count;
                            ref_count++;
                        }

                    if (!strcmp(rulesplit, "sid" ))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The \"sid\" appears to be incomplete at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            Remove_Spaces(arg);
                            rulestruct[counters->rulecount].s_sid = atol(arg);
                        }


                    if (!strcmp(rulesplit, "syslog_tag" ))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The \"syslog_tag\" appears to be incomplete at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }
                            Remove_Spaces(arg);
                            if (strlen(arg) > MAX_SYSLOG_TAG)
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The complete \"syslog_tag\" appears to be exceeding the max length at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            ptmp = strtok_r(arg, "|", &tok);
                            while ( ptmp != NULL )
                                {
                                    if (strlen(ptmp) > MAX_SYSLOG_TAG)
                                        {
                                            Sagan_Log(ERROR, "[%s, line %d] The individual \"syslog_tag\" appears to be exceeding the max length at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                        }

                                    ptmp = strtok_r(NULL, "|", &tok);
                                }

                            strlcpy(rulestruct[counters->rulecount].s_tag, arg, sizeof(rulestruct[counters->rulecount].s_tag));
                        }


                    if (!strcmp(rulesplit, "syslog_facility" ))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The \"facility\" appears to be incomplete at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            Remove_Spaces(arg);
                            strlcpy(rulestruct[counters->rulecount].s_facility, arg, sizeof(rulestruct[counters->rulecount].s_facility));
                        }

                    if (!strcmp(rulesplit, "syslog_level" ))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The \"level\" appears to be incomplete at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            Remove_Spaces(arg);
                            strlcpy(rulestruct[counters->rulecount].s_level, arg, sizeof(rulestruct[counters->rulecount].s_level));
                        }

                    if (!strcmp(rulesplit, "syslog_priority" ))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The \"syslog_priority\" appears to be incomplete at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            Remove_Spaces(arg);
                            strlcpy(rulestruct[counters->rulecount].s_syspri, arg, sizeof(rulestruct[counters->rulecount].s_syspri));
                        }


                    if ( !strcmp(rulesplit, "pri" ) || !strcmp(rulesplit, "priority" ) )
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The \"priority\" appears to be incomplete at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            Remove_Spaces(arg);
                            rulestruct[counters->rulecount].s_pri = atoi(arg);
                        }

#ifdef HAVE_LIBESMTP

                    if (!strcmp(rulesplit, "email" ))
                        {
                            arg = strtok_r(NULL, " ", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The \"email\" appears to be incomplete at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            if (!strcmp(config->sagan_esmtp_server, "" ))
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Line %d of %s has the \"email:\" option,  but no SMTP server is specified in the %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname, config->sagan_config);
                                }

                            Remove_Spaces(arg);
                            strlcpy(rulestruct[counters->rulecount].email, arg, sizeof(rulestruct[counters->rulecount].email));
                            rulestruct[counters->rulecount].email_flag=1;
                            config->sagan_esmtp_flag=1;
                        }
#endif


#ifdef HAVE_LIBLOGNORM

                    /* Our Liblognorm friends changed the way it works!  We use to load normalization rule base files
                       as they were needed. ln_loadSample no longer accepts multiple calls.  This means that _all_
                       liblognorm rules need to be loaded from one file at one time.  This depreciates "normalize: type;"
                               in favor of a simple "normalize"; */

                    if (!strcmp(rulesplit, "normalize" ))
                        {
                            rulestruct[counters->rulecount].normalize = 1;

                            /* Test for old liblognorm/Sagan usage.  If old method is found,  produce a warning */

                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg != NULL )
                                {
                                    Sagan_Log(ERROR, "Detected a rule that uses the older \'normalize\' method.  Please consider updating \'%s\' at line %d.  Abort", ruleset_fullname, linecount);
                                }
                        }

#endif

                    /* Quoted information (content, pcre, msg)  */

                    if (!strcmp(rulesplit, "msg" ))
                        {
                            arg = strtok_r(NULL, ";", &saveptrrule2);

                            Between_Quotes(arg, tmp2, sizeof(tmp2), ruleset_fullname, linecount, true);

                            if (tmp2[0] == '\0' )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The \"msg\" appears to be incomplete at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            strlcpy(rulestruct[counters->rulecount].s_msg, tmp2, sizeof(rulestruct[counters->rulecount].s_msg));
                        }

                    /* Good ole "content" style search */

                    if (!strcmp(rulesplit, "content" ))
                        {
                            if ( content_count > MAX_CONTENT )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] There is to many \"content\" types in the rule at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            arg = strtok_r(NULL, ";", &saveptrrule2);

                            /* For content: ! "something" */

                            if ( Check_Content_Not(arg) == true )
                                {
                                    rulestruct[counters->rulecount].content_not[content_count] = true;
                                }

                            Between_Quotes(arg, tmp2, sizeof(tmp2), ruleset_fullname, linecount, true);

                            if (tmp2[0] == '\0' )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The \"content\" appears to be incomplete at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            /* Convert HEX encoded data */

                            Content_Pipe(tmp2, linecount, ruleset_fullname, rule_tmp, sizeof(rule_tmp));
                            strlcpy(final_content, rule_tmp, sizeof(final_content));

                            strlcpy(rulestruct[counters->rulecount].content[content_count], final_content, sizeof(rulestruct[counters->rulecount].content[content_count]));
                            final_content[0] = '\0';
                            content_count++;
                            rulestruct[counters->rulecount].content_count=content_count;
                        }

                    /* Single option,  but "nocase" works better here */

                    if (!strcmp(rulesplit, "nocase"))
                        {
                            if ( content_count >= 1 )
                                {
                                    strtok_r(NULL, ":", &saveptrrule2);
                                    rulestruct[counters->rulecount].content_case[content_count - 1] = true;
                                }
                            else
                                {
                                    Sagan_Log(ERROR, "There is no 'content' to apply a 'nocase' to in %s at line %d!", ruleset_fullname, linecount );
                                }

                        }

                    if (!strcmp(rulesplit, "offset"))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The \"offset\" appears to be missing at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            if ( content_count >= 1)
                                {
                                    rulestruct[counters->rulecount].s_offset[content_count - 1] = atoi(arg);
                                }
                            else
                                {
                                    Sagan_Log(ERROR, "There is no 'content' to apply a 'offset' to in %s at line %d!", ruleset_fullname, linecount );
                                }
                        }

                    if (!strcmp(rulesplit, "meta_offset"))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The \"meta_offset\" appears to be missing at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            if ( meta_content_count >= 1)
                                {
                                    rulestruct[counters->rulecount].meta_offset[meta_content_count - 1] = atoi(arg);
                                }
                            else
                                {
                                    Sagan_Log(ERROR, "There is no 'meta_content' to apply a 'meta_offset' to in %s at line %d!", ruleset_fullname, linecount );
                                }
                        }


                    if (!strcmp(rulesplit, "depth"))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The \"depth\" appears to be missing at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            if ( content_count >= 1 )
                                {
                                    rulestruct[counters->rulecount].s_depth[content_count - 1] = atoi(arg);
                                }
                            else
                                {
                                    Sagan_Log(ERROR, "There is no 'content' to apply a 'depth' to in %s at line %d!", ruleset_fullname, linecount );
                                }
                        }

                    if (!strcmp(rulesplit, "meta_depth"))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The \"meta_depth\" appears to be missing at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            if ( meta_content_count >= 1 )
                                {
                                    rulestruct[counters->rulecount].meta_depth[meta_content_count - 1] = atoi(arg);
                                }
                            else
                                {
                                    Sagan_Log(ERROR, "There is no 'meta_content' to apply a 'meta_depth' to in %s at line %d!", ruleset_fullname, linecount );
                                }
                        }


                    if (!strcmp(rulesplit, "distance"))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The \"distance\" appears to be missing at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            if ( content_count >= 1 )
                                {
                                    rulestruct[counters->rulecount].s_distance[content_count - 1] = atoi(arg);
                                }
                            else
                                {
                                    Sagan_Log(ERROR, "There is no 'content' to apply a 'distance' to in %s at line %d!", ruleset_fullname, linecount );
                                }
                        }

                    if (!strcmp(rulesplit, "meta_distance"))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The \"meta_distance\" appears to be missing at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            if ( meta_content_count >= 1 )
                                {
                                    rulestruct[counters->rulecount].meta_distance[meta_content_count - 1] = atoi(arg);
                                }
                            else
                                {
                                    Sagan_Log(ERROR, "There is no 'meta_content' to apply a 'meta_distance' to in %s at line %d!", ruleset_fullname, linecount );
                                }

                        }


                    if (!strcmp(rulesplit, "within"))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The \"within\" appears to be missing at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            if ( content_count >= 1 )
                                {
                                    rulestruct[counters->rulecount].s_within[content_count - 1] = atoi(arg);
                                }
                            else
                                {
                                    Sagan_Log(ERROR, "There is no 'content' to apply a 'within' to in %s at line %d!", ruleset_fullname, linecount );
                                }
                        }


                    if (!strcmp(rulesplit, "meta_within"))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The \"meta_within\" appears to be missing at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            if ( meta_content_count >= 1 )
                                {
                                    rulestruct[counters->rulecount].meta_within[meta_content_count - 1] = atoi(arg);
                                }
                            else
                                {
                                    Sagan_Log(ERROR, "There is no 'meta_content' to apply a 'meta_within' to in %s at line %d!", ruleset_fullname, linecount );
                                }
                        }


                    /* PCRE needs a little extra "work" */

                    if (!strcmp(rulesplit, "pcre" ))
                        {

                            if ( pcre_count > MAX_PCRE )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] There is to many \"pcre\" types in the rule at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            arg = strtok_r(NULL, ";", &saveptrrule2);

                            Between_Quotes(arg, tmp2, sizeof(tmp2), ruleset_fullname, linecount, false);

                            if (tmp2[0] == '\0' )
                                {
                                    Sagan_Log(ERROR, "The \"pcre\" appears to be incomplete at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            pcreflag=false;

                            memset(pcrerule, 0, sizeof(pcrerule));

                            for ( i = 1; i < strlen(tmp2); i++)
                                {

                                    if ( tmp2[i] == '/' && tmp2[i-1] != '\\' )
                                        {
                                            pcreflag = true;
                                        }

                                    if ( pcreflag == false )
                                        {
                                            snprintf(tmp, sizeof(tmp), "%c", tmp2[i]);
                                            strlcat(pcrerule, tmp, sizeof(pcrerule));
                                        }

                                    /* are we /past/ and at the args? */

                                    if ( pcreflag == true )
                                        {

                                            switch(tmp2[i])
                                                {

                                                case 'i':
                                                    if ( pcreflag == true ) pcreoptions |= PCRE_CASELESS;
                                                    break;
                                                case 's':
                                                    if ( pcreflag == true ) pcreoptions |= PCRE_DOTALL;
                                                    break;
                                                case 'm':
                                                    if ( pcreflag == true ) pcreoptions |= PCRE_MULTILINE;
                                                    break;
                                                case 'x':
                                                    if ( pcreflag == true ) pcreoptions |= PCRE_EXTENDED;
                                                    break;
                                                case 'A':
                                                    if ( pcreflag == true ) pcreoptions |= PCRE_ANCHORED;
                                                    break;
                                                case 'E':
                                                    if ( pcreflag == true ) pcreoptions |= PCRE_DOLLAR_ENDONLY;
                                                    break;
                                                case 'G':
                                                    if ( pcreflag == true ) pcreoptions |= PCRE_UNGREEDY;
                                                    break;


                                                    /* PCRE options that aren't really used? */

                                                    /*
                                                      case 'f':
                                                            if ( pcreflag == 1 ) pcreoptions |= PCRE_FIRSTLINE; break;
                                                      case 'C':
                                                            if ( pcreflag == 1 ) pcreoptions |= PCRE_AUTO_CALLOUT; break;
                                                      case 'J':
                                                            if ( pcreflag == 1 ) pcreoptions |= PCRE_DUPNAMES; break;
                                                      case 'N':
                                                            if ( pcreflag == 1 ) pcreoptions |= PCRE_NO_AUTO_CAPTURE; break;
                                                      case 'X':
                                                            if ( pcreflag == 1 ) pcreoptions |= PCRE_EXTRA; break;
                                                      case '8':
                                                            if ( pcreflag == 1 ) pcreoptions |= PCRE_UTF8; break;
                                                      case '?':
                                                            if ( pcreflag == 1 ) pcreoptions |= PCRE_NO_UTF8_CHECK; break;
                                                            */

                                                }
                                        }
                                }


                            if ( pcreflag == 0 )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Missing last '/' in pcre: %s at line %d, Abort", __FILE__, __LINE__, ruleset_fullname, linecount);
                                }


                            /* We store the compiled/study results.  This saves us some CPU time during searching - Champ Clark III - 02/01/2011 */

                            rulestruct[counters->rulecount].re_pcre[pcre_count] =  pcre_compile( pcrerule, pcreoptions, &error, &erroffset, NULL );

#ifdef PCRE_HAVE_JIT

                            if ( config->pcre_jit == true )
                                {
                                    pcreoptions |= PCRE_STUDY_JIT_COMPILE;
                                }
#endif

                            rulestruct[counters->rulecount].pcre_extra[pcre_count] = pcre_study( rulestruct[counters->rulecount].re_pcre[pcre_count], pcreoptions, &error);

#ifdef PCRE_HAVE_JIT

                            if ( config->pcre_jit == true )
                                {
                                    int jit = 0;
                                    rc = 0;

                                    rc = pcre_fullinfo(rulestruct[counters->rulecount].re_pcre[pcre_count], rulestruct[counters->rulecount].pcre_extra[pcre_count], PCRE_INFO_JIT, &jit);

                                    if (rc != 0 || jit != 1)
                                        {
                                            Sagan_Log(WARN, "[%s, line %d] PCRE JIT does not support regexp in %s at line %d (pcre: \"%s\"). Continuing without PCRE JIT enabled for this rule.", __FILE__, __LINE__, ruleset_fullname, linecount, pcrerule);
                                        }
                                }

#endif

                            if (  rulestruct[counters->rulecount].re_pcre[pcre_count]  == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] PCRE failure in %s at %d [%d: %s], Abort", __FILE__, __LINE__, ruleset_fullname, linecount, erroffset, error);
                                }

                            pcre_count++;
                            rulestruct[counters->rulecount].pcre_count=pcre_count;
                        }

                    /* Time based alerting */

                    if (!strcmp(rulesplit, "alert_time"))
                        {

                            rulestruct[counters->rulecount].alert_time_flag = 1;

                            tok_tmp = strtok_r(NULL, ":", &saveptrrule2);
                            Var_To_Value(tok_tmp, tmp1, sizeof(tmp1));

                            tmptoken = strtok_r(tmp1, ",", &saveptrrule2);

                            while( tmptoken != NULL )
                                {

                                    if (Sagan_strstr(tmptoken, "days"))
                                        {
                                            tmptok_tmp = strtok_r(tmptoken, " ", &saveptrrule3);
                                            tmptok_tmp = strtok_r(NULL, " ", &saveptrrule3);
                                            Remove_Spaces(tmptok_tmp);

                                            if (strlen(tmptok_tmp) > 7 )
                                                {
                                                    Sagan_Log(ERROR, "[%s, line %d] To many days (%s) in 'alert_time' in %s at line %d, Abort.", __FILE__, __LINE__, tmptok_tmp, ruleset_fullname, linecount);
                                                }

                                            strlcpy(alert_time_tmp, tmptok_tmp, sizeof(alert_time_tmp));

                                            for (i=0; i<strlen(alert_time_tmp); i++)
                                                {
                                                    snprintf(tmp, sizeof(tmp), "%c", alert_time_tmp[i]);

                                                    if (!Is_Numeric(tmp))
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] The day '%c' 'alert_time / days' is invalid in %s at line %d, Abort.", __FILE__, __LINE__,  alert_time_tmp[i], ruleset_fullname, linecount);
                                                        }

                                                    if ( atoi(tmp) == 0 ) rulestruct[counters->rulecount].alert_days ^= SUNDAY;
                                                    if ( atoi(tmp) == 1 ) rulestruct[counters->rulecount].alert_days ^= MONDAY;
                                                    if ( atoi(tmp) == 2 ) rulestruct[counters->rulecount].alert_days ^= TUESDAY;
                                                    if ( atoi(tmp) == 3 ) rulestruct[counters->rulecount].alert_days ^= WEDNESDAY;
                                                    if ( atoi(tmp) == 4 ) rulestruct[counters->rulecount].alert_days ^= THURSDAY;
                                                    if ( atoi(tmp) == 5 ) rulestruct[counters->rulecount].alert_days ^= FRIDAY;
                                                    if ( atoi(tmp) == 6 ) rulestruct[counters->rulecount].alert_days ^= SATURDAY;

                                                }

                                        }

                                    if (Sagan_strstr(tmptoken, "hours"))
                                        {

                                            tmptok_tmp = strtok_r(tmptoken, " ", &saveptrrule3);
                                            tmptok_tmp = strtok_r(NULL, " ", &saveptrrule3);
                                            Remove_Spaces(tmptok_tmp);

                                            if ( strlen(tmptok_tmp) > 9 || strlen(tmptok_tmp) < 9 )
                                                {
                                                    Sagan_Log(ERROR, "[%s, line %d] Improper 'alert_time' format in %s at line %d, Abort.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                                }

                                            snprintf(alert_time_tmp, sizeof(alert_time_tmp), "%s", tmptok_tmp);

                                            /* Start hour */

                                            snprintf(alert_tmp_hour, sizeof(alert_tmp_hour), "%c%c", alert_time_tmp[0], alert_time_tmp[1]);

                                            if ( atoi(alert_tmp_hour) > 23 )
                                                {
                                                    Sagan_Log(ERROR, "[%s, line %d] Starting 'alert_time' hour cannot be over 23 in %s at line %d, Abort.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                                }

                                            snprintf(alert_tmp_minute, sizeof(alert_tmp_minute), "%c%c", alert_time_tmp[2], alert_time_tmp[3]);

                                            if ( atoi(alert_tmp_minute) > 59 )
                                                {
                                                    Sagan_Log(ERROR, "[%s, line %d] Starting 'alert_time' minute cannot be over 59 in %s at line %d, Abort.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                                }

                                            snprintf(alert_time_all, sizeof(alert_time_all), "%s%s", alert_tmp_hour, alert_tmp_minute);
                                            rulestruct[counters->rulecount].aetas_start = atoi(alert_time_all);

                                            /* End hour */

                                            snprintf(alert_tmp_hour, sizeof(alert_tmp_hour), "%c%c", alert_time_tmp[5], alert_time_tmp[6]);

                                            if ( atoi(alert_tmp_hour) > 23 )
                                                {
                                                    Sagan_Log(ERROR, "[%s, line %d] Ending 'alert_time' hour cannot be over 23 in %s at line %d, Abort.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                                }

                                            snprintf(alert_tmp_minute, sizeof(alert_tmp_minute), "%c%c", alert_time_tmp[7], alert_time_tmp[8]);

                                            if ( atoi(alert_tmp_minute) > 59 )
                                                {
                                                    Sagan_Log(ERROR, "[%s, line %d] Ending 'alert_time' minute cannot be over 59 in %s at line %d, Abort.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                                }

                                            snprintf(alert_time_all, sizeof(alert_time_all), "%s%s", alert_tmp_hour, alert_tmp_minute);

                                            rulestruct[counters->rulecount].aetas_end = atoi(alert_time_all);

                                        }

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);
                                }

                        }

                    /* Threshold */

                    if (!strcmp(rulesplit, "threshold" ))
                        {

                            valid = 0;

                            tok_tmp = strtok_r(NULL, ":", &saveptrrule2);
                            tmptoken = strtok_r(tok_tmp, ",", &saveptrrule2);

                            while( tmptoken != NULL )
                                {

                                    if (Sagan_strstr(tmptoken, "type"))
                                        {

                                            valid++;


                                            if (Sagan_strstr(tmptoken, "limit"))
                                                {
                                                    rulestruct[counters->rulecount].threshold2_type = THRESHOLD_LIMIT;
                                                    valid++;
                                                }

                                            else if (Sagan_strstr(tmptoken, "suppress"))
                                                {
                                                    rulestruct[counters->rulecount].threshold2_type = THRESHOLD_SUPPRESS;
                                                    valid++;
                                                }

                                            if ( rulestruct[counters->rulecount].threshold2_type == 0 )
                                                {
                                                    Sagan_Log(ERROR, "[%s, line %d] Invalid threshold type '%s' at line %d in %s. Threshold type must be 'limit' or 'suppress'. Abort.", __FILE__, __LINE__, tmptoken, linecount, ruleset_fullname);
                                                }

                                        }


                                    if (Sagan_strstr(tmptoken, "track"))
                                        {
                                            valid++;

                                            if (Sagan_strstr(tmptoken, "by_src"))
                                                {
                                                    rulestruct[counters->rulecount].threshold2_method_src = true;
                                                    valid++;
                                                }

                                            if (Sagan_strstr(tmptoken, "by_dst"))
                                                {
                                                    rulestruct[counters->rulecount].threshold2_method_dst = true;
                                                    valid++;
                                                }

                                            if (Sagan_strstr(tmptoken, "by_username") || Sagan_strstr(tmptoken, "by_string"))
                                                {
                                                    rulestruct[counters->rulecount].threshold2_method_username = true;
                                                    valid++;
                                                }

                                            if (Sagan_strstr(tmptoken, "by_srcport"))
                                                {
                                                    rulestruct[counters->rulecount].threshold2_method_srcport = true;
                                                    valid++;
                                                }

                                            if (Sagan_strstr(tmptoken, "by_dstport"))
                                                {
                                                    rulestruct[counters->rulecount].threshold2_method_dstport = true;
                                                    valid++;
                                                }
                                        }

                                    if (Sagan_strstr(tmptoken, "count"))
                                        {

                                            valid++;

                                            tmptok_tmp = strtok_r(tmptoken, " ", &saveptrrule3);
                                            tmptok_tmp = strtok_r(NULL, " ", &saveptrrule3);
                                            rulestruct[counters->rulecount].threshold2_count = atoi(tmptok_tmp);

                                            if ( rulestruct[counters->rulecount].threshold2_count == 0 )
                                                {
                                                    Sagan_Log(ERROR, "[%s, line %d] Invalid threshold count '%s' at line %d in %s. Abort.", __FILE__, __LINE__, tmptok_tmp, linecount, ruleset_fullname);
                                                }

                                        }

                                    if (Sagan_strstr(tmptoken, "seconds"))
                                        {

                                            valid++;

                                            tmptok_tmp = strtok_r(tmptoken, " ", &saveptrrule3);
                                            tmptok_tmp = strtok_r(NULL, " ", &saveptrrule3 );
                                            rulestruct[counters->rulecount].threshold2_seconds = atoi(tmptok_tmp);

                                            if ( rulestruct[counters->rulecount].threshold2_seconds == 0 )
                                                {
                                                    Sagan_Log(ERROR, "[%s, line %d] Invalid threshold time '%s' at line %d in %s. Abort.", __FILE__, __LINE__, tmptok_tmp, linecount, ruleset_fullname);
                                                }
                                        }

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);
                                }

                            /* Sanity check */

                            if ( valid < 6 )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] 'threshold' keyword appears to be invalid at line %d in %s. Abort.", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            if ( rulestruct[counters->rulecount].threshold2_count == 0 )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] No 'threshold' count specified at line %d in %s. Abort.", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            if ( rulestruct[counters->rulecount].threshold2_seconds == 0 )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] No 'threshold' time (seconds) specified at line %d in %s. Abort.", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                        }

                    /* "after"; similar to thresholding,  but the opposite direction */

                    if (!strcmp(rulesplit, "after" ))
                        {

                            valid = 0;

                            rulestruct[counters->rulecount].after2 = true;

                            tok_tmp = strtok_r(NULL, ":", &saveptrrule2);

                            if ( tok_tmp == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d]  %s on line %d appears to be incorrect.  \"after\" options appear incomplete. Abort!", __FILE__, __LINE__, ruleset_fullname, linecount);
                                }


                            tmptoken = strtok_r(tok_tmp, ",", &saveptrrule2);

                            while( tmptoken != NULL )
                                {

                                    if (Sagan_strstr(tmptoken, "track"))
                                        {
                                            valid++;

                                            strtok_r(tmptoken, " ", &after_value1);

                                            if ( after_value1 == NULL )
                                                {
                                                    Sagan_Log(ERROR, "[%s, line %d]  %s on line %d appears to be incorrect.  \"after\" options appear incomplete. Abort!", __FILE__, __LINE__, ruleset_fullname, linecount);
                                                }

                                            Remove_Return(after_value1);

                                            after_value2 = strtok_r(after_value1, "&", &after_value3);

                                            while ( after_value2 != NULL )
                                                {

                                                    if (!strcmp(after_value2, "by_src"))
                                                        {
                                                            valid++;
                                                            rulestruct[counters->rulecount].after2_method_src = true;
                                                        }

                                                    if (!strcmp(after_value2, "by_dst"))
                                                        {
                                                            valid++;
                                                            rulestruct[counters->rulecount].after2_method_dst = true;
                                                        }

                                                    if (!strcmp(after_value2, "by_username") || Sagan_strstr(tmptoken, "by_string"))
                                                        {
                                                            valid++;
                                                            rulestruct[counters->rulecount].after2_method_username = true;
                                                        }

                                                    if(!strcmp(after_value2, "by_srcport"))
                                                        {
                                                            valid++;
                                                            rulestruct[counters->rulecount].after2_method_srcport  = true;
                                                        }

                                                    if(!strcmp(after_value2, "by_dstport"))
                                                        {
                                                            valid++;
                                                            rulestruct[counters->rulecount].after2_method_dstport  = true;
                                                        }

                                                    after_value2 = strtok_r(NULL, "&", &after_value3);
                                                }


                                        }

                                    if (Sagan_strstr(tmptoken, "count"))
                                        {

                                            valid++;

                                            tmptok_tmp = strtok_r(tmptoken, " ", &saveptrrule3);
                                            tmptok_tmp = strtok_r(NULL, " ", &saveptrrule3);
                                            rulestruct[counters->rulecount].after2_count = atoi(tmptok_tmp);

                                            if ( rulestruct[counters->rulecount].after2_count == 0 )
                                                {
                                                    Sagan_Log(ERROR, "[%s, line %d] Invalid after count '%s' at line %d in %s. Abort.", __FILE__, __LINE__, tmptok_tmp, linecount, ruleset_fullname);
                                                }

                                        }

                                    if (Sagan_strstr(tmptoken, "seconds"))
                                        {

                                            valid++;

                                            tmptok_tmp = strtok_r(tmptoken, " ", &saveptrrule3);
                                            tmptok_tmp = strtok_r(NULL, " ", &saveptrrule3 );
                                            rulestruct[counters->rulecount].after2_seconds = atoi(tmptok_tmp);

                                            if ( rulestruct[counters->rulecount].after2_seconds == 0 )
                                                {
                                                    Sagan_Log(ERROR, "[%s, line %d] Invalid after time '%s' at line %d in %s. Abort.", __FILE__, __LINE__, tmptok_tmp, linecount, ruleset_fullname);
                                                }

                                        }


                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                }

                            /* Sanity check */

                            if ( valid < 4 )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] 'after' keyword appears to be invalid at line %d in %s. Abort.", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }


                            if ( rulestruct[counters->rulecount].after2_count == 0 )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] No 'after' count specified at line %d in %s. Abort.", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            if ( rulestruct[counters->rulecount].after2_seconds == 0 )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] No 'after' time (seconds) specified at line %d in %s. Abort.", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                        }

                    /* Blacklist */

                    if (!strcmp(rulesplit, "blacklist"))
                        {
                            tok_tmp = strtok_r(NULL, ":", &saveptrrule2);

                            if ( tok_tmp == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d]  %s on line %d appears to be incorrect.  \"blacklist:\" options appear incomplete, Abort.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                }

                            Remove_Spaces(tok_tmp);

                            tmptoken = strtok_r(tok_tmp, ",", &saveptrrule3);

                            while( tmptoken != NULL )
                                {

                                    found = 0;

                                    if (!strcmp(tmptoken, "by_src"))
                                        {
                                            rulestruct[counters->rulecount].blacklist_ipaddr_src = 1;
                                            rulestruct[counters->rulecount].blacklist_flag = 1;
                                            found = 1;
                                        }

                                    if (!strcmp(tmptoken, "by_dst"))
                                        {
                                            rulestruct[counters->rulecount].blacklist_ipaddr_dst = 1;
                                            rulestruct[counters->rulecount].blacklist_flag = 1;
                                            found = 1;
                                        }

                                    if (!strcmp(tmptoken, "both"))
                                        {
                                            rulestruct[counters->rulecount].blacklist_ipaddr_both = 1;
                                            rulestruct[counters->rulecount].blacklist_flag = 1;
                                            found = 1;
                                        }

                                    if (!strcmp(tmptoken, "all"))
                                        {
                                            rulestruct[counters->rulecount].blacklist_ipaddr_all = 1;
                                            rulestruct[counters->rulecount].blacklist_flag = 1;
                                            found = 1;
                                        }

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule3);
                                }

                        }

                    /* Bro/Zeek Intel */

                    if (!strcmp(rulesplit, "bro-intel") || !strcmp(rulesplit, "zeek-intel") )
                        {
                            tok_tmp = strtok_r(NULL, ":", &saveptrrule2);

                            if ( tok_tmp == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d]  %s on line %d appears to be incorrect.  \"zeek-intel:\" options appear incomplete, Abort.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                }

                            Remove_Spaces(tok_tmp);

                            tmptoken = strtok_r(tok_tmp, ",", &saveptrrule3);

                            while( tmptoken != NULL )
                                {

                                    found = 0;

                                    if (!strcmp(tmptoken, "by_src"))
                                        {
                                            rulestruct[counters->rulecount].zeekintel_ipaddr_src = 1;
                                            rulestruct[counters->rulecount].zeekintel_flag = 1;
                                            found = 1;
                                        }

                                    if (!strcmp(tmptoken, "by_dst"))
                                        {
                                            rulestruct[counters->rulecount].zeekintel_ipaddr_dst = 1;
                                            rulestruct[counters->rulecount].zeekintel_flag = 1;
                                            found = 1;
                                        }

                                    if (!strcmp(tmptoken, "both"))
                                        {
                                            rulestruct[counters->rulecount].zeekintel_ipaddr_both = 1;
                                            rulestruct[counters->rulecount].zeekintel_flag = 1;
                                            found = 1;
                                        }

                                    if (!strcmp(tmptoken, "all"))
                                        {
                                            rulestruct[counters->rulecount].zeekintel_ipaddr_all = 1;
                                            rulestruct[counters->rulecount].zeekintel_flag = 1;
                                            found = 1;
                                        }

                                    if (!strcmp(tmptoken, "domain"))
                                        {
                                            rulestruct[counters->rulecount].zeekintel_domain = 1;
                                            rulestruct[counters->rulecount].zeekintel_flag = 1;
                                            found = 1;
                                        }

                                    if (!strcmp(tmptoken, "file_hash"))
                                        {
                                            rulestruct[counters->rulecount].zeekintel_file_hash = 1;
                                            rulestruct[counters->rulecount].zeekintel_flag = 1;
                                            found = 1;
                                        }

                                    if (!strcmp(tmptoken, "url"))
                                        {
                                            rulestruct[counters->rulecount].zeekintel_url = 1;
                                            rulestruct[counters->rulecount].zeekintel_flag = 1;
                                            found = 1;
                                        }

                                    if (!strcmp(tmptoken, "software"))
                                        {
                                            rulestruct[counters->rulecount].zeekintel_software = 1;
                                            rulestruct[counters->rulecount].zeekintel_flag = 1;
                                            found = 1;
                                        }

                                    if (!strcmp(tmptoken, "email"))
                                        {
                                            rulestruct[counters->rulecount].zeekintel_email = 1;
                                            rulestruct[counters->rulecount].zeekintel_flag = 1;
                                            found = 1;
                                        }

                                    if (!strcmp(tmptoken, "user_name"))
                                        {
                                            rulestruct[counters->rulecount].zeekintel_user_name = 1;
                                            rulestruct[counters->rulecount].zeekintel_flag = 1;
                                            found = 1;
                                        }

                                    if (!strcmp(tmptoken, "file_name"))
                                        {
                                            rulestruct[counters->rulecount].zeekintel_file_name = 1;
                                            rulestruct[counters->rulecount].zeekintel_flag = 1;
                                            found = 1;
                                        }

                                    if (!strcmp(tmptoken, "cert_hash"))
                                        {
                                            rulestruct[counters->rulecount].zeekintel_cert_hash = 1;
                                            rulestruct[counters->rulecount].zeekintel_flag = 1;
                                            found = 1;
                                        }

                                    if ( found == 0 )
                                        {
                                            Sagan_Log(ERROR, "[%s, line %d] %s on line %d has an unknown \"brointel\" option \"%s\", Abort.", __FILE__, __LINE__, ruleset_fullname, linecount, tmptoken);
                                        }

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule3);
                                }

                        }

                    if (!strcmp(rulesplit, "external"))
                        {

                            tok_tmp = strtok_r(NULL, ":", &saveptrrule2);

                            if ( tok_tmp == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] %s at line %d has 'external' option  but no external 'program' is specified, Abort", __FILE__, __LINE__, ruleset_fullname, linecount);
                                }

                            Remove_Spaces(tok_tmp);

                            if (stat(tok_tmp, &filecheck) != 0 )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] %s at line %d has 'external' option but external program '%s' does not exist, Abort", __FILE__, __LINE__, ruleset_fullname, linecount, tok_tmp);
                                }

                            if (access(tok_tmp, X_OK) == -1)
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] %s at line %d has 'external' option but external program '%s' is not executable, Abort", __FILE__, __LINE__, ruleset_fullname, linecount, tok_tmp);
                                }

                            rulestruct[counters->rulecount].external_flag = 1;
                            strlcpy(rulestruct[counters->rulecount].external_program, tok_tmp, sizeof(rulestruct[counters->rulecount].external_program));

                        }

#ifdef WITH_OFFLOAD

                    if (!strcmp(rulesplit, "offload"))
                        {

                            offload_flag = true;

                            tok_tmp = strtok_r(NULL, ";", &saveptrrule2);

                            if ( tok_tmp == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] %s at line %d has 'offload' option  but no offload 'location' is specified, Abort", __FILE__, __LINE__, ruleset_fullname, linecount);
                                }

                            /* In case the URL has spaces,  we use Between_Quotes */

                            Between_Quotes(tok_tmp, tmp2, sizeof(tmp2), ruleset_fullname, linecount, true);

                            rulestruct[counters->rulecount].offload_flag = 1;
                            strlcpy(rulestruct[counters->rulecount].offload_location, tmp2, sizeof(rulestruct[counters->rulecount].offload_location));

                        }
#endif

#ifndef WITH_OFFLOAD

                    if (!strcmp(rulesplit, "offload"))
                        {
                            Sagan_Log(ERROR, "%s has 'offload' rulesoption,  but support isn't compiled in.", ruleset_fullname);
                        }
#endif


#ifdef WITH_BLUEDOT

                    if (!strcmp(rulesplit, "bluedot"))
                        {

                            if ( config->bluedot_flag == 0 )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] %s at line %d has 'bluedot' option enabled,  but 'processor bluedot' is not configured, Abort", __FILE__, __LINE__, ruleset_fullname, linecount);
                                }

                            tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                            if (!Sagan_strstr(tmptoken, "type"))
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] No Bluedot 'type' found in %s at line %d, Abort", __FILE__, __LINE__, ruleset_fullname, linecount);
                                }

                            if ( Sagan_strstr(tmptoken, "type" ))
                                {

                                    if ( Sagan_strstr(tmptoken, "ip_reputation" ))
                                        {

                                            tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                            if ( Sagan_strstr(tmptoken, "track" ))
                                                {

                                                    /* 1 == src,  2 == dst,  3 == both,  4 == all */

                                                    if ( Sagan_strstr(tmptoken, "by_src" ))
                                                        {
                                                            rulestruct[counters->rulecount].bluedot_ipaddr_type  = 1;
                                                        }

                                                    if ( Sagan_strstr(tmptoken, "by_dst" ))
                                                        {
                                                            rulestruct[counters->rulecount].bluedot_ipaddr_type  = 2;
                                                        }

                                                    if ( Sagan_strstr(tmptoken, "both" ))
                                                        {
                                                            rulestruct[counters->rulecount].bluedot_ipaddr_type  = 3;
                                                        }

                                                    if ( Sagan_strstr(tmptoken, "all" ))
                                                        {
                                                            rulestruct[counters->rulecount].bluedot_ipaddr_type  = 4;
                                                        }

                                                    if ( rulestruct[counters->rulecount].bluedot_ipaddr_type == 0 )
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] No Bluedot by_src, by_dst, both or all specified in %s at line %d, Abort.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                                        }

                                                }

                                            tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                            if (!Sagan_strstr(tmptoken, "mdate_effective_period" ) && !Sagan_strstr(tmptoken, "cdate_effective_period" ) && !Sagan_strstr(tmptoken, "none" ))
                                                {
                                                    Sagan_Log(ERROR, "[%s, line %d] No Bluedot 'mdate_effective_period', 'cdate_effective_period' or 'none' not specified in %s at line %d, Abort", __FILE__, __LINE__, ruleset_fullname, linecount);
                                                }

                                            if (!Sagan_strstr(tmptoken, "none"))
                                                {

                                                    tok_tmp = strtok_r(tmptoken, " ", &saveptrrule3);

                                                    if (Sagan_strstr(tmptoken, "mdate_effective_period" ))
                                                        {

                                                            bluedot_time = strtok_r(NULL, " ", &saveptrrule3);

                                                            if ( bluedot_time == NULL )
                                                                {
                                                                    Sagan_Log(ERROR, "[%s, line %d] %s at line %d has no Bluedot numeric time value, Abort.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                                                }

                                                            bluedot_type = strtok_r(NULL, " ", &saveptrrule3);

                                                            if ( bluedot_type == NULL )
                                                                {
                                                                    Sagan_Log(ERROR, "[%s, line %d] %s at line %d has not Bluedot timeframe type (hour, week, month, year, etc) specified, Abort.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                                                }

                                                            Remove_Spaces(bluedot_time);
                                                            Remove_Spaces(bluedot_type);

                                                            bluedot_time_u32 = atol(bluedot_time);

                                                            if ( bluedot_time_u32 == 0 )
                                                                {
                                                                    Sagan_Log(ERROR, "[%s, line %d] %s at line %d has no or invalid Bluedot timeframe, Abort.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                                                }

                                                            rulestruct[counters->rulecount].bluedot_mdate_effective_period = Value_To_Seconds(bluedot_type, bluedot_time_u32);
                                                        }
                                                    else if (Sagan_strstr(tmptoken, "cdate_effective_period" ))
                                                        {
                                                            bluedot_time = strtok_r(NULL, " ", &saveptrrule3);

                                                            if ( bluedot_time == NULL )
                                                                {
                                                                    Sagan_Log(ERROR, "[%s, line %d] %s at line %d has no Bluedot numeric time value, Abort.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                                                }

                                                            bluedot_type = strtok_r(NULL, " ", &saveptrrule3);

                                                            if ( bluedot_type == NULL )
                                                                {
                                                                    Sagan_Log(ERROR, "[%s, line %d] %s at line %d has not Bluedot timeframe type (hour, week, month, year, etc) specified, Abort", __FILE__, __LINE__, ruleset_fullname, linecount);
                                                                }

                                                            Remove_Spaces(bluedot_time);
                                                            Remove_Spaces(bluedot_type);

                                                            bluedot_time_u32 = atol(bluedot_time);

                                                            if ( bluedot_time_u32 == 0 )
                                                                {
                                                                    Sagan_Log(ERROR, "[%s, line %d] %s at line %d has no or invalid Bluedot timeframe, Abort", __FILE__, __LINE__, ruleset_fullname, linecount);
                                                                }

                                                            rulestruct[counters->rulecount].bluedot_cdate_effective_period = Value_To_Seconds(bluedot_type, bluedot_time_u32);
                                                        }

                                                }
                                            else
                                                {

                                                    rulestruct[counters->rulecount].bluedot_mdate_effective_period = 0;
                                                    rulestruct[counters->rulecount].bluedot_cdate_effective_period = 0;

                                                }

                                            tmptoken = strtok_r(NULL, ";", &saveptrrule2);

                                            if ( tmptoken == NULL )
                                                {
                                                    Sagan_Log(ERROR, "[%s, line %d] %s at line %d has no Bluedot categories defined, Abort", __FILE__, __LINE__, ruleset_fullname, linecount);
                                                }

                                            Remove_Spaces(tmptoken);

                                            Sagan_Verify_Categories( tmptoken, counters->rulecount, ruleset_fullname, linecount, BLUEDOT_LOOKUP_IP);


                                        }

                                    if ( Sagan_strstr(tmptoken, "ja3" ))
                                        {
                                            rulestruct[counters->rulecount].bluedot_ja3 = true;

                                            tmptok_tmp = strtok_r(NULL, ";", &saveptrrule2);   /* Support var's */

                                            if ( tmptok_tmp == NULL )
                                                {
                                                    Sagan_Log(ERROR, "[%s, line %d] %s at line %d has no Bluedot categories defined, Abort", __FILE__, __LINE__, ruleset_fullname, linecount, tmptok_tmp);
                                                }

                                            Var_To_Value(tmptok_tmp, tmp1, sizeof(tmp1));

                                            Sagan_Verify_Categories( tmp1, counters->rulecount, ruleset_fullname, linecount, BLUEDOT_LOOKUP_HASH);
                                        }


                                    if ( Sagan_strstr(tmptoken, "file_hash" ))
                                        {
                                            rulestruct[counters->rulecount].bluedot_file_hash = true;

                                            tmptok_tmp = strtok_r(NULL, ";", &saveptrrule2);   /* Support var's */

                                            if ( tmptok_tmp == NULL )
                                                {
                                                    Sagan_Log(ERROR, "[%s, line %d] %s at line %d has no Bluedot categories defined, Abort!", __FILE__, __LINE__, ruleset_fullname, linecount, tmptok_tmp);
                                                }

                                            Var_To_Value(tmptok_tmp, tmp1, sizeof(tmp1));

                                            Sagan_Verify_Categories( tmp1, counters->rulecount, ruleset_fullname, linecount, BLUEDOT_LOOKUP_HASH);
                                        }

                                    if ( Sagan_strstr(tmptoken, "url" ))

                                        {
                                            rulestruct[counters->rulecount].bluedot_url = true;

                                            tmptok_tmp = strtok_r(NULL, ";", &saveptrrule2);   /* Support var's */

                                            if ( tmptok_tmp == NULL )
                                                {
                                                    Sagan_Log(ERROR, "[%s, line %d] %s at line %d has no Bluedot categories defined, Abort", __FILE__, __LINE__, ruleset_fullname, linecount, tmptok_tmp);
                                                }

                                            Var_To_Value(tmptok_tmp, tmp1, sizeof(tmp1));

                                            Sagan_Verify_Categories( tmp1, counters->rulecount, ruleset_fullname, linecount, BLUEDOT_LOOKUP_URL);
                                        }


                                    if ( Sagan_strstr(tmptoken, "filename" ))
                                        {
                                            rulestruct[counters->rulecount].bluedot_filename = true;

                                            tmptok_tmp = strtok_r(NULL, ";", &saveptrrule2);   /* Support var's */

                                            if ( tmptok_tmp == NULL )
                                                {
                                                    Sagan_Log(ERROR, "[%s, line %d] %s at line %d has no Bluedot categories defined, Abort", __FILE__, __LINE__, ruleset_fullname, linecount, tmptok_tmp);
                                                }

                                            Var_To_Value(tmptok_tmp, tmp1, sizeof(tmp1));

                                            Sagan_Verify_Categories( tmp1, counters->rulecount, ruleset_fullname, linecount, BLUEDOT_LOOKUP_FILENAME);
                                        }

                                    /* Error  check (  set flag? */
                                }
                        }

#endif

#ifndef WITH_BLUEDOT

                    if (!strcmp(rulesplit, "bluedot"))
                        {
                            Sagan_Log(ERROR, "%s has Bluedot rules,  but support isn't compiled in, Abort", ruleset_fullname);
                        }
#endif

#ifdef HAVE_LIBFASTJSON

                    /***********************************************/
                    /* Suricata/Snort style "metadata" rule option */
                    /***********************************************/

                    metadata_array_count = 0;

                    if (!strcmp(rulesplit, "metadata"))
                        {

                            arg = strtok_r(NULL, ";", &saveptrrule2);

                            if ( arg == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] The \"metadata\" option appears to be incomplete at line %d in %s, Abort", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            tmptoken = strtok_r(arg, ",", &saveptrrule3);

                            while ( tmptoken != NULL )
                                {

                                    tok_tmp = strtok_r(tmptoken, " ", &saveptrmeta);
                                    metadata_jarray[metadata_array_count] = json_object_new_array();
                                    meta_bool = false;

                                    while ( tok_tmp != NULL )
                                        {

                                            if ( meta_bool == false )
                                                {
                                                    strlcpy(meta_key, tok_tmp, sizeof(meta_key));
                                                    meta_bool = true;
                                                }
                                            else
                                                {
                                                    metadata_jstring = json_object_new_string(tok_tmp);
                                                    json_object_array_add(metadata_jarray[metadata_array_count],metadata_jstring);
                                                }

                                            tok_tmp = strtok_r(NULL, " ", &saveptrmeta);

                                        }

                                    json_object_object_add(metadata_jobj, meta_key, metadata_jarray[metadata_array_count]);

                                    metadata_array_count++;

                                    if ( metadata_array_count > MAX_METADATA )
                                        {
                                            Sagan_Log(ERROR, "[%s, line %d] To many 'metadata' fields in rule at line %d in %s. Abort.", __FILE__, __LINE__, linecount, ruleset_fullname);
                                        }

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule3);

                                }

                            strlcpy(rulestruct[counters->rulecount].metadata_json, json_object_to_json_string(metadata_jobj), sizeof(rulestruct[counters->rulecount].metadata_json));

                        }

#endif

                    /*************************/
                    /* Validate rule options */
                    /*************************/

                    strlcpy(valid_rules, VALID_RULE_OPTIONS, sizeof(valid_rules));

                    arg = strtok_r( valid_rules, ",", &saveptrcheck);

                    is_valid = false;

                    while ( arg != NULL )
                        {

                            /* the == '\0' is for things like "rev:3; )" (note the space) */

                            if ( ( !strcmp(tokenrule, arg) ) || tokenrule[0] == '\0' )
                                {

                                    /* Got valid rule option, check no further */

                                    is_valid = true;
                                    break;
                                }

                            arg = strtok_r(NULL, ",", &saveptrcheck);

                        }

                    if ( is_valid == false )
                        {
                            Sagan_Log(ERROR, "[%s, line %d] Got bad rule option '%s' on line %d of %s. Abort.", __FILE__, __LINE__, tokenrule, linecount, ruleset_fullname);
                        }

                    /*************************/
                    /* -< Go to next line >- */
                    /*************************/

                    tokenrule = strtok_r(NULL, ";", &saveptrrule1);
                }

            /* Some new stuff (normalization) stuff needs to be added */

            if ( debug->debugload )
                {

                    Sagan_Log(DEBUG, "---[Rule %" PRIu64 "]------------------------------------------------------", rulestruct[counters->rulecount].s_sid);


                    Sagan_Log(DEBUG, "= Position: %d", counters->rulecount);
                    Sagan_Log(DEBUG, "= SID: %" PRIu64 "", rulestruct[counters->rulecount].s_sid);
                    Sagan_Log(DEBUG, "= Rev: %d", rulestruct[counters->rulecount].s_rev);
                    Sagan_Log(DEBUG, "= Msg: %s", rulestruct[counters->rulecount].s_msg);
                    Sagan_Log(DEBUG, "= Pri: %d", rulestruct[counters->rulecount].s_pri);
                    Sagan_Log(DEBUG, "= Classtype: %s", rulestruct[counters->rulecount].s_classtype);
                    Sagan_Log(DEBUG, "= Drop: %d", rulestruct[counters->rulecount].drop);
                    Sagan_Log(DEBUG, "= default_dst_port: %d", rulestruct[counters->rulecount].default_dst_port);

                    if ( rulestruct[counters->rulecount].s_find_src_ip != 0 )
                        {
                            Sagan_Log(DEBUG, "= parse_src_ip");
                        }

                    if ( rulestruct[counters->rulecount].s_find_port != 0 )
                        {
                            Sagan_Log(DEBUG, "= parse_port");
                        }

                    for (i=0; i<content_count; i++)
                        {
                            Sagan_Log(DEBUG, "= [%d] content: \"%s\"", i, rulestruct[counters->rulecount].content[i]);
                        }

                    for (i=0; i<ref_count; i++)
                        {
                            Sagan_Log(DEBUG, "= [%d] reference: \"%s\"", i,  rulestruct[counters->rulecount].s_reference[i]);
                        }
                }

            __atomic_add_fetch(&counters->rulecount, 1,  __ATOMIC_SEQ_CST);

        } /* end of while loop */

#ifdef HAVE_LIBFASTJSON

    json_object_put(metadata_jobj);

#endif


    fclose(rulesfile);
}
