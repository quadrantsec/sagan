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

/* sagan.c
 *
 * This is the main "thread" and engine that looks for events & patterns
 * based on 'snort like' rule sets.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
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
#include <signal.h>
#include <limits.h>
#include <stdint.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <glob.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "version.h"

#include "credits.h"
#include "flexbit-mmap.h"
#include "processor.h"
#include "sagan-config.h"
#include "config-yaml.h"
#include "ignore-list.h"
#include "key.h"
#include "lockfile.h"
#include "signal-handler.h"
#include "usage.h"
#include "stats.h"
#include "ipc.h"
#include "tracking-syslog.h"
#include "geoip.h"
#include "parsers/parsers.h"

#include "input-pipe.h"

#ifdef HAVE_LIBFASTJSON
#include "input-json.h"
#endif

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#ifdef HAVE_LIBPCAP
#include "plog.h"
#endif

#ifdef HAVE_LIBLOGNORM
#include "liblognormalize.h"
#endif

#include "routing.h"
#include "processors/engine.h"
#include "rules.h"
#include "processors/blacklist.h"
#include "processors/track-clients.h"
#include "processors/client-stats.h"
#include "processors/zeek-intel.h"
#include "processors/stats-json.h"

#include "input-plugins/file.h"
#include "input-plugins/gzip.h"
#include "input-plugins/fifo.h"

#define OVECCOUNT 30

/* Init */

struct _SaganCounters *counters = NULL;
struct _SaganConfig *config = NULL;
struct _SaganDebug *debug = NULL;
struct _SaganDNSCache *dnscache = NULL;
struct _Track_Clients_Networks *Track_Clients_Networks = NULL;
struct _Sagan_Track_Clients *SaganTrackClients;

#ifdef HAVE_LIBFASTJSON
struct _Syslog_JSON_Map *Syslog_JSON_Map = NULL;
struct _JSON_Message_Map *JSON_Message_Map = NULL;
#endif

/* Already Init'ed */

extern struct _Rule_Struct *rulestruct;

#ifdef WITH_BLUEDOT
#include "processors/bluedot.h"
#endif

#ifdef HAVE_LIBHIREDIS
#include <hiredis/hiredis.h>
#include "redis.h"
#endif

struct _Sagan_Pass_Syslog *SaganPassSyslog = NULL;

uint_fast16_t proc_msgslot = 0;
uint_fast16_t proc_running = 0;

bool death=false;


pthread_cond_t SaganProcDoWork=PTHREAD_COND_INITIALIZER;
pthread_mutex_t SaganProcWorkMutex=PTHREAD_MUTEX_INITIALIZER;

extern pthread_mutex_t SaganRulesLoadedMutex;

/* ########################################################################
 * Start of main() thread
 * ######################################################################## */

int main(int argc, char **argv)
{

    (void)SetThreadName("SaganMain");

    const struct option long_options[] =
    {
        { "help",         no_argument,          NULL,   'h' },
        { "debug",        required_argument,    NULL,   'd' },
        { "daemon",       no_argument,          NULL,   'D' },
        { "user",         required_argument,    NULL,   'u' },
        { "chroot",       required_argument,    NULL,   'c' },
        { "credits",	  no_argument,		NULL,	'C' },
        { "config",       required_argument,    NULL,   'f' },
        { "log",          required_argument,    NULL,   'l' },
        { "file",	  required_argument,    NULL,   'F' },
        { "quiet", 	  no_argument, 		NULL, 	'Q' },
        { "threads",	  required_argument,    NULL,   't' },
        { "rules", 	  required_argument,    NULL,   'r' },
        { "test", 	  no_argument, 		NULL,	'T' },
        {0, 0, 0, 0}
    };

    static const char *short_options =
        "l:f:u:r:F:d:c:t:pDhCQT";

    int option_index = 0;

    uint_fast16_t max_threads_override = 0;
    uint_fast16_t z = 0;

    FILE *test_open;			/* Used to test file access */

    bool test_mode = false;

    /****************************************************************************/
    /* libpcap/PLOG (syslog sniffer) local variables                            */
    /****************************************************************************/

#ifdef HAVE_LIBPCAP
    pthread_t pcap_thread;
    pthread_attr_t thread_pcap_attr;
    pthread_attr_init(&thread_pcap_attr);
    pthread_attr_setdetachstate(&thread_pcap_attr,  PTHREAD_CREATE_DETACHED);
#endif

    /****************************************************************************/
    /* Redis local variables                                                    */
    /****************************************************************************/

#ifdef HAVE_LIBHIREDIS

    char redis_reply[5] = { 0 };
    char redis_command[8] = { 0 };

#endif

    /****************************************************************************/
    /* JSON Stats local variables                                               */
    /****************************************************************************/

    pthread_t stats_json_thread;
    pthread_attr_t thread_stats_json_attr;
    pthread_attr_init(&thread_stats_json_attr);
    pthread_attr_setdetachstate(&thread_stats_json_attr,  PTHREAD_CREATE_DETACHED);

    /****************************************************************************/
    /* Client local variables                                              */
    /****************************************************************************/

    pthread_t client_stats_thread;
    pthread_attr_t thread_client_stats_attr;
    pthread_attr_init(&thread_client_stats_attr);
    pthread_attr_setdetachstate(&thread_client_stats_attr,  PTHREAD_CREATE_DETACHED);

    /****************************************************************************/
    /* Various local variables						        */
    /****************************************************************************/

    /* Block all signals,  we create a signal handling thread */

    sigset_t signal_set;
    pthread_t sig_thread;
    sigfillset( &signal_set );
    pthread_sigmask( SIG_BLOCK, &signal_set, NULL );

    /* Key board handler (displays stats, etc */

    pthread_t key_thread;
    pthread_attr_t key_thread_attr;
    pthread_attr_init(&key_thread_attr);
    pthread_attr_setdetachstate(&key_thread_attr,  PTHREAD_CREATE_DETACHED);

    /* client_tracker_report_handler thread */

    pthread_t ct_report_thread;
    pthread_attr_t ct_report_thread_attr;
    pthread_attr_init(&ct_report_thread_attr);
    pthread_attr_setdetachstate(&ct_report_thread_attr,  PTHREAD_CREATE_DETACHED);

    /* Rule tracking for syslog output */;

    pthread_t tracking_thread;
    pthread_attr_t tracking_thread_attr;
    pthread_attr_init(&tracking_thread_attr);
    pthread_attr_setdetachstate(&tracking_thread_attr,  PTHREAD_CREATE_DETACHED);

    signed char c;
    int rc=0;

    uint_fast16_t i = 0;

    time_t t;
    struct tm *run;

    bool debugflag = false;

    /* Allocate memory for global struct _SaganDebug */

    debug = malloc(sizeof(_SaganDebug));

    if ( debug == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for debug. Abort!", __FILE__, __LINE__);
        }

    memset(debug, 0, sizeof(_SaganDebug));

    /* Allocate memory for global struct _SaganConfig */

    config = malloc(sizeof(_SaganConfig));

    if ( config == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for config. Abort!", __FILE__, __LINE__);
        }

    /* Allocate memory for global struct _SaganCounters */

    counters = malloc(sizeof(_SaganCounters));

    if ( counters == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for counters. Abort!", __FILE__, __LINE__);
        }

    memset(counters, 0, sizeof(_SaganCounters)); 	/* Set all counters to zero */

    /* Allocate memory for global struct _SaganDNSCache */

    dnscache = malloc(sizeof(_SaganDNSCache));

    if ( dnscache == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for dnscache. Abort!", __FILE__, __LINE__);
        }

#if defined(HAVE_LIBFASTJSON)

    /* Allocate memory for global Syslog_JSON_Map */

    Syslog_JSON_Map = malloc(sizeof(_Syslog_JSON_Map));

    if ( Syslog_JSON_Map == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for Syslog_JSON_Map. Abort!", __FILE__, __LINE__);
        }

#endif

    t = time(NULL);
    run=localtime(&t);
    strftime(config->sagan_startutime, sizeof(config->sagan_startutime), "%s",  run);

    strlcpy(config->sagan_config, CONFIG_FILE_PATH, sizeof(config->sagan_config));

    config->sagan_fifo[0] = '\0';	/* Set this here.  This could be a file via
    					   comamnd line or FIFO via configuration
					   file */

    /* We set the config->sagan_log_filepath to the system default.  It'll be fopen'ed
       shortly - 06/03/2011 - Champ Clark III */

    strlcpy(config->sagan_log_filepath, SAGANLOG, sizeof(config->sagan_log_filepath));
    config->sagan_runas = RUNAS;

    /* "systemd" wants to start Sagan in the foreground,  but doesn't know what to
     * do with stdin/stdout.  Hence,  CPU goes to 100%.  This detects our terminal
     * type ( >/dev/null </dev/null ) and tell's Sagan to ignore input and output.
     *
     * For more details, see:
     *
     * https://groups.google.com/forum/#!topic/sagan-users/kgJvf1eyQcg
     *
     */

    if ( !isatty(0) || !isatty(1) || !isatty(2) )
        {
            config->quiet = true;
        }

    /* Get command line arg's */

    while ((c = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1)
        {

            switch(c)
                {

                case 'h':
                    Usage();
                    exit(0);
                    break;

                case 'Q':
                    config->quiet = true;
                    break;

                case 'C':
                    Credits();
                    exit(0);
                    break;

                case 'T':
                    test_mode = true;
                    break;

                case 'd':

                    if (Sagan_strstr(optarg, "malformed"))
                        {
                            debug->debugmalformed = true;
                            debugflag = true;
                        }

                    if (Sagan_strstr(optarg, "parse_ip"))
                        {
                            debug->debugparse_ip = true;
                            debugflag = true;
                        }

                    if (Sagan_strstr(optarg, "limits"))
                        {
                            debug->debuglimits = true;
                            debugflag = true;
                        }

                    if (Sagan_strstr(optarg, "syslog"))
                        {
                            debug->debugsyslog = true;
                            debugflag = true;
                        }

                    if (Sagan_strstr(optarg, "load"))
                        {
                            debug->debugload = true;
                            debugflag = true;
                        }

                    if (Sagan_strstr(optarg, "external"))
                        {
                            debug->debugexternal = true;
                            debugflag = true;
                        }

                    if (Sagan_strstr(optarg, "threads"))
                        {
                            debug->debugthreads = true;
                            debugflag = true;
                        }

                    if (Sagan_strstr(optarg, "flexbit"))
                        {
                            debug->debugflexbit = true;
                            debugflag = true;
                        }

                    if (Sagan_strstr(optarg, "xbit"))
                        {
                            debug->debugxbit = true;
                            debugflag = true;
                        }


                    if (Sagan_strstr(optarg, "engine"))
                        {
                            debug->debugengine = true;
                            debugflag = true;
                        }

                    if (Sagan_strstr(optarg, "zeekintel"))
                        {
                            debug->debugbrointel = true;
                            debugflag = true;
                        }

                    if (Sagan_strstr(optarg, "ipc"))
                        {
                            debug->debugipc = true;
                            debugflag = true;
                        }

                    if (Sagan_strstr(optarg, "json"))
                        {
                            debug->debugjson = true;
                            debugflag = true;
                        }

                    if (Sagan_strstr(optarg, "client-stats"))
                        {
                            debug->debugclient_stats = true;
                            debugflag = true;
                        }

                    if (Sagan_strstr(optarg, "track-clients"))
                        {
                            debug->debugtrack_clients = true;
                            debugflag = true;
                        }


#ifdef HAVE_LIBMAXMINDDB

                    if (Sagan_strstr(optarg, "geoip"))
                        {
                            debug->debuggeoip2 = true;
                            debugflag = true;
                        }
#endif

#ifdef HAVE_LIBLOGNORM
                    if (Sagan_strstr(optarg, "normalize" ))
                        {
                            debug->debugnormalize = true;
                            debugflag = true;
                        }
#endif

#ifdef HAVE_LIBESMTP
                    if (Sagan_strstr(optarg, "smtp"))
                        {
                            debug->debugesmtp = true;
                            debugflag = true;
                        }
#endif

#ifdef HAVE_LIBPCAP
                    if (Sagan_strstr(optarg, "plog"))
                        {
                            debug->debugplog = true;
                            debugflag = true;
                        }
#endif

#ifdef WITH_BLUEDOT
                    if (Sagan_strstr(optarg, "bluedot"))
                        {
                            debug->debugbluedot = true;
                            debugflag = true;
                        }
#endif

#ifdef HAVE_LIBHIREDIS
                    if (Sagan_strstr(optarg, "redis"))
                        {
                            debug->debugredis = true;
                            debugflag = true;
                        }
#endif

                    /* If option is unknown */

                    if ( debugflag == false )
                        {
                            fprintf(stderr, "Unknown debug option %s!\n", optarg);
                            exit(1);
                        }

                    break;

                case 'D':
                    config->daemonize = true;
                    break;

                case 'u':
                    config->sagan_runas=optarg;
                    break;

                case 'c':
                    Chroot(optarg);
                    break;

                case 'F':
                    config->sagan_is_file = true;
                    strlcpy(config->sagan_fifo,optarg,sizeof(config->sagan_fifo) - 1);
                    break;

                case 'f':
                    strlcpy(config->sagan_config,optarg,sizeof(config->sagan_config) - 1);
                    break;

                case 'l':
                    strlcpy(config->sagan_log_filepath,optarg,sizeof(config->sagan_log_filepath) - 1);
                    break;

                case 't':

                    max_threads_override = atoi(optarg);

                    if ( max_threads_override == 0 )
                        {
                            Sagan_Log(ERROR, "[%s, line %d] --threads / -t option is zero or invalid.", __FILE__, __LINE__);
                        }

                    break;

                case 'r':

                    config->rules_from_file_flag = true;
                    strlcpy(config->rules_from_file, optarg, sizeof(config->rules_from_file) );

                    break;

                default:
                    fprintf(stderr, "Invalid argument! See below for command line switches.\n");
                    Usage();
                    exit(0);
                    break;
                }
        }

    if (( config->sagan_log_stream = fopen( config->sagan_log_filepath, "a" )) == NULL )
        {

            /* We can't use Sagan_Log() because we can't _open_ the log! */

            fprintf(stderr, "[%s, line %d] Cannot open %s (%s). Abort.\n", __FILE__, __LINE__, config->sagan_log_filepath, strerror(errno));
            exit(-1);

        }

    config->sagan_log_stream_int = fileno( config->sagan_log_stream );

    /* If in "test" mode,  let the user know.  Disabled config->daemon! */

    if ( test_mode == true )
        {
            Sagan_Log(NORMAL, "*******************************************************************************");
            Sagan_Log(NORMAL, "** Running Sagan in 'test'. Engine will not start after testing is complete. **");
            Sagan_Log(NORMAL, "*******************************************************************************");
            config->daemonize = false;
        }

    /* Become a daemon if requested */

    Sagan_Log(NORMAL, "Sagan's PID is %d", getpid() );

    if ( config->daemonize )
        {

            Sagan_Log(NORMAL, "Becoming a daemon!");

            pid_t pid = 0;
            pid = fork();

            if ( pid == 0 )
                {

                    /* Child */

                    if ( setsid() == -1 )
                        {
                            Sagan_Log(ERROR, "[%s, line %d] Failed creating new session while daemonizing", __FILE__, __LINE__);
                            exit(1);
                        }

                    pid = fork();

                    if ( pid == 0 )
                        {

                            /* Grandchild, the actual daemon */

                            if ( chdir("/") == -1 )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Failed changing directory to / after daemonizing [errno %d]", __FILE__, __LINE__, errno);
                                    exit(1);
                                }

                            /* Close and re-open stdin, stdout, and stderr, so as to
                               to release anyone waiting on them. */

                            close(0);
                            close(1);
                            close(2);

                            if ( open("/dev/null", O_RDONLY) == -1 )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Failed reopening stdin after daemonizing [errno %d]", __FILE__, __LINE__, errno);
                                }

                            if ( open("/dev/null", O_WRONLY) == -1 )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Failed reopening stdout after daemonizing [errno %d]", __FILE__, __LINE__, errno);
                                }

                            if ( open("/dev/null", O_RDWR) == -1 )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Failed reopening stderr after daemonizing [errno %d]", __FILE__, __LINE__, errno);
                                }

                        }
                    else if ( pid < 0 )
                        {

                            Sagan_Log(ERROR, "[%s, line %d] Failed second fork while daemonizing", __FILE__, __LINE__);
                            exit(1);

                        }
                    else
                        {

                            exit(0);
                        }

                }
            else if ( pid < 0 )
                {

                    Sagan_Log(ERROR, "[%s, line %d] Failed first fork while daemonizing", __FILE__, __LINE__);
                    exit(1);

                }
            else
                {

                    /* Wait for child to exit */
                    waitpid(pid, NULL, 0);
                    exit(0);
                }
        }


    /* Create the signal handlers thread _after_ the fork() so it can properly
     * handly signals - Champ Clark III - 06/13/2011 */

    /* No reason to start a signal handler if we are just "testing"
       Champ Clark III / 06/09/2022 */

    if ( test_mode == false )
        {

            rc = pthread_create( &sig_thread, NULL, (void *)Sig_Handler, NULL );

            if ( rc != 0  )
                {
                    Remove_Lock_File();
                    Sagan_Log(ERROR, "[%s, line %d] Error creating signal handler thread. [error: %d]", __FILE__, __LINE__, rc);
                }

        }


#ifdef PCRE_HAVE_JIT

    /* We test if pages will support RWX before loading rules.  If it doesn't due to the OS,
       we want to disable PCRE JIT now.  This prevents confusing warnings of PCRE JIT during
       rule load */

    config->pcre_jit = true;

    if (PageSupportsRWX() == false)
        {
            Sagan_Log(WARN, "The operating system doens't allow RWX pages.  Disabling PCRE JIT.");
            config->pcre_jit = false;
        }

#endif

    pthread_mutex_lock(&SaganRulesLoadedMutex);
    (void)Load_YAML_Config(config->sagan_config, true);

    /* If we are in "test" mode, we can stop here */

    if ( test_mode == true )
        {
            pthread_mutex_unlock(&SaganRulesLoadedMutex);

            Sagan_Log(NORMAL, "******************************************************************");
            Sagan_Log(NORMAL, "*** Sagan 'test' mode complete.  Looks like everything passed! ***");
            Sagan_Log(NORMAL, "******************************************************************");

            fclose( config->sagan_log_stream );
            exit(0);
        }

    if ( config->sagan_log_syslog == true )
        {
            openlog("sagan", LOG_PID, LOG_DAEMON);
        }

    pthread_mutex_unlock(&SaganRulesLoadedMutex);

    /* This is for --threads (over rides the sagan.yaml file) */

    if ( max_threads_override != 0 )
        {
            config->max_processor_threads = max_threads_override;
        }

    SaganPassSyslog = malloc(config->max_processor_threads * sizeof(_Sagan_Pass_Syslog));

    if ( SaganPassSyslog == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SaganPassSyslog. Abort!", __FILE__, __LINE__);
        }

    for ( z = 0; z < config->max_processor_threads; z++ )
        {

            for ( i = 0; i < config->max_batch; i++ )
                {

                    SaganPassSyslog[z].batch[i] = malloc( config->message_buffer_size );

                    if ( SaganPassSyslog[z].batch[i] == NULL )
                        {
                            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for *SaganPassSyslog[z].batch. Abort!", __FILE__, __LINE__);
                        }
                }
        }


    pthread_t processor_id[config->max_processor_threads];
    pthread_attr_t thread_processor_attr;
    pthread_attr_init(&thread_processor_attr);
    pthread_attr_setdetachstate(&thread_processor_attr,  PTHREAD_CREATE_DETACHED);

#ifdef HAVE_LIBHIREDIS

    /* Redis "writer" threads */

    pthread_t redis_writer_processor_id[config->redis_max_writer_threads];
    pthread_attr_t redis_writer_thread_processor_attr;
    pthread_attr_init(&redis_writer_thread_processor_attr);
    pthread_attr_setdetachstate(&redis_writer_thread_processor_attr,  PTHREAD_CREATE_DETACHED);

#endif

    Sagan_Log(NORMAL, "Configuration file %s loaded and %d rules loaded.", config->sagan_config, counters->rulecount);
    Sagan_Log(NORMAL, "There are %d rules loaded.", counters->rulecount);
    Sagan_Log(NORMAL, "%d flexbit(s) are in use.", counters->flexbit_total_counter);
    Sagan_Log(NORMAL, "%d xbit(s) are in use.", counters->xbit_total_counter);
    Sagan_Log(NORMAL, "%d dynamic rule(s) are loaded.", counters->dynamic_rule_count);

#ifdef HAVE_LIBFASTJSON

    Sagan_Log(NORMAL, "Named pipe/FIFO input type: %s", config->input_type == INPUT_PIPE ? "Pipe":"JSON");
    Sagan_Log(NORMAL, "JSON Parsing              : %s", config->json_parse_data == true ? "Enabled":"Disabled");
    Sagan_Log(NORMAL, "Client Stats              : %s", config->client_stats_flag == true ? "Enabled":"Disabled");

#endif

    Sagan_Log(NORMAL, "Syslog batch:             : %d", config->max_batch);


#ifdef PCRE_HAVE_JIT

    Sagan_Log(NORMAL, "PCRE JIT                  : %s", config->pcre_jit == true ? "Enabled":"Disabled");

#endif

    Sagan_Log(NORMAL, "");
    Sagan_Log(NORMAL, "Sagan version %s is firing up on %s (cluster: %s)", VERSION, config->sagan_sensor_name, config->sagan_cluster_name);
    Sagan_Log(NORMAL, "");

#ifdef HAVE_LIBPCAP

    /* Spawn a thread to 'sniff' syslog traffic (sagan-plog.c).  This redirects syslog
       traffic to the /dev/log socket.  This needs "root" access,  so we drop priv's
       after this thread is started */

    if ( config->plog_flag )
        {

            rc = pthread_create( &pcap_thread, NULL, (void *)Plog_Handler, NULL );

            if ( rc != 0 )
                {
                    Remove_Lock_File();
                    Sagan_Log(ERROR, "[%s, line %d] Error creating libpcap handler thread [error: %d].", __FILE__, __LINE__, rc);
                }

            sleep(1); 	/* Sleep to avoid race between main() and plog thread
		   	plog thread needs "root" rights before sagan_droppriv().
		   	In some cases main() run sagan_droppriv() before thread
		   	can complete - Champ Clark - 07/20/2011 */

        }
#endif



    Droppriv();              /* Become the Sagan user */

    CheckLockFile();


    Sagan_Log(NORMAL, "---------------------------------------------------------------------------");

    IPC_Init();

    if ( config->stats_json_flag )
        {

            Stats_JSON_Init();

            rc = pthread_create( &stats_json_thread, NULL, (void *)Stats_JSON_Handler, NULL );

            if ( rc != 0 )
                {
                    Remove_Lock_File();
                    Sagan_Log(ERROR, "[%s, line %d] Error creating stats-json thread [error: %d].", __FILE__, __LINE__, rc);
                }
        }


    if ( config->client_stats_flag )
        {

            Client_Stats_Init();

            rc = pthread_create( &client_stats_thread, NULL, (void *)Client_Stats_Handler, NULL );

            if ( rc != 0 )
                {
                    Remove_Lock_File();
                    Sagan_Log(ERROR, "[%s, line %d] Error creating Clients Stats thread [error: %d].", __FILE__, __LINE__, rc);
                }
        }

    /****************************************************************************
     * Test file append access
     ****************************************************************************/

    /* EVE log */

    if ( config->eve_flag  )
        {
            if (( test_open = fopen( config->eve_filename, "a" )) == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Cannot open %s (%s). Abort", __FILE__, __LINE__, config->eve_filename, strerror(errno));
                }

            fclose(test_open);
        }

    /* Alert log */

    if ( config->alert_flag )
        {
            if (( test_open = fopen( config->sagan_alert_filepath, "a" )) == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Cannot open %s (%s). Abort", __FILE__, __LINE__, config->sagan_alert_filepath, strerror(errno));
                }

            fclose(test_open);
        }

    /* Fast log */

    if ( config->fast_flag )
        {
            if (( test_open = fopen( config->fast_filename, "a" )) == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Cannot open %s (%s). Abort", __FILE__, __LINE__,config->fast_filename, strerror(errno));
                }

            fclose(test_open);
        }


    /****************************************************************************
     * Display processor information as we load
     ****************************************************************************/

    /* Sagan_Track_Clients processor ********************************************/

    if ( config->sagan_track_clients_flag )
        {

            /* We run a thread for tracking syslog hosts */

            rc = pthread_create( &ct_report_thread, NULL, (void *)Track_Clients_Thread, NULL );

            if ( rc != 0 )
                {
                    Remove_Lock_File();
                    Sagan_Log(ERROR, "[%s, line %d] Error creating client_tracker_report_client thread. [error: %d]", __FILE__, __LINE__, rc);
                }

            if ( config->pp_sagan_track_clients )
                {
                    Sagan_Log(NORMAL, "");
                    Sagan_Log(NORMAL, "Client Tracking Processor: %d minute(s)", config->pp_sagan_track_clients);
                }

        }

    /* Sagan Blacklist IP processor *********************************************/

    if ( config->blacklist_flag )
        {

            Sagan_Blacklist_Init();
            Sagan_Blacklist_Load();

        }

#ifdef WITH_BLUEDOT
    if ( config->bluedot_flag )
        {

            /* Lookup Bluedot IP so we don't explode DNS :) */

            rc = DNS_Lookup( config->bluedot_host, config->bluedot_ip, sizeof(config->bluedot_ip) );

            /* Record epoch so we can determine TTL */

            config->bluedot_dns_last_lookup = atol(config->sagan_startutime);

            if ( rc != 0 )
                {
                    Sagan_Log(ERROR, "Cannot look up IP address for '%s'.  Abort!", config->bluedot_host );
                }

            Sagan_Log(NORMAL, "");
            Sagan_Log(NORMAL, "Bluedot IP: %s", config->bluedot_ip);
            Sagan_Log(NORMAL, "Bluedot URL: http://%s/%s", config->bluedot_ip, config->bluedot_uri);
            Sagan_Log(NORMAL, "Bluedot Device ID: %s", config->bluedot_device_id);
            Sagan_Log(NORMAL, "Bluedot Categories File: %s", config->bluedot_cat);
            Sagan_Log(NORMAL, "Bluedot loaded %d categories.", counters->bluedot_cat_count);
            Sagan_Log(NORMAL, "Bluedot Cache Timeout: %d minutes.", config->bluedot_timeout  / 60);
            Sagan_Log(NORMAL, "Bluedot IP Cache Size: %" PRIu64 "", config->bluedot_ip_max_cache);
            Sagan_Log(NORMAL, "Bluedot IP Queue Size: %" PRIu64 "", config->bluedot_ip_queue);
            Sagan_Log(NORMAL, "Bluedot Hash Cache Size: %" PRIu64 "", config->bluedot_hash_max_cache);
            Sagan_Log(NORMAL, "Bluedot URL Cache Size: %" PRIu64 "", config->bluedot_url_max_cache);
            Sagan_Log(NORMAL, "Bluedot Filename Cache Size: %" PRIu64 "", config->bluedot_filename_max_cache);
            Sagan_Log(NORMAL, "Bluedot JA3 Cache Size: %" PRIu64 "", config->bluedot_ja3_max_cache);

        }

#endif


    /* Sagan Zeek Intel processor *******************************************/

    if ( config->zeekintel_flag )
        {

            Sagan_Log(NORMAL, "");

            ZeekIntel_Load_File();

            Sagan_Log(NORMAL, "Zeek Intel::ADDR Loaded: %d", counters->zeekintel_addr_count);
            Sagan_Log(NORMAL, "Zeek Intel::DOMAIN Loaded: %d", counters->zeekintel_domain_count);
            Sagan_Log(NORMAL, "Zeek Intel::FILE_HASH Loaded: %d", counters->zeekintel_file_hash_count);
            Sagan_Log(NORMAL, "Zeek Intel::URL Loaded: %d", counters->zeekintel_url_count);
            Sagan_Log(NORMAL, "Zeek Intel::SOFTWARE Loaded: %d", counters->zeekintel_software_count);
            Sagan_Log(NORMAL, "Zeek Intel::EMAIL Loaded: %d", counters->zeekintel_email_count);
            Sagan_Log(NORMAL, "Zeek Intel::USER_NAME Loaded: %d", counters->zeekintel_user_name_count);
            Sagan_Log(NORMAL, "Zeek Intel::FILE_NAME Loaded: %d", counters->zeekintel_file_name_count);
            Sagan_Log(NORMAL, "Zeek Intel::CERT_HASH Loaded: %d", counters->zeekintel_cert_hash_count);
            Sagan_Log(NORMAL, "Zeek Intel Duplicates Detected: %d", counters->zeekintel_dups);

        }


    /***************************************************************************
     * Output plugins
     ***************************************************************************/

#ifdef HAVE_LIBESMTP

    if ( config->sagan_esmtp_flag )
        {
            Sagan_Log(NORMAL, "");

            Sagan_Log(NORMAL, "E-Mail will be sent from: %s", config->sagan_esmtp_from);
            Sagan_Log(NORMAL, "SMTP server is set to: %s", config->sagan_esmtp_server);
        }

#endif

    /***************************************************************************
     * Non-Processor/Output option
     ***************************************************************************/

    /* What to "ignore" ********************************************************/

    if ( config->sagan_droplist_flag )
        {

            Load_Ignore_List();
            Sagan_Log(NORMAL, "");
            Sagan_Log(NORMAL, "Loaded %d ignore/drop list item(s).", counters->droplist_count);

        }

    /***************************************************************************
     * Continue with normal startup!
     ***************************************************************************/

    Sagan_Log(NORMAL, "");
    Sagan_Log(NORMAL, " ,-._,-. 	-*> Sagan! <*-");
    Sagan_Log(NORMAL, " \\/)\"(\\/	Version %s", VERSION);
    Sagan_Log(NORMAL, "  (_o_)	Champ Clark III & The Quadrant InfoSec Team [quadrantsec.com]");
    Sagan_Log(NORMAL, "  /   \\/)	Copyright (C) 2009-2023 Quadrant Information Security, et al.");
    Sagan_Log(NORMAL, " (|| ||) 	Using PCRE version: %s", pcre_version());
    Sagan_Log(NORMAL, "  oo-oo");
    Sagan_Log(NORMAL, "");


    /* We don't want the Key_Handler() if we're in daemon mode! */

    if (!config->daemonize )
        {

            if (!config->quiet)
                {

                    rc = pthread_create( &key_thread, NULL, (void *)Key_Handler, NULL );

                    if ( rc != 0 )
                        {

                            Remove_Lock_File();
                            Sagan_Log(ERROR, "[%s, line %d] Error creating Key_Handler() thread. [error: %d]", __FILE__, __LINE__, rc);

                        }
                }
        }

#ifdef HAVE_LIBHIREDIS

    /* Right now,  Redis is only used for xbit/flexbit storage */

    if ( config->redis_flag )
        {

            Redis_Writer_Init();
            Redis_Reader_Connect();

            strlcpy(redis_command, "PING", sizeof(redis_command));

            Redis_Reader(redis_command, redis_reply, sizeof(redis_reply));

            if (!strcmp(redis_reply, "PONG"))
                {
                    Sagan_Log(NORMAL, "Got 'reader' PONG from Redis at %s:%d.", config->redis_server, config->redis_port);
                }
            else
                {
                    Sagan_Log(ERROR, "Failed to get PONG.  Got \"%s\" instead. Abort!", redis_reply);
                }

            Sagan_Log(NORMAL, "");

        }

#endif

#ifdef WITH_SYSLOG

    if ( config->rule_tracking_flag == true )
        {

            rc = pthread_create( &tracking_thread, NULL, (void *)RuleTracking_Syslog, NULL );

            if ( rc != 0 )
                {

                    Remove_Lock_File();
                    Sagan_Log(ERROR, "[%s, line %d] Error creating RuleTracking_Syslog() thread. [error: %d]", __FILE__, __LINE__, rc);

                }

        }
#endif

    Sagan_Log(NORMAL, "Spawning %d Processor Threads.", config->max_processor_threads);

    for (i = 0; i < config->max_processor_threads; i++)
        {

            rc = pthread_create ( &processor_id[i], &thread_processor_attr, (void *)Processor, NULL );

            if ( rc != 0 )
                {

                    Remove_Lock_File();
                    Sagan_Log(ERROR, "Could not pthread_create() for I/O processors [error: %d]", rc);

                }
        }

#ifdef HAVE_LIBHIREDIS

    if ( config->redis_flag )
        {

            Sagan_Log(NORMAL, "Spawning %d Redis Writer Threads.", config->redis_max_writer_threads);

            for (i = 0; i < config->redis_max_writer_threads; i++)
                {

                    rc = pthread_create ( &redis_writer_processor_id[i], &redis_writer_thread_processor_attr, (void *)Redis_Writer, NULL );

                    if ( rc != 0 )
                        {

                            Remove_Lock_File();
                            Sagan_Log(ERROR, "Could not pthread_create() for I/O redis writers [error: %d]", rc);

                        }
                }
        }

#endif

    Sagan_Log(NORMAL, "");

    if ( config->sagan_is_file == true )
        {

            glob_t globbuf = {0};

            glob(config->sagan_fifo, GLOB_DOOFFS, NULL, &globbuf);

            for (size_t z = 0; z != globbuf.gl_pathc; ++z)
                {

                    if ( globbuf.gl_pathv[z][ strlen(globbuf.gl_pathv[z]) - 3 ] == '.' &&
                            globbuf.gl_pathv[z][ strlen(globbuf.gl_pathv[z]) - 2 ] == 'g' &&
                            globbuf.gl_pathv[z][ strlen(globbuf.gl_pathv[z]) - 1 ] == 'z' )
                        {

#ifdef HAVE_LIBZ
                            GZIP_Input( globbuf.gl_pathv[z] );
#endif

#ifndef	HAVE_LIBZ
                            Sagan_Log(WARN, "[%s, line %d] Sagan lack gzip/libz support.  Skipping %s.", __FILE__, __LINE__, globbuf.gl_pathv[z]);
#endif

                        }
                    else
                        {
                            File_Input( globbuf.gl_pathv[z] );
                        }
                }


        }

    if ( config->sagan_is_file == false )
        {

            /* Can only be FIFO right now */

            FIFO_Input();

        }

    /* The input plugin is done.  Wait for any busy threads before exiting */

    while(proc_msgslot != 0 || proc_running != 0)
        {
            Sagan_Log(NORMAL, "Waiting on %d/%d threads....", proc_msgslot, proc_running);
            sleep(1);
        }

    Statistics();
    Remove_Lock_File();

    return(0);

} /* End of main */


