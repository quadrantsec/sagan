#include <stdio.h>

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <zlib.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"
#include "ignore-list.h"

#include "lockfile.h"
#include "stats.h"

#include "parsers/parsers.h"


extern struct _Sagan_Ignorelist *SaganIgnorelist;
extern struct _SaganCounters *counters;
extern struct _SaganConfig *config;


bool Ignore( const char *syslogstring )
{

    uint32_t k = 0;

    for (k = 0; k < counters->droplist_count; k++)
        {

            if (Sagan_strstr(syslogstring, SaganIgnorelist[k].ignore_string))
                {

                    /* Found ignore keyword! */

                    counters->bytes_ignored = counters->bytes_ignored + strlen( syslogstring );
                    counters->ignore_count++;

                    return(true);

                }
        }


    /* Nothing found */

    return(false);
}


