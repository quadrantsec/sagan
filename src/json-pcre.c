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

/* json-pcre.c controls how 'json_pcre: "{key}", "/{pcre}/";' rule options
   works.  This works similar to "pcre" but on JSON key/value pairs */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBFASTJSON

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "rules.h"
#include "json-content.h"
#include "util-base64.h"

#include "parsers/parsers.h"

extern struct _Rule_Struct *rulestruct;

bool JSON_Pcre(int rule_position, _Sagan_JSON *JSON_LOCAL)
{

    int i=0;
    int a=0;
    int rc=0;

    char tmp_string[JSON_MAX_VALUE_SIZE] = { 0 };

    int ovector[PCRE_OVECCOUNT];

    for (i=0; i < rulestruct[rule_position].json_decode_base64_pcre_count; i++)
        {

            for (a=0; a < JSON_LOCAL->json_count; a++)
                {

                    if ( !strcmp(JSON_LOCAL->json_key[a], rulestruct[rule_position].json_pcre_key[i] ) )
                        {

                            if ( rulestruct[rule_position].json_decode_base64_pcre[i] == true )
                                {

                                    Base64Decode( (const unsigned char*)JSON_LOCAL->json_value[a], strlen(JSON_LOCAL->json_value[a]),  tmp_string, JSON_MAX_VALUE_SIZE);

                                }
                            else
                                {

                                    memcpy( tmp_string, JSON_LOCAL->json_value[a], JSON_MAX_VALUE_SIZE);

                                }

                            rc = pcre_exec( rulestruct[rule_position].json_re_pcre[i], rulestruct[rule_position].json_pcre_extra[i], tmp_string, (int)strlen(tmp_string), 0, 0, ovector, PCRE_OVECCOUNT);

                            /* If it's _not_ a match, no need to test other conditions */

                            if ( rc < 0 )
                                {
                                    return(false);
                                }
                        }
                }
        }

    /* All conditions matched,  so return true */

    return(true);
}

#endif
