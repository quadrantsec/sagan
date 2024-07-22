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

/* json-content.c controls the 'json-content: "{key}", "{content}";" rule option.
   This works similar to "content" but searches json key/value pairs */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBFASTJSON

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"
#include "rules.h"
#include "json-content.h"
#include "search-type.h"
#include "util-base64.h"

#include "parsers/parsers.h"

extern struct _Rule_Struct *rulestruct;
extern struct _SaganConfig *config;

bool JSON_Content(uint_fast32_t rule_position, _Sagan_JSON *JSON_LOCAL)
{

    uint_fast16_t i = 0;
    uint_fast16_t a = 0;

    char *tmp_string = malloc( config->message_buffer_size );

    if ( tmp_string == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __FILE__, __LINE__);
        }

    tmp_string[0] = '\0';

    bool key_search = false;

    for (i=0; i < rulestruct[rule_position].json_content_count; i++)
        {

            key_search = false;

            for (a=0; a < JSON_LOCAL->json_count; a++)
                {

                    /* Search for the "key" specified in json_content */

                    if ( !strcmp(JSON_LOCAL->json_key[a], rulestruct[rule_position].json_content_key[i] ) )
                        {

                            key_search = true;

                            if ( rulestruct[rule_position].json_decode_base64[i] == true )
                                {

                                    Base64Decode( (const unsigned char*)JSON_LOCAL->json_value[a], strlen(JSON_LOCAL->json_value[a]), tmp_string, config->message_buffer_size);

                                }
                            else
                                {

                                    /* Clear previous value */

                                    tmp_string[0] = '\0';
                                    memcpy( tmp_string, JSON_LOCAL->json_value[a], config->message_buffer_size );

                                }

                            /* Key was found,  is this a "nocase" rule or is it case sensitive */

                            if ( rulestruct[rule_position].json_content_case[i] == true )
                                {

                                    /* Is this a json_content or json_content:! */

                                    if ( rulestruct[rule_position].json_content_not[i] == false )
                                        {

                                            if ( Search_Nocase( tmp_string, rulestruct[rule_position].json_content_content[i], false, rulestruct[rule_position].json_content_strstr[i] ) == false  )
                                                {

                                                    free(tmp_string);
                                                    return(false);

                                                }

                                        }
                                    else
                                        {

                                            if ( Search_Nocase(tmp_string, rulestruct[rule_position].json_content_content[i], false, rulestruct[rule_position].json_content_strstr[i] ) == true )
                                                {
                                                    free(tmp_string);
                                                    return(false);
                                                }


                                        }

                                }
                            else
                                {

                                    /* Case sensitive */

                                    if ( rulestruct[rule_position].json_content_not[i] == false )
                                        {

                                            if ( Search_Case(tmp_string, rulestruct[rule_position].json_content_content[i], rulestruct[rule_position].json_content_strstr[i]) ==  false )
                                                {
                                                    free(tmp_string);
                                                    return(false);
                                                }

                                        }
                                    else
                                        {

                                            if ( Search_Case(tmp_string, rulestruct[rule_position].json_content_content[i], rulestruct[rule_position].json_content_strstr[i]) == true )
                                                {
                                                    free(tmp_string);
                                                    return(false);
                                                }

                                        }

                                }
                        }
                }

            /* If we don't find the key, there is no point going any further */

            if ( key_search == false )
                {
                    free(tmp_string);
                    return(false);
                }

        }

    /* If everything lines up,  we have a full json_content match */

    free(tmp_string);
    return(true);

}

#endif
