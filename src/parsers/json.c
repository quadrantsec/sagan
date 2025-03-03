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

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBFASTJSON

#include <stdio.h>
#include <string.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"
#include "version.h"
#include "debug.h"

extern struct _SaganCounters *counters;
extern struct _SaganConfig *config;
extern struct _SaganDebug *debug;

void Parse_JSON ( char *syslog_string, struct _Sagan_JSON *JSON_LOCAL )
{

    struct json_object *json_obj = NULL;

    uint_fast16_t i;
    uint_fast16_t json_count = 1;

    struct json_object_iterator it;
    struct json_object_iterator itEnd;

    const char *key = NULL;
    const char *val_str = NULL;

    struct json_object *val;

    /* The raw syslog is the first "nested" level".  Copy that.  This will be the
       first entry in the array  */

    json_count = 1;

    JSON_LOCAL->json_key[0][0] = '\0';
    strlcpy(JSON_LOCAL->json_value[0], syslog_string, config->message_buffer_size);

    for (i = 0; i < json_count; i++ )
        {

            if ( JSON_LOCAL->json_value[i][0] == '{' || JSON_LOCAL->json_value[i][1] == '{' || JSON_LOCAL->json_value[i][2] == '{' )
                {

                    json_obj = json_tokener_parse(JSON_LOCAL->json_value[i]);

                    if ( json_obj != NULL )
                        {

                            it = json_object_iter_begin(json_obj);
                            itEnd = json_object_iter_end(json_obj);

                            while (!json_object_iter_equal(&it, &itEnd))
                                {

                                    key = json_object_iter_peek_name(&it);
                                    val = json_object_iter_peek_value(&it);
                                    val_str = json_object_get_string(val);

                                    snprintf(JSON_LOCAL->json_key[json_count], JSON_MAX_KEY_SIZE, "%s.%s", JSON_LOCAL->json_key[i], key);
                                    JSON_LOCAL->json_key[json_count][JSON_MAX_KEY_SIZE - 1] = '\0';

                                    if ( val_str != NULL )
                                        {
                                            strlcpy(JSON_LOCAL->json_value[json_count], val_str, config->message_buffer_size);
                                        }
                                    else
                                        {
                                            strlcpy(JSON_LOCAL->json_value[json_count], "null", config->message_buffer_size);
                                        }

                                    if ( debug->debugjson )
                                        {

                                            Sagan_Log(DEBUG, "[%s, line %d] [%d] Key : %s, Value: %s", __FILE__, __LINE__, json_count, JSON_LOCAL->json_key[json_count], JSON_LOCAL->json_value[json_count] );

                                        }

                                    json_count++;

                                    /* Check to see if we have to many JSON objects to put into
                                    * memory */

                                    if ( json_count == JSON_MAX_OBJECTS )
                                        {

                                            Sagan_Log(WARN, "Sagan has been compiled to support %d JSON object.  More than %d objects (key/value pairs) were found.  This means that some of the JSON key/values had to be dropped.  Recompile with more JSON_MAX_OBJECTS in the sagan-defs.h to support more objects.  Sagan will process what data it was able to keep.", JSON_MAX_OBJECTS, JSON_MAX_OBJECTS);

                                            JSON_LOCAL->json_count = json_count;

                                            json_object_put(json_obj);
                                            return;

                                        }


                                    json_object_iter_next(&it);

                                }
                        }

                    json_object_put(json_obj);

                }
        }

    JSON_LOCAL->json_count = json_count;

}

void Get_Key_Value( struct _Sagan_JSON *JSON_LOCAL, const char *key, char *value, size_t size)
{

    uint16_t a = 0;

    for ( a = 0; a < JSON_LOCAL->json_count; a++ )
        {

            if ( !strcmp( JSON_LOCAL->json_key[a], key ) )
                {
                    snprintf(value, size, "%s", JSON_LOCAL->json_value[a]);
                    return;
                }
        }

}

#endif

