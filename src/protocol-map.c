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

/* gen-msg.c
 *
 * Reads in the sagan-gen-msg.map.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "protocol-map.h"

extern struct _SaganCounters *counters;
extern struct _SaganConfig *config;
extern struct _SaganDebug *debug;
extern struct _Sagan_Protocol_Map_Message *map_message;
extern struct _Sagan_Protocol_Map_Program *map_program;

void Load_Protocol_Map( const char *map )
{

    FILE *mapfile;
    char mapbuf[1024];

    uint32_t line_number = 0;

    struct json_object *json_obj = NULL;
    struct json_object *tmp = NULL;

    const char *type = NULL;
    const char *protocol_number = NULL;
    const char *case_sensitive = NULL;
    const char *string = NULL;

//    char *saveptr=NULL;

//    char *map1=NULL;
//    char *map2=NULL;
//    char *map3=NULL;
//    char *map4=NULL;

    counters->mapcount_message = 0;
    counters->mapcount_program = 0;

    Sagan_Log(NORMAL, "Loading protocol map file. [%s]", map);


    if (( mapfile = fopen(map, "r" )) == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Cannot open protocol map file (%s)", __FILE__, __LINE__, map);
        }

    while(fgets(mapbuf, 1024, mapfile) != NULL)
        {

            /* Skip comments and blank linkes */

            if (mapbuf[0] == '#' || mapbuf[0] == 10 || mapbuf[0] == ';' || mapbuf[0] == 32)
                {

                    line_number++;
                    continue;
                }
            else
                {

                    line_number++;

                    json_obj = json_tokener_parse(mapbuf);

                    if (json_object_object_get_ex(json_obj, "type", &tmp))
                        {
                            type = json_object_get_string(tmp);
                        }
                    else
                        {
                            Sagan_Log(ERROR, "[%s, line %d] 'type' not specified at line %d", __FILE__, __LINE__, line_number );
                        }

                    if (json_object_object_get_ex(json_obj, "protocol_number", &tmp))
                        {
                            protocol_number  = json_object_get_string(tmp);
                        }
                    else
                        {
                            Sagan_Log(ERROR, "[%s, line %d] 'protocol_number' not specified at line %d", __FILE__, __LINE__, line_number );
                        }

                    if (json_object_object_get_ex(json_obj, "case_sensitive", &tmp))
                        {
                            case_sensitive  = json_object_get_string(tmp);
                        }
                    else
                        {
                            Sagan_Log(ERROR, "[%s, line %d] 'case_sensitive' not specified at line %d", __FILE__, __LINE__, line_number );
                        }

                    if (json_object_object_get_ex(json_obj, "string", &tmp))
                        {
                            string  = json_object_get_string(tmp);
                        }
                    else
                        {
                            Sagan_Log(ERROR, "[%s, line %d] 'string' not specified at %d", __FILE__, __LINE__, line_number);
                        }

                    if ( !strcmp(type, "message" ) )
                        {

                            map_message = (_Sagan_Protocol_Map_Message *) realloc(map_message, (counters->mapcount_message+1) * sizeof(_Sagan_Protocol_Map_Message));

                            if ( map_message == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for map_message. Abort!", __FILE__, __LINE__);
                                }

//                            memset(&map_message[counters->mapcount_message], 0, sizeof(struct _Sagan_Protocol_Map_Message));

                            map_message[counters->mapcount_message].proto = atoi( protocol_number );

                            if ( map_message[counters->mapcount_message].proto == 0 )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Protocol number is invalid at line %d.", __FILE__, __LINE__, line_number);
                                }

                            if ( !strcmp(case_sensitive, "true" ) )
                                {
                                    map_message[counters->mapcount_message].nocase = true;
                                }


                            strlcpy( map_message[counters->mapcount_message].search, string, sizeof( map_message[counters->mapcount_message].search ) );

                            counters->mapcount_message++;

                        }

                    else if ( !strcmp(type, "program" ) )
                        {

                            map_program = (_Sagan_Protocol_Map_Program *) realloc(map_program, (counters->mapcount_program+1) * sizeof(_Sagan_Protocol_Map_Program));

                            if ( map_program == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for map_program. Abort!", __FILE__, __LINE__);
                                }

//                            memset(&map_program[counters->mapcount_program], 0, sizeof(struct _Sagan_Protocol_Map_Program));

                            map_program[counters->mapcount_program].proto = atoi( protocol_number );

                            if ( map_program[counters->mapcount_program].proto == 0 )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Protocol number is invalid at line %d.", __FILE__, __LINE__, line_number);
                                }

                            if ( !strcmp(case_sensitive, "true" ) )
                                {
                                    map_program[counters->mapcount_program].nocase = true;
                                }

                            strlcpy( map_program[counters->mapcount_program].program, string, sizeof(map_program[counters->mapcount_program].program) );

                            counters->mapcount_program++;

                        }

                    else
                        {

                            Sagan_Log(ERROR, "[%s, line %d]  Invalid 'type' specified at line %d. Need to be 'message' or 'program'.", __FILE__, __LINE__, line_number );


                        }

                }
        }

    fclose(mapfile);

    json_object_put(json_obj);

    Sagan_Log(NORMAL, "%d protocols loaded. Loaded %d 'message' search items and %d 'program' items.", counters->mapcount_message + counters->mapcount_program, counters->mapcount_message, counters->mapcount_program);


}

