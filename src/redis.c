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

/* redis.c - Function that access/write to Redis database */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBHIREDIS

#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <hiredis/hiredis.h>

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include "sagan.h"
#include "sagan-config.h"
#include "lockfile.h"
#include "redis.h"

//#define	  MAX_REDIS_KEY_SIZE 		128

extern struct _SaganConfig *config;
extern struct _SaganDebug *debug;

uint_fast16_t redis_msgslot = 0;

extern bool death;

pthread_cond_t SaganRedisDoWork=PTHREAD_COND_INITIALIZER;
pthread_mutex_t SaganRedisWorkMutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t RedisReaderMutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t RedisWriterMutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t RedisErrorMutex=PTHREAD_MUTEX_INITIALIZER;

bool connection_write_error = false;
bool connection_read_error = false;

redisContext *c_writer_redis;

struct _Sagan_Redis_Write *Sagan_Redis_Write = NULL;

/*****************************************************************************
 * Redis_Writer_Init - Redis "writer" threads initialization.
 *****************************************************************************/

void Redis_Writer_Init ( void )
{

    Sagan_Redis_Write = malloc(config->redis_max_writer_threads * sizeof(struct _Sagan_Redis_Write));

    if ( Sagan_Redis_Write == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for Sagan_Redis_Write. Abort!", __FILE__, __LINE__);
        }

    Sagan_Redis_Write->value = malloc( config->message_buffer_size * 2);

    if ( Sagan_Redis_Write->value == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __FILE__, __LINE__);
        }


    Sagan_Redis_Write->key = malloc( MAX_REDIS_KEY_SIZE + 1 );

    if ( Sagan_Redis_Write->key == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory.", __FILE__, __LINE__);
        }

}

/*****************************************************************************
 * Redis_Reader_Connect - Connection for "read" operations.  These are
 * non-threaded operations
 *****************************************************************************/

void Redis_Reader_Connect ( void )
{

    redisReply *reply;
    bool authenticated = false;

    while ( authenticated == false )
        {

            config->c_reader_redis = NULL;

            while ( config->c_reader_redis == NULL || config->c_reader_redis->err )
                {

                    struct timeval timeout = { 1, 500000 }; // 5.5 seconds
                    config->c_reader_redis = redisConnectWithTimeout(config->redis_server, config->redis_port, timeout);

                    if (config->c_reader_redis == NULL || config->c_reader_redis->err)
                        {

                            if (config->c_reader_redis)
                                {

                                    /* NULL the context after freeing so the loop
                                       condition doesn't read freed memory. */

                                    redisFree(config->c_reader_redis);
                                    config->c_reader_redis = NULL;
                                    Sagan_Log(WARN, "[%s, line %d] Redis 'reader' connection error! Sleeping for 2 seconds!", __FILE__, __LINE__);

                                }
                            else
                                {
                                    Sagan_Log(WARN, "[%s, line %d] Redis 'reader' connection error - Can't allocate Redis context", __FILE__, __LINE__);
                                }
                            sleep(2);
                        }
                }

            /******************/
            /* Log into Redis */
            /******************/

            if ( config->redis_password[0] != '\0' )
                {

                    reply = redisCommand(config->c_reader_redis, "AUTH %s", config->redis_password);

                    if ( reply == NULL )
                        {

                            /* redisCommand() returns NULL when the connection drops
                               mid-AUTH, which is exactly what happens during Redis
                               connectivity problems.  Dereferencing reply->str here was
                               the crash.  Free the context, back off, and retry the
                               whole connect/auth sequence. */

                            redisFree(config->c_reader_redis);
                            config->c_reader_redis = NULL;
                            Sagan_Log(WARN, "[%s, line %d] Redis 'reader' disconnected during AUTH! Sleeping for 2 seconds!", __FILE__, __LINE__);
                            sleep(2);
                            continue;

                        }

                    if ( reply->str != NULL && !strcmp(reply->str, "OK"))
                        {

                            if ( debug->debugredis )
                                {

                                    Sagan_Log( DEBUG, "Authentication success for 'reader' to Redis server at %s:%d (pthread ID: %lu).", config->redis_server, config->redis_port, pthread_self() );

                                }

                            freeReplyObject(reply);

                        }
                    else
                        {

                            /* A real (non-NULL) reply that isn't "OK" means the
                               password is wrong.  That's fatal, as before. */

                            freeReplyObject(reply);
                            Remove_Lock_File();
                            Sagan_Log(ERROR, "Authentication failure for 'reader' to to Redis server at %s:%d (pthread ID: %lu). Abort!", config->redis_server, config->redis_port, pthread_self() );

                        }
                }

            authenticated = true;

        }

    pthread_mutex_lock(&RedisErrorMutex);
    connection_read_error = false;
    pthread_mutex_unlock(&RedisErrorMutex);

}

/*****************************************************************************
 * Redis_Writer_Connect - Handles login and auth for "writer" (detached)
 * Redis threads
 *****************************************************************************/

void Redis_Writer_Connect(void)
{

    redisReply *reply;
    bool authenticated = false;

    while ( authenticated == false )
        {

            c_writer_redis = NULL;

            while ( c_writer_redis == NULL || c_writer_redis->err )
                {

                    struct timeval timeout = { 5, 500000 }; // 5.5 seconds
                    c_writer_redis = redisConnectWithTimeout(config->redis_server, config->redis_port, timeout);

                    if (c_writer_redis == NULL || c_writer_redis->err)
                        {

                            if (c_writer_redis)
                                {

                                    /* Free the failed context (was leaked on every
                                       retry) and NULL it so the loop condition doesn't
                                       read freed memory. */

                                    redisFree(c_writer_redis);
                                    c_writer_redis = NULL;
                                    Sagan_Log(WARN, "[%s, line %d] Redis 'writer' connection error! Sleeping for 2 seconds.", __FILE__, __LINE__);

                                }
                            else
                                {

                                    Sagan_Log(ERROR, "[%s, line %d] Redis 'writer' connection error - Can't allocate Redis context.", __FILE__, __LINE__);

                                }

                            sleep(2);
                        }

                }

            /******************/
            /* Log into Redis */
            /******************/

            if ( config->redis_password[0] != '\0' )
                {

                    reply = redisCommand(c_writer_redis, "AUTH %s", config->redis_password);

                    if ( reply == NULL )
                        {

                            /* Connection dropped during AUTH.  Free the context, back
                               off, and retry rather than dereferencing a NULL reply
                               (crash under Redis connectivity loss). */

                            redisFree(c_writer_redis);
                            c_writer_redis = NULL;
                            Sagan_Log(WARN, "[%s, line %d] Redis 'writer' disconnected during AUTH! Sleeping for 2 seconds!", __FILE__, __LINE__);
                            sleep(2);
                            continue;

                        }

                    if ( reply->str != NULL && !strcmp(reply->str, "OK"))
                        {

                            if ( debug->debugredis )
                                {

                                    Sagan_Log( DEBUG, "Authentication success for 'writer' to Redis server at %s:%d (pthread ID: %lu).", config->redis_server, config->redis_port, pthread_self() );

                                }

                            freeReplyObject(reply);

                        }
                    else
                        {

                            /* A real (non-NULL) reply that isn't "OK" means the
                               password is wrong.  That's fatal, as before. */

                            freeReplyObject(reply);
                            Remove_Lock_File();
                            Sagan_Log(ERROR, "Authentication failure for 'writer' to to Redis server at %s:%d (pthread ID: %lu). Abort!", config->redis_server, config->redis_port, pthread_self() );

                        }
                }

            authenticated = true;

        }

    pthread_mutex_lock(&RedisErrorMutex);
    connection_write_error = false;
    pthread_mutex_unlock(&RedisErrorMutex);

}

/*****************************************************************************
 * Redis_Writer - Threads that "write" to Redis.  We spawn up several to
 * avoid blocking.  Writer accepts "stacked" commands seperated by ;
 *****************************************************************************/

void Redis_Writer ( void )
{

#ifdef HAVE_SYS_PRCTL_H
    (void)SetThreadName("SaganRedisWriter");
#endif

    redisReply *reply;

    char command[16] = { 0 };
    char key[128] = { 0 };
    uint_fast32_t expire = 0;

    char *value = malloc( config->message_buffer_size * 2 );

    if ( value  == NULL )
        {
            fprintf(stderr, "[%s, line %d] Fatal Error: Can't allocate memory! Abort!\n", __FILE__, __LINE__);
            exit(-1);
        }

    value[0] = '\0';

    Redis_Writer_Connect();

    /* Redis "threaded" operations */

    while ( death == false )
        {

            pthread_mutex_lock(&SaganRedisWorkMutex);

            while ( redis_msgslot == 0 ) pthread_cond_wait(&SaganRedisDoWork, &SaganRedisWorkMutex);

            redis_msgslot--;

            strlcpy(command, Sagan_Redis_Write[redis_msgslot].command, sizeof(command));
            strlcpy(key, Sagan_Redis_Write[redis_msgslot].key, sizeof(key));
            strlcpy(value, Sagan_Redis_Write[redis_msgslot].value, config->message_buffer_size * 2);
            expire = Sagan_Redis_Write[redis_msgslot].expire;

            pthread_mutex_unlock(&SaganRedisWorkMutex);

            if ( connection_write_error == true )
                {
                    Sagan_Log(WARN, "[%s, line %d] Redis is an error state.  Cannot write.", __FILE__, __LINE__);
                }
            else
                {

                    if ( debug->debugredis )
                        {

                            if ( expire == 0 )
                                {
                                    Sagan_Log(DEBUG, "Thread %u received the following work: '%s %s %s'", pthread_self(), command, key, value);
                                }
                            else
                                {
                                    Sagan_Log(DEBUG, "Thread %u received the following work: '%s %s %s EX %d'", pthread_self(), command, key, value, expire);
                                }


                        }


                    if ( expire == 0 )
                        {
                            pthread_mutex_lock(&RedisWriterMutex);
                            reply = redisCommand(c_writer_redis, "%s %s %s", command, key, value);
                            pthread_mutex_unlock(&RedisWriterMutex);
                        }
                    else
                        {
                            pthread_mutex_lock(&RedisWriterMutex);
                            reply = redisCommand(c_writer_redis, "%s %s %s EX %d", command, key, value, expire);
                            pthread_mutex_unlock(&RedisWriterMutex);
                        }

                    if ( reply != NULL )
                        {

                            if ( debug->debugredis )
                                {
                                    Sagan_Log(DEBUG, "Thread %u reply-str: '%s'", pthread_self(), reply->str);
                                }

                            freeReplyObject(reply);

                        }
                    else
                        {

                            Sagan_Log(WARN, "[%s, line %d] Got disconnected from Redis.  Reconnecting....", __FILE__, __LINE__);

                            pthread_mutex_lock(&RedisErrorMutex);
                            connection_write_error = true;
                            pthread_mutex_unlock(&RedisErrorMutex);

                            Redis_Writer_Connect();
                        }

                }
        }

    free(value);
    free(Sagan_Redis_Write);

}

/*****************************************************************************
 * Redis_Reader - This is _not_ a threaded operation and can't be :( This
 * function only returns _one_ result (not an array), even if they query
 * returns more than one result.
 *****************************************************************************/

void Redis_Reader ( const char *redis_command, char *str, size_t size )
{

    redisReply *reply;

    char command_copy[512] = { 0 };
    const char *argv[8] = { NULL };
    size_t argvlen[8] = { 0 };
    int argc = 0;
    char *token = NULL;
    char *sp = NULL;

    if ( connection_read_error == true )
        {
            Sagan_Log(WARN, "[%s, line %d] Redis is an error state.  Cannot write.", __FILE__, __LINE__);
            str[0] = '\0';
            return;
        }
    else
        {

            /* Split the command on spaces and use redisCommandArgv() so the
               command string is never run through printf-style formatting.
               The old code passed it as the format string, so a '%' inside
               a key (or stored data echoed into a command) was interpreted
               as a printf conversion - undefined behavior/crash. */

            strlcpy(command_copy, redis_command, sizeof(command_copy));

            token = strtok_r(command_copy, " ", &sp);

            while ( token != NULL && argc < 8 )
                {
                    argv[argc] = token;
                    argvlen[argc] = strlen(token);
                    argc++;
                    token = strtok_r(NULL, " ", &sp);
                }

            if ( argc == 0 )
                {
                    str[0] = '\0';
                    return;
                }

            pthread_mutex_lock(&RedisReaderMutex);
            reply = redisCommandArgv(config->c_reader_redis, argc, argv, argvlen);
            pthread_mutex_unlock(&RedisReaderMutex);

            if ( reply != NULL )
                {

                    if ( debug->debugredis )
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] Redis Command: \"%s\"", __FILE__, __LINE__, redis_command);

                            if ( reply->type == REDIS_REPLY_NIL )
                                {

                                    Sagan_Log(DEBUG, "[%s, line %d] Got NULL response.", __FILE__, __LINE__, redis_command);

                                }

                        }

                    if ( ( reply->type == REDIS_REPLY_STATUS || reply->type == REDIS_REPLY_STRING ) && reply->len > 0 )
                        {

                            if ( debug->debugredis )
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] Redis 'string' Reply: \"%s\"", __FILE__, __LINE__, reply->str);
                                }

                            /* Use "%s" so the reply is copied as data, never interpreted
                               as a printf format.  snprintf() bounds by 'size' and always
                               NUL-terminates, so do NOT write str[reply->len] (reply->len
                               can exceed 'size' and that write overran the buffer). */

                            snprintf(str, size, "%s", reply->str);

                        }
                    else if ( reply->type == REDIS_REPLY_ARRAY && reply->elements > 0 && reply->element[0]->str != NULL )
                        {

                            if ( debug->debugredis )
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] Redis 'array' Reply: \"%s\"", __FILE__, __LINE__, reply->element[0]->str);
                                }

                            snprintf(str, size, "%s", reply->element[0]->str);

                        }

                    freeReplyObject(reply);
                }
            else
                {

                    Sagan_Log(WARN, "[%s, line %d] Got disconnected from Redis.  Reconnecting....", __FILE__, __LINE__);

                    /* Error state, so we need to return "false" (failure) for the lookup.  This
                       insures that */

                    str[0] = '\0';

                    pthread_mutex_lock(&RedisErrorMutex);
                    connection_read_error = true;
                    pthread_mutex_unlock(&RedisErrorMutex);

                    Redis_Reader_Connect();
                }
        }
}

#endif
