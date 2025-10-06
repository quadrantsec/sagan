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

    config->c_reader_redis = NULL;

    while ( config->c_reader_redis == NULL || config->c_reader_redis->err )
        {

            struct timeval timeout = { 1, 500000 }; // 5.5 seconds
            config->c_reader_redis = redisConnectWithTimeout(config->redis_server, config->redis_port, timeout);

            if (config->c_reader_redis == NULL || config->c_reader_redis->err)
                {

                    if (config->c_reader_redis)
                        {
                            redisFree(config->c_reader_redis);
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

            if (!strcmp(reply->str, "OK"))
                {

                    if ( debug->debugredis )
                        {

                            Sagan_Log( DEBUG, "Authentication success for 'reader' to Redis server at %s:%d (pthread ID: %lu).", config->redis_server, config->redis_port, pthread_self() );

                        }

                }
            else
                {

                    Remove_Lock_File();
                    Sagan_Log(ERROR, "Authentication failure for 'reader' to to Redis server at %s:%d (pthread ID: %lu). Abort!", config->redis_server, config->redis_port, pthread_self() );

                }
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

    c_writer_redis = NULL;

    while ( c_writer_redis == NULL || c_writer_redis->err )
        {

            struct timeval timeout = { 5, 500000 }; // 5.5 seconds
            c_writer_redis = redisConnectWithTimeout(config->redis_server, config->redis_port, timeout);

            if (c_writer_redis == NULL || c_writer_redis->err)
                {

                    if (c_writer_redis)
                        {

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

            if (!strcmp(reply->str, "OK"))
                {

                    if ( debug->debugredis )
                        {

                            Sagan_Log( DEBUG, "Authentication success for 'writer' to Redis server at %s:%d (pthread ID: %lu).", config->redis_server, config->redis_port, pthread_self() );

                        }

                }
            else
                {

                    Remove_Lock_File();
                    Sagan_Log(ERROR, "Authentication failure for 'writer' to to Redis server at %s:%d (pthread ID: %lu). Abort!", config->redis_server, config->redis_port, pthread_self() );

                }
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

    if ( connection_read_error == true )
        {
            Sagan_Log(WARN, "[%s, line %d] Redis is an error state.  Cannot write.", __FILE__, __LINE__);
            str[0] = '\0';
            return;
        }
    else
        {
            pthread_mutex_lock(&RedisReaderMutex);
            reply = redisCommand(config->c_reader_redis, redis_command);
            pthread_mutex_unlock(&RedisReaderMutex);

            if ( reply != NULL )
                {

                    if ( debug->debugredis )
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] Redis Command: \"%s\"", __FILE__, __LINE__, redis_command);
                        }

                    if ( reply->type == REDIS_REPLY_STRING && reply->len > 0 )
                        {

			    printf("----> IN STRING\n");
			   fflush(stdout);

                            if ( debug->debugredis )
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] Redis 'string' Reply: \"%s\"", __FILE__, __LINE__, reply->str);
                                }

                            snprintf(str, size, reply->str);
                            str[reply->len] = '\0';

                        }
                    else if ( reply->type == REDIS_REPLY_ARRAY && reply->elements > 0 )
                        {

                            printf("----> IN ARRAYn");
                           fflush(stdout);

                            if ( debug->debugredis )
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] Redis 'array' Reply: \"%s\"", __FILE__, __LINE__, reply->element[0]->str);
                                }

                            snprintf(str, size, reply->element[0]->str);
                            str[reply->len] = '\0';

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
