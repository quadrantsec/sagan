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

/* util.c
 *
 * Various re-usable functions.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util-base64.h"

static const char *b64codes = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const unsigned char base64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


/********************************************************************************
 * Base64Encode - Returns a base64 encoded string.  This was taken from
 * Suricata.  I believe it was derived from Jouni Malinen work from:
 *
 * http://web.mit.edu/freebsd/head/contrib/wpa/src/utils/base64.c
 * http://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c
 *
 ********************************************************************************/

int Base64Encode(const unsigned char *in,  unsigned long inlen, unsigned char *out, unsigned long *outlen)
{
    unsigned long i, len2, leven;
    unsigned char *p;

    if(in == NULL || out == NULL || outlen == NULL)
        {
            return -1;
        }

    /* valid output size ? */
    len2 = 4 * ((inlen + 2) / 3);
    if (*outlen < len2 + 1)
        {
            *outlen = len2 + 1;
            return -1;
        }
    p = out;
    leven = 3*(inlen / 3);
    for (i = 0; i < leven; i += 3)
        {
            *p++ = b64codes[(in[0] >> 2) & 0x3F];
            *p++ = b64codes[(((in[0] & 3) << 4) + (in[1] >> 4)) & 0x3F];
            *p++ = b64codes[(((in[1] & 0xf) << 2) + (in[2] >> 6)) & 0x3F];
            *p++ = b64codes[in[2] & 0x3F];
            in += 3;
        }

    /* Pad it if necessary...  */
    if (i < inlen)
        {
            unsigned a = in[0];
            unsigned b = (i+1 < inlen) ? in[1] : 0;

            *p++ = b64codes[(a >> 2) & 0x3F];
            *p++ = b64codes[(((a & 3) << 4) + (b >> 4)) & 0x3F];
            *p++ = (i+1 < inlen) ? b64codes[(((b & 0xf) << 2)) & 0x3F] : '=';
            *p++ = '=';
        }

    /* append a NULL byte */
    *p = '\0';
    /* return ok */
    *outlen = p - out;

    return 0;

}

int Base64Decode(const unsigned char *src, size_t len, char *str, size_t size)
{

    unsigned char dtable[256], *out, *pos, block[4], tmp;
    size_t i, count, olen;
    int pad = 0;

    memset(dtable, 0x80, 256);
    for (i = 0; i < sizeof(base64_table) - 1; i++)
        dtable[base64_table[i]] = (unsigned char) i;
    dtable['='] = 0;

    count = 0;
    for (i = 0; i < len; i++)
        {
            if (dtable[src[i]] != 0x80)
                count++;
        }

    if (count == 0 || count % 4)
        {
            return -1;
        }

    olen = count / 4 * 3;
    pos = out = malloc(olen);
    if (out == NULL)
        return -1;

    count = 0;
    for (i = 0; i < len; i++)
        {
            tmp = dtable[src[i]];
            if (tmp == 0x80)
                continue;

            if (src[i] == '=')
                pad++;
            block[count] = tmp;
            count++;
            if (count == 4)
                {
                    *pos++ = (block[0] << 2) | (block[1] >> 4);
                    *pos++ = (block[1] << 4) | (block[2] >> 2);
                    *pos++ = (block[2] << 6) | block[3];
                    count = 0;
                    if (pad)
                        {
                            if (pad == 1)
                                pos--;
                            else if (pad == 2)
                                pos -= 2;
                            else
                                {
                                    /* Invalid padding */
                                    free(out);
                                    return -1;
                                }
                            break;
                        }
                }
        }

    snprintf(str, size, "%s", out);

    return 0;
}

