/* ASN.1 Object identifier (OID) registry
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

/*
 *  Copyright (c) 2012-2019 Finnbarr P. Murphy.   All rights reserved.
 *
 *  Modified to work in EDKII environment.
 *
 */

#include "UefiBaseType.h"
#include <unicode/ustdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "oid_registry.h"
#include "oid_registry_data.h"  
#include <cerrno>

/*
 * Find an OID registration for the specified data
 * @data: Binary representation of the OID
 * @datasize: Size of the binary representation
 */
enum OID 
Lookup_OID(const void *data, size_t datasize)
{
    const unsigned char *octets = data;
    enum OID oid;
    unsigned char xhash;
    //unsigned i, j, k, hash; //TO DO: WTF? "unsigned"?  "unsigned" what?  Compiler is *assuming* int
    size_t i, j, k, hash; //TO DO: WTF? "unsigned"?  "unsigned" what?  Compiler is *assuming* int
    long len;

    /* Hash the OID data */
    hash = datasize - 1;
    for (i = 0; i < datasize; i++)
    {
        size_t octet = octets[i];
        hash += octet * 33;
    }
    hash = (hash >> 24) ^ (hash >> 16) ^ (hash >> 8) ^ hash;
    hash &= 0xff;

    /* Binary search the OID registry.  OIDs are stored in ascending order
     * of hash value then ascending order of size and then in ascending
     * order of reverse value.
     */
    i = 0;
    k = OID__NR;
    while (i < k) {
        j = (i + k) / 2;

        xhash = oid_search_table[j].hash;
        if (xhash > hash) {
            k = j;
            continue;
        }
        if (xhash < hash) {
            i = j + 1;
            continue;
        }

        oid = oid_search_table[j].oid;
        len = oid_index[oid + 1] - oid_index[oid];
        if (len > datasize) {
            k = j;
            continue;
        }
        if (len < datasize) {
            i = j + 1;
            continue;
        }

        /* Variation is most likely to be at the tail end of the
         * OID, so do the comparison in reverse.
         */
        while (len > 0) {
            unsigned char a = oid_data[oid_index[oid] + --len];
            unsigned char b = octets[len];
            if (a > b) {
                k = j;
                goto next;
            }
            if (a < b) {
                i = j + 1;
                goto next;
            }
        }
        return oid;
    next:
        ;
    }

    return OID__NR;
}


/*
 * Print an Object Identifier into a buffer
 * @data: The encoded OID to print
 * @datasize: The size of the encoded OID
 * @buffer: The buffer to render into
 * @bufsize: The size of the buffer
 *
 * The OID is rendered into the buffer in "a.b.c.d" format and the number of
 * bytes is returned.  -EBADMSG is returned if the data could not be intepreted
 * and -ENOBUFS if the buffer was too small.
 */
int 
Sprint_OID(const void *data, size_t datasize, UChar *buffer, long bufsize)
{
    unsigned char* cpy_data = calloc(datasize + 1, sizeof(unsigned char));
    memcpy_s(cpy_data, (datasize + 1), data, datasize);

    unsigned char *v = cpy_data, *end = v + datasize;
    unsigned int num;
    unsigned int seven = 7;
    unsigned char n;
    long ret;
    int count;
    int bufutil = 0;
    char* index = buffer;
    long origsize = bufsize;
    if (v >= end)
    {
        return -EBADMSG;
    }

    n = (unsigned char)*v++;
    //count = swprintf_s(buffer, bufsize, "%d.%d", n / 40, n % 40);
    count = u_sprintf(buffer, "%d.%d", n / 40, n % 40);
    //ret = count = strlen(buffer);
    ret = bufutil += count;
    //buffer += count; //TODO: I suspect this pointer arithmetic is what is causing the heap corruption
    bufsize -= count;
    if (bufsize == 0)
    {
        return -ENOBUFS;
    }

    while (v < end) {
        num = 0;
        n = (unsigned char)*v++;
        if (!(n & 0x80)) {
            num = n;
        } else {
            num = n & 0x7f;
            do {
                if (v >= end)
                {
                    return -EBADMSG;
                }
                n = (unsigned char)*v++; //TODO: this bit shift is almost certainly causing the stack corruption error
                num <<= seven; 
                num |= n & 0x7f;
            } while (n & 0x80);
        }
        count = u_sprintf(buffer, ".%ld", num);
        //count = swprintf_s((buffer + bufutil), bufsize, ".%ld", num);
        
        //ret += count = strlen(buffer);
        ret = bufutil += count;
        //buffer += count;
        bufsize -= count;
        if (bufsize == 0)
        {
            return -ENOBUFS;
        }
    }
    //buffer += 1;
    //memset((buffer + bufutil + 1), 0, (origsize - bufutil));
    buffer[bufutil] = 0;

    return ret;
}
