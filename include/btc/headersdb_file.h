/*

 The MIT License (MIT)

 Copyright (c) 2015 Jonas Schnelli

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.
 
*/

#ifndef __LIBIOP_HEADERSDB_FILE_H__
#define __LIBIOP_HEADERSDB_FILE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "iop.h"
#include "blockchain.h"
#include "buffer.h"
#include "chainparams.h"

#include "headersdb.h"

#include <stdio.h>

/* filebased headers database (including binary tree option for fast access)
*/
typedef struct iop_headers_db_
{
    FILE *headers_tree_file;
    iop_bool read_write_file;

    void *tree_root;
    iop_bool use_binary_tree;

    unsigned int max_hdr_in_mem;
    iop_blockindex genesis;
    iop_blockindex *chaintip;
    iop_blockindex *chainbottom;
} iop_headers_db;

iop_headers_db *iop_headers_db_new(const iop_chainparams* chainparams, iop_bool inmem_only);
void iop_headers_db_free(iop_headers_db *db);

iop_bool iop_headers_db_load(iop_headers_db* db, const char *filename);
iop_blockindex * iop_headers_db_connect_hdr(iop_headers_db* db, struct const_buffer *buf, iop_bool load_process, iop_bool *connected);

void iop_headers_db_fill_block_locator(iop_headers_db* db, vector *blocklocators);

iop_blockindex * iop_headersdb_find(iop_headers_db* db, uint256 hash);
iop_blockindex * iop_headersdb_getchaintip(iop_headers_db* db);
iop_bool iop_headersdb_disconnect_tip(iop_headers_db* db);

iop_bool iop_headersdb_has_checkpoint_start(iop_headers_db* db);
void iop_headersdb_set_checkpoint_start(iop_headers_db* db, uint256 hash, uint32_t height);


// interface function pointer bindings
static const iop_headers_db_interface iop_headers_db_interface_file = {
    (void* (*)(const iop_chainparams*, iop_bool))iop_headers_db_new,
    (void (*)(void *))iop_headers_db_free,
    (iop_bool (*)(void *, const char *))iop_headers_db_load,
    (void (*)(void* , vector *))iop_headers_db_fill_block_locator,
    (iop_blockindex *(*)(void* , struct const_buffer *, iop_bool , iop_bool *))iop_headers_db_connect_hdr,

    (iop_blockindex* (*)(void *))iop_headersdb_getchaintip,
    (iop_bool (*)(void *))iop_headersdb_disconnect_tip,

    (iop_bool (*)(void *))iop_headersdb_has_checkpoint_start,
    (void (*)(void *, uint256, uint32_t))iop_headersdb_set_checkpoint_start
};

#ifdef __cplusplus
}
#endif

#endif //__LIBIOP_HEADERSDB_FILE_H__
