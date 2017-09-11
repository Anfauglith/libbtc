/*

 The MIT License (MIT)

 Copyright (c) 2016 Thomas Kerin
 Copyright (c) 2016 libiop developers

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

#ifndef LIBIOP_BLOCK_H
#define LIBIOP_BLOCK_H

#ifdef __cplusplus
extern "C" {
#endif

#include "iop.h"

#include "buffer.h"
#include "cstr.h"
#include "hash.h"

#include <stddef.h>

typedef struct iop_block_header_ {
    int32_t version;
    uint256 prev_block;
    uint256 merkle_root;
    uint32_t timestamp;
    uint32_t bits;
    uint32_t nonce;
} iop_block_header;

LIBIOP_API iop_block_header* iop_block_header_new();
LIBIOP_API void iop_block_header_free(iop_block_header* header);
LIBIOP_API int iop_block_header_deserialize(iop_block_header* header, struct const_buffer* buf);
LIBIOP_API void iop_block_header_serialize(cstring* s, const iop_block_header* header);
LIBIOP_API void iop_block_header_copy(iop_block_header* dest, const iop_block_header* src);
LIBIOP_API iop_bool iop_block_header_hash(iop_block_header* header, uint256 hash);

#ifdef __cplusplus
}
#endif

#endif //__LIBIOP_BLOCK_H__
