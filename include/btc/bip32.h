/**
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
 * Copyright (c) 2015 Douglas J. Bakkumk
 * Copyright (c) 2015 Jonas Schnelli
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef __LIBIOP_BIP32_H__
#define __LIBIOP_BIP32_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "iop.h"
#include "chainparams.h"

#include <stdint.h>

#define IOP_BIP32_CHAINCODE_SIZE 32

typedef struct
{
    uint32_t depth;
    uint32_t fingerprint;
    uint32_t child_num;
    uint8_t chain_code[IOP_BIP32_CHAINCODE_SIZE];
    uint8_t private_key[IOP_ECKEY_PKEY_LENGTH];
    uint8_t public_key[IOP_ECKEY_COMPRESSED_LENGTH];
} iop_hdnode;


#define iop_hdnode_private_ckd_prime(X, I) iop_hdnode_private_ckd((X), ((I) | 0x80000000))


LIBIOP_API iop_hdnode* iop_hdnode_new();
LIBIOP_API iop_hdnode* iop_hdnode_copy(iop_hdnode* hdnode);
LIBIOP_API void iop_hdnode_free(iop_hdnode* node);
LIBIOP_API iop_bool iop_hdnode_public_ckd(iop_hdnode* inout, uint32_t i);
LIBIOP_API iop_bool iop_hdnode_from_seed(const uint8_t* seed, int seed_len, iop_hdnode* out);
LIBIOP_API iop_bool iop_hdnode_private_ckd(iop_hdnode* inout, uint32_t i);
LIBIOP_API void iop_hdnode_fill_public_key(iop_hdnode* node);
LIBIOP_API void iop_hdnode_serialize_public(const iop_hdnode* node, const iop_chainparams* chain, char* str, int strsize);
LIBIOP_API void iop_hdnode_serialize_private(const iop_hdnode* node, const iop_chainparams* chain, char* str, int strsize);

/* gives out the raw sha256/ripemd160 hash */
LIBIOP_API void iop_hdnode_get_hash160(const iop_hdnode* node, uint160 hash160_out);
LIBIOP_API void iop_hdnode_get_p2pkh_address(const iop_hdnode* node, const iop_chainparams* chain, char* str, int strsize);
LIBIOP_API iop_bool iop_hdnode_get_pub_hex(const iop_hdnode* node, char* str, size_t* strsize);
LIBIOP_API iop_bool iop_hdnode_deserialize(const char* str, const iop_chainparams* chain, iop_hdnode* node);

//!derive iop_hdnode from extended private or extended public key orkey
//if you use pub child key derivation, pass usepubckd=true
LIBIOP_API iop_bool iop_hd_generate_key(iop_hdnode* node, const char* keypath, const uint8_t* keymaster, const uint8_t* chaincode, iop_bool usepubckd);

//!checks if a node has the according private key (or if its a pubkey only node)
LIBIOP_API iop_bool iop_hdnode_has_privkey(iop_hdnode* node);

#ifdef __cplusplus
}
#endif

#endif // __LIBIOP_BIP32_H__
