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

#ifndef __LIBIOP_ECC_KEY_H__
#define __LIBIOP_ECC_KEY_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "iop.h"

#include <stddef.h>

typedef struct iop_key_ {
    uint8_t privkey[IOP_ECKEY_PKEY_LENGTH];
} iop_key;

typedef struct iop_pubkey_ {
    iop_bool compressed;
    uint8_t pubkey[IOP_ECKEY_UNCOMPRESSED_LENGTH];
} iop_pubkey;

LIBIOP_API void iop_privkey_init(iop_key* privkey);
LIBIOP_API iop_bool iop_privkey_is_valid(iop_key* privkey);
LIBIOP_API void iop_privkey_cleanse(iop_key* privkey);
LIBIOP_API void iop_privkey_gen(iop_key* privkey);
LIBIOP_API iop_bool iop_privkey_verify_pubkey(iop_key* privkey, iop_pubkey* pubkey);

LIBIOP_API void iop_pubkey_init(iop_pubkey* pubkey);
LIBIOP_API iop_bool iop_pubkey_is_valid(iop_pubkey* pubkey);
LIBIOP_API void iop_pubkey_cleanse(iop_pubkey* pubkey);
LIBIOP_API void iop_pubkey_from_key(iop_key* privkey, iop_pubkey* pubkey_inout);

//get the hash160 (single SHA256 + RIPEMD160)
LIBIOP_API void iop_pubkey_get_hash160(const iop_pubkey* pubkey, uint160 hash160);

//get the hex representation of a pubkey, strsize must be at leat 66 bytes
LIBIOP_API iop_bool iop_pubkey_get_hex(const iop_pubkey* pubkey, char* str, size_t* strsize);

//sign a 32byte message/hash and returns a DER encoded signature (through *sigout)
LIBIOP_API iop_bool iop_key_sign_hash(const iop_key* privkey, const uint256 hash, unsigned char* sigout, size_t* outlen);

//sign a 32byte message/hash and returns a 64 byte compact signature (through *sigout)
LIBIOP_API iop_bool iop_key_sign_hash_compact(const iop_key* privkey, const uint256 hash, unsigned char* sigout, size_t* outlen);

//sign a 32byte message/hash and returns a 64 byte compact signature (through *sigout) plus a 1byte recovery id
LIBIOP_API iop_bool iop_key_sign_hash_compact_recoverable(const iop_key* privkey, const uint256 hash, unsigned char* sigout, size_t* outlen, int *recid);

LIBIOP_API iop_bool iop_key_sign_recover_pubkey(const unsigned char* sig, const uint256 hash, int recid, iop_pubkey* pubkey);

//verifies a DER encoded signature with given pubkey and return true if valid
LIBIOP_API iop_bool iop_pubkey_verify_sig(const iop_pubkey* pubkey, const uint256 hash, unsigned char* sigder, int len);

#ifdef __cplusplus
}
#endif

#endif //__LIBIOP_ECC_KEY_H__
