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

#include <iop/ecc_key.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <iop/ecc.h>
#include <iop/hash.h>
#include <iop/random.h>
#include <iop/utils.h>

#include "ripemd160.h"


void iop_privkey_init(iop_key* privkey)
{
    memset(&privkey->privkey, 0, IOP_ECKEY_PKEY_LENGTH);
}


iop_bool iop_privkey_is_valid(iop_key* privkey)
{
    return iop_ecc_verify_privatekey(privkey->privkey);
}


void iop_privkey_cleanse(iop_key* privkey)
{
    memset(&privkey->privkey, 0, IOP_ECKEY_PKEY_LENGTH);
}


void iop_privkey_gen(iop_key* privkey)
{
    if (privkey == NULL)
        return;

    do {
        assert(iop_random_bytes(privkey->privkey, IOP_ECKEY_PKEY_LENGTH, 0));
    } while (iop_ecc_verify_privatekey(privkey->privkey) == 0);
}


iop_bool iop_privkey_verify_pubkey(iop_key* privkey, iop_pubkey* pubkey)
{
    uint256 rnddata, hash;
    assert(iop_random_bytes(rnddata, IOP_HASH_LENGTH, 0));
    iop_hash(rnddata, IOP_HASH_LENGTH, hash);

    unsigned char sig[74];
    size_t siglen = 74;

    if (!iop_key_sign_hash(privkey, hash, sig, &siglen))
        return false;

    return iop_pubkey_verify_sig(pubkey, hash, sig, siglen);
}


void iop_pubkey_init(iop_pubkey* pubkey)
{
    if (pubkey == NULL)
        return;

    memset(pubkey->pubkey, 0, IOP_ECKEY_UNCOMPRESSED_LENGTH);
    pubkey->compressed = false;
}


iop_bool iop_pubkey_is_valid(iop_pubkey* pubkey)
{
    return iop_ecc_verify_pubkey(pubkey->pubkey, pubkey->compressed);
}


void iop_pubkey_cleanse(iop_pubkey* pubkey)
{
    if (pubkey == NULL)
        return;

    memset(pubkey->pubkey, 0, IOP_ECKEY_UNCOMPRESSED_LENGTH);
}


void iop_pubkey_get_hash160(const iop_pubkey* pubkey, uint160 hash160)
{
    uint256 hashout;
    iop_hash_sngl_sha256(pubkey->pubkey, pubkey->compressed ? IOP_ECKEY_COMPRESSED_LENGTH : IOP_ECKEY_UNCOMPRESSED_LENGTH, hashout);

    ripemd160(hashout, sizeof(hashout), hash160);
}


iop_bool iop_pubkey_get_hex(const iop_pubkey* pubkey, char* str, size_t* strsize)
{
    if (*strsize < IOP_ECKEY_COMPRESSED_LENGTH * 2)
        return false;
    utils_bin_to_hex((unsigned char*)pubkey->pubkey, IOP_ECKEY_COMPRESSED_LENGTH, str);
    *strsize = IOP_ECKEY_COMPRESSED_LENGTH * 2;
    return true;
}


void iop_pubkey_from_key(iop_key* privkey, iop_pubkey* pubkey_inout)
{
    if (pubkey_inout == NULL || privkey == NULL)
        return;

    size_t in_out_len = IOP_ECKEY_COMPRESSED_LENGTH;

    iop_ecc_get_pubkey(privkey->privkey, pubkey_inout->pubkey, &in_out_len, true);
    pubkey_inout->compressed = true;
}


iop_bool iop_key_sign_hash(const iop_key* privkey, const uint256 hash, unsigned char* sigout, size_t* outlen)
{
    return iop_ecc_sign(privkey->privkey, hash, sigout, outlen);
}


iop_bool iop_key_sign_hash_compact(const iop_key* privkey, const uint256 hash, unsigned char* sigout, size_t* outlen)
{
    return iop_ecc_sign_compact(privkey->privkey, hash, sigout, outlen);
}

iop_bool iop_key_sign_hash_compact_recoverable(const iop_key* privkey, const uint256 hash, unsigned char* sigout, size_t* outlen, int* recid)
{
    return iop_ecc_sign_compact_recoverable(privkey->privkey, hash, sigout, outlen, recid);
}

iop_bool iop_key_sign_recover_pubkey(const unsigned char* sig, const uint256 hash, int recid, iop_pubkey* pubkey)
{
    uint8_t pubkeybuf[128];
    size_t outlen = 128;
    if (!iop_ecc_recover_pubkey(sig, hash, recid, pubkeybuf, &outlen) || outlen > IOP_ECKEY_UNCOMPRESSED_LENGTH) {
        return 0;
    }
    memset(pubkey->pubkey, 0, sizeof(pubkey->pubkey));
    memcpy(pubkey->pubkey, pubkeybuf, outlen);
    if (outlen == IOP_ECKEY_COMPRESSED_LENGTH) {
        pubkey->compressed = true;
    }
    return 1;
}

iop_bool iop_pubkey_verify_sig(const iop_pubkey* pubkey, const uint256 hash, unsigned char* sigder, int len)
{
    return iop_ecc_verify_sig(pubkey->pubkey, pubkey->compressed, hash, sigder, len);
}
