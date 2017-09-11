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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <iop/ecc_key.h>

#include "utest.h"
#include <iop/utils.h>

void test_eckey()
{
    iop_key key;
    iop_privkey_init(&key);
    assert(iop_privkey_is_valid(&key) == 0);
    iop_privkey_gen(&key);
    assert(iop_privkey_is_valid(&key) == 1);

    iop_pubkey pubkey;
    iop_pubkey_init(&pubkey);
    assert(iop_pubkey_is_valid(&pubkey) == 0);
    iop_pubkey_from_key(&key, &pubkey);
    assert(iop_pubkey_is_valid(&pubkey) == 1);

    assert(iop_privkey_verify_pubkey(&key, &pubkey) == 1);

    unsigned int i;
    for (i = 33; i < IOP_ECKEY_UNCOMPRESSED_LENGTH; i++)
        assert(pubkey.pubkey[i] == 0);

    uint8_t* hash = utils_hex_to_uint8((const char*)"26db47a48a10b9b0b697b793f5c0231aa35fe192c9d063d7b03a55e3c302850a");
    unsigned char sig[74];
    size_t outlen = 74;
    iop_key_sign_hash(&key, hash, sig, &outlen);

    unsigned char sigcmp[64];
    size_t outlencmp = 64;
    iop_key_sign_hash_compact(&key, hash, sigcmp, &outlencmp);

    unsigned char sigcmp_rec[64];
    size_t outlencmp_rec = 64;
    int recid;
    iop_pubkey pubkey_rec;
    iop_pubkey_init(&pubkey_rec);
    iop_key_sign_hash_compact_recoverable(&key, hash, sigcmp_rec, &outlencmp_rec, &recid);
    iop_key_sign_recover_pubkey(sigcmp_rec, hash, recid, &pubkey_rec);
    u_assert_int_eq(iop_pubkey_verify_sig(&pubkey, hash, sig, outlen), true);
    u_assert_int_eq(iop_pubkey_verify_sig(&pubkey, hash, sig, outlen), true);
    int test = sizeof(pubkey.pubkey);
    u_assert_mem_eq(pubkey.pubkey, pubkey_rec.pubkey, sizeof(pubkey.pubkey));


    size_t size = 66;
    char str[size];
    int r = iop_pubkey_get_hex(&pubkey, str, &size);
    u_assert_int_eq(r, true);
    u_assert_int_eq(size, 66);

    size = 50;
    r = iop_pubkey_get_hex(&pubkey, str, &size);
    u_assert_int_eq(r, false);
    iop_privkey_cleanse(&key);
    iop_pubkey_cleanse(&pubkey);
}
