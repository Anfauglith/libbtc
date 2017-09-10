/**
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
 * Copyright (c) 2015 Douglas J. Bakkumk
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


#include <iop/bip32.h>

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <iop/base58.h>
#include <iop/ecc.h>
#include <iop/ecc_key.h>
#include <iop/hash.h>
#include <iop/sha2.h>
#include <iop/utils.h>

#include "memory.h"

#include "ripemd160.h"

// write 4 big endian bytes
static void write_be(uint8_t* data, uint32_t x)
{
    data[0] = x >> 24;
    data[1] = x >> 16;
    data[2] = x >> 8;
    data[3] = x;
}


// read 4 big endian bytes
static uint32_t read_be(const uint8_t* data)
{
    return (((uint32_t)data[0]) << 24) |
           (((uint32_t)data[1]) << 16) |
           (((uint32_t)data[2]) << 8) |
           (((uint32_t)data[3]));
}

iop_hdnode* iop_hdnode_new()
{
    iop_hdnode* hdnode;
    hdnode = iop_calloc(1, sizeof(*hdnode));
    return hdnode;
}

iop_hdnode* iop_hdnode_copy(iop_hdnode* hdnode)
{
    iop_hdnode* newnode = iop_hdnode_new();

    newnode->depth = hdnode->depth;
    newnode->fingerprint = hdnode->fingerprint;
    newnode->child_num = hdnode->child_num;
    memcpy(newnode->chain_code, hdnode->chain_code, sizeof(hdnode->chain_code));
    memcpy(newnode->private_key, hdnode->private_key, sizeof(hdnode->private_key));
    memcpy(newnode->public_key, hdnode->public_key, sizeof(hdnode->public_key));

    return newnode;
}

void iop_hdnode_free(iop_hdnode* hdnode)
{
    memset(hdnode->chain_code, 0, sizeof(hdnode->chain_code));
    memset(hdnode->private_key, 0, sizeof(hdnode->private_key));
    memset(hdnode->public_key, 0, sizeof(hdnode->public_key));
    iop_free(hdnode);
}

iop_bool iop_hdnode_from_seed(const uint8_t* seed, int seed_len, iop_hdnode* out)
{
    uint8_t I[IOP_ECKEY_PKEY_LENGTH + IOP_BIP32_CHAINCODE_SIZE];
    memset(out, 0, sizeof(iop_hdnode));
    out->depth = 0;
    out->fingerprint = 0x00000000;
    out->child_num = 0;
    hmac_sha512((const uint8_t*)"IoP seed", 12, seed, seed_len, I);
    memcpy(out->private_key, I, IOP_ECKEY_PKEY_LENGTH);

    if (!iop_ecc_verify_privatekey(out->private_key)) {
        memset(I, 0, sizeof(I));
        return false;
    }

    memcpy(out->chain_code, I + IOP_ECKEY_PKEY_LENGTH, IOP_BIP32_CHAINCODE_SIZE);
    iop_hdnode_fill_public_key(out);
    memset(I, 0, sizeof(I));
    return true;
}


iop_bool iop_hdnode_public_ckd(iop_hdnode* inout, uint32_t i)
{
    uint8_t data[1 + 32 + 4];
    uint8_t I[32 + IOP_BIP32_CHAINCODE_SIZE];
    uint8_t fingerprint[32];

    if (i & 0x80000000) { // private derivation
        return false;
    } else { // public derivation
        memcpy(data, inout->public_key, IOP_ECKEY_COMPRESSED_LENGTH);
    }
    write_be(data + IOP_ECKEY_COMPRESSED_LENGTH, i);

    sha256_Raw(inout->public_key, IOP_ECKEY_COMPRESSED_LENGTH, fingerprint);
    ripemd160(fingerprint, 32, fingerprint);
    inout->fingerprint = (fingerprint[0] << 24) + (fingerprint[1] << 16) + (fingerprint[2] << 8) + fingerprint[3];

    memset(inout->private_key, 0, 32);

    int failed = 0;
    hmac_sha512(inout->chain_code, 32, data, sizeof(data), I);
    memcpy(inout->chain_code, I + 32, IOP_BIP32_CHAINCODE_SIZE);


    if (!iop_ecc_public_key_tweak_add(inout->public_key, I))
        failed = false;

    if (!failed) {
        inout->depth++;
        inout->child_num = i;
    }

    // Wipe all stack data.
    memset(data, 0, sizeof(data));
    memset(I, 0, sizeof(I));
    memset(fingerprint, 0, sizeof(fingerprint));

    return failed ? false : true;
}


iop_bool iop_hdnode_private_ckd(iop_hdnode* inout, uint32_t i)
{
    uint8_t data[1 + IOP_ECKEY_PKEY_LENGTH + 4];
    uint8_t I[IOP_ECKEY_PKEY_LENGTH + IOP_BIP32_CHAINCODE_SIZE];
    uint8_t fingerprint[IOP_BIP32_CHAINCODE_SIZE];
    uint8_t p[IOP_ECKEY_PKEY_LENGTH], z[IOP_ECKEY_PKEY_LENGTH];

    if (i & 0x80000000) { // private derivation
        data[0] = 0;
        memcpy(data + 1, inout->private_key, IOP_ECKEY_PKEY_LENGTH);
    } else { // public derivation
        memcpy(data, inout->public_key, IOP_ECKEY_COMPRESSED_LENGTH);
    }
    write_be(data + IOP_ECKEY_COMPRESSED_LENGTH, i);

    sha256_Raw(inout->public_key, IOP_ECKEY_COMPRESSED_LENGTH, fingerprint);
    ripemd160(fingerprint, 32, fingerprint);
    inout->fingerprint = (fingerprint[0] << 24) + (fingerprint[1] << 16) +
                         (fingerprint[2] << 8) + fingerprint[3];

    memset(fingerprint, 0, sizeof(fingerprint));
    memcpy(p, inout->private_key, IOP_ECKEY_PKEY_LENGTH);

    hmac_sha512(inout->chain_code, IOP_BIP32_CHAINCODE_SIZE, data, sizeof(data), I);
    memcpy(inout->chain_code, I + IOP_ECKEY_PKEY_LENGTH, IOP_BIP32_CHAINCODE_SIZE);
    memcpy(inout->private_key, I, IOP_ECKEY_PKEY_LENGTH);

    memcpy(z, inout->private_key, IOP_ECKEY_PKEY_LENGTH);

    int failed = 0;
    if (!iop_ecc_verify_privatekey(z)) {
        failed = 1;
        return false;
    }

    memcpy(inout->private_key, p, IOP_ECKEY_PKEY_LENGTH);
    if (!iop_ecc_private_key_tweak_add(inout->private_key, z)) {
        failed = 1;
    }

    if (!failed) {
        inout->depth++;
        inout->child_num = i;
        iop_hdnode_fill_public_key(inout);
    }

    memset(data, 0, sizeof(data));
    memset(I, 0, sizeof(I));
    memset(p, 0, sizeof(p));
    memset(z, 0, sizeof(z));
    return true;
}


void iop_hdnode_fill_public_key(iop_hdnode* node)
{
    size_t outsize = IOP_ECKEY_COMPRESSED_LENGTH;
    iop_ecc_get_pubkey(node->private_key, node->public_key, &outsize, true);
}


static void iop_hdnode_serialize(const iop_hdnode* node, uint32_t version, char use_public, char* str, int strsize)
{
    uint8_t node_data[78];
    write_be(node_data, version);
    node_data[4] = node->depth;
    write_be(node_data + 5, node->fingerprint);
    write_be(node_data + 9, node->child_num);
    memcpy(node_data + 13, node->chain_code, IOP_BIP32_CHAINCODE_SIZE);
    if (use_public) {
        memcpy(node_data + 45, node->public_key, IOP_ECKEY_COMPRESSED_LENGTH);
    } else {
        node_data[45] = 0;
        memcpy(node_data + 46, node->private_key, IOP_ECKEY_PKEY_LENGTH);
    }
    iop_base58_encode_check(node_data, 78, str, strsize);
}


void iop_hdnode_serialize_public(const iop_hdnode* node, const iop_chainparams* chain, char* str, int strsize)
{
    iop_hdnode_serialize(node, chain->b58prefix_bip32_pubkey, 1, str, strsize);
}


void iop_hdnode_serialize_private(const iop_hdnode* node, const iop_chainparams* chain, char* str, int strsize)
{
    iop_hdnode_serialize(node, chain->b58prefix_bip32_privkey, 0, str, strsize);
}


void iop_hdnode_get_hash160(const iop_hdnode* node, uint160 hash160_out)
{
    uint256 hashout;
    iop_hash_sngl_sha256(node->public_key, IOP_ECKEY_COMPRESSED_LENGTH, hashout);
    ripemd160(hashout, sizeof(hashout), hash160_out);
}

void iop_hdnode_get_p2pkh_address(const iop_hdnode* node, const iop_chainparams* chain, char* str, int strsize)
{
    uint8_t hash160[sizeof(uint160)+1];
    hash160[0] = chain->b58prefix_pubkey_address;
    iop_hdnode_get_hash160(node, hash160 + 1);
    iop_base58_encode_check(hash160, sizeof(hash160), str, strsize);
}

iop_bool iop_hdnode_get_pub_hex(const iop_hdnode* node, char* str, size_t* strsize)
{
    iop_pubkey pubkey;
    iop_pubkey_init(&pubkey);
    memcpy(&pubkey.pubkey, node->public_key, IOP_ECKEY_COMPRESSED_LENGTH);
    pubkey.compressed = true;

    return iop_pubkey_get_hex(&pubkey, str, strsize);
}


// check for validity of curve point in case of public data not performed
iop_bool iop_hdnode_deserialize(const char* str, const iop_chainparams* chain, iop_hdnode* node)
{
    uint8_t node_data[strlen(str)];
    memset(node, 0, sizeof(iop_hdnode));
    size_t outlen = 0;

    outlen = iop_base58_decode_check(str, node_data, sizeof(node_data));
    if (!outlen) {
        return false;
    }
    uint32_t version = read_be(node_data);
    if (version == chain->b58prefix_bip32_pubkey) { // public node
        memcpy(node->public_key, node_data + 45, IOP_ECKEY_COMPRESSED_LENGTH);
    } else if (version == chain->b58prefix_bip32_privkey) { // private node
        if (node_data[45]) {                                // invalid data
            return false;
        }
        memcpy(node->private_key, node_data + 46, IOP_ECKEY_PKEY_LENGTH);
        iop_hdnode_fill_public_key(node);
    } else {
        return false; // invalid version
    }
    node->depth = node_data[4];
    node->fingerprint = read_be(node_data + 5);
    node->child_num = read_be(node_data + 9);
    memcpy(node->chain_code, node_data + 13, IOP_BIP32_CHAINCODE_SIZE);
    return true;
}

iop_bool iop_hd_generate_key(iop_hdnode* node, const char* keypath, const uint8_t* keymaster, const uint8_t* chaincode, iop_bool usepubckd)
{
    static char delim[] = "/";
    static char prime[] = "phH\'";
    static char digits[] = "0123456789";
    uint64_t idx = 0;
    assert(strlens(keypath) < 1024);
    char *pch, *kp = iop_malloc(strlens(keypath) + 1);

    if (!kp) {
        return false;
    }

    if (strlens(keypath) < strlens("m/")) {
        goto err;
    }

    memset(kp, 0, strlens(keypath) + 1);
    memcpy(kp, keypath, strlens(keypath));

    if (kp[0] != 'm' || kp[1] != '/') {
        goto err;
    }

    node->depth = 0;
    node->child_num = 0;
    node->fingerprint = 0;
    memcpy(node->chain_code, chaincode, IOP_BIP32_CHAINCODE_SIZE);
    if (usepubckd == true) {
        memcpy(node->public_key, keymaster, IOP_ECKEY_COMPRESSED_LENGTH);
    } else {
        memcpy(node->private_key, keymaster, IOP_ECKEY_PKEY_LENGTH);
        iop_hdnode_fill_public_key(node);
    }

    pch = strtok(kp + 2, delim);
    while (pch != NULL) {
        size_t i = 0;
        int prm = 0;
        for (; i < strlens(pch); i++) {
            if (strchr(prime, pch[i])) {
                if ((i != strlens(pch) - 1) || usepubckd == true) {
                    goto err;
                }
                prm = 1;
            } else if (!strchr(digits, pch[i])) {
                goto err;
            }
        }

        idx = strtoull(pch, NULL, 10);
        if (idx > UINT32_MAX) {
            goto err;
        }

        if (prm) {
            if (iop_hdnode_private_ckd_prime(node, idx) != true) {
                goto err;
            }
        } else {
            if ((usepubckd == true ? iop_hdnode_public_ckd(node, idx) : iop_hdnode_private_ckd(node, idx)) != true) {
                goto err;
            }
        }
        pch = strtok(NULL, delim);
    }
    iop_free(kp);
    return true;

err:
    iop_free(kp);
    return false;
}

iop_bool iop_hdnode_has_privkey(iop_hdnode* node)
{
    int i;
    for (i = 0; i < IOP_ECKEY_PKEY_LENGTH; ++i) {
        if (node->private_key[i] != 0)
            return true;
    }
    return false;
}
