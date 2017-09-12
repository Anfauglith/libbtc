/**********************************************************************
 * Copyright (c) 2016 Jonas Schnelli                                  *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <iop/base58.h>
#include <iop/bip32.h>
#include <iop/ecc.h>
#include <iop/ecc_key.h>
#include <iop/net.h>
#include <iop/random.h>
#include <iop/serialize.h>
#include <iop/tx.h>
#include <iop/utils.h>

#include <assert.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

iop_bool address_from_pubkey(const iop_chainparams* chain, const char* pubkey_hex, char* address)
{
    if (!pubkey_hex || strlen(pubkey_hex) != 66)
        return false;

    iop_pubkey pubkey;
    iop_pubkey_init(&pubkey);
    pubkey.compressed = 1;

    size_t outlen = 0;
    utils_hex_to_bin(pubkey_hex, pubkey.pubkey, strlen(pubkey_hex), (int*)&outlen);
    assert(iop_pubkey_is_valid(&pubkey) == 1);

    uint8_t hash160[sizeof(uint160)+1];
    hash160[0] = chain->b58prefix_pubkey_address;
    iop_pubkey_get_hash160(&pubkey, hash160 + 1);

    iop_base58_encode_check(hash160, sizeof(hash160), address, 98);

    return true;
}

iop_bool pubkey_from_privatekey(const iop_chainparams* chain, const char* privkey_wif, char* pubkey_hex, size_t* sizeout)
{
    uint8_t privkey_data[strlen(privkey_wif)];
    size_t outlen = 0;
    outlen = iop_base58_decode_check(privkey_wif, privkey_data, sizeof(privkey_data));
    if (privkey_data[0] != chain->b58prefix_secret_address)
        return false;

    iop_key key;
    iop_privkey_init(&key);
    memcpy(key.privkey, privkey_data + 1, 32);

    iop_pubkey pubkey;
    iop_pubkey_init(&pubkey);
    assert(iop_pubkey_is_valid(&pubkey) == 0);
    iop_pubkey_from_key(&key, &pubkey);
    iop_privkey_cleanse(&key);

    iop_pubkey_get_hex(&pubkey, pubkey_hex, sizeout);
    iop_pubkey_cleanse(&pubkey);

    return true;
}

iop_bool gen_privatekey(const iop_chainparams* chain, char* privkey_wif, size_t strsize_wif, char* privkey_hex_or_null)
{
    uint8_t pkeybase58c[34];
    pkeybase58c[0] = chain->b58prefix_secret_address;
    pkeybase58c[33] = 1; /* always use compressed keys */

    iop_key key;
    iop_privkey_init(&key);
    iop_privkey_gen(&key);
    memcpy(&pkeybase58c[1], key.privkey, IOP_ECKEY_PKEY_LENGTH);
    assert(iop_base58_encode_check(pkeybase58c, 34, privkey_wif, strsize_wif) != 0);

    // also export the hex privkey if use had passed in a valid pointer
    // will always export 32 bytes
    if (privkey_hex_or_null != NULL)
        utils_bin_to_hex(key.privkey, IOP_ECKEY_PKEY_LENGTH, privkey_hex_or_null);
    iop_privkey_cleanse(&key);
    return true;
}

iop_bool hd_gen_master(const iop_chainparams* chain, char* inputseed, size_t seedsize, char* masterkeyhex, size_t strsize)
{
    iop_hdnode node;
    uint8_t seed[seedsize];
    
    if (inputseed==0) {
        assert(iop_random_bytes(seed, seedsize, true));
    } else {
        memcpy(seed, utils_hex_to_uint8(inputseed), seedsize);
    } 
    printf("seed: %s\n", utils_uint8_to_hex(seed,seedsize));
    iop_hdnode_from_seed(seed, seedsize, &node);
    memset(seed, 0, seedsize);
    iop_hdnode_serialize_private(&node, chain, masterkeyhex, strsize);
    memset(&node, 0, sizeof(node));
    return true;
}

iop_bool hd_print_node(const iop_chainparams* chain, const char* nodeser)
{
    iop_hdnode node;
    if (!iop_hdnode_deserialize(nodeser, chain, &node))
        return false;

    size_t strsize = 128;
    char str[strsize];
    iop_hdnode_get_p2pkh_address(&node, chain, str, strsize);

    printf("ext key: %s\n", nodeser);

    size_t privkey_wif_size_bin = 34;
    uint8_t pkeybase58c[privkey_wif_size_bin];
    pkeybase58c[0] = chain->b58prefix_secret_address;
    pkeybase58c[33] = 1; /* always use compressed keys */
    size_t privkey_wif_size = 128;
    char privkey_wif[privkey_wif_size];
    memcpy(&pkeybase58c[1], node.private_key, IOP_ECKEY_PKEY_LENGTH);
    assert(iop_base58_encode_check(pkeybase58c, privkey_wif_size_bin, privkey_wif, privkey_wif_size) != 0);
    printf("privatekey WIF: %s\n", privkey_wif);

    printf("depth: %d\n", node.depth);
    printf("p2pkh address: %s\n", str);

    if (!iop_hdnode_get_pub_hex(&node, str, &strsize))
        return false;
    printf("pubkey hex: %s\n", str);

    strsize = 128;
    iop_hdnode_serialize_public(&node, chain, str, strsize);
    printf("extended pubkey: %s\n", str);
    return true;
}

iop_bool hd_derive(const iop_chainparams* chain, const char* masterkey, const char* keypath, char* extkeyout, size_t extkeyout_size)
{
    iop_hdnode node, nodenew;
    if (!iop_hdnode_deserialize(masterkey, chain, &node))
        return false;

    //check if we only have the publickey
    bool pubckd = !iop_hdnode_has_privkey(&node);

    //derive child key, use pubckd or privckd
    if (!iop_hd_generate_key(&nodenew, keypath, pubckd ? node.public_key : node.private_key, node.chain_code, pubckd))
        return false;

    if (pubckd)
        iop_hdnode_serialize_public(&nodenew, chain, extkeyout, extkeyout_size);
    else
        iop_hdnode_serialize_private(&nodenew, chain, extkeyout, extkeyout_size);
    return true;
}
