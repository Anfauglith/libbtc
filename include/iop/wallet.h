/*

 The MIT License (MIT)

 Copyright (c) 2016 Jonas Schnelli

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

#ifndef __LIBIOP_WALLET_H__
#define __LIBIOP_WALLET_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "iop.h"

#include <iop/blockchain.h>

#include "bip32.h"
#include "buffer.h"
#include "tx.h"

#include <stddef.h>
#include <stdint.h>

/** single key/value record */
typedef struct iop_wallet {
    FILE *dbfile;
    iop_hdnode* masterkey;
    uint32_t next_childindex; //cached next child index
    const iop_chainparams* chain;
    uint32_t bestblockheight;
    vector* spends;

    /* use binary trees for in-memory mapping for wtxs, keys */
    void* wtxes_rbtree;
    void* hdkeys_rbtree;
} iop_wallet;

typedef struct iop_wtx_ {
    uint256 tx_hash_cache;
    uint32_t height;
    iop_tx* tx;
} iop_wtx;

typedef struct iop_wallet_hdnode_ {
    uint160 pubkeyhash;
    iop_hdnode *hdnode;
} iop_wallet_hdnode;

typedef struct iop_output_ {
    uint32_t i;
    iop_wtx* wtx;
} iop_output;

/** wallet transaction (wtx) functions */
LIBIOP_API iop_wtx* iop_wallet_wtx_new();
LIBIOP_API void iop_wallet_wtx_free(iop_wtx* wtx);
LIBIOP_API void iop_wallet_wtx_serialize(cstring* s, const iop_wtx* wtx);
LIBIOP_API iop_bool iop_wallet_wtx_deserialize(iop_wtx* wtx, struct const_buffer* buf);
/** ------------------------------------ */

/** wallet hdnode (wallet_hdnode) functions */
LIBIOP_API iop_wallet_hdnode* iop_wallet_hdnode_new();
LIBIOP_API void iop_wallet_hdnode_free(iop_wallet_hdnode* whdnode);
LIBIOP_API void iop_wallet_hdnode_serialize(cstring* s, const iop_chainparams *params, const iop_wallet_hdnode* whdnode);
LIBIOP_API iop_bool iop_wallet_hdnode_deserialize(iop_wallet_hdnode* whdnode, const iop_chainparams *params, struct const_buffer* buf);
/** ------------------------------------ */

/** wallet outputs (prev wtx + n) functions */
LIBIOP_API iop_output* iop_wallet_output_new();
LIBIOP_API void iop_wallet_output_free(iop_output* output);
/** ------------------------------------ */

LIBIOP_API iop_wallet* iop_wallet_new(const iop_chainparams *params);
LIBIOP_API void iop_wallet_free(iop_wallet* wallet);

/** load the wallet, sets masterkey, sets next_childindex */
LIBIOP_API iop_bool iop_wallet_load(iop_wallet* wallet, const char* file_path, int *error, iop_bool *created);

/** writes the wallet state to disk */
LIBIOP_API iop_bool iop_wallet_flush(iop_wallet* wallet);

/** set the master key of new created wallet
 consuming app needs to ensure that we don't override exiting masterkeys */
LIBIOP_API void iop_wallet_set_master_key_copy(iop_wallet* wallet, iop_hdnode* masterkey);

/** derives the next child hdnode (memory is owned by the wallet) */
LIBIOP_API iop_wallet_hdnode* iop_wallet_next_key(iop_wallet* wallet);

/** writes all available addresses (P2PKH) to the addr_out vector */
LIBIOP_API void iop_wallet_get_addresses(iop_wallet* wallet, vector* addr_out);

/** searches after a hdnode by given P2PKH (base58(hash160)) address */
LIBIOP_API iop_wallet_hdnode* iop_wallet_find_hdnode_byaddr(iop_wallet* wallet, const char* search_addr);

/** adds transaction to the wallet (hands over memory management) */
LIBIOP_API iop_bool iop_wallet_add_wtx_move(iop_wallet* wallet, iop_wtx* wtx);

/** looks if a key with the hash160 (SHA256/RIPEMD) exists */
LIBIOP_API iop_bool iop_wallet_have_key(iop_wallet* wallet, uint160 hash160);

/** gets credit from given transaction */
LIBIOP_API int64_t iop_wallet_get_balance(iop_wallet* wallet);

/** gets credit from given transaction */
LIBIOP_API int64_t iop_wallet_wtx_get_credit(iop_wallet* wallet, iop_wtx* wtx);

/** checks if a transaction outpoint is owned by the wallet */
LIBIOP_API iop_bool iop_wallet_txout_is_mine(iop_wallet* wallet, iop_tx_out* tx_out);

/** checks if a transaction outpoint is owned by the wallet */
LIBIOP_API void iop_wallet_add_to_spent(iop_wallet* wallet, iop_wtx* wtx);
LIBIOP_API iop_bool iop_wallet_is_spent(iop_wallet* wallet, uint256 hash, uint32_t n);
LIBIOP_API iop_bool iop_wallet_get_unspent(iop_wallet* wallet, vector* unspents);

/** checks a transaction or relevance to the wallet */
LIBIOP_API void iop_wallet_check_transaction(void *ctx, iop_tx *tx, unsigned int pos, iop_blockindex *pindex);

#ifdef __cplusplus
}
#endif

#endif //__LIBIOP_WALLET_H__
