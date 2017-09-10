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

#include <iop/base58.h>
#include <iop/blockchain.h>
#include <iop/serialize.h>
#include <iop/wallet.h>
#include <iop/utils.h>

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <search.h>

#define COINBASE_MATURITY 100

uint8_t WALLET_DB_REC_TYPE_MASTERKEY = 0;
uint8_t WALLET_DB_REC_TYPE_PUBKEYCACHE = 1;
uint8_t WALLET_DB_REC_TYPE_TX = 2;

static const unsigned char file_hdr_magic[4] = {0xA8, 0xF0, 0x11, 0xC5}; /* header magic */
static const uint32_t current_version = 1;

static const char* hdkey_key = "hdkey";
static const char* hdmasterkey_key = "mstkey";
static const char* tx_key = "tx";


/* ====================== */
/* compare btree callback */
/* ====================== */
int iop_wallet_hdnode_compare(const void *l, const void *r)
{
    const iop_wallet_hdnode *lm = l;
    const iop_wallet_hdnode *lr = r;

    uint8_t *pubkeyA = (uint8_t *)lm->pubkeyhash;
    uint8_t *pubkeyB = (uint8_t *)lr->pubkeyhash;

    /* byte per byte compare */
    /* TODO: switch to memcmp */
    for (unsigned int i = 0; i < sizeof(uint160); i++) {
        uint8_t iA = pubkeyA[i];
        uint8_t iB = pubkeyB[i];
        if (iA > iB)
            return -1;
        else if (iA < iB)
            return 1;
    }

    return 0;
}

int iop_wtx_compare(const void *l, const void *r)
{
    const iop_wtx *lm = l;
    const iop_wtx *lr = r;

    uint8_t *hashA = (uint8_t *)lm->tx_hash_cache;
    uint8_t *hashB = (uint8_t *)lr->tx_hash_cache;

    /* byte per byte compare */
    for (unsigned int i = 0; i < sizeof(uint256); i++) {
        uint8_t iA = hashA[i];
        uint8_t iB = hashB[i];
        if (iA > iB)
            return -1;
        else if (iA < iB)
            return 1;
    }

    return 0;
}


/*
 ==========================================================
 WALLET TRANSACTION (WTX) FUNCTIONS
 ==========================================================
*/

iop_wtx* iop_wallet_wtx_new()
{
    iop_wtx* wtx;
    wtx = iop_calloc(1, sizeof(*wtx));
    wtx->height = 0;
    wtx->tx = iop_tx_new();

    return wtx;
}

iop_wtx* iop_wallet_wtx_copy(iop_wtx* wtx)
{
    iop_wtx* wtx_copy;
    wtx_copy = iop_wallet_wtx_new();
    iop_tx_copy(wtx_copy->tx, wtx->tx);

    return wtx_copy;
}

void iop_wallet_wtx_free(iop_wtx* wtx)
{
    iop_tx_free(wtx->tx);
    iop_free(wtx);
}

void iop_wallet_wtx_serialize(cstring* s, const iop_wtx* wtx)
{
    ser_u32(s, wtx->height);
    ser_u256(s, wtx->tx_hash_cache);
    iop_tx_serialize(s, wtx->tx);
}

iop_bool iop_wallet_wtx_deserialize(iop_wtx* wtx, struct const_buffer* buf)
{
    deser_u32(&wtx->height, buf);
    deser_u256(wtx->tx_hash_cache, buf);
    return iop_tx_deserialize(buf->p, buf->len, wtx->tx, NULL);
}

/*
 ==========================================================
 WALLET HDNODE (WALLET_HDNODE) FUNCTIONS
 ==========================================================
*/

iop_wallet_hdnode* iop_wallet_hdnode_new()
{
    iop_wallet_hdnode* whdnode;
    whdnode = iop_calloc(1, sizeof(*whdnode));
    whdnode->hdnode = iop_hdnode_new();

    return whdnode;
}
void iop_wallet_hdnode_free(iop_wallet_hdnode* whdnode)
{
    iop_hdnode_free(whdnode->hdnode);
    iop_free(whdnode);
}

void iop_wallet_hdnode_serialize(cstring* s, const iop_chainparams *params, const iop_wallet_hdnode* whdnode)
{
    ser_bytes(s, whdnode->pubkeyhash, sizeof(uint160));
    char strbuf[196];
    iop_hdnode_serialize_private(whdnode->hdnode, params, strbuf, sizeof(strbuf));
    ser_str(s, strbuf, sizeof(strbuf));
}

iop_bool iop_wallet_hdnode_deserialize(iop_wallet_hdnode* whdnode, const iop_chainparams *params, struct const_buffer* buf) {
    deser_bytes(&whdnode->pubkeyhash, buf, sizeof(uint160));
    char strbuf[196];
    if (!deser_str(strbuf, buf, sizeof(strbuf))) return false;
    if (!iop_hdnode_deserialize(strbuf, params, whdnode->hdnode)) return false;
    return true;
}

/*
 ==========================================================
 WALLET OUTPUT (prev wtx + n) FUNCTIONS
 ==========================================================
 */

iop_output* iop_wallet_output_new()
{
    iop_output* output;
    output = iop_calloc(1, sizeof(*output));
    output->i = 0;
    output->wtx = iop_wallet_wtx_new();

    return output;
}

void iop_wallet_output_free(iop_output* output)
{
    iop_wallet_wtx_free(output->wtx);
    iop_free(output);
}

/*
 ==========================================================
 WALLET CORE FUNCTIONS
 ==========================================================
 */
iop_wallet* iop_wallet_new(const iop_chainparams *params)
{
    iop_wallet* wallet;
    wallet = iop_calloc(1, sizeof(*wallet));
    wallet->masterkey = NULL;
    wallet->chain = params;
    wallet->spends = vector_new(10, free);

    wallet->wtxes_rbtree = 0;
    wallet->hdkeys_rbtree = 0;
    return wallet;
}

void iop_wallet_free(iop_wallet* wallet)
{
    if (!wallet)
        return;

    if (wallet->dbfile) {
        fclose(wallet->dbfile);
        wallet->dbfile = NULL;
    }

    if (wallet->spends) {
        vector_free(wallet->spends, true);
        wallet->spends = NULL;
    }

    if (wallet->masterkey)
        iop_free(wallet->masterkey);

    iop_btree_tdestroy(wallet->wtxes_rbtree, iop_free);
    iop_btree_tdestroy(wallet->hdkeys_rbtree, iop_free);

    iop_free(wallet);
}

//void iop_wallet_logdb_append_cb(void* ctx, logdb_bool load_phase, logdb_record* rec)
//{
//    iop_wallet* wallet = (iop_wallet*)ctx;
//    if (load_phase) {
//        if (wallet->masterkey == NULL && rec->mode == RECORD_TYPE_WRITE && rec->key->len > strlen(hdmasterkey_key) && memcmp(rec->key->str, hdmasterkey_key, strlen(hdmasterkey_key)) == 0) {
//            wallet->masterkey = iop_hdnode_new();
//            iop_hdnode_deserialize(rec->value->str, wallet->chain, wallet->masterkey);
//        }
//        if (rec->key->len == strlen(hdkey_key) + sizeof(uint160) && memcmp(rec->key->str, hdkey_key, strlen(hdkey_key)) == 0) {
//            iop_hdnode* hdnode = iop_hdnode_new();
//            iop_hdnode_deserialize(rec->value->str, wallet->chain, hdnode);

//            /* rip out the hash from the record key (avoid re-SHA256) */
//            cstring* keyhash160 = cstr_new_buf(rec->key->str + strlen(hdkey_key), sizeof(uint160));

//            /* add hdnode to the rbtree */
//            RBTreeInsert(wallet->hdkeys_rbtree, keyhash160, hdnode);

//            if (hdnode->child_num + 1 > wallet->next_childindex)
//                wallet->next_childindex = hdnode->child_num + 1;
//        }

//        if (rec->key->len == strlen(tx_key) + SHA256_DIGEST_LENGTH && memcmp(rec->key->str, tx_key, strlen(tx_key)) == 0) {
//            iop_wtx* wtx = iop_wallet_wtx_new();
//            struct const_buffer buf = {rec->value->str, rec->value->len};

//            /* deserialize transaction */
//            iop_wallet_wtx_deserialize(wtx, &buf);

//            /* rip out the hash from the record key (avoid re-SHA256) */
//            cstring* wtxhash = cstr_new_buf(rec->key->str + strlen(tx_key), SHA256_DIGEST_LENGTH);

//            /* add wtx to the rbtree */
//            RBTreeInsert(wallet->wtxes_rbtree, wtxhash, wtx);

//            /* add to spends */
//            iop_wallet_add_to_spent(wallet, wtx);
//        }
//    }
//}

iop_bool iop_wallet_load(iop_wallet* wallet, const char* file_path, int *error, iop_bool *created)
{
    (void)(error);
    if (!wallet)
        return false;

    struct stat buffer;
    *created = true;
    if (stat(file_path, &buffer) == 0)
        *created = false;

    wallet->dbfile = fopen(file_path, *created ? "a+b" : "r+b");

    if (*created) {
        // write file-header-magic
        if (fwrite(file_hdr_magic, 4, 1, wallet->dbfile ) != 1 ) return false;

        // write version
        uint32_t v = htole32(current_version);
        if (fwrite(&v, sizeof(v), 1, wallet->dbfile ) != 1) return false;

        // write genesis
        if (fwrite(wallet->chain->genesisblockhash, sizeof(uint256), 1, wallet->dbfile ) != 1) return false;

        iop_file_commit(wallet->dbfile);
    }
    else {
        // check file-header-magic, version and genesis
        uint8_t buf[sizeof(file_hdr_magic)+sizeof(current_version)+sizeof(uint256)];
        if ( (uint32_t)buffer.st_size < (uint32_t)(sizeof(buf)) ||
             fread(buf, sizeof(buf), 1, wallet->dbfile ) != 1 ||
             memcmp(buf, file_hdr_magic, sizeof(file_hdr_magic))
            )
        {
            fprintf(stderr, "Wallet file: error reading database file\n");
            return false;
        }
        if (le32toh(*(buf+sizeof(file_hdr_magic))) > current_version) {
            fprintf(stderr, "Wallet file: unsupported file version\n");
            return false;
        }
        if (memcmp(buf+sizeof(file_hdr_magic)+sizeof(current_version), wallet->chain->genesisblockhash, sizeof(uint256)) != 0) {
            fprintf(stderr, "Wallet file: different network\n");
            return false;
        }
        // read

        while (!feof(wallet->dbfile))
        {
            uint8_t rectype;
            if (fread(&rectype, 1, 1, wallet->dbfile ) != 1) {
                // no more record, break
                break;
            }

            if (rectype == WALLET_DB_REC_TYPE_MASTERKEY) {
                uint32_t len;
                char strbuf[196];
                if (!deser_varlen_from_file(&len, wallet->dbfile)) return false;
                if (len > sizeof(strbuf)) { return false; }
                if (fread(strbuf, len, 1, wallet->dbfile ) != 1) return false;
                size_t test = strlen(strbuf);
                wallet->masterkey = iop_hdnode_new();
                printf("xpriv: %s\n", strbuf);
                iop_hdnode_deserialize(strbuf, wallet->chain, wallet->masterkey );
                int i = 0;
            }

            if (rectype == WALLET_DB_REC_TYPE_PUBKEYCACHE) {
                uint32_t len;

                iop_wallet_hdnode *whdnode = iop_wallet_hdnode_new();
                if (fread(whdnode->pubkeyhash, sizeof(uint160), 1, wallet->dbfile ) != 1) {
                    iop_wallet_hdnode_free(whdnode);
                    return false;
                }

                // read the varint for the stringlength
                char strbuf[1024];
                if (!deser_varlen_from_file(&len, wallet->dbfile)) {
                    iop_wallet_hdnode_free(whdnode);
                    return false;
                }
                if (len > sizeof(strbuf)) { return false; }
                if (fread(strbuf, len, 1, wallet->dbfile ) != 1) {
                    iop_wallet_hdnode_free(whdnode);
                    return false;
                }
                // deserialize the hdnode
                if (!iop_hdnode_deserialize(strbuf, wallet->chain, whdnode->hdnode)) {
                    iop_wallet_hdnode_free(whdnode);
                    return false;
                }

                // add the node to the binary tree
                iop_wallet_hdnode* checknode = tsearch(whdnode, &wallet->hdkeys_rbtree, iop_wallet_hdnode_compare);

            }
        }
    }

    return true;
}

iop_bool iop_wallet_flush(iop_wallet* wallet)
{
    iop_file_commit(wallet->dbfile);
    return true;
}

void iop_wallet_set_master_key_copy(iop_wallet* wallet, iop_hdnode* masterkey)
{
    if (!masterkey)
        return;

    if (wallet->masterkey != NULL) {
        //changing the master key should not be done,...
        //anyways, we are going to accept that at this point
        //consuming application needs to take care about that
        iop_hdnode_free(wallet->masterkey);
        wallet->masterkey = NULL;
    }
    wallet->masterkey = iop_hdnode_copy(masterkey);

    cstring* record = cstr_new_sz(256);
    ser_bytes(record, &WALLET_DB_REC_TYPE_MASTERKEY, 1);
    char strbuf[196];
    iop_hdnode_serialize_private(wallet->masterkey, wallet->chain, strbuf, sizeof(strbuf));
    printf("xpriv: %s\n", strbuf);
    ser_str(record, strbuf, sizeof(strbuf));

    if ( fwrite(record->str, record->len, 1, wallet->dbfile) != 1 ) {
        fprintf(stderr, "Writing master private key record failed\n");
    }
    cstr_free(record, true);

    iop_file_commit(wallet->dbfile);
}

iop_wallet_hdnode* iop_wallet_next_key(iop_wallet* wallet)
{
    if (!wallet || !wallet->masterkey)
        return NULL;

    //for now, only m/k is possible
    iop_wallet_hdnode *whdnode = iop_wallet_hdnode_new();
    iop_hdnode_free(whdnode->hdnode);
    whdnode->hdnode = iop_hdnode_copy(wallet->masterkey);
    iop_hdnode_private_ckd(whdnode->hdnode, wallet->next_childindex);
    iop_hdnode_get_hash160(whdnode->hdnode, whdnode->pubkeyhash);

    //add it to the binary tree
    // tree manages memory
    iop_wallet_hdnode* checknode = tsearch(whdnode, &wallet->hdkeys_rbtree, iop_wallet_hdnode_compare);

    //serialize and store node
    cstring* record = cstr_new_sz(256);
    ser_bytes(record, &WALLET_DB_REC_TYPE_PUBKEYCACHE, 1);
    iop_wallet_hdnode_serialize(record, wallet->chain, whdnode);

    if (fwrite(record->str, record->len, 1, wallet->dbfile) != 1) {
        fprintf(stderr, "Writing childkey failed\n");
    }
    cstr_free(record, true);

    iop_file_commit(wallet->dbfile);

    //increase the in-memory counter (cache)
    wallet->next_childindex++;

    return whdnode;
}

void iop_wallet_get_addresses(iop_wallet* wallet, vector* addr_out)
{
    (void)(wallet);
    (void)(addr_out);
//    rb_red_blk_node* hdkey_rbtree_node;

//    if (!wallet)
//        return;

//    while ((hdkey_rbtree_node = rbtree_enumerate_next(wallet->hdkeys_rbtree))) {
//        cstring* key = hdkey_rbtree_node->key;
//        uint8_t hash160[sizeof(uint160)+1];
//        hash160[0] = wallet->chain->b58prefix_pubkey_address;
//        memcpy(hash160 + 1, key->str, sizeof(uint160));

//        size_t addrsize = 98;
//        char* addr = iop_calloc(1, addrsize);
//        iop_base58_encode_check(hash160, sizeof(uint160)+1, addr, addrsize);
//        vector_add(addr_out, addr);
//    }
}

iop_wallet_hdnode* iop_wallet_find_hdnode_byaddr(iop_wallet* wallet, const char* search_addr)
{
    if (!wallet || !search_addr)
        return NULL;

    uint8_t hashdata[strlen(search_addr)];
    memset(hashdata, 0, sizeof(uint160));
    int outlen = iop_base58_decode_check(search_addr, hashdata, strlen(search_addr));
    if (outlen == 0) {
        return NULL;
    }

    iop_wallet_hdnode* whdnode_search;
    whdnode_search = iop_calloc(1, sizeof(*whdnode_search));
    memcpy(whdnode_search->pubkeyhash, hashdata+1, sizeof(uint160));

    iop_wallet_hdnode *needle = tfind(whdnode_search, &wallet->hdkeys_rbtree, iop_wallet_hdnode_compare); /* read */
    if (needle) {
        needle = *(iop_wallet_hdnode **)needle;
    }
    iop_free(whdnode_search);

    return needle;
}

iop_bool iop_wallet_add_wtx_move(iop_wallet* wallet, iop_wtx* wtx)
{
    if (!wallet || !wtx)
        return false;

    cstring* record = cstr_new_sz(1024);
    ser_bytes(record, &WALLET_DB_REC_TYPE_TX, 1);
    iop_wallet_wtx_serialize(record, wtx);

    if (fwrite(record->str, record->len, 1, wallet->dbfile) ) {
        fprintf(stderr, "Writing master private key record failed\n");
    }
    cstr_free(record, true);

    //add to spends
    iop_wallet_add_to_spent(wallet, wtx);

    //add it to the binary tree
    iop_wtx* checkwtx = tsearch(wtx, &wallet->wtxes_rbtree, iop_wtx_compare);
    if (checkwtx) {
        // remove existing wtx
        checkwtx = *(iop_wtx **)checkwtx;
        tdelete(checkwtx, &wallet->wtxes_rbtree, iop_wtx_compare);
        iop_wallet_wtx_free(checkwtx);

        // insert again
        iop_wtx* checkwtx = tsearch(wtx, &wallet->wtxes_rbtree, iop_wtx_compare);
    }


    return true;
}

iop_bool iop_wallet_have_key(iop_wallet* wallet, uint160 hash160)
{
    if (!wallet)
        return false;

    iop_wallet_hdnode* whdnode_search;
    whdnode_search = iop_calloc(1, sizeof(*whdnode_search));
    memcpy(whdnode_search->pubkeyhash, hash160, sizeof(uint160));

    iop_wallet_hdnode *needle = tfind(whdnode_search, &wallet->hdkeys_rbtree, iop_wallet_hdnode_compare); /* read */
    if (needle) {
        needle = *(iop_wallet_hdnode **)needle;
    }
    iop_free(whdnode_search);

    return (needle != NULL);
}

int64_t iop_wallet_get_balance(iop_wallet* wallet)
{
    int64_t credit = 0;

    if (!wallet)
        return false;

//    // enumerate over the rbtree, calculate balance
//    while ((hdkey_rbtree_node = rbtree_enumerate_next(wallet->wtxes_rbtree))) {
//        iop_wtx* wtx = hdkey_rbtree_node->info;
//        credit += iop_wallet_wtx_get_credit(wallet, wtx);
//    }

    return credit;
}

int64_t iop_wallet_wtx_get_credit(iop_wallet* wallet, iop_wtx* wtx)
{
    int64_t credit = 0;

    if (iop_tx_is_coinbase(wtx->tx) &&
        (wallet->bestblockheight < COINBASE_MATURITY || wtx->height > wallet->bestblockheight - COINBASE_MATURITY))
        return credit;

    uint256 hash;
    iop_tx_hash(wtx->tx, hash);
    unsigned int i = 0;
    if (wtx->tx->vout) {
        for (i = 0; i < wtx->tx->vout->len; i++) {
            iop_tx_out* tx_out;
            tx_out = vector_idx(wtx->tx->vout, i);

            if (!iop_wallet_is_spent(wallet, hash, i)) {
                if (iop_wallet_txout_is_mine(wallet, tx_out))
                    credit += tx_out->value;
            }
        }
    }
    return credit;
}

iop_bool iop_wallet_txout_is_mine(iop_wallet* wallet, iop_tx_out* tx_out)
{
    if (!wallet || !tx_out) return false;

    iop_bool ismine = false;

    vector* vec = vector_new(16, free);
    enum iop_tx_out_type type2 = iop_script_classify(tx_out->script_pubkey, vec);

    //TODO: Multisig, etc.
    if (type2 == IOP_TX_PUBKEYHASH) {
        //TODO: find a better format for vector elements (not a pure pointer)
        uint8_t* hash160 = vector_idx(vec, 0);
        if (iop_wallet_have_key(wallet, hash160))
            ismine = true;
    }

    vector_free(vec, true);

    return ismine;
}

iop_bool iop_wallet_is_mine(iop_wallet* wallet, const iop_tx *tx)
{
    if (!wallet || !tx) return false;
    if (tx->vout) {
        for (unsigned int i = 0; i < tx->vout->len; i++) {
            iop_tx_out* tx_out = vector_idx(tx->vout, i);
            if (tx_out && iop_wallet_txout_is_mine(wallet, tx_out)) {
                return true;
            }
        }
    }
    return false;
}

int64_t iop_wallet_get_debit_txi(iop_wallet *wallet, const iop_tx_in *txin) {
    if (!wallet || !txin) return 0;

    iop_wtx wtx;
    memcpy(wtx.tx_hash_cache, txin->prevout.hash, sizeof(wtx.tx_hash_cache));

    iop_wtx* checkwtx = tfind(&wtx, &wallet->wtxes_rbtree, iop_wtx_compare);
    if (checkwtx) {
        // remove existing wtx
        checkwtx = *(iop_wtx **)checkwtx;
        //todo get debig
    }

    return 0;
}

int64_t iop_wallet_get_debit_tx(iop_wallet *wallet, const iop_tx *tx) {
    int64_t debit = 0;
    if (tx->vin) {
        for (unsigned int i = 0; i < tx->vin->len; i++) {
            iop_tx_in* tx_in= vector_idx(tx->vin, i);
            if (tx_in) {
                debit += iop_wallet_get_debit_txi(wallet, tx_in);
            }
        }
    }
    return debit;
}

iop_bool iop_wallet_is_from_me(iop_wallet *wallet, const iop_tx *tx)
{
    return (iop_wallet_get_debit_tx(wallet, tx) > 0);
}

void iop_wallet_add_to_spent(iop_wallet* wallet, iop_wtx* wtx) {
    if (!wallet || !wtx)
        return;

    if (iop_tx_is_coinbase(wtx->tx))
        return;

    unsigned int i = 0;
    if (wtx->tx->vin) {
        for (i = 0; i < wtx->tx->vin->len; i++) {
            iop_tx_in* tx_in = vector_idx(wtx->tx->vin, i);

            //add to spends
            iop_tx_outpoint* outpoint = iop_calloc(1, sizeof(iop_tx_outpoint));
            memcpy(outpoint, &tx_in->prevout, sizeof(iop_tx_outpoint));
            vector_add(wallet->spends, outpoint);
        }
    }
}

iop_bool iop_wallet_is_spent(iop_wallet* wallet, uint256 hash, uint32_t n)
{
    if (!wallet)
        return false;

    unsigned int i = 0;
    for (i = wallet->spends->len; i > 0; i--) {
        iop_tx_outpoint* outpoint = vector_idx(wallet->spends, i - 1);
        if (memcmp(outpoint->hash, hash, IOP_HASH_LENGTH) == 0 && n == outpoint->n)
            return true;
    }
    return false;
}

iop_bool iop_wallet_get_unspent(iop_wallet* wallet, vector* unspents)
{
    (void)(wallet);
    (void)(unspents);
    return true;
//    rb_red_blk_node* hdkey_rbtree_node;

//    if (!wallet)
//        return false;

//    while ((hdkey_rbtree_node = rbtree_enumerate_next(wallet->wtxes_rbtree))) {
//        iop_wtx* wtx = hdkey_rbtree_node->info;
//        cstring* key = hdkey_rbtree_node->key;
//        uint8_t* hash = (uint8_t*)key->str;

//        unsigned int i = 0;
//        if (wtx->tx->vout) {
//            for (i = 0; i < wtx->tx->vout->len; i++) {
//                iop_tx_out* tx_out;
//                tx_out = vector_idx(wtx->tx->vout, i);

//                if (!iop_wallet_is_spent(wallet, hash, i)) {
//                    if (iop_wallet_txout_is_mine(wallet, tx_out)) {
//                        iop_output* output = iop_wallet_output_new();
//                        iop_wallet_wtx_free(output->wtx);
//                        output->wtx = iop_wallet_wtx_copy(wtx);
//                        output->i = i;
//                        vector_add(unspents, output);
//                    }
//                }
//            }
//        }
//    }

//    return true;
}

void iop_wallet_check_transaction(void *ctx, iop_tx *tx, unsigned int pos, iop_blockindex *pindex) {
    (void)(pos);
    (void)(pindex);
    iop_wallet *wallet = (iop_wallet *)ctx;
    if (iop_wallet_is_mine(wallet, tx) || iop_wallet_is_from_me(wallet, tx)) {
        int i = 0;
        printf("\nFound relevant transaction!\n");
    }
}
