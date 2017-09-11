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


#ifndef __LIBIOP_TX_H__
#define __LIBIOP_TX_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "iop.h"

#include "chainparams.h"
#include "cstr.h"
#include "hash.h"
#include "script.h"
#include "vector.h"


typedef struct iop_script_ {
    int* data;
    size_t limit;   // Total size of the vector
    size_t current; //Number of vectors in it at present
} iop_script;

typedef struct iop_tx_outpoint_ {
    uint256 hash;
    uint32_t n;
} iop_tx_outpoint;

typedef struct iop_tx_in_ {
    iop_tx_outpoint prevout;
    cstring* script_sig;
    uint32_t sequence;
} iop_tx_in;

typedef struct iop_tx_out_ {
    int64_t value;
    cstring* script_pubkey;
} iop_tx_out;

typedef struct iop_tx_ {
    int32_t version;
    vector* vin;
    vector* vout;
    uint32_t locktime;
} iop_tx;


//!create a new tx input
LIBIOP_API iop_tx_in* iop_tx_in_new();
LIBIOP_API void iop_tx_in_free(iop_tx_in* tx_in);
LIBIOP_API void iop_tx_in_copy(iop_tx_in* dest, const iop_tx_in* src);

//!create a new tx output
LIBIOP_API iop_tx_out* iop_tx_out_new();
LIBIOP_API void iop_tx_out_free(iop_tx_out* tx_out);
LIBIOP_API void iop_tx_out_copy(iop_tx_out* dest, const iop_tx_out* src);

//!create a new tx input
LIBIOP_API iop_tx* iop_tx_new();
LIBIOP_API void iop_tx_free(iop_tx* tx);
LIBIOP_API void iop_tx_copy(iop_tx* dest, const iop_tx* src);

//!deserialize/parse a p2p serialized iop transaction
LIBIOP_API int iop_tx_deserialize(const unsigned char* tx_serialized, size_t inlen, iop_tx* tx, size_t* consumed_length);

//!serialize a lbc iop data structure into a p2p serialized buffer
LIBIOP_API void iop_tx_serialize(cstring* s, const iop_tx* tx);

LIBIOP_API void iop_tx_hash(const iop_tx* tx, uint8_t* hashout);

LIBIOP_API iop_bool iop_tx_sighash(const iop_tx* tx_to, const cstring* fromPubKey, unsigned int in_num, int hashtype, uint8_t* hash);

LIBIOP_API iop_bool iop_tx_add_address_out(iop_tx* tx, const iop_chainparams* chain, int64_t amount, const char* address);
LIBIOP_API iop_bool iop_tx_add_p2sh_hash160_out(iop_tx* tx, int64_t amount, uint160 hash160);
LIBIOP_API iop_bool iop_tx_add_p2pkh_hash160_out(iop_tx* tx, int64_t amount, uint160 hash160);
LIBIOP_API iop_bool iop_tx_add_p2pkh_out(iop_tx* tx, int64_t amount, const iop_pubkey* pubkey);

LIBIOP_API iop_bool iop_tx_add_data_out(iop_tx* tx, const int64_t amount, const uint8_t *data, const size_t datalen);
LIBIOP_API iop_bool iop_tx_add_puzzle_out(iop_tx* tx, const int64_t amount, const uint8_t *puzzle, const size_t puzzlelen);

LIBIOP_API iop_bool iop_tx_outpoint_is_null(iop_tx_outpoint* tx);
LIBIOP_API iop_bool iop_tx_is_coinbase(iop_tx* tx);
#ifdef __cplusplus
}
#endif

#endif //__LIBIOP_TX_H__
