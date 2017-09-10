/*

 The MIT License (MIT)

 Copyright 2012 exMULTI, Inc.
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

#include <iop/script.h>

#include <assert.h>
#include <string.h>

#include <iop/buffer.h>
#include <iop/serialize.h>

iop_bool iop_script_copy_without_op_codeseperator(const cstring* script_in, cstring* script_out)
{
    if (script_in->len == 0)
        return false; /* EOF */

    struct const_buffer buf = {script_in->str, script_in->len};
    unsigned char opcode;
    while (buf.len > 0) {
        if (!deser_bytes(&opcode, &buf, 1))
            goto err_out;

        uint32_t data_len = 0;

        if (opcode < OP_PUSHDATA1 && opcode > OP_0) {
            data_len = opcode;
            cstr_append_buf(script_out, &opcode, 1);
        } else if (opcode == OP_PUSHDATA1) {
            uint8_t v8;
            if (!deser_bytes(&v8, &buf, 1))
                goto err_out;
            cstr_append_buf(script_out, &opcode, 1);
            cstr_append_buf(script_out, &v8, 1);
            data_len = v8;
        } else if (opcode == OP_PUSHDATA2) {
            uint16_t v16;
            if (!deser_u16(&v16, &buf))
                goto err_out;
            cstr_append_buf(script_out, &opcode, 1);
            cstr_append_buf(script_out, &v16, 2);
            data_len = v16;
        } else if (opcode == OP_PUSHDATA4) {
            uint32_t v32;
            if (!deser_u32(&v32, &buf))
                goto err_out;
            cstr_append_buf(script_out, &opcode, 1);
            cstr_append_buf(script_out, &v32, 5);
            data_len = v32;
        } else if (opcode == OP_CODESEPARATOR)
            continue;

        if (data_len > 0) {
            assert(data_len < 16777215); //limit max push to 0xFFFFFF
            unsigned char bufpush[data_len];
            deser_bytes(&bufpush, &buf, data_len);
            cstr_append_buf(script_out, &bufpush, data_len);
        } else
            cstr_append_buf(script_out, &opcode, 1);
    }

    return true;

err_out:
    return false;
}

iop_script_op* iop_script_op_new()
{
    iop_script_op* script_op;
    script_op = iop_calloc(1, sizeof(*script_op));

    return script_op;
}


void iop_script_op_free(iop_script_op* script_op)
{
    if (script_op->data) {
        iop_free(script_op->data);
        script_op->data = NULL;
    }
    script_op->datalen = 0;
    script_op->op = OP_0;
}

void iop_script_op_free_cb(void* data)
{
    iop_script_op* script_op = data;
    iop_script_op_free(script_op);

    iop_free(script_op);
}

iop_bool iop_script_get_ops(const cstring* script_in, vector* ops_out)
{
    if (script_in->len == 0)
        return false; /* EOF */

    struct const_buffer buf = {script_in->str, script_in->len};
    unsigned char opcode;

    iop_script_op* op = NULL;
    while (buf.len > 0) {
        op = iop_script_op_new();

        if (!deser_bytes(&opcode, &buf, 1))
            goto err_out;

        op->op = opcode;

        uint32_t data_len;

        if (opcode < OP_PUSHDATA1) {
            data_len = opcode;
        } else if (opcode == OP_PUSHDATA1) {
            uint8_t v8;
            if (!deser_bytes(&v8, &buf, 1))
                goto err_out;
            data_len = v8;
        } else if (opcode == OP_PUSHDATA2) {
            uint16_t v16;
            if (!deser_u16(&v16, &buf))
                goto err_out;
            data_len = v16;
        } else if (opcode == OP_PUSHDATA4) {
            uint32_t v32;
            if (!deser_u32(&v32, &buf))
                goto err_out;
            data_len = v32;
        } else {
            vector_add(ops_out, op);
            continue;
        }

        op->data = iop_calloc(1, data_len);
        memcpy(op->data, buf.p, data_len);
        op->datalen = data_len;

        vector_add(ops_out, op);

        if (!deser_skip(&buf, data_len))
            goto err_out;
    }

    return true;
err_out:
    iop_script_op_free(op);
    return false;
}

static inline iop_bool iop_script_is_pushdata(const enum opcodetype op)
{
    return (op <= OP_PUSHDATA4);
}

static iop_bool iop_script_is_op(const iop_script_op* op, enum opcodetype opcode)
{
    return (op->op == opcode);
}

static iop_bool iop_script_is_op_pubkey(const iop_script_op* op)
{
    if (!iop_script_is_pushdata(op->op))
        return false;
    if (op->datalen < 33 || op->datalen > 120)
        return false;
    return true;
}

static iop_bool iop_script_is_op_pubkeyhash(const iop_script_op* op)
{
    if (!iop_script_is_pushdata(op->op))
        return false;
    if (op->datalen != 20)
        return false;
    return true;
}

// OP_PUBKEY, OP_CHECKSIG
iop_bool iop_script_is_pubkey(const vector* ops)
{
    return ((ops->len == 2) &&
            iop_script_is_op(vector_idx(ops, 1), OP_CHECKSIG) &&
            iop_script_is_op_pubkey(vector_idx(ops, 0)));
}

// OP_DUP, OP_HASH160, OP_PUBKEYHASH, OP_EQUALVERIFY, OP_CHECKSIG,
iop_bool iop_script_is_pubkeyhash(const vector* ops, vector* data_out)
{
    if ((ops->len == 5) &&
        iop_script_is_op(vector_idx(ops, 0), OP_DUP) &&
        iop_script_is_op(vector_idx(ops, 1), OP_HASH160) &&
        iop_script_is_op_pubkeyhash(vector_idx(ops, 2)) &&
        iop_script_is_op(vector_idx(ops, 3), OP_EQUALVERIFY) &&
        iop_script_is_op(vector_idx(ops, 4), OP_CHECKSIG)) {
        if (data_out) {
            //copy the data (hash160) in case of a non empty vector
            const iop_script_op* op = vector_idx(ops, 2);
            uint8_t* buffer = iop_calloc(1, sizeof(uint160));
            memcpy(buffer, op->data, sizeof(uint160));
            vector_add(data_out, buffer);
        }
        return true;
    }
    return false;
}

// OP_HASH160, OP_PUBKEYHASH, OP_EQUAL
iop_bool iop_script_is_scripthash(const vector* ops)
{
    return ((ops->len == 3) &&
            iop_script_is_op(vector_idx(ops, 0), OP_HASH160) &&
            iop_script_is_op_pubkeyhash(vector_idx(ops, 1)) &&
            iop_script_is_op(vector_idx(ops, 2), OP_EQUAL));
}

static iop_bool iop_script_is_op_smallint(const iop_script_op* op)
{
    return ((op->op == OP_0) ||
            (op->op >= OP_1 && op->op <= OP_16));
}

iop_bool iop_script_is_multisig(const vector* ops)
{
    if ((ops->len < 3) || (ops->len > (16 + 3)) ||
        !iop_script_is_op_smallint(vector_idx(ops, 0)) ||
        !iop_script_is_op_smallint(vector_idx(ops, ops->len - 2)) ||
        !iop_script_is_op(vector_idx(ops, ops->len - 1), OP_CHECKMULTISIG))
        return false;

    unsigned int i;
    for (i = 1; i < (ops->len - 2); i++)
        if (!iop_script_is_op_pubkey(vector_idx(ops, i)))
            return false;

    return true;
}

enum iop_tx_out_type iop_script_classify_ops(const vector* ops)
{
    if (iop_script_is_pubkeyhash(ops, NULL))
        return IOP_TX_PUBKEYHASH;
    if (iop_script_is_scripthash(ops))
        return IOP_TX_SCRIPTHASH;
    if (iop_script_is_pubkey(ops))
        return IOP_TX_PUBKEY;
    if (iop_script_is_multisig(ops))
        return IOP_TX_MULTISIG;

    return IOP_TX_NONSTANDARD;
}

enum iop_tx_out_type iop_script_classify(const cstring* script, vector* data_out)
{
    //INFO: could be speed up by not forming a vector
    //      and directly parse the script cstring

    enum iop_tx_out_type tx_out_type = IOP_TX_NONSTANDARD;
    vector* ops = vector_new(10, iop_script_op_free_cb);
    iop_script_get_ops(script, ops);

    if (iop_script_is_pubkeyhash(ops, data_out))
        tx_out_type = IOP_TX_PUBKEYHASH;
    if (iop_script_is_scripthash(ops))
        tx_out_type = IOP_TX_SCRIPTHASH;
    if (iop_script_is_pubkey(ops))
        tx_out_type = IOP_TX_PUBKEY;
    if (iop_script_is_multisig(ops))
        tx_out_type = IOP_TX_MULTISIG;

    vector_free(ops, true);
    return tx_out_type;
}

iop_bool iop_script_extract_pkh(const cstring* script, uint8_t* data)
{
    // expected that data is a 20byte buffer

    iop_bool suc = false;

    vector* ops = vector_new(10, iop_script_op_free_cb);
    iop_script_get_ops(script, ops);
    iop_script_op* op = vector_idx(ops, 2);
    if (op && iop_script_is_op_pubkeyhash(op)) {
        memcpy(data, op->data, 20);
        suc = true;
    }
    vector_free(ops, true);
    return suc;
}

enum opcodetype iop_encode_op_n(const int n)
{
    assert(n >= 0 && n <= 16);
    if (n == 0)
        return OP_0;
    return (enum opcodetype)(OP_1 + n - 1);
}


void iop_script_append_op(cstring* script_in, enum opcodetype op)
{
    cstr_append_buf(script_in, &op, 1);
}


void iop_script_append_pushdata(cstring* script_in, const unsigned char* data, const size_t datalen)
{
    if (datalen < OP_PUSHDATA1) {
        cstr_append_buf(script_in, (unsigned char*)&datalen, 1);
    } else if (datalen <= 0xff) {
        iop_script_append_op(script_in, OP_PUSHDATA1);
        cstr_append_buf(script_in, (unsigned char*)&datalen, 1);
    } else if (datalen <= 0xffff) {
        iop_script_append_op(script_in, OP_PUSHDATA2);
        uint16_t v = htole16(datalen);
        cstr_append_buf(script_in, &v, sizeof(v));
    } else {
        iop_script_append_op(script_in, OP_PUSHDATA4);
        uint32_t v = htole32(datalen);
        cstr_append_buf(script_in, &v, sizeof(v));
    }
    cstr_append_buf(script_in, data, datalen);
}

iop_bool iop_script_build_multisig(cstring* script_in, const unsigned int required_signatures, const vector* pubkeys_chars)
{
    cstr_resize(script_in, 0); //clear script

    if (required_signatures > 16 || pubkeys_chars->len > 16)
        return false;
    enum opcodetype op_req_sig = iop_encode_op_n(required_signatures);
    cstr_append_buf(script_in, &op_req_sig, 1);

    int i;
    for (i = 0; i < (int)pubkeys_chars->len; i++) {
        iop_pubkey* pkey = pubkeys_chars->data[i];
        iop_script_append_pushdata(script_in, pkey->pubkey, (pkey->compressed ? IOP_ECKEY_COMPRESSED_LENGTH : IOP_ECKEY_UNCOMPRESSED_LENGTH));
    }

    enum opcodetype op_pub_len = iop_encode_op_n(pubkeys_chars->len);
    cstr_append_buf(script_in, &op_pub_len, 1);

    enum opcodetype op_checkmultisig = OP_CHECKMULTISIG;
    cstr_append_buf(script_in, &op_checkmultisig, 1);

    return true;
}

iop_bool iop_script_build_p2pkh(cstring* script_in, const uint160 hash160)
{
    cstr_resize(script_in, 0); //clear script

    iop_script_append_op(script_in, OP_DUP);
    iop_script_append_op(script_in, OP_HASH160);


    iop_script_append_pushdata(script_in, (unsigned char*)hash160, sizeof(uint160));
    iop_script_append_op(script_in, OP_EQUALVERIFY);
    iop_script_append_op(script_in, OP_CHECKSIG);

    return true;
}

iop_bool iop_script_build_p2sh(cstring* script_in, const uint160 hash160)
{
    cstr_resize(script_in, 0); //clear script
    iop_script_append_op(script_in, OP_HASH160);
    iop_script_append_pushdata(script_in, (unsigned char*)hash160, sizeof(uint160));
    iop_script_append_op(script_in, OP_EQUAL);

    return true;
}
