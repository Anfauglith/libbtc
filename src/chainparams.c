/*

 The MIT License (MIT)

 Copyright (c) 2017 Jonas Schnelli

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

#include <btc/chainparams.h>

const btc_chainparams btc_chainparams_main = {
    "main",
    0x75, // base58Prefixes[PUBKEY_ADDRESS] 
    0xA4, // base58Prefixes[SCRIPT_ADDRESS] 
    0x31, // base58Prefixes[SECRET_KEY] 
    0xAE3416F6, // base58Prefixes[SECRET_KEY] 
    0x2780915F, // base58Prefixes[EXT_PUBLIC_KEY] 
    {0xfd, 0xb0, 0xbb, 0xd3}, // pchMessageStart 
    {0xb3,0x2d,0xc8,0xb6,0xbf,0x41,0x2c,0xf7,0x1a,0xbb,0x8d,0x43,0x33,0x49,0xf1,0x6a,0x77,0xe0,0x64,0xbe,0xe8,0x9b,0xcb,0x56,0xe5,0x2e,0x5f,0xbf,0x00,0x00,0x00,0x00}, // hashGenesisBlock 
    4877,
    {{"mainnet.iop.cash"}, 0},
    0x03,
    "tx", false
};
const btc_chainparams btc_chainparams_test = {
    "testnet3",
    0x82, // base58Prefixes[PUBKEY_ADDRESS] 
    0x31, // base58Prefixes[SCRIPT_ADDRESS] 
    0x4c, // base58Prefixes[SECRET_KEY] 
    0x2B7FA42A, // base58Prefixes[SECRET_KEY] 
    0xBB8F4852, // base58Prefixes[EXT_PUBLIC_KEY] 
    {0xb1, 0xfc, 0x50, 0xb3}, // pchMessageStart 
    {0xa3,0xf3,0xd7,0x18,0x20,0xea,0x72,0x60,0x9c,0x0b,0xa9,0x99,0xe5,0x77,0x40,0x31,0x20,0xe5,0xbe,0x4f,0x4f,0xda,0x0c,0x23,0x63,0xb8,0x2b,0x6f,0x00,0x00,0x00,0x00}, // hashGenesisBlock 
    7475,
    {{"testnet.iop.cash"}, 0},
    0x06,
    "txtest", true
};
const btc_chainparams btc_chainparams_regtest = {
    "regtest",
    0x82, // base58Prefixes[PUBKEY_ADDRESS] 
    0x31, // base58Prefixes[SCRIPT_ADDRESS] 
    0x4c, // base58Prefixes[SECRET_KEY] 
    0x2B7FA42A, // base58Prefixes[EXT_SECRET_KEY] 
    0xBB8F4852, // base58Prefixes[EXT_PUBLIC_KEY] 
    {0x35, 0xb2, 0xcc, 0x9e}, // pchMessageStart 
    {0xb5,0xb8,0x71,0x45,0xe5,0xfc,0x1b,0x8c,0x23,0x1f,0x9f,0x9d,0x54,0x1e,0x9d,0x2b,0x60,0xae,0x44,0x4b,0xb2,0x4a,0xae,0xc3,0xee,0x56,0x36,0x4b,0xaa,0x5b,0xac,0x13}, // hashGenesisBlock 
    14877,
    {0},
    0x06,
    "txtest", true
};


const iop_checkpoint iop_mainnet_checkpoint_array[] = {
    {     0, "00000000bf5f2ee556cb9be8be64e0776af14933438dbb1af72c41bfb6c82db3", 1463452181, 0x1d00ffff},
    { 20000, "000000000205ce279aed9220fbac67f6f7a863f898f98ef0cdeae863e2d19bc1", 1484149380, 0x1c0bc873},
    { 47654, "00000000118494c6822e81f33ef08f074991a76fbae32425482a6bfecc26ec0a", 1502262660, 0x1c123f62}};
