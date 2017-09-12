/**********************************************************************
 * Copyright (c) 2016 Jonas Schnelli                                  *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <iop/base58.h>
#include <iop/chainparams.h>
#include <iop/tool.h>

#include <iop/utils.h>

#include "utest.h"

void test_tool()
{
    char addr[100];
    u_assert_int_eq(address_from_pubkey(&iop_chainparams_main, "030ccbcfec9cc8a601f40d6c60a52cf5a0912a89bf05b39c49f7a48d67bf7bbc99", addr), true);
    u_assert_str_eq(addr, "p82Y2T7j69womoz1iFSubRAU8vtyCYLHzm");

    size_t pubkeylen = 100;
    char pubkey[pubkeylen];
    u_assert_int_eq(pubkey_from_privatekey(&iop_chainparams_main, "8GthpqVQmmMbGEW8x5Y22n47ufjghyNanAaAtdKrTNuaQ7tRmtwX", pubkey, &pubkeylen), true);
    u_assert_str_eq(pubkey, "030ccbcfec9cc8a601f40d6c60a52cf5a0912a89bf05b39c49f7a48d67bf7bbc99");

    size_t privkeywiflen = 100;
    char privkeywif[privkeywiflen];
    char privkeyhex[100];
    u_assert_int_eq(gen_privatekey(&iop_chainparams_main, privkeywif, privkeywiflen, NULL), true);
    u_assert_int_eq(gen_privatekey(&iop_chainparams_main, privkeywif, privkeywiflen, privkeyhex), true);

    uint8_t privkey_data[strlen(privkeywif)];
    size_t outlen = iop_base58_decode_check(privkeywif, privkey_data, sizeof(privkey_data));
    u_assert_int_eq(privkey_data[0] == iop_chainparams_main.b58prefix_secret_address, true);

    char privkey_hex_or_null[65];
    utils_bin_to_hex(privkey_data+1, IOP_ECKEY_PKEY_LENGTH, privkey_hex_or_null);
    u_assert_str_eq(privkeyhex,privkey_hex_or_null);

    size_t masterkeysize = 200;
    char masterkey[masterkeysize];
    u_assert_int_eq(hd_gen_master(&iop_chainparams_main, NULL, 32, masterkey, masterkeysize), true);
    u_assert_int_eq(hd_print_node(&iop_chainparams_main, masterkey), true);

    size_t extoutsize = 200;
    char extout[extoutsize];
    const char *privkey = "dywPw75G43VTMBbkZg4KynAZezAUnC5BTqnn93h2PRn36JZmMD95uyAHEFjqybT89FnEs39dUnGWY1GjEiNXz548BZURTVP2YGqrZH4d36wk7BAt";

    u_assert_int_eq(hd_derive(&iop_chainparams_main, privkey, "m/1", extout, extoutsize), true);
    u_assert_str_eq(extout, "dywPw77XU3CkfwCLahdLbAjT3xduXYKcsWBXDwckn4Y3dRGYAogppSRjpjAmjQQctDg8Yc75huNNbkDfYwDeCSDD3cjbvA8R4hWfkT878WKGapSy");

    u_assert_int_eq(hd_derive(&iop_chainparams_main, privkey, "m/1'", extout, extoutsize), true);
    u_assert_str_eq(extout, "dywPw77XU3CkpGrsYtXs4icKTrcVW3smk1kEgCcHuMiCsdBZEaM2qSTU7LNmCMszzeK2tZvR34ipDz5rNbimD3rKk1oQrrwtMAMir2CSgoMMNyDV");

    u_assert_int_eq(hd_derive(&iop_chainparams_main, "9PPHAFG6zkbkpX856Z4MctZHew9p2dtAqZGFBbGpCrEjDUbuDQ2m1t2rHKQe1VbwDvfxPXMAFPFtMFc58BioVGHwjKuTUWwFVZ3HRXwrWTwtc237", "m/1", extout, extoutsize), true);

    u_assert_int_eq(hd_derive(&iop_chainparams_main, privkey, "m/", extout, extoutsize), true);
    u_assert_str_eq(extout, privkey);

    u_assert_int_eq(hd_derive(&iop_chainparams_main, privkey, "m", extout, extoutsize), false);
    u_assert_int_eq(hd_derive(&iop_chainparams_main, privkey, "n/1", extout, extoutsize), false);
}
