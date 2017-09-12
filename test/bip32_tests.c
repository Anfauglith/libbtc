/**********************************************************************
 * Copyright (c) 2015 Jonas Schnelli                                  *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <iop/bip32.h>

#include "utest.h"
#include <iop/utils.h>

void test_bip32()
{
    iop_hdnode node, node2, node3, node4;
    char str[113];
    int r;
    uint8_t private_key_master[32];
    uint8_t chain_code_master[32];

    /* init m */
    iop_hdnode_from_seed(utils_hex_to_uint8("000102030405060708090a0b0c0d0e0f"), 16, &node);
    //printf("chain code: %s\n", utils_uint8_to_hex(node.chain_code,32)); 
    //printf("priv key: %s\n", utils_uint8_to_hex(node.private_key,32)); 
    //printf("pub key: %s\n", utils_uint8_to_hex(node.public_key,33)); 
    /* [Chain m] */
    memcpy(private_key_master,
           utils_hex_to_uint8("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"),
           32);
    memcpy(chain_code_master,
           utils_hex_to_uint8("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"),
           32);
    u_assert_int_eq(node.fingerprint, 0x00000000);
    u_assert_mem_eq(node.chain_code, chain_code_master, 32);
    u_assert_mem_eq(node.private_key, private_key_master, 32);
    u_assert_mem_eq(node.public_key,
                    utils_hex_to_uint8("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"),
                    33);    
    iop_hdnode_serialize_private(&node, &iop_chainparams_main, str, sizeof(str));
    //printf("%s\n",str);
    u_assert_str_eq(str,
        "dywPw75G43VTMBbkZg4KynAZezAUnC5BTqnn93h2PRn36JZmMD95uyAHEFjqybT89FnEs39dUnGWY1GjEiNXz548BZURTVP2YGqrZH4d36wk7BAt");
    r = iop_hdnode_deserialize(str, &iop_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    u_assert_mem_eq(&node, &node2, sizeof(iop_hdnode));

    iop_hdnode_get_p2pkh_address(&node, &iop_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str, "pAJtXHuMsyEDCHR2axbggc4EebDfBx7xtz");

    iop_hdnode_serialize_public(&node, &iop_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "9PPHAFDqaktTVmXV5XVM1VzQFxgPHHdjRtsW6hM5pDUigMu8PoV27QmPgqyiFgckwv8vEzPRj261iGCfxbpKbdJxcZXBVmfRvYuvr2dwq2VgUYm3");
    r = iop_hdnode_deserialize(str, &iop_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    memcpy(&node3, &node, sizeof(iop_hdnode));
    memset(&node3.private_key, 0, 32);
    u_assert_mem_eq(&node2, &node3, sizeof(iop_hdnode));


    /* [Chain m/0'] */
    char path0[] = "m/0'";
    iop_hd_generate_key(&node, path0, private_key_master, chain_code_master, false);
    u_assert_int_eq(node.fingerprint, 0x3442193e);
    u_assert_mem_eq(node.chain_code,
                    utils_hex_to_uint8("47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"),
                    32);
    u_assert_mem_eq(node.private_key,
                    utils_hex_to_uint8("edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"),
                    32);
    u_assert_mem_eq(node.public_key,
                    utils_hex_to_uint8("035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56"),
                    33);
    iop_hdnode_serialize_private(&node, &iop_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "dywPw77XU3CkpGrsYpfTgyvSHsCatWtjpDsG9jJTHPsRDGkxdaRP6PPpKNtCPNiUUfVcpkCXB9ZqQPda7S8ZhieQNMYVyZFhgWoZSz5FtXzvb7TD");
    r = iop_hdnode_deserialize(str, &iop_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    u_assert_mem_eq(&node, &node2, sizeof(iop_hdnode));

    iop_hdnode_get_p2pkh_address(&node, &iop_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str, "pDwbiWJnmYec8qasZQ6cJ1CjQXjCCrK12L");

    iop_hdnode_serialize_public(&node, &iop_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "9PPHAFG6zkbkxrnc4g6UihkGtqiVPcTHnGwz7NxWiBa6oL6KgAmKHpzvmy84fTtKefSpmzbiHtKZ8zqk3aDHjaLgzdQeDyJEBUDq4Ya5PL3ZMKxA");
    r = iop_hdnode_deserialize(str, &iop_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    memcpy(&node3, &node, sizeof(iop_hdnode));
    memset(&node3.private_key, 0, 32);
    u_assert_mem_eq(&node2, &node3, sizeof(iop_hdnode));


    /* [Chain m/0'/1] */
    char path1[] = "m/0'/1";
    iop_hd_generate_key(&node, path1, private_key_master, chain_code_master, false);
    u_assert_int_eq(node.fingerprint, 0x5c1bd648);
    u_assert_mem_eq(node.chain_code,
                    utils_hex_to_uint8("2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19"),
                    32);
    u_assert_mem_eq(node.private_key,
                    utils_hex_to_uint8("3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"),
                    32);
    u_assert_mem_eq(node.public_key,
                    utils_hex_to_uint8("03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c"),
                    33);
    iop_hdnode_serialize_private(&node, &iop_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "dywPw79hbEzJhfZkcf7W8iBLATwUYaGivDtzSfd87z9C2DPkqoxtE7CEdLT6cnmfYGRPsCHGrxPRqULXXa55vqzCM8hzR52fQaZLJesaG4zkbLkr");
    r = iop_hdnode_deserialize(str, &iop_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    u_assert_mem_eq(&node, &node2, sizeof(iop_hdnode));
    iop_hdnode_get_p2pkh_address(&node, &iop_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str, "pNxGrHV3TjZbf9Wtieimpm74oqJtn6oeRs");
    iop_hdnode_serialize_public(&node, &iop_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "9PPHAFJH7xPJrFVV8WYXAS1AmSTP3fqGtGyiQKHBYmqscGj7tQJpRYoM5vgxtsxnE5PY7xKLLfk1F7SEXAX2Z3frtK4UAGW52wrqLBJcAd2kCUFa");
    r = iop_hdnode_deserialize(str, &iop_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    memcpy(&node3, &node, sizeof(iop_hdnode));
    memset(&node3.private_key, 0, 32);
    u_assert_mem_eq(&node2, &node3, sizeof(iop_hdnode));

    /* [Chain m/0'/1/2'] */
    char path2[] = "m/0'/1/2'";
    iop_hd_generate_key(&node, path2, private_key_master, chain_code_master, false);
    u_assert_int_eq(node.fingerprint, 0xbef5a2f9);
    u_assert_mem_eq(node.chain_code,
                    utils_hex_to_uint8("04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f"),
                    32);
    u_assert_mem_eq(node.private_key,
                    utils_hex_to_uint8("cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca"),
                    32);
    u_assert_mem_eq(node.public_key,
                    utils_hex_to_uint8("0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2"),
                    33);
    iop_hdnode_serialize_private(&node, &iop_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "dywPw7CJsHX8ZNSc2XHJDxmjXpwWgoRbSVSaS1AMoEUVBPG8HDp5Lux54EteYLotAEeuMhkJFYrNktkMRoGpgS17YFoS5ReDxjVaFG9KUhayQq2d");
    r = iop_hdnode_deserialize(str, &iop_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    u_assert_mem_eq(&node, &node2, sizeof(iop_hdnode));
    iop_hdnode_get_p2pkh_address(&node, &iop_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str, "pTHY3J2refjJNiRxsZULaquH2vFX68tAFZ");
    iop_hdnode_serialize_public(&node, &iop_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "9PPHAFLtPzv8hxNLYNiKFgba8oTRBtz9QYXJPepRE2BAmSbVKpA1YMZBWq8WpRyy4XFySJqS5H7yrVNoVcrAqkmQRNWczrQ3B2ou1tzXJiEyNRqq");
    r = iop_hdnode_deserialize(str, &iop_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    memcpy(&node3, &node, sizeof(iop_hdnode));
    memset(&node3.private_key, 0, 32);
    u_assert_mem_eq(&node2, &node3, sizeof(iop_hdnode));

    /* [Chain m/0'/1/2'/2] */
    char path3[] = "m/0'/1/2'/2";
    iop_hd_generate_key(&node, path3, private_key_master, chain_code_master, false);
    u_assert_int_eq(node.fingerprint, 0xee7ab90c);
    u_assert_mem_eq(node.chain_code,
                    utils_hex_to_uint8("cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd"),
                    32);
    u_assert_mem_eq(node.private_key,
                    utils_hex_to_uint8("0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4"),
                    32);
    u_assert_mem_eq(node.public_key,
                    utils_hex_to_uint8("02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29"),
                    33);
    iop_hdnode_serialize_private(&node, &iop_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "dywPw7EYG7xFWYvH1bkmwf2wciSfztEtB82tdSeF6VS1ehhgtauhhyimRSU7U28HchKJnmYRxAmcKoZobGTj8dRetTC27ptK4HaPxR7neD5HswBs");
    r = iop_hdnode_deserialize(str, &iop_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    u_assert_mem_eq(&node, &node2, sizeof(iop_hdnode));
    iop_hdnode_get_p2pkh_address(&node, &iop_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str, "pRHLWKW6rKWD4Anpibwz4wdTrM6msp7fj6");
    iop_hdnode_serialize_public(&node, &iop_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "9PPHAFP7nqMFf8r1XTBnyNrnDgxaVyoS9B7cb6JJXH8hEm33wBFduRKst2hyk7JxSw48An9ZFR8ToY7hcBGWqr4qd676FmBbMrznqugS9rrxoLxB");
    r = iop_hdnode_deserialize(str, &iop_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    memcpy(&node3, &node, sizeof(iop_hdnode));
    memset(&node3.private_key, 0, 32);
    u_assert_mem_eq(&node2, &node3, sizeof(iop_hdnode));

    /* [Chain m/0'/1/2'/2/1000000000] */
    char path4[] = "m/0'/1/2'/2/1000000000";
    iop_hd_generate_key(&node, path4, private_key_master, chain_code_master, false);
    u_assert_int_eq(node.fingerprint, 0xd880d7d8);
    u_assert_mem_eq(node.chain_code,
                    utils_hex_to_uint8("c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e"),
                    32);
    u_assert_mem_eq(node.private_key,
                    utils_hex_to_uint8("471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8"),
                    32);
    u_assert_mem_eq(node.public_key,
                    utils_hex_to_uint8("022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011"),
                    33);
    iop_hdnode_serialize_private(&node, &iop_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str, "dywPw7GG2bdrkg3fD86ZPmaWM29fzgUTUwXhfEtdejiPnun5PJ376W925haGXez4pcERsNwqCx8bGecLiGdjWAVfca9ffAP5HQV9fhTLzxDQaeCV");
    r = iop_hdnode_deserialize(str, &iop_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    u_assert_mem_eq(&node, &node2, sizeof(iop_hdnode));
    iop_hdnode_get_p2pkh_address(&node, &iop_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str, "pR7J3ZgX6PUvkZAQsZJr8e2s77JqZc6Yej");
    iop_hdnode_serialize_public(&node, &iop_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "9PPHAFQqZK2ruFyPiyXaRVQLwzfaVn31SzcRctYh5XR5Ny7SRtP3Hwk8YHp8ok8sPnKCtFqqnvUPc5KQCmgurwvLTwNFNdj1SfUNUie45775hZ2T");
    r = iop_hdnode_deserialize(str, &iop_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    memcpy(&node3, &node, sizeof(iop_hdnode));
    memset(&node3.private_key, 0, 32);
    u_assert_mem_eq(&node2, &node3, sizeof(iop_hdnode));


    char str_pub_ckd[] = "9PPHAFDqaktTVmXV5WGqB4t96tUYU2eEHiNefcdyPgjNrK2wj4mFp1F24wywsBffoF7XBDqQ9vD9MyeLeUKGzx1PLyetZhoSw5LZDVtnUNyF1Lfn";

    r = iop_hdnode_deserialize(str_pub_ckd, &iop_chainparams_main, &node4);
    r = iop_hdnode_public_ckd(&node4, 123);
    u_assert_int_eq(r, true);
    iop_hdnode_serialize_public(&node4, &iop_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str, "9PPHAFFxg48JLqEesDtaRLZfQQ59E2CS7BWLBPouw5m6YdscfwkpKaPadnqM7EGQy8V7WV4CxFiLFz2oikMY8MiKemRCifUi1qWUut4Ww9TNnao1");


    r = iop_hdnode_public_ckd(&node4, 0x80000000 + 1); //try deriving a hardened key (= must fail)
    u_assert_int_eq(r, false);


    char str_pub_ckd_tn[] = "gpPfUTqtXLyH6r3w1i1kfhn6myKd41DHzcYjXAeJgT5DCq7BD37ijHR5aYUKNCZtRBQ4FYQzGnkqvDPuJRtJTpZDkkFHyvpQjRvm7h3B5Wm3ekZS";

    r = iop_hdnode_deserialize(str_pub_ckd_tn, &iop_chainparams_test, &node4);
    r = iop_hdnode_public_ckd(&node4, 123);
    u_assert_int_eq(r, true);
    iop_hdnode_get_p2pkh_address(&node4, &iop_chainparams_test, str, sizeof(str));
    u_assert_str_eq(str, "uYW83ZuM5mGy4L6URaju8Hh41PY4GyF8DZ");
    size_t size = sizeof(str);
    size_t sizeSmall = 55;
    r = iop_hdnode_get_pub_hex(&node4, str, &sizeSmall);
    u_assert_int_eq(r, false);
    r = iop_hdnode_get_pub_hex(&node4, str, &size);
    u_assert_int_eq(size, 66);
    u_assert_int_eq(r, true);
    u_assert_str_eq(str, "03b902c4a09e3142a1e54ebe13bfadb3829f5f09c622a6545f99c3038655b5bc05");
    iop_hdnode_serialize_public(&node4, &iop_chainparams_test, str, sizeof(str));
    u_assert_str_eq(str, "gpPfUTtPpvGGPiLn2hHEZzsfis4eTRcyRZoFhd1yLAKFa6cD1n9xSRybMjJm4zs4AaHkTXCaf4VrkeanCWUQHZuiRCpHk1aFkC33Wffaja2cjc6S");

    iop_hdnode *nodeheap;
    nodeheap = iop_hdnode_new();
    iop_hdnode *nodeheap_copy = iop_hdnode_copy(nodeheap);

    u_assert_int_eq(memcmp(nodeheap->private_key, nodeheap_copy->private_key, 32), 0);
    u_assert_int_eq(memcmp(nodeheap->public_key, nodeheap_copy->public_key, 33), 0)

    iop_hdnode_free(nodeheap);
    iop_hdnode_free(nodeheap_copy);
}
