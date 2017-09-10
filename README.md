<img src="http://libiop.github.io/images/libiop/logo@2x.png" alt="Icon" style="width:64px;"/>

libiop – A fast, clean and small iop C library
=============================================================

[![Build Status](https://travis-ci.org/libiop/libiop.svg?branch=master)](https://travis-ci.org/libiop/libiop)  [![Coverage Status](https://coveralls.io/repos/libiop/libiop/badge.svg?branch=master&service=github)](https://coveralls.io/github/libiop/libiop?branch=master)


What is libiop?
----------------

Libiop is a very portable C library for creating and manipulating iop data structures and interacting with the p2p network.

Current features
----------------
* Generating and storing private and public keys
* ECDSA secp256k1 signing and verification (through [libsecp256k1](https://github.com/iop-core/secp256k1) included as git subtree)
* Generate recoverable signatures (and recover pubkey from signatures)
* BIP32 hierarchical deterministic key derivation
* Transaction generation, manipulation, signing and ser-/deserialization including P2PKH, P2SH, multisig
* Address generation
* Base58check encoding
* Native implementation of SHA256, SHA512, SHA512_HMAC, RIPEMD-160 including NIST testvectors
* Native constant time AES (+256CBC) cipher implementation including NIST testvectors
* Keystore (wallet) databases (through logdb https://github.com/liblogdb/liblogdb)
* Event based iop P2P client capable of connecting to multiple nodes in a single thread (requires [libevent](https://github.com/libevent/libevent))
* Support for transaction references (BIP XXXX)

Advantages of libiop?
----------------

* No dependencies in case no p2p network client is required (only dependency is [libsecp256k1](https://github.com/iop-core/secp256k1) added as git subtree)
* The only dependency for the p2p network client is [libevent](https://github.com/libevent/libevent) (very portable)
* optimized for MCU and low mem environments
* ~full test coverage
* mem leak free (valgrind check during CI)

The ioptool CLI
----------------

##### Generate a new privatekey WIF and HEX encoded:

    ./ioptool -command genkey
    > privatekey WIF: KwmAqzEiP7nJbQi6ofQywSEad4j5b9BXDJvyypQDDLSvrV6wACG8
    > privatekey HEX: 102f1d9d91fa1c8d816ef469e74c1153a6b453d2a991e77fe187e5514a7b18ac

##### Generate the public key and p2pkh address from a WIF encoded private key

    /ioptool -command pubfrompriv -p KwmAqzEiP7nJbQi6ofQywSEad4j5b9BXDJvyypQDDLSvrV6wACG8
    > pubkey: 023d86ca58e2519cce1729b4d36dfe5a053ad5f4ae6f7ef9360bee4e657f7e41c9
    > p2pkh address: 1N5ZkjyabcZLLHMweJrSkn3qedsPGzAx9m

##### Generate the P2PKH address from a hex encoded compact public key

    ./ioptool -command addrfrompub -pubkey 023d86ca58e2519cce1729b4d36dfe5a053ad5f4ae6f7ef9360bee4e657f7e41c9
    > p2pkh address: 1N5ZkjyabcZLLHMweJrSkn3qedsPGzAx9m


##### Generate new BIP32 master key

    ./ioptool -command hdgenmaster
    > masterkey: xprv9s21ZrQH143K3C5hLMq2Upsh8mf9Z1p5C4QuXJkiodSSihp324YnWpFfRjvP7gqocJKz4oakVwZn5cUgRYTHtNRvGqU5DU2Gn8MPM9jHvfC


##### Print HD node

    ./ioptool -command hdprintkey -privkey xprv9s21ZrQH143K3C5hLMq2Upsh8mf9Z1p5C4QuXJkiodSSihp324YnWpFfRjvP7gqocJKz4oakVwZn5cUgRYTHtNRvGqU5DU2Gn8MPM9jHvfC
    > ext key: xprv9s21ZrQH143K3C5hLMq2Upsh8mf9Z1p5C4QuXJkiodSSihp324YnWpFfRjvP7gqocJKz4oakVwZn5cUgRYTHtNRvGqU5DU2Gn8MPM9jHvfC
    > depth: 0
    > p2pkh address: 1Fh1zA8mD6S2LBbCqdViEGuV3oDhggX3k4
    > pubkey hex: 0394a83fcfa131afc47a3fcd1d32db399a0ffa7e68844546b2df7ed9f5ebd07b09
    > extended pubkey: xpub661MyMwAqRbcFgAASPN2qxpRgoVdxUXvZHLWKhALMxyRbW9BZbs34ca9H3LrdsKxdMD4o5Fc7eqDg19cRTj3V9dCCeM4R1DRn8DvUq3rMva


##### Derive child key (second child key at level 1 in this case)

    ./ioptool -command hdderive -keypath m/1h -privkey xprv9s21ZrQH143K3C5hLMq2Upsh8mf9Z1p5C4QuXJkiodSSihp324YnWpFfRjvP7gqocJKz4oakVwZn5cUgRYTHtNRvGqU5DU2Gn8MPM9jHvfC
    > ext key: xprv9v5qiRbzrbhUzAVBdtfqi1tQx5tiRJ2jpNtAw8bRec8sTivLw55H85SoRTizNdx2JSVL4sNxmjvseASZkwpUopby3iGiJWnVH3Wjg2GkjrD
    > depth: 1
    > p2pkh address: 1DFBGZdcADGTcWwDEgf15RGPqnjmW2gokC
    > pubkey hex: 0203a85ec401e66a218bf1583112599ee2a1268ebc90d91b7f457c87a50f2b011b
    > extended pubkey: xpub695C7w8tgyFnCeZejvCr59q9W7jCpkkbBbomjX13CwfrLXFVUcPXfsmHGiSfpYds2JuHrXAFEoikMX6725W8VgrVL5x4ojBw9QFAPgtdw1G

The iop-send-tx CLI
----------------
This tools can be used to broadcast a raw transaction to peers retrived from a dns seed or specified by ip/port.
The application will try to connect to max 6 peers, send the transaction two two of them and listens on the remaining ones if the transaction has been relayed back.

##### Send a raw transaction to random peers on mainnet

    ./iop-send-tx <txhex>

##### Send a raw transaction to random peers on testnet and show debug infos

    ./iop-send-tx -d -t <txhex>

##### Send a raw transaction to specific peers on mainnet and show debug infos use a timeout of 5s

    ./iop-send-tx -d -s 5 -i 192.168.1.110:8333,127.0.0.1:8333 <txhex>

How to Build
----------------

#### Full library including CLI tool and wallet database
```
./autogen.sh
./configure
make check
```

#### Pure library without wallet support
```
./autogen.sh
./configure --disable-wallet --disable-tools
make check
```
