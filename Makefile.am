ACLOCAL_AMFLAGS = -I build-aux/m4
.PHONY: gen
.INTERMEDIATE: $(GENBIN)

DIST_SUBDIRS = src/secp256k1

LIBSECP256K1=src/secp256k1/libsecp256k1.la

$(LIBSECP256K1): $(wildcard src/secp256k1/src/*) $(wildcard src/secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

lib_LTLIBRARIES = libiop.la
include_HEADERS = \
    include/iop/aes256_cbc.h \
    include/iop/base58.h \
    include/iop/bip32.h \
    include/iop/block.h \
    include/iop/iop.h \
    include/iop/buffer.h \
    include/iop/chainparams.h \
    include/iop/cstr.h \
    include/iop/ctaes.h \
    include/iop/ecc_key.h \
    include/iop/ecc.h \
    include/iop/hash.h \
    include/iop/portable_endian.h \
    include/iop/random.h \
    include/iop/script.h \
    include/iop/segwit_addr.h \
    include/iop/serialize.h \
    include/iop/sha2.h \
    include/iop/tool.h \
    include/iop/tx.h \
    include/iop/txref_code.h \
    include/iop/utils.h \
    include/iop/vector.h

noinst_HEADERS = \
	src/ripemd160.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libiop.pc

libiop_la_SOURCES = \
    src/aes256_cbc.c \
    src/base58.c \
    src/bip32.c \
    src/block.c \
    src/buffer.c \
    src/chainparams.c \
    src/commontools.c \
    src/cstr.c \
    src/ctaes.c \
    src/ecc_key.c \
    src/ecc_libsecp256k1.c \
    src/memory.c \
    src/memory.h \
    src/random.c \
    src/ripemd160.c \
    src/script.c \
    src/segwit_addr.c \
    src/serialize.c \
    src/sha2.c \
    src/tx.c \
    src/txref_code.c \
    src/utils.c \
    src/vector.c

libiop_la_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src/logdb/include
libiop_la_LIBADD = $(LIBSECP256K1)

if USE_TESTS
noinst_PROGRAMS = tests
tests_LDADD = libiop.la
tests_SOURCES = \
    test/aes_tests.c \
    test/base58check_tests.c \
    test/bip32_tests.c \
    test/block_tests.c \
    test/buffer_tests.c \
    test/cstr_tests.c \
    test/ecc_tests.c \
    test/eckey_tests.c \
    test/hash_tests.c \
    test/memory_tests.c \
    test/random_tests.c \
    test/serialize_tests.c \
    test/sha2_tests.c \
    test/utest.h \
    test/unittester.c \
    test/tx_tests.c \
    test/txref_tests.c \
    test/utils_tests.c \
    test/vector_tests.c

tests_CFLAGS = $(libiop_la_CFLAGS)
tests_CPPFLAGS = -I$(top_srcdir)/src
tests_LDFLAGS = -static
TESTS = tests
endif

if WITH_WALLET

libiop_la_SOURCES += \
    src/logdb/logdb_core.c \
    src/logdb/logdb_memdb_llist.c \
    src/logdb/logdb_memdb_rbtree.c \
    src/logdb/logdb_rec.c \
    src/logdb/red_black_tree.c

include_HEADERS += \
    src/logdb/include/logdb/logdb_base.h \
    src/logdb/include/logdb/logdb_core.h \
    src/logdb/include/logdb/logdb_memdb_llist.h \
    src/logdb/include/logdb/logdb_memdb_rbtree.h \
    src/logdb/include/logdb/logdb_rec.h \
    src/logdb/include/logdb/logdb.h \
    src/logdb/include/logdb/red_black_tree.h

include_HEADERS += \
    include/iop/wallet.h

libiop_la_SOURCES += \
    src/wallet.c

if USE_TESTS
tests_SOURCES += \
    test/wallet_tests.c \
    src/logdb/test/logdb_tests.c \
    src/logdb/test/tests_red_black_tree.c
endif
endif

if WITH_NET
include_HEADERS += \
    include/iop/headersdb.h \
    include/iop/headersdb_file.h \
    include/iop/protocol.h \
    include/iop/net.h \
    include/iop/netspv.h

libiop_la_SOURCES += \
    src/headersdb_file.c \
    src/net.c \
    src/netspv.c \
    src/protocol.c

libiop_la_LIBADD += $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS)
libiop_la_CFLAGS += $(EVENT_CFLAGS) $(EVENT_PTHREADS_CFLAGS)

if USE_TESTS
tests_SOURCES += \
    test/net_tests.c \
    test/netspv_tests.c \
    test/protocol_tests.c
tests_LDADD += $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS)
tests_LDFLAGS += -levent
endif
endif

if WITH_TOOLS
if USE_TESTS
tests_SOURCES += \
    test/tool_tests.c
endif
instdir=$(prefix)/bin
inst_PROGRAMS = ioptool
ioptool_LDADD = libiop.la
ioptool_SOURCES = \
    src/tools/ioptool.c
ioptool_CFLAGS = $(libiop_la_CFLAGS)
ioptool_CPPFLAGS = -I$(top_srcdir)/src
ioptool_LDFLAGS = -static

inst_PROGRAMS += iop-send-tx
iop_send_tx_LDADD = libiop.la $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS)
iop_send_tx_SOURCES = \
    src/tools/iop-send-tx.c
iop_send_tx_CFLAGS = $(libiop_la_CFLAGS) $(EVENT_CFLAGS) $(EVENT_PTHREADS_CFLAGS)
iop_send_tx_CPPFLAGS = -I$(top_srcdir)/src
iop_send_tx_LDFLAGS = -static

inst_PROGRAMS += iop-spv
iop_spv_LDADD = libiop.la
iop_spv_SOURCES = \
    src/tools/iop-spv.c
iop_spv_CFLAGS = $(libiop_la_CFLAGS)
iop_spv_CPPFLAGS = -I$(top_srcdir)/src
iop_spv_LDFLAGS = -static

inst_PROGRAMS += iop-txref
iop_txref_LDADD = libiop.la
iop_txref_SOURCES = \
    src/tools/iop-txref.c
iop_txref_CFLAGS = $(libiop_la_CFLAGS)
iop_txref_CPPFLAGS = -I$(top_srcdir)/src
iop_txref_LDFLAGS = -static


endif

clean-local:
	-$(MAKE) -C src/secp256k1 clean
