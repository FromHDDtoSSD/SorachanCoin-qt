
bin_PROGRAMS = SorachanCoind
INCLUDES = -I../library/boost_1_68_0/include -I../library/libressl-2.8.2/include -I../library/blake2/include -I../library/sqlite/include
SorachanCoind_CXXFLAGS = -std=c++11 -DUSE_QUANTUM -DWALLET_SQL_MODE -DBLK_SQL_MODE -DUSE_IPV6 -DBOOST_NO_CXX11_SCOPED_ENUMS -w -Wno-delete-incomplete -Wno-deprecated-declarations -Wno-placement-new
SorachanCoind_LDADD = -lpthread \
 ../library/boost_1_68_0/lib/libboost_system.a \
 ../library/boost_1_68_0/lib/libboost_filesystem.a \
 ../library/boost_1_68_0/lib/libboost_program_options.a \
 ../library/boost_1_68_0/lib/libboost_thread.a \
 ../library/boost_1_68_0/lib/libboost_chrono.a \
 ../library/libressl-2.8.2/lib/libssl.a \
 ../library/libressl-2.8.2/lib/libcrypto.a \
 ../library/blake2/lib/libb2.a \
 ../library/sqlite/lib/libsqlite3.a \
 -lz \
 -ldl \

SorachanCoind_SOURCES = \
 address/base58.cpp \
 address/bech32.cpp \
 address/key_io.cpp \
 bench/be_aes.cpp \
 bench/be_bench.cpp \
 bench/be_hash.cpp \
 bip32/hdchain.cpp \
 bip32/hdwalletutil.cpp \
 block/block.cpp \
 block/block_alert.cpp \
 block/block_check.cpp \
 block/block_info.cpp \
 block/block_locator.cpp \
 block/block_process.cpp \
 block/block_keyhasher.cpp \
 block/block_chain.cpp \
 block/cscript.cpp \
 block/transaction.cpp \
 block/witness.cpp \
 cleanse/cleanse.cpp \
 compat/glibc_compat.cpp \
 compat/glibc_sanity.cpp \
 compat/glibcxx_sanity.cpp \
 const/chainparams.cpp \
 const/chainparamsbase.cpp \
 const/clientversion.cpp \
 const/net_processing.cpp \
 crypto/aes.cpp \
 crypto/blake2.cpp \
 crypto/chacha20.cpp \
 crypto/hmac_qhash65536.cpp \
 crypto/hmac_sha256.cpp \
 crypto/hmac_sha512.cpp \
 crypto/qhash65536.cpp \
 crypto/ripemd160.cpp \
 crypto/sha1.cpp \
 crypto/sha256.cpp \
 crypto/sha256_avx2.cpp \
 crypto/sha256_shani.cpp \
 crypto/sha256_sse4.cpp \
 crypto/sha256_sse41.cpp \
 crypto/sha512.cpp \
 file_operate/fs.cpp \
 file_operate/iofs.cpp \
 json/json_spirit_reader_template.cpp \
 json/json_spirit_value.cpp \
 json/json_spirit_writer.cpp \
 key/privkey.cpp \
 key/pubkey.cpp \
 libstr/cmstring.cpp \
 merkle/merkle_tree.cpp \
 merkle/merkle_tx.cpp \
 miner/diff.cpp \
 prime/autocheckpoint.cpp \
 quantum/quantum.cpp \
 random/random.cpp \
 rpc/bitcoinrpc.cpp \
 rpc/rpcblockchain.cpp \
 rpc/rpccrypto.cpp \
 rpc/rpcdump.cpp \
 rpc/rpcmining.cpp \
 rpc/rpcnet.cpp \
 rpc/rpcrawtransaction.cpp \
 rpc/rpcwallet.cpp \
 script/interpreter.cpp \
 script/lscript.cpp \
 script/script.cpp \
 script/script_error.cpp \
 script/sign.cpp \
 script/standard.cpp \
 sync/lsync.cpp \
 sync/sync.cpp \
 util/arginit.cpp \
 util/args.cpp \
 util/exception.cpp \
 util/logging.cpp \
 util/strencodings.cpp \
 util/system.cpp \
 util/time.cpp \
 util/thread.cpp \
 PoBench/pob_challenge.cpp \
 PoBench/pob_proof.cpp \
 PoBench/pob_plot.cpp \
 Lyra2RE/Lyra2.c \
 Lyra2RE/Lyra2RE.c \
 Lyra2RE/Sponge.c \
 Lyra2RE/blake.c \
 Lyra2RE/bmw.c \
 Lyra2RE/cubehash.c \
 Lyra2RE/groestl.c \
 Lyra2RE/keccak.c \
 Lyra2RE/skein.c \
 addrman.cpp \
 alert.cpp \
 checkpoints.cpp \
 crypter.cpp \
 cryptogram.cpp \
 db.cpp \
 db_addr.cpp \
 ecies.cpp \
 init.cpp \
 ipcollector.cpp \
 irc.cpp \
 kernel.cpp \
 kernel_worker.cpp \
 kernelrecord.cpp \
 key.cpp \
 keystore.cpp \
 main.cpp \
 miner.cpp \
 net.cpp \
 netbase.cpp \
 noui.cpp \
 ntp.cpp \
 pbkdf2.cpp \
 protocol.cpp \
 stun.cpp \
 txdb-leveldb.cpp \
 util.cpp \
 version.cpp \
 wallet.cpp \
 walletdb.cpp \
 scrypt.cpp
