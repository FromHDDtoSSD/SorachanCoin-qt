
bin_PROGRAMS = SorachanCoind
INCLUDES = -Ileveldb/include -Ileveldb/helpers
SorachanCoind_CXXFLAGS = -std=c++11 -DUSE_LEVELDB -DUSE_IPV6 -DBOOST_NO_CXX11_SCOPED_ENUMS -w -Wno-delete-incomplete -Wno-deprecated-declarations -Wno-placement-new
SorachanCoind_LDADD = -lpthread \
 -lboost_system \
 -lboost_filesystem \
 -lboost_program_options \
 -lboost_thread \
 -lboost_chrono \
 -lssl \
 -lcrypto \
 -ldb_cxx \
 -lz \
 -ldl \
 ./leveldb/libleveldb.a \
 ./leveldb/libmemenv.a

SorachanCoind_SOURCES = alert.cpp \
 version.cpp \
 checkpoints.cpp \
 netbase.cpp \
 addrman.cpp \
 crypter.cpp \
 key.cpp \
 db.cpp \
 init.cpp \
 irc.cpp \
 keystore.cpp \
 main.cpp \
 miner.cpp \
 net.cpp \
 protocol.cpp \
 bitcoinrpc.cpp \
 rpcdump.cpp \
 rpcnet.cpp \
 rpcmining.cpp \
 rpcwallet.cpp \
 rpcblockchain.cpp \
 rpcrawtransaction.cpp \
 script.cpp \
 sync.cpp \
 util.cpp \
 wallet.cpp \
 walletdb.cpp \
 noui.cpp \
 kernel.cpp \
 pbkdf2.cpp \
 scrypt.cpp \
 ntp.cpp \
 stun.cpp \
 rpccrypt.cpp \
 base58.cpp \
 kernel_worker.cpp \
 ecies.cpp \
 cryptogram.cpp \
 ipcollector.cpp \
 txdb-leveldb.cpp

