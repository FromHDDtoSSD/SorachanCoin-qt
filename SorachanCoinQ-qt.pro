TEMPLATE = app
TARGET = SorachanCoinQ-qt
VERSION = 2.3.9

INCLUDEPATH += src src/json src/qt
QT += core gui network
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

#
# Qt informations
#
message(Qt version: $$[QT_VERSION])
#message(Qt is installed in $$[QT_INSTALL_PREFIX])
#message(Documentation: $$[QT_INSTALL_DOCS])
#message(Header files: $$[QT_INSTALL_HEADERS])
#message(Libraries: $$[QT_INSTALL_LIBS])
#message(Binary files (executables): $$[QT_INSTALL_BINS])
#message(Plugins: $$[QT_INSTALL_PLUGINS])
#message(Data files: $$[QT_INSTALL_DATA])
#message(Translation files: $$[QT_INSTALL_TRANSLATIONS])

#
# SorachanCoin build conf
#
win32: LIB_CURRENT_PATH=E:/cointools
else {
    macx: LIB_CURRENT_PATH=/develop/SorachanCoin-qt/cointools
    else: LIB_CURRENT_PATH=/opt/cointools
}
BOOST_PATH_SUFFIX=68_0
BDB_LIB_SUFFIX=-4.8
CONFIG += no_include_pwd
CONFIG += thread
CONFIG += static
macx: {
    QMAKE_CC = /bin/clang
    QMAKE_CXX = /bin/clang++
}
DEFINES += QT_GUI BOOST_THREAD_USE_LIB BOOST_SPIRIT_THREADSAFE __STDC_FORMAT_MACROS __STDC_LIMIT_MACROS
freebsd-g++: QMAKE_TARGET.arch = $$QMAKE_HOST.arch
linux-g++: QMAKE_TARGET.arch = $$QMAKE_HOST.arch
linux-g++-32: QMAKE_TARGET.arch = i686
linux-g++-64: QMAKE_TARGET.arch = x86_64
win32-g++-cross: QMAKE_TARGET.arch = $$TARGET_PLATFORM

#
# RELEASE
# 0: with debug console, DEBUG mode
# 1: no debug console, Release mode
#
RELEASE=0

#
# WHEN STARTUP, DEBUG_ALGO_BENCHMARK_TEST
# 0: Disable
# 1: Enable (when RELEASE==0)
#
DEBUG_ALGO_BENCHMARK_TEST=0

#
# WHEN STARTUP, DEBUG_RUNTIME_TEST
# 0: Disable
# 1: Enable (when RELEASE==0)
#
DEBUG_RUNTIME_TEST=0

#
# ALGO DEBUG_CS OUTPUT (e.g. prevector)
# 0: Disable
# 1: Enable (when RELEASE==0)
#
DEBUG_ALGO_CS_OUTPUT=0

#
# Build mode
#
USE_DBUS=0
BITCOIN_NEED_QT_PLUGINS=0
WINXP_BUILD=0
64BIT_BUILD=0

#
# O3 and indicate libraries
# there is no probrem, all set 1.
#
USE_O3=1
USE_LEVELDB=1
USE_UPNP=1
USE_IPV6=1
USE_QRCODE=1

#
# prevector or std::vector<uint8_t>
# there is no probrem, all set 1.
#
USE_PREVECTOR=1
USE_PREVECTOR_S=1

#
# OPTION USE
#
# QUANTUM: LamportSignature, CQHASH65536 (later Ver2, must be using!)
# KNOWLEDGE_DB: Blockchain Database (with the "blockchain mini filesystem" library, optional)
#
USE_QUANTUM=1
USE_KNOWLEDGE_DB=-

#
# Memory and Benchmark test
#
contains(RELEASE, 0) {
    DEBUG_ALGO_CHECK=0
    contains(DEBUG_ALGO_BENCHMARK_TEST, 1) {
        contains(USE_QUANTUM, 1) {
            contains(USE_LATEST_CRYPTO, 1) {
                DEBUG_ALGO_CHECK=1
            }
        }
    }
    DEFINES += DEBUG
} else {
    DEBUG_RUNTIME_TEST=0
    DEBUG_ALGO_CHECK=0
    DEBUG_ALGO_CS_OUTPUT=0
}

#
# LIMIT FLAGS
# Especially there is no necessary, all set flags to 0 below.
#
# LIMIT_NOMP_MODE: This official pool has been operating stably and continuously for over 6000 hours, and there is no problem even now.
#
LIMIT_NOMP_MODE=0

#
# Libraries setting
#
contains (64BIT_BUILD, 1) {
    64BIT_SUFFIX=64
}
contains (WINXP_BUILD, 1) {
    message(WINXP BUILD MODE LEVELDB 0)
    USE_LEVELDB=0
    BOOST_PATH_SUFFIX=55_0
    64BIT_BUILD=0
} else {
    message(NO WINXP BUILD)
}
windows: {
    BOOST_LIB_SUFFIX=-mgw73-mt-x64-1_68
    contains(64BIT_BUILD, 0) {
        BOOST_LIB_SUFFIX=-mgw73-mt-x32-1_68
        contains (WINXP_BUILD, 1) {
            BOOST_LIB_SUFFIX=-mgw63-mt-1_55
        }
    }
}
BOOST_THREAD_LIB_SUFFIX = $$BOOST_LIB_SUFFIX
BOOST_INCLUDE_PATH=$${LIB_CURRENT_PATH}$${64BIT_SUFFIX}/boost_1_$${BOOST_PATH_SUFFIX}
BOOST_LIB_PATH=$${LIB_CURRENT_PATH}$${64BIT_SUFFIX}/boost_1_$${BOOST_PATH_SUFFIX}/stage/lib
BDB_INCLUDE_PATH=$${LIB_CURRENT_PATH}$${64BIT_SUFFIX}/db-4.8.30/build_unix
BDB_LIB_PATH=$${LIB_CURRENT_PATH}$${64BIT_SUFFIX}/db-4.8.30/build_unix/.libs
OPENSSL_INCLUDE_PATH=$${LIB_CURRENT_PATH}$${64BIT_SUFFIX}/libressl-2.8.2/include
OPENSSL_LIB_PATH=$${LIB_CURRENT_PATH}$${64BIT_SUFFIX}/libressl-2.8.2
QRENCODE_INCLUDE_PATH=$${LIB_CURRENT_PATH}$${64BIT_SUFFIX}/qrencode-4.0.2/include
QRENCODE_LIB_PATH=$${LIB_CURRENT_PATH}$${64BIT_SUFFIX}/qrencode-4.0.2/lib
UPNP_INC_PATH=$${LIB_CURRENT_PATH}$${64BIT_SUFFIX}/miniupnpc
UPNP_LIB_PATH=$${LIB_CURRENT_PATH}$${64BIT_SUFFIX}/miniupnpc/libminiupnpc.a
BLAKE2_INC_PATH=$${LIB_CURRENT_PATH}$${64BIT_SUFFIX}/blake2/src
BLAKE2_LIB_PATH=$${LIB_CURRENT_PATH}$${64BIT_SUFFIX}/blake2/src/.libs
contains (WINXP_BUILD, 1) {
    OPENSSL_INCLUDE_PATH=$${LIB_CURRENT_PATH}$${64BIT_SUFFIX}/openssl-1.0.2o/include
    OPENSSL_LIB_PATH=$${LIB_CURRENT_PATH}$${64BIT_SUFFIX}/openssl-1.0.2o
}

#
# Build setting
#
OBJECTS_DIR = build
MOC_DIR = build
UI_DIR = build
QMAKE_CXXFLAGS += -std=c++11
contains(RELEASE, 1) {
    macx:QMAKE_CXXFLAGS += -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.12.sdk -mmacosx-version-min=10.7
    macx:QMAKE_CFLAGS += -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.12.sdk -mmacosx-version-min=10.7
    macx:QMAKE_OBJECTIVE_CFLAGS += -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.12.sdk -mmacosx-version-min=10.7

    !windows:!macx {
        # Linux: static link
        LIBS += -Wl,-Bstatic
    }
} else {
    QMAKE_CXXFLAGS -= -O2
    QMAKE_CFLAGS -= -O2

    QMAKE_CFLAGS += -g -O0
    QMAKE_CXXCFLAGS += -g -O0
}

#
# -O3 optimized setting
#
contains(RELEASE, 1) {
    contains(USE_O3, 1) {
        message(Building O3 optimization flag)
        QMAKE_CXXFLAGS_RELEASE -= -O2
        QMAKE_CFLAGS_RELEASE -= -O2

        QMAKE_CXXFLAGS += -O3
        QMAKE_CFLAGS += -O3
    } else {
        message(Building without O3 optimization flag [-O2])
    }
} else {
    message(Building without O3 optimization flag [-g -O0])
}

#
# Buffer security
#
!win32 {
    # for extra security against potential buffer overflows: enable GCCs Stack Smashing Protection
    QMAKE_CXXFLAGS *= -fstack-protector-all --param ssp-buffer-size=1
    QMAKE_LFLAGS *= -fstack-protector-all --param ssp-buffer-size=1
}
# win32: for extra security on Windows: enable ASLR and DEP via GCC linker flags

#
# STATIC build setting
#
win32:QMAKE_LFLAGS *= -Wl,--dynamicbase -Wl,--nxcompat
win32:QMAKE_LFLAGS += -static-libgcc -static-libstdc++

#
# Crypto++ 8.1
#
contains(USE_QUANTUM, 1) {
    DEFINES += CRYPTOPP_NO_ASSIGN_TO_INTEGER
}

#
# DSUB and QT_PLUGINS
#
contains(USE_DBUS, 1) {
    message(Building with DBUS (Freedesktop notifications) support)
    DEFINES += USE_DBUS
    QT += dbus
}
contains(BITCOIN_NEED_QT_PLUGINS, 1) {
    DEFINES += BITCOIN_NEED_QT_PLUGINS
    QTPLUGIN += qcncodecs qjpcodecs qtwcodecs qkrcodecs qtaccessiblewidgets
}

#
# LevelDB setting
#
contains(USE_LEVELDB, 1) {
    message(Building with LevelDB transaction index)
    DEFINES += USE_LEVELDB
    INCLUDEPATH += $${LIB_CURRENT_PATH}$${64BIT_SUFFIX}/leveldb-1.2/include $${LIB_CURRENT_PATH}$${64BIT_SUFFIX}/leveldb-1.2/helpers
    LIBS += $${LIB_CURRENT_PATH}$${64BIT_SUFFIX}/leveldb-1.2/libleveldb.a $${LIB_CURRENT_PATH}$${64BIT_SUFFIX}/leveldb-1.2/libmemenv.a
    genleveldb.target = $${LIB_CURRENT_PATH}$${64BIT_SUFFIX}/leveldb-1.2/libleveldb.a
    genleveldb.depends = FORCE
    PRE_TARGETDEPS += $${LIB_CURRENT_PATH}$${64BIT_SUFFIX}/leveldb-1.2/libleveldb.a
    QMAKE_EXTRA_TARGETS += genleveldb
    SOURCES += src/txdb-leveldb.cpp
} else {
    message(Building with Berkeley DB transaction index and wallet database)
    SOURCES += src/txdb-bdb.cpp
}

#
# use: qmake "USE_IPV6=1" (enabled by default; default)
#  or: qmake "USE_IPV6=0" (disabled by default)
#  or: qmake "USE_IPV6=-" (not supported)
#
contains(USE_IPV6, -) {
    message(Building without IPv6 support)
} else {
    message(Building with IPv6 support)
    DEFINES += USE_IPV6=$$USE_IPV6
}

#
# use: qmake "USE_UPNP=1" ( enabled by default; default)
#  or: qmake "USE_UPNP=0" (disabled by default)
#  or: qmake "USE_UPNP=-" (not supported)
#
contains(USE_UPNP, -) {
    message(Building without UPNP support)
} else {
    message(Building with UPNP support)
    DEFINES += USE_UPNP=$$USE_UPNP STATICLIB

    INCLUDEPATH += $$UPNP_INC_PATH
    LIBS += $$UPNP_LIB_PATH
    win32 {
        LIBS += -liphlpapi
    }
    contains(64BIT_BUILD, 1) {
        DEFINES += MINIUPNP_STATICLIB
    }
}

#
# libqrencode (https://fukuchi.org/works/qrencode/index.html) must be installed for support
# use: qmake "USE_QRCODE=1" ( enabled by default; default)
#  or: qmake "USE_QRCODE=-" (not supported)
#
contains(USE_QRCODE, -) {
    message(Building without QRCode support)
} else {
    message(Building with QRCode support)
    DEFINES += USE_QRCODE
    LIBS += -lqrencode
}

#
# prevector
# 0: std::vector<uint8_t>
# 1: prevector
#
contains(USE_PREVECTOR, 1) {
    message(Building with prevector support)
    DEFINES += USE_PREVECTOR
} else {
    message(Building without prevector support)
}
contains(USE_PREVECTOR_S, 1) {
    message(Building with prevector_s support)
    DEFINES += USE_PREVECTOR_S
} else {
    message(Building without ptrvector_s support)
}

#
# use: qmake "USE_QUANTUM=1" ( enabled by default; default)
#  or: qmake "USE_QUANTUM=0" (disabled by default)
#  or: qmake "USE_QUANTUM=-" (not supported)
#
# BLAKE2HASH: https://github.com/BLAKE2/libb2
#
contains(USE_QUANTUM, -) {
    message(Building without QUANTUM support)
} else {
    message(Building with QUANTUM support)
    DEFINES += USE_QUANTUM=$$USE_QUANTUM

    INCLUDEPATH += $$BLAKE2_INC_PATH
    LIBS += -lb2
}

#
# use: qmake "USE_KNOWLEDGE_DB=1" ( enabled by default)
#  or: qmake "USE_KNOWLEDGE_DB=0" (disabled by default; default)
#  or: qmake "USE_KNOWLEDGE_DB=-" (not supported)
#
contains(USE_KNOWLEDGE_DB, -) {
    message(Building without KNOWLEDGE_DB support)
} else {
    message(Building with KNOWLEDGE_DB support)
    DEFINES += USE_KNOWLEDGE_DB=$$USE_KNOWLEDGE_DB
}

#
# Memory and Benchmark
#
contains(DEBUG_ALGO_CS_OUTPUT, 1) {
    DEFINES += DEBUG_ALGO_CS_OUTPUT
}
contains(DEBUG_ALGO_CHECK, 1) {
    DEFINES += DEBUG_ALGO_CHECK
}
contains(DEBUG_RUNTIME_TEST, 1) {
    DEFINES += DEBUG_RUNTIME_TEST
}

#
# use: qmake "LIMIT_NOMP_MODE=1" ( enabled by default)
#  or: qmake "LIMIT_NOMP_MODE=0" (disabled by default; default)
#
contains(LIMIT_NOMP_MODE, 0) {
    message(Building without NOMP_MODE limit)
} else {
    message(Building with NOMP_MODE limit)
    DEFINES += LIMIT_NOMP_MODE=$$LIMIT_NOMP_MODE
}

#
# warning(-W -Wno) and error(-Werror=) flags setting
#
QMAKE_CXXFLAGS_WARN_ON = -fdiagnostics-show-option -Wall -Wextra -Werror=return-type -Werror=unused-result -Werror=comment -Wno-stringop-overflow -Wno-ignored-qualifiers -Wformat -Wformat-security -Wno-misleading-indentation -Wno-strict-aliasing -Wno-cpp -Wno-extra -Wno-reorder -Wno-expansion-to-defined -Wno-unused-local-typedefs -Wno-unused-function -Wno-unused-parameter -Wstack-protector -Wno-delete-incomplete -Wno-deprecated-declarations -Wno-placement-new

#
# target source codes
#
DEPENDPATH += src src/json src/qt
HEADERS += src/qt/bitcoingui.h \
    src/qt/intro.h \
    src/qt/transactiontablemodel.h \
    src/qt/addresstablemodel.h \
    src/qt/optionsdialog.h \
    src/qt/coincontroldialog.h \
    src/qt/coincontroltreewidget.h \
    src/qt/sendcoinsdialog.h \
    src/qt/addressbookpage.h \
    src/qt/signverifymessagedialog.h \
    src/qt/aboutdialog.h \
    src/qt/editaddressdialog.h \
    src/qt/bitcoinaddressvalidator.h \
    src/qt/mintingfilterproxy.h \
    src/qt/mintingtablemodel.h \
    src/qt/mintingview.h \
    src/kernelrecord.h \
    src/alert.h \
    src/addrman.h \
    src/base58.h \
    src/bignum.h \
    src/checkpoints.h \
    src/compat.h \
    src/coincontrol.h \
    src/sync/sync.h \
    src/sync/lsync.h \
    src/util.h \
    src/timestamps.h \
    src/hash.h \
    src/uint256.h \
    src/kernel.h \
    src/scrypt.h \
    src/pbkdf2.h \
    src/kernel_worker.h \
    src/serialize.h \
    src/main.h \
    src/miner.h \
    src/net.h \
    src/ministun.h \
    src/key.h \
    src/db.h \
    src/txdb.h \
    src/txdb-bdb.h \
    src/txdb-leveldb.h \
    src/walletdb.h \
    src/db_addr.h \
    src/script.h \
    src/init.h \
    src/irc.h \
    src/mruset.h \
    src/json/json_spirit_writer_template.h \
    src/json/json_spirit_writer.h \
    src/json/json_spirit_value.h \
    src/json/json_spirit_utils.h \
    src/json/json_spirit_stream_reader.h \
    src/json/json_spirit_reader_template.h \
    src/json/json_spirit_reader.h \
    src/json/json_spirit_error_position.h \
    src/json/json_spirit.h \
    src/qt/clientmodel.h \
    src/qt/guiutil.h \
    src/qt/transactionrecord.h \
    src/qt/guiconstants.h \
    src/qt/optionsmodel.h \
    src/qt/monitoreddatamapper.h \
    src/qt/transactiondesc.h \
    src/qt/transactiondescdialog.h \
    src/qt/bitcoinamountfield.h \
    src/wallet.h \
    src/keystore.h \
    src/qt/transactionfilterproxy.h \
    src/qt/transactionview.h \
    src/qt/walletmodel.h \
    src/qt/overviewpage.h \
    src/qt/csvmodelwriter.h \
    src/crypter.h \
    src/qt/sendcoinsentry.h \
    src/qt/qvalidatedlineedit.h \
    src/qt/bitcoinunits.h \
    src/qt/qvaluecombobox.h \
    src/qt/askpassphrasedialog.h \
    src/qt/trafficgraphwidget.h \
    src/protocol.h \
    src/qt/notificator.h \
    src/qt/qtipcserver.h \
    src/allocator/allocators.h \
    src/ui_interface.h \
    src/qt/rpcconsole.h \
    src/version.h \
    src/ntp.h \
    src/netbase.h \
    src/const/clientversion.h \
    src/qt/multisigaddressentry.h \
    src/qt/multisiginputentry.h \
    src/qt/multisigdialog.h \
    src/qt/secondauthdialog.h \
    src/ies.h \
    src/ipcollector.h \
    src/prevector/prevector.h \
    src/prevector/prevector_s.h \
    src/quantum/quantum.h \
    src/debugcs/debugcs.h \
    src/compat/compat.h \
    src/compat/byteswap.h \
    src/compat/endian.h \
    src/compat/sanity.h \
    src/bench/bench.h \
    src/crypto/ctaes/ctaes.h \
    src/crypto/aes.h \
    src/crypto/chacha20.h \
    src/crypto/common.h \
    src/crypto/hmac_sha256.h \
    src/crypto/hmac_sha512.h \
    src/crypto/ripemd160.h \
    #src/crypto/_scrypt.h \
    src/crypto/sha1.h \
    src/crypto/sha256.h \
    src/crypto/sha512.h \
    src/crypto/qhash65536.h \
    src/crypto/blake2.h \
    src/crypto/hmac_qhash65536.h \
    src/univalue/univalue.h \
    src/univalue/univalue_escapes.h \
    src/univalue/univalue_utffilter.h \
    src/univalue/univaluetest.h \
    src/block/block.h \
    src/block/transaction.h \
    src/block/witness.h \
    src/block/cscript.h \
    src/block/block_process.h \
    src/block/block_locator.h \
    src/block/block_info.h \
    src/block/block_alert.h \
    src/block/block_check.h \
    src/prime/autocheckpoint.h \
    src/merkle/merkle_tx.h \
    src/merkle/merkle_tree.h \
    src/const/block_param.h \
    src/const/no_instance.h \
    src/file_operate/file_open.h \
    src/file_operate/autofile.h \
    src/file_operate/fs.h \
    src/file_operate/iofs.h \
    src/boot/shutdown.h \
    src/miner/diff.h \
    src/rpc/bitcoinrpc.h \
    src/allocator/qtsecure.h \
    src/bip32/hdchain.h \
    src/bip32/hdwalletutil.h \
    src/key/pubkey.h \
    src/key/privkey.h \
    src/cleanse/cleanse.h \
    src/random/random.h \
    src/util/time.h \
    src/util/tinyformat.h \
    src/util/logging.h \
    src/util/strencodings.h \
    src/util/memory.h \
    src/util/system.h \
    src/util/args.h \
    src/util/c_overload.h \
    src/thread/threadsafety.h \
    src/address/bech32.h \
    src/const/chainparamsbase.h \
    src/const/chainparams.h \
    src/const/attributes.h \
    src/const/assumptions.h \
    src/const/macro.h \
    src/script/lscript.h \
    src/script/scriptnum.h \
    src/consensus/consensus.h \
    src/consensus/params.h \
    src/noexcept/throw.hpp \
    src/noexcept/try.hpp \
    src/noexcept/noexcept_detail/ceh.hpp \
    src/noexcept/noexcept_detail/eh.hpp \
    src/noexcept/noexcept_detail/error.hpp \
    src/noexcept/noexcept_config/assert.hpp \
    src/noexcept/noexcept_config/inline.hpp \
    src/noexcept/noexcept_config/rtti.hpp \
    src/noexcept/noexcept_config/thread_local.hpp \
    src/noexcept/noexcept_config/throw_exception.hpp

SOURCES += src/qt/bitcoin.cpp src/qt/bitcoingui.cpp \
    src/qt/intro.cpp \
    src/qt/transactiontablemodel.cpp \
    src/qt/addresstablemodel.cpp \
    src/qt/optionsdialog.cpp \
    src/qt/sendcoinsdialog.cpp \
    src/qt/coincontroldialog.cpp \
    src/qt/coincontroltreewidget.cpp \
    src/qt/addressbookpage.cpp \
    src/qt/signverifymessagedialog.cpp \
    src/qt/aboutdialog.cpp \
    src/qt/editaddressdialog.cpp \
    src/qt/bitcoinaddressvalidator.cpp \
    src/qt/trafficgraphwidget.cpp \
    src/qt/mintingfilterproxy.cpp \
    src/qt/mintingtablemodel.cpp \
    src/qt/mintingview.cpp \
    src/kernelrecord.cpp \
    src/alert.cpp \
    src/version.cpp \
    src/sync/sync.cpp \
    src/sync/lsync.cpp \
    src/util.cpp \
    src/netbase.cpp \
    src/ntp.cpp \
    src/key.cpp \
    src/script.cpp \
    src/main.cpp \
    src/miner.cpp \
    src/init.cpp \
    src/net.cpp \
    src/stun.cpp \
    src/irc.cpp \
    src/checkpoints.cpp \
    src/addrman.cpp \
    src/db.cpp \
    src/walletdb.cpp \
    src/db_addr.cpp \
    src/qt/clientmodel.cpp \
    src/qt/guiutil.cpp \
    src/qt/transactionrecord.cpp \
    src/qt/optionsmodel.cpp \
    src/qt/monitoreddatamapper.cpp \
    src/qt/transactiondesc.cpp \
    src/qt/transactiondescdialog.cpp \
    src/qt/bitcoinstrings.cpp \
    src/qt/bitcoinamountfield.cpp \
    src/wallet.cpp \
    src/keystore.cpp \
    src/qt/transactionfilterproxy.cpp \
    src/qt/transactionview.cpp \
    src/qt/walletmodel.cpp \
    src/qt/overviewpage.cpp \
    src/qt/csvmodelwriter.cpp \
    src/crypter.cpp \
    src/qt/sendcoinsentry.cpp \
    src/qt/qvalidatedlineedit.cpp \
    src/qt/bitcoinunits.cpp \
    src/qt/qvaluecombobox.cpp \
    src/qt/askpassphrasedialog.cpp \
    src/protocol.cpp \
    src/qt/notificator.cpp \
    src/qt/qtipcserver.cpp \
    src/qt/rpcconsole.cpp \
    src/noui.cpp \
    src/kernel.cpp \
    src/scrypt-arm.S \
    src/scrypt-x86.S \
    src/scrypt-x86_64.S \
    src/scrypt.cpp \
    src/pbkdf2.cpp \
    src/kernel_worker.cpp \
    src/qt/multisigaddressentry.cpp \
    src/qt/multisiginputentry.cpp \
    src/qt/multisigdialog.cpp \
    src/qt/secondauthdialog.cpp \
    src/base58.cpp \
    src/cryptogram.cpp \
    src/ecies.cpp \
    src/ipcollector.cpp \
    src/quantum/quantum.cpp \
    src/bench/be_bench.cpp \
    src/bench/be_prevector.cpp \
    src/bench/be_aes.cpp \
    src/bench/be_hash.cpp \
    src/bench/be_univalue.cpp \
    src/compat/glibc_compat.cpp \
    src/compat/glibc_sanity.cpp \
    src/compat/glibcxx_sanity.cpp \
    src/crypto/ctaes/ctaes.c \
    src/crypto/ctaes/ctaestest.cpp \
    #src/crypto/ctaes/_bench.cpp \
    src/crypto/aes.cpp \
    src/crypto/chacha20.cpp \
    src/crypto/hmac_sha256.cpp \
    src/crypto/hmac_sha512.cpp \
    src/crypto/ripemd160.cpp \
    #src/crypto/_scrypt.cpp \
    #src/crypto/_scrypt-sse2.cpp \
    src/crypto/sha1.cpp \
    src/crypto/sha256.cpp \
    src/crypto/sha256_avx2.cpp \
    src/crypto/sha256_shani.cpp \
    src/crypto/sha256_sse4.cpp \
    src/crypto/sha256_sse41.cpp \
    src/crypto/sha512.cpp \
    src/crypto/qhash65536.cpp \
    src/crypto/blake2.cpp \
    src/crypto/hmac_qhash65536.cpp \
    src/univalue/univalue.cpp \
    src/univalue/univalue_get.cpp \
    src/univalue/univalue_read.cpp \
    src/univalue/univalue_write.cpp \
    src/block/block.cpp \
    src/block/transaction.cpp \
    src/block/witness.cpp \
    src/block/cscript.cpp \
    src/block/block_process.cpp \
    src/block/block_info.cpp \
    src/block/block_locator.cpp \
    src/block/block_alert.cpp \
    src/block/block_check.cpp \
    src/prime/autocheckpoint.cpp \
    src/merkle/merkle_tx.cpp \
    src/merkle/merkle_tree.cpp \
    src/miner/diff.cpp \
    src/rpc/bitcoinrpc.cpp \
    src/rpc/rpccrypt.cpp \
    src/rpc/rpcdump.cpp \
    src/rpc/rpcnet.cpp \
    src/rpc/rpcmining.cpp \
    src/rpc/rpcwallet.cpp \
    src/rpc/rpcblockchain.cpp \
    src/rpc/rpcrawtransaction.cpp \
    src/bip32/hdchain.cpp \
    src/key/pubkey.cpp \
    src/key/privkey.cpp \
    src/cleanse/cleanse.cpp \
    src/random/random.cpp \
    src/util/time.cpp \
    src/util/logging.cpp \
    src/util/strencodings.cpp \
    src/util/system.cpp \
    src/util/args.cpp \
    src/util/arginit.cpp \
    src/file_operate/fs.cpp \
    src/file_operate/iofs.cpp \
    src/address/bech32.cpp \
    src/const/chainparamsbase.cpp \
    src/const/chainparams.cpp \
    src/const/clientversion.cpp \
    src/bip32/hdwalletutil.cpp \
    src/script/lscript.cpp \
    src/noexcept/noexcept_detail/eh.cpp \
    src/noexcept/noexcept_detail/error.cpp \
    src/json/json_spirit_reader_template.cpp

RESOURCES += \
    src/qt/bitcoin.qrc

FORMS += \
    src/qt/forms/intro.ui \
    src/qt/forms/coincontroldialog.ui \
    src/qt/forms/sendcoinsdialog.ui \
    src/qt/forms/addressbookpage.ui \
    src/qt/forms/signverifymessagedialog.ui \
    src/qt/forms/aboutdialog.ui \
    src/qt/forms/editaddressdialog.ui \
    src/qt/forms/transactiondescdialog.ui \
    src/qt/forms/overviewpage.ui \
    src/qt/forms/sendcoinsentry.ui \
    src/qt/forms/askpassphrasedialog.ui \
    src/qt/forms/rpcconsole.ui \
    src/qt/forms/optionsdialog.ui \
    src/qt/forms/multisigaddressentry.ui \
    src/qt/forms/multisiginputentry.ui \
    src/qt/forms/multisigdialog.ui \
    src/qt/forms/secondauthdialog.ui

contains(USE_QRCODE, 1) {
    HEADERS += src/qt/qrcodedialog.h
    SOURCES += src/qt/qrcodedialog.cpp
    FORMS += src/qt/forms/qrcodedialog.ui
}

CODECFORTR = UTF-8

#
# for lrelease/lupdate
# also add new translations to src/qt/bitcoin.qrc under translations/
#
TRANSLATIONS = $$files(src/qt/locale/bitcoin_*.ts)
isEmpty(QMAKE_LRELEASE) {
    win32:QMAKE_LRELEASE = $$[QT_INSTALL_BINS]/lrelease.exe
    else:QMAKE_LRELEASE = $$[QT_INSTALL_BINS]/lrelease
}
isEmpty(QM_DIR):QM_DIR = $$PWD/src/qt/locale

#
# automatically build translations, so they can be included in resource file
#
TSQM.name = lrelease ${QMAKE_FILE_IN}
TSQM.input = TRANSLATIONS
TSQM.output = $$QM_DIR/${QMAKE_FILE_BASE}.qm
TSQM.commands = $$QMAKE_LRELEASE ${QMAKE_FILE_IN} -qm ${QMAKE_FILE_OUT}
TSQM.CONFIG = no_link
QMAKE_EXTRA_COMPILERS += TSQM

#
# "Other files" to show in Qt Creator
#
OTHER_FILES += doc/*.rst doc/*.txt doc/README README.md res/bitcoin-qt.rc

#
# windows: indicate define
#
windows:DEFINES += WIN32
windows:RC_FILE = src/qt/res/bitcoin-qt.rc
windows:!contains(MINGW_THREAD_BUGFIX, 0) {
    #
    # At least qmake's win32-g++-cross profile is missing the -lmingwthrd
    # thread-safety flag. GCC has -mthreads to enable this, but it doesn't
    # work with static linking. -lmingwthrd must come BEFORE -lmingw, so
    # it is prepended to QMAKE_LIBS_QT_ENTRY.
    # It can be turned off with MINGW_THREAD_BUGFIX=0, just in case it causes
    # any problems on some untested qmake profile now or in the future.
    #
    DEFINES += _MT BOOST_THREAD_PROVIDES_GENERIC_SHARED_MUTEX_ON_WIN
    QMAKE_LIBS_QT_ENTRY = -lmingwthrd $$QMAKE_LIBS_QT_ENTRY
}

#
# linux: indicate define
#
!windows:!macx {
    DEFINES += LINUX
    LIBS += -lrt
}

#
# OSX: build setting
#
macx:HEADERS += src/qt/macdockiconhandler.h src/qt/macnotificationhandler.h
macx:OBJECTIVE_SOURCES += src/qt/macdockiconhandler.mm src/qt/macnotificationhandler.mm
macx:LIBS += -framework Foundation -framework ApplicationServices -framework AppKit
macx:DEFINES += MAC_OSX MSG_NOSIGNAL=0
macx:ICON = src/qt/res/icons/SorachanCoin.icns
macx:TARGET = "SorachanCoin-qt"
macx:QMAKE_CFLAGS_THREAD += -pthread
macx:QMAKE_LFLAGS_THREAD += -pthread
macx:QMAKE_CXXFLAGS_THREAD += -pthread

#
# Set libraries and includes at end, to use platform-defined defaults if not overridden
#
INCLUDEPATH += $$BOOST_INCLUDE_PATH $$BDB_INCLUDE_PATH $$OPENSSL_INCLUDE_PATH $$QRENCODE_INCLUDE_PATH
LIBS += $$join(BOOST_LIB_PATH,,-L,) $$join(BDB_LIB_PATH,,-L,) $$join(OPENSSL_LIB_PATH,,-L,) $$join(QRENCODE_LIB_PATH,,-L,) $$join(BLAKE2_LIB_PATH,,-L,)
LIBS += -lssl -lcrypto -ldb_cxx$${BDB_LIB_SUFFIX}

#
# -lgdi32 has to happen after -lcrypto
#
windows:LIBS += -lws2_32 -lshlwapi -lmswsock -lole32 -loleaut32 -luuid -lgdi32
LIBS += -lboost_system$$BOOST_LIB_SUFFIX -lboost_filesystem$$BOOST_LIB_SUFFIX -lboost_program_options$$BOOST_LIB_SUFFIX -lboost_thread$$BOOST_THREAD_LIB_SUFFIX -lboost_chrono$$BOOST_LIB_SUFFIX
windows:LIBS += -Wl,-Bstatic -lpthread -Wl,-Bdynamic
contains(RELEASE, 1) {
    !windows:!macx {
        # Linux: turn dynamic linking back on for c/c++ runtime libraries
        LIBS += -Wl,-Bdynamic
    }
}
linux-* {
    # We may need some linuxism here
    LIBS += -ldl
}
netbsd-*|freebsd-*|openbsd-* {
    # libexecinfo is required for back trace
    LIBS += -lexecinfo
}

#
# translation files, lrelease
#
system($$QMAKE_LRELEASE -silent $$PWD/src/qt/locale/translations.pro)
