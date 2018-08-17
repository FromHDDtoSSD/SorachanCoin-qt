TEMPLATE = app
TARGET = SorachanCoin-qt
VERSION = 1.0.0

INCLUDEPATH += src src/json src/qt

QT += core gui network
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += no_include_pwd
CONFIG += thread
CONFIG += static

DEFINES += QT_GUI BOOST_THREAD_USE_LIB BOOST_SPIRIT_THREADSAFE __STDC_FORMAT_MACROS __STDC_LIMIT_MACROS

RELEASE=1
USE_DBUS=0
BITCOIN_NEED_QT_PLUGINS=0

USE_O3=1
USE_LEVELDB=1
USE_UPNP=0
USE_IPV6=-
USE_QRENCODE=0

freebsd-g++: QMAKE_TARGET.arch = $$QMAKE_HOST.arch
linux-g++: QMAKE_TARGET.arch = $$QMAKE_HOST.arch
linux-g++-32: QMAKE_TARGET.arch = i686
linux-g++-64: QMAKE_TARGET.arch = x86_64
win32-g++-cross: QMAKE_TARGET.arch = $$TARGET_PLATFORM

# for boost 1.55, add -mt to the boost libraries
# use: qmake BOOST_LIB_SUFFIX=-mt
# for boost thread win32 with _win32 sufix
# use: BOOST_THREAD_LIB_SUFFIX=_win32-... or when linking against a specific BerkelyDB version: BDB_LIB_SUFFIX=-4.8
win32 {
	message(WINDOWS INCLUDE and LIBRARY PATH)
	BOOST_LIB_SUFFIX=-mgw63-mt-1_55

	BOOST_INCLUDE_PATH=E:/cointools/boost-1.55
	BOOST_LIB_PATH=E:/cointools/boost-1.55/stage/lib
	BDB_INCLUDE_PATH=E:/cointools/db-4.8.30/build_unix
	BDB_LIB_PATH=E:/cointools/db-4.8.30/build_unix
	OPENSSL_INCLUDE_PATH=E:/cointools/openssl-1.0.2o/include
	OPENSSL_LIB_PATH=E:/cointools/openssl-1.0.2o
	QRENCODE_INCLUDE_PATH=E:/cointools/qrencode-3.4.4
	QRENCODE_LIB_PATH=E:/cointools/qrencode-3.4.4/libs
	UPNP_INC_PATH=E:/cointools/miniupnpc-1.6
	UPNP_LIBS_PATH=E:/cointools/miniupnpc-1.6
} else {
	message(UNIX INCLUDE and LIBRARY PATH)
	BOOST_LIB_SUFFIX=-mgw63-mt-1_55

        BOOST_INCLUDE_PATH=/opt/boost-1.55
        BOOST_LIB_PATH=/opt/boost-1.55/stage/lib
        BDB_INCLUDE_PATH=/opt/db-4.8.30/build_unix
        BDB_LIB_PATH=/opt/db-4.8.30/build_unix
        OPENSSL_INCLUDE_PATH=/opt/openssl-1.0.2o/include
        OPENSSL_LIB_PATH=/opt/openssl-1.0.2o
        QRENCODE_INCLUDE_PATH=/opt/qrencode-3.4.4
        QRENCODE_LIB_PATH=/opt/qrencode-3.4.4/libs
        UPNP_INC_PATH=/opt/miniupnpc-1.6
        UPNP_LIBS_PATH=/opt/miniupnpc-1.6
}

OBJECTS_DIR = build
MOC_DIR = build
UI_DIR = build

contains(RELEASE, 1) {
    macx:QMAKE_CXXFLAGS += -isysroot /Applications/Xcode-beta.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.11.sdk -mmacosx-version-min=10.7
    macx:QMAKE_CFLAGS += -isysroot /Applications/Xcode-beta.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.11.sdk -mmacosx-version-min=10.7
    macx:QMAKE_OBJECTIVE_CFLAGS += -isysroot /Applications/Xcode-beta.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.11.sdk -mmacosx-version-min=10.7

    !windows:!macx {
        # Linux: static link
        LIBS += -Wl,-Bstatic
    }
}
contains(RELEASE, 0) {
    QMAKE_CXXFLAGS -= -O2
    QMAKE_CFLAGS -= -O2

    QMAKE_CFLAGS += -g -O0
    QMAKE_CXXCFLAGS += -g -O0
}

!win32 {
	# for extra security against potential buffer overflows: enable GCCs Stack Smashing Protection
	QMAKE_CXXFLAGS *= -fstack-protector-all --param ssp-buffer-size=1
	QMAKE_LFLAGS *= -fstack-protector-all --param ssp-buffer-size=1

	# We need to exclude this for Windows cross compile with MinGW 4.2.x, as it will result in a non-working executable!
	# This can be enabled for Windows, when we switch to MinGW >= 4.4.x.
}
# for extra security on Windows: enable ASLR and DEP via GCC linker flags

win32:QMAKE_LFLAGS *= -Wl,--dynamicbase -Wl,--nxcompat
win32:QMAKE_LFLAGS += -static-libgcc -static-libstdc++

#
# libqrencode (https://fukuchi.org/works/qrencode/index.html) must be installed for support
#
contains(USE_QRENCODE, 1) {
	message(Building with QRCode support)
	DEFINES += USE_QRCODE
	LIBS += -lqrencode
}
contains(USE_DBUS, 1) {
	message(Building with DBUS (Freedesktop notifications) support)
	DEFINES += USE_DBUS
	QT += dbus
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

contains(BITCOIN_NEED_QT_PLUGINS, 1) {
	DEFINES += BITCOIN_NEED_QT_PLUGINS
	QTPLUGIN += qcncodecs qjpcodecs qtwcodecs qkrcodecs qtaccessiblewidgets
}

contains(USE_LEVELDB, 1) {
        message(Building with LevelDB transaction index)
	DEFINES += USE_LEVELDB

	win32 {
                INCLUDEPATH += E:/cointools/leveldb-1.2/include E:/cointools/leveldb-1.2/helpers
                LIBS += E:/cointools/leveldb-1.2/libleveldb.a E:/cointools/leveldb-1.2/libmemenv.a

		SOURCES += src/txdb-leveldb.cpp

                genleveldb.target = E:/cointools/leveldb-1.2/libleveldb.a
		genleveldb.depends = FORCE
                PRE_TARGETDEPS += E:/cointools/leveldb-1.2/libleveldb.a
		QMAKE_EXTRA_TARGETS += genleveldb
	} else {
                INCLUDEPATH += /opt/leveldb-1.2/include /opt/leveldb-1.2/helpers
                LIBS += /opt/leveldb-1.2/libleveldb.a /opt/leveldb-1.2/libmemenv.a

		SOURCES += src/txdb-leveldb.cpp

                genleveldb.target = /opt/leveldb-1.2/libleveldb.a
		genleveldb.depends = FORCE
                PRE_TARGETDEPS += /opt/leveldb-1.2/libleveldb.a
		QMAKE_EXTRA_TARGETS += genleveldb
	}
} else {
	message(Building with Berkeley DB transaction index and wallet database)
	SOURCES += src/txdb-bdb.cpp
}

#
# use: qmake "USE_UPNP=1" ( enabled by default; default)
#  or: qmake "USE_UPNP=0" (disabled by default)
#  or: qmake "USE_UPNP=-" (not supported)
#
contains(USE_UPNP, 1) {
	message(Building with UPNP support)
	INCLUDEPATH += UPNP_INC_PATH
	LIBS += UPNP_LIBS_PATH
}

# regenerate src/build.h
!windows|contains(USE_BUILD_INFO, 1) {
	genbuild.depends = FORCE
	genbuild.commands = cd $$PWD; /bin/sh share/genbuild.sh $$OUT_PWD/build/build.h
	genbuild.target = $$OUT_PWD/build/build.h
	PRE_TARGETDEPS += $$OUT_PWD/build/build.h
	QMAKE_EXTRA_TARGETS += genbuild
	DEFINES += HAVE_BUILD_INFO
}

contains(USE_O3, 1) {
	message(Building O3 optimization flag)
	QMAKE_CXXFLAGS_RELEASE -= -O2
	QMAKE_CFLAGS_RELEASE -= -O2
	QMAKE_CXXFLAGS += -O3
	QMAKE_CFLAGS += -O3
}

QMAKE_CXXFLAGS_WARN_ON = -fdiagnostics-show-option -Wall -Wextra -Wno-ignored-qualifiers -Wformat -Wformat-security -Wno-unused-parameter -Wstack-protector

# Input
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
	src/sync.h \
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
	src/walletdb.h \
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
	src/bitcoinrpc.h \
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
	src/allocators.h \
	src/ui_interface.h \
	src/qt/rpcconsole.h \
	src/version.h \
	src/ntp.h \
	src/netbase.h \
	src/clientversion.h \
	src/qt/multisigaddressentry.h \
	src/qt/multisiginputentry.h \
	src/qt/multisigdialog.h \
	src/qt/secondauthdialog.h \
	src/ies.h \
	src/ipcollector.h

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
	src/sync.cpp \
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
	src/bitcoinrpc.cpp \
	src/rpccrypt.cpp \
	src/rpcdump.cpp \
	src/rpcnet.cpp \
	src/rpcmining.cpp \
	src/rpcwallet.cpp \
	src/rpcblockchain.cpp \
	src/rpcrawtransaction.cpp \
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
	src/ipcollector.cpp

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

# for lrelease/lupdate
# also add new translations to src/qt/bitcoin.qrc under translations/
TRANSLATIONS = $$files(src/qt/locale/bitcoin_*.ts)

isEmpty(QMAKE_LRELEASE) {
        win32:QMAKE_LRELEASE = E:/cointools/Qt/5.4/mingw491_32/bin/lrelease.exe
	else:QMAKE_LRELEASE = $$[QT_INSTALL_BINS]/lrelease
}
isEmpty(QM_DIR):QM_DIR = $$PWD/src/qt/locale

# automatically build translations, so they can be included in resource file
TSQM.name = lrelease ${QMAKE_FILE_IN}
TSQM.input = TRANSLATIONS
TSQM.output = $$QM_DIR/${QMAKE_FILE_BASE}.qm
TSQM.commands = $$QMAKE_LRELEASE ${QMAKE_FILE_IN} -qm ${QMAKE_FILE_OUT}
TSQM.CONFIG = no_link
QMAKE_EXTRA_COMPILERS += TSQM

# "Other files" to show in Qt Creator
OTHER_FILES += \
	doc/*.rst doc/*.txt doc/README README.md res/bitcoin-qt.rc

#
# platform specific defaults, if not overridden on command line
#
isEmpty(BOOST_LIB_SUFFIX) {
	windows:BOOST_LIB_SUFFIX = -mgw63-mt-1_55
	else:BOOST_LIB_SUFFIX = -mt
}
isEmpty(BOOST_THREAD_LIB_SUFFIX) {
	BOOST_THREAD_LIB_SUFFIX = $$BOOST_LIB_SUFFIX
}
isEmpty(BDB_LIB_PATH) {
        windows:BDB_LIB_PATH = C:/db-4.8.30/build_unix
        else:BDB_LIB_PATH = /opt/db-4.8.30/build_unix
}
isEmpty(OPENSSL_LIB_PATH) {
        windows:OPENSSL_LIB_PATH = C:/openssl-1.0.2o
        else:OPENSSL_LIB_PATH = /opt/openssl-1.0.2o/lib
}
isEmpty(BDB_LIB_SUFFIX) {
	BDB_LIB_SUFFIX = -4.8
}
isEmpty(BDB_INCLUDE_PATH) {
        windows:BDB_INCLUDE_PATH = C:/db-4.8.30/build_unix
        else:BDB_INCLUDE_PATH = /opt/db-4.8.30/build_unix
}
isEmpty(OPENSSL_INCLUDE_PATH) {
        windows:OPENSSL_INCLUDE_PATH = C:/openssl-1.0.2o/include
        else:OPENSSL_INCLUDE_PATH = /opt/openssl-1.0.2o/include
}
isEmpty(BOOST_LIB_PATH) {
        windows:BOOST_LIB_PATH = C:/boost-1.55/stage/lib
        else:BOOST_LIB_PATH = /opt/boost-1.55/stage/lib
}
isEmpty(BOOST_INCLUDE_PATH) {
        windows:BOOST_INCLUDE_PATH = C:/boost-1.55/include
        else:BOOST_INCLUDE_PATH = /opt/boost-1.55/include
}

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

!windows:!macx {
	DEFINES += LINUX
	LIBS += -lrt
}

macx:HEADERS += src/qt/macdockiconhandler.h \
				src/qt/macnotificationhandler.h
macx:OBJECTIVE_SOURCES += 	src/qt/macdockiconhandler.mm \
							src/qt/macnotificationhandler.mm
macx:LIBS += -framework Foundation -framework ApplicationServices -framework AppKit
macx:DEFINES += MAC_OSX MSG_NOSIGNAL=0
macx:ICON = src/qt/res/icons/bitcoin.icns
macx:TARGET = "SorachanCoin-qt"
macx:QMAKE_CFLAGS_THREAD += -pthread
macx:QMAKE_LFLAGS_THREAD += -pthread
macx:QMAKE_CXXFLAGS_THREAD += -pthread

#
# Set libraries and includes at end, to use platform-defined defaults if not overridden
#
INCLUDEPATH += $$BOOST_INCLUDE_PATH $$BDB_INCLUDE_PATH $$OPENSSL_INCLUDE_PATH $$QRENCODE_INCLUDE_PATH
LIBS += $$join(BOOST_LIB_PATH,,-L,) $$join(BDB_LIB_PATH,,-L,) $$join(OPENSSL_LIB_PATH,,-L,) $$join(QRENCODE_LIB_PATH,,-L,)
#LIBS += -lssl -lcrypto -ldb_cxx$$BDB_LIB_SUFFIX
LIBS += -lssl -lcrypto -ldb_cxx

#
# -lgdi32 has to happen after -lcrypto (see  #681)
#
windows:LIBS += -lws2_32 -lshlwapi -lmswsock -lole32 -loleaut32 -luuid -lgdi32
LIBS += -lboost_system$$BOOST_LIB_SUFFIX -lboost_filesystem$$BOOST_LIB_SUFFIX -lboost_program_options$$BOOST_LIB_SUFFIX -lboost_thread$$BOOST_THREAD_LIB_SUFFIX
windows:LIBS += -lboost_chrono$$BOOST_LIB_SUFFIX -Wl,-Bstatic -lpthread -Wl,-Bdynamic

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

system($$QMAKE_LRELEASE -silent $$PWD/src/qt/locale/translations.pro)

