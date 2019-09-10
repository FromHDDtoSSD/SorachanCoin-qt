#!/bin/sh
# Copyright (c) 2013-2016 The Bitcoin Core developers
# Copyright (c) 2017-2019 The SorachanCoin Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

PROGNAME=$(basename $0)
CMD_MAKE="make"
(! command -v gmake >/dev/null) || CMD_MAKE="gmake"
command -v autoreconf >/dev/null || \
 (echo "configuration failed, please install autoconf first" && exit 1)

usage() {
 echo "Usage: SorachanCoin ${PROGNAME}"
 echo "Options:"
 echo "-h, --help: View usage"
 echo "--prefix: --prefix=[install path] (e.g. --prefix=/opt/SorachanCoin)"
 echo "--build-unix: Build a UNIX system (e.g. FreeBSD)."
 echo "--with-no-build-library: Use the package without building the necessary libraries."
}

PREFIX=""
WITH_NO_BUILD_LIBRARY="FALSE"
BUILD_UNIX="FALSE"
for OPT in "$@"
do
 case "$OPT" in
  '-h'|'--help')
  usage
  exit 1;;
  --prefix*)
  PREFIX="$OPT";;
  '--with-no-build-library')
  WITH_NO_BUILD_LIBRARY="TRUE";;
  '--build-unix')
  BUILD_UNIX="TRUE";;
 esac
done

WORK_DIR="work"
LIBRARY_DIR="library"
bdb_dir="db-4.8.30"
boost_dir="boost_1_68_0"
libressl_dir="libressl-2.8.2"
srcdir="$(dirname $(realpath $0))"
cd "$srcdir"
mkdir -p "$WORK_DIR"
mkdir -p "$LIBRARY_DIR"

build_bdb() {
 bdb_wget="https://download.oracle.com/berkeley-db/db-4.8.30.NC.tar.gz"
 cd "$srcdir"/"$WORK_DIR"
 mkdir -p "$bdb_dir"
 cd "$bdb_dir"
 wget "$bdb_wget"
 tar zxvf db-4.8.30.NC.tar.gz
 cd db-4.8.30.NC/dbinc
 chmod +w atomic.h
 sed -i -e 's/__atomic_compare_exchange/__db_atomic_compare_exchange/g' atomic.h
 cd ../build_unix/
 ../dist/configure --enable-cxx --disable-shared --with-pic --prefix="$srcdir"/"$LIBRARY_DIR"/"$bdb_dir"
 ${CMD_MAKE}
 ${CMD_MAKE} install
}

build_boost() {
 boost_wget="https://sourceforge.net/projects/boost/files/boost/1.68.0/boost_1_68_0.tar.gz/download"
 cd "$srcdir"/"$WORK_DIR"
 mkdir -p "$boost_dir"
 cd "$boost_dir"
 wget "$boost_wget" -O boost_1_68_0.tar.gz
 tar zxvf boost_1_68_0.tar.gz
 cd boost_1_68_0
 ./bootstrap.sh --with-toolset=gcc
 ./b2 install -j2 --toolset=gcc --variant=release --link=static --threading=multi --with-system --with-filesystem --with-program_options --with-thread --with-chrono --prefix="$srcdir"/"$LIBRARY_DIR"/"$boost_dir"
}

build_libressl() {
 libressl_wget="https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.8.2.tar.gz"
 cd "$srcdir"/"$WORK_DIR"
 mkdir -p "$libressl_dir"
 cd "$libressl_dir"
 wget "$libressl_wget"
 tar zxvf libressl-2.8.2.tar.gz
 cd libressl-2.8.2
 ./config --prefix="$srcdir"/"$LIBRARY_DIR"/"$libressl_dir" shared
 ${CMD_MAKE}
 ${CMD_MAKE} install
}

if [ ${WITH_NO_BUILD_LIBRARY} = "FALSE" ]; then
 cd "$srcdir"/"$LIBRARY_DIR"
 if [ ! -d ${bdb_dir} ]; then
  build_bdb
 fi
 cd "$srcdir"/"$LIBRARY_DIR"
 if [ ! -d ${boost_dir} ]; then
  build_boost
 fi
 cd "$srcdir"/"$LIBRARY_DIR"
 if [ ! -d ${libressl_dir} ]; then
  build_libressl
 fi
fi
if [ ${WITH_NO_BUILD_LIBRARY} = "FALSE"  ]; then
 mv "$srcdir"/src/Makefile.am.library "$srcdir"/src/Makefile.am
else
 mv "$srcdir"/src/Makefile.am.pac "$srcdir"/src/Makefile.am
fi
cd "$srcdir"
autoreconf --install
chmod 700 configure
./configure ${PREFIX}
if [ ${BUILD_UNIX} = "FALSE" ]; then
 ${CMD_MAKE} -C src/leveldb
 ${CMD_MAKE} -C src/leveldb memenv_test
else
 cd ./src/leveldb
 chmod +x ./build_detect_platform
 ./build_detect_platform build_config.mk ./
 make -f makefile.unix-freebsd
 make memenv_test -f makefile.unix-freebsd
 cd ../
fi

echo "Building SorachanCoin is ready."

