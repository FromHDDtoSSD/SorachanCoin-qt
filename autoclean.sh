#!/bin/sh
# Copyright (c) 2013-2016 The Bitcoin Core developers
# Copyright (c) 2017-2019 The SorachanCoin Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

CMD_MAKE="make"
(! command -v gmake >/dev/null) || CMD_MAKE="gmake"

${CMD_MAKE} clean
${CMD_MAKE} -C src/leveldb clean

WORK_DIR="work"
LIBRARY_DIR="library"
srcdir="$(dirname $(realpath $0))"
cd "$srcdir"
rm -rf "$WORK_DIR"
rm -rf "$LIBRARY_DIR"

rm -f Makefile
rm -f Makefile.in
rm -f aclocal.m4
rm -rf autom4te.cache
rm -f config.h
rm -f config.h.in
rm -f config.log
rm -f config.status
rm -f depcomp
rm -f install-sh
rm -f missing
rm -f stamp-h1
rm -f compile
rm -f configure

if [ -f ${srcdir}/src/Makefile.am.sqlite ]; then
 if [ -f ${srcdir}/src/Makefile.am ]; then
  if [ -f ${srcdir}/src/Makefile.am.library ]; then
   mv "$srcdir"/src/Makefile.am "$srcdir"/src/Makefile.am.pac
  fi
  if [ -f ${srcdir}/src/Makefile.am.pac ]; then
   mv "$srcdir"/src/Makefile.am "$srcdir"/src/Makefile.am.library
  fi
 fi
else
 if [ -f ${srcdir}/src/Makefile.am ]; then
  mv "$srcdir"/src/Makefile.am "$srcdir"/src/Makefile.am.sqlite
 fi
fi
