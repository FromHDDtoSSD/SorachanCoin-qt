// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MACRO_H
#define BITCOIN_MACRO_H

#define BEGIN(a)            ((char *)&(a))
#define END(a)              ((char *)&((&(a))[1]))
#define UBEGIN(a)           ((unsigned char *)&(a))
#define UEND(a)             ((unsigned char *)&((&(a))[1]))
#define ARRAYLEN(array)     (sizeof(array)/sizeof((array)[0]))

#define UVOIDBEGIN(a)       ((void *)&(a))
#define CVOIDBEGIN(a)       ((const void *)&(a))
#define UINTBEGIN(a)        ((uint32_t *)&(a))
#define CUINTBEGIN(a)       ((const uint32_t *)&(a))

#endif
