// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QTIPCSERVER_H
#define QTIPCSERVER_H

// Define Bitcoin-Qt message queue name
#define BITCOINURI_QUEUE_NAME "SorachanCoinURI"

namespace qti_server {
void ipcScanRelay(int argc, char *argv[]);
void ipcInit(int argc, char *argv[]);
}

#endif // QTIPCSERVER_H
