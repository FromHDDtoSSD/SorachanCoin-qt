// Copyright (c) 2018-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SORACHANCOIN_MINIWIONDOW_H
#define SORACHANCOIN_MINIWIONDOW_H
#if defined(QT_GUI) && defined(WIN32)

#include <winapi/common.h>

#define IDS_MINIW_TITLE                        L"SorachanCoin-Core mini window"
#define IDS_MINIW_WINDOWCLASSNAME              L"prediction-system-mini-window"
#define IDS_MINIW_HIDECLASSNAME                L"prediction-system-mini-hide"

constexpr int MINIW_WIDTH = 400;
constexpr int MINIW_HEIGHT = 150;
constexpr int MINIW_MARGIN = 50;

#endif
#endif // SORACHANCOIN_MINIWIONDOW_H
