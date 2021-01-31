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
#define IDS_BUTTON_GET_ADDRESS                 _("deposit address").c_str()
#define IDS_EDIT_WALLET_STATUS                 _("").c_str()
#define IDM_TO_STAKING                         _("staking ...").c_str()
#define IDM_TO_UNLOCK                          _("unlock SORA").c_str()
#define IDM_TO_ENCRYPT                         _("encrypt SORA").c_str()

constexpr int IDC_BUTTON_GET_ADDRESS = 2000;
constexpr int IDC_BUTTON_WALLET_STATUS = 2001;
constexpr int IDC_EDIT_WALLET_STATUS = 2002;

constexpr int MINIW_WIDTH = 500;
constexpr int MINIW_HEIGHT = 150;
constexpr int MINIW_MARGIN = 50;
constexpr int TASKTRY_ID = 1000;
constexpr int MINIW_TIMER = 1001;

constexpr int FONT_CHEIGHT = 32;

#define WM_TASKTRAY_CALLBACK_MESSAGE WM_APP + 1

#endif
#endif // SORACHANCOIN_MINIWIONDOW_H
