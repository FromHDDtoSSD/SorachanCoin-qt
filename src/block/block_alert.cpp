// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <block/block_alert.h>
#include <checkpoints.h>
#include <kernel.h>
#include <alert.h>

std::string block_alert::GetWarnings(std::string strFor)
{
    int nPriority = 0;
    std::string strStatusBar;
    std::string strRPC;
    if (map_arg::GetBoolArg("-testsafemode"))
        strRPC = "test";

    // Misc warnings like out of disk space and clock is wrong
    if (! excep::get_strMiscWarning().empty()) {
        nPriority = 1000;
        strStatusBar = excep::get_strMiscWarning();
    }

    // if detected unmet upgrade requirement enter safe mode
    // Note: Modifier upgrade requires blockchain redownload if past protocol switch
    if (bitkernel<uint256>::IsFixedModifierInterval(bitkernel<uint256>::nModifierUpgradeTime + util::nOneDay)) {    // 1 day margin
        nPriority = 5000;
        strStatusBar = strRPC = "WARNING: Blockchain redownload required approaching or past v.1.0.0 upgrade deadline.";
    }

    // if detected invalid checkpoint enter safe mode
    if (Checkpoints::manage::getHashInvalidCheckpoint() != 0) {
        nPriority = 3000;
        strStatusBar = strRPC = _("WARNING: Invalid checkpoint found! Displayed transactions may not be correct! You may need to upgrade, or notify developers.");
    }

    // Alerts
    {
        LOCK(CUnsignedAlert::cs_mapAlerts);
        for(std::pair<const uint256, CAlert> &item: CAlert::mapAlerts) {
            const CAlert &alert = item.second;
            if (alert.AppliesToMe() && alert.nPriority > nPriority) {
                nPriority = alert.nPriority;
                strStatusBar = alert.strStatusBar;
                if (nPriority > 1000) strRPC = strStatusBar;
            }
        }
    }

    if (strFor == "statusbar")
        return strStatusBar;
    else if (strFor == "rpc")
        return strRPC;

    assert(!"block_alert::GetWarnings() : invalid parameter");
    return "error";
}
