// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#ifndef _BITCOINALERT_H_
#define _BITCOINALERT_H_ 1

#include <set>
#include <string>

#include "uint256.h"
#include "util.h"
#include "sync.h"

class CNode;

/** Alerts are for notifying old versions if they become too obsolete and
 * need to upgrade.  The message is displayed in the status bar.
 * Alert messages are broadcast as a vector of signed data.  Unserializing may
 * not read the entire buffer if the alert is for a newer version, but older
 * versions can still relay the original data.
 */
class CUnsignedAlert
{
//private:
    // CUnsignedAlert(const CUnsignedAlert &); // {}
    // CUnsignedAlert &operator=(const CUnsignedAlert &); // {}

public:
    static CCriticalSection cs_mapAlerts;

public:
    int nVersion;
    int64_t nRelayUntil;                // when newer nodes stop relaying to newer nodes
    int64_t nExpiration;
    int nID;
    int nCancel;
    std::set<int> setCancel;
    int nMinVer;                        // lowest version inclusive
    int nMaxVer;                        // highest version inclusive
    std::set<std::string> setSubVer;    // empty matches all
    int nPriority;

    //
    // Actions
    //
    std::string strComment;
    std::string strStatusBar;
    std::string strReserved;

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
        nVersion = this->nVersion;

        READWRITE(this->nRelayUntil);
        READWRITE(this->nExpiration);
        READWRITE(this->nID);
        READWRITE(this->nCancel);
        READWRITE(this->setCancel);
        READWRITE(this->nMinVer);
        READWRITE(this->nMaxVer);
        READWRITE(this->setSubVer);
        READWRITE(this->nPriority);

        READWRITE(this->strComment);
        READWRITE(this->strStatusBar);
        READWRITE(this->strReserved);
    )

    void SetNull();
    std::string ToString() const;
};

/** An alert is a combination of a serialized CUnsignedAlert and a signature. */
class CAlert : public CUnsignedAlert
{
//private:
    // CAlert(const CAlert &); // {}
    // CAlert &operator=(const CAlert &); // {}

private:
    //
    // Public keys
    //
    static const char *pszMainKey;
    static const char *pszTestKey;

public:
    static std::map<uint256, CAlert> mapAlerts;

    std::vector<unsigned char> vchMsg;
    std::vector<unsigned char> vchSig;

    CAlert() {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->vchMsg);
        READWRITE(this->vchSig);
    )

    void SetNull();
    bool IsNull() const;
    uint256 GetHash() const;
    bool IsInEffect() const;
    bool Cancels(const CAlert& alert) const;
    bool AppliesTo(int nVersion, std::string strSubVerIn) const;
    bool AppliesToMe() const;
    bool RelayTo(CNode* pnode) const;
    bool CheckSignature() const;
    bool ProcessAlert();

    //
    // Get copy of (active) alert object by hash. Returns a null alert if it is not found.
    //
    static CAlert getAlertByHash(const uint256 &hash);
};

#endif
//@
