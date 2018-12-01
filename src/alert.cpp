//
// Alert system
//

#include <boost/foreach.hpp>
#include <map>

#include "alert.h"
#include "key.h"
#include "net.h"
#include "ui_interface.h"

CCriticalSection CUnsignedAlert::cs_mapAlerts;
std::map<uint256, CAlert> CAlert::mapAlerts;
const char *CAlert::pszMainKey = "04c98776bba066e7dafe8c132375543e90fa59fb9b42437e3e419b67b6715040f6220c589c17715a4b4cfe28d4aaac5bb3a5d8322be8bfdbd6260b38f0e4f8ac4b";
const char *CAlert::pszTestKey = "048865826ff800e4ca41d1432e848ddf34475a7334097fe53c0e03240522c50b79a1ee1a1f17bb058ea00f45edd39c033e0117ad5e7e86d52e92a114eb8fb24a62";

//
// How can create a new pszMainKey?
// (https://bitcointalk.org/index.php?topic=2941743.0)
// openssl genpkey -algorithm ec -outform der -pkeyopt ec_paramgen_curve:secp256k1 -text
// Thank you.
//

void CUnsignedAlert::SetNull()
{
    nVersion = 1;
    nRelayUntil = 0;
    nExpiration = 0;
    nID = 0;
    nCancel = 0;
    setCancel.clear();
    nMinVer = 0;
    nMaxVer = 0;
    setSubVer.clear();
    nPriority = 0;

    strComment.clear();
    strStatusBar.clear();
    strReserved.clear();
}

std::string CUnsignedAlert::ToString() const
{
    std::string strSetCancel;
    BOOST_FOREACH(int n, setCancel)
    {
        strSetCancel += strprintf("%d ", n);
    }

    std::string strSetSubVer;
    BOOST_FOREACH(std::string str, setSubVer)
    {
        strSetSubVer += "\"" + str + "\" ";
    }

    return strprintf(
        "CAlert(\n"
        "    nVersion     = %d\n"
        "    nRelayUntil  = %" PRId64 "\n"
        "    nExpiration  = %" PRId64 "\n"
        "    nID          = %d\n"
        "    nCancel      = %d\n"
        "    setCancel    = %s\n"
        "    nMinVer      = %d\n"
        "    nMaxVer      = %d\n"
        "    setSubVer    = %s\n"
        "    nPriority    = %d\n"
        "    strComment   = \"%s\"\n"
        "    strStatusBar = \"%s\"\n"
        ")\n",
        nVersion,
        nRelayUntil,
        nExpiration,
        nID,
        nCancel,
        strSetCancel.c_str(),
        nMinVer,
        nMaxVer,
        strSetSubVer.c_str(),
        nPriority,
        strComment.c_str(),
        strStatusBar.c_str());
}

void CAlert::SetNull()
{
    CUnsignedAlert::SetNull();
    vchMsg.clear();
    vchSig.clear();
}

bool CAlert::IsNull() const
{
    return (nExpiration == 0);
}

uint256 CAlert::GetHash() const
{
    return hash_basis::Hash(vchMsg.begin(), vchMsg.end());
}

bool CAlert::IsInEffect() const
{
    return (bitsystem::GetAdjustedTime() < nExpiration);
}

bool CAlert::Cancels(const CAlert &alert) const
{
    if (! IsInEffect()) {
        return false;    // this was a no-op before 31403
    }
    return (alert.nID <= nCancel || setCancel.count(alert.nID));
}

bool CAlert::AppliesTo(int nVersion, std::string strSubVerIn) const
{
    // TODO: rework for client-version-embedded-in-strSubVer ?
    return (IsInEffect() &&
            nMinVer <= nVersion &&
            nVersion <= nMaxVer &&
            (setSubVer.empty() || setSubVer.count(strSubVerIn)));
}

bool CAlert::AppliesToMe() const
{
    return AppliesTo(version::PROTOCOL_VERSION, format_version::FormatSubVersion(version::CLIENT_NAME, version::CLIENT_VERSION, std::vector<std::string>()));
}

bool CAlert::RelayTo(CNode* pnode) const
{
    if (! IsInEffect()) {
        return false;
    }

    //
    // don't relay to nodes which haven't sent their version message
    //
    if (pnode->nVersion == 0) {
        return false;
    }

    //
    // returns true if wasn't already contained in the set
    //
    if (pnode->setKnown.insert(GetHash()).second) {
        if (AppliesTo(pnode->nVersion, pnode->strSubVer) ||
            AppliesToMe() ||
            bitsystem::GetAdjustedTime() < nRelayUntil) {
            pnode->PushMessage("alert", *this);
            return true;
        }
    }
    return false;
}

bool CAlert::CheckSignature() const
{
    CPubKey key;
    key.Set(hex::ParseHex(args_bool::fTestNet ? pszTestKey : pszMainKey));
    if (! key.Verify(hash_basis::Hash(vchMsg.begin(), vchMsg.end()), vchSig)) {
        return print::error("CAlert::CheckSignature() : verify signature failed");
    }

    // Now unserialize the data
    CDataStream sMsg(vchMsg, SER_NETWORK, version::PROTOCOL_VERSION);
    sMsg >> *(CUnsignedAlert *)this;
    return true;
}

CAlert CAlert::getAlertByHash(const uint256 &hash)
{
    CAlert retval;
    {
        LOCK(CUnsignedAlert::cs_mapAlerts);
        std::map<uint256, CAlert>::iterator mi = CAlert::mapAlerts.find(hash);
        if(mi != CAlert::mapAlerts.end()) {
            retval = mi->second;
        }
    }
    return retval;
}

bool CAlert::ProcessAlert()
{
    if (! CheckSignature()) {
        return false;
    }
    if (! IsInEffect()) {
        return false;
    }

    //
    // alert.nID=max is reserved for if the alert key is
    // compromised. It must have a pre-defined message,
    // must never expire, must apply to all versions,
    // and must cancel all previous alerts or it will be ignored (so an attacker can't send an "everything is OK, don't panic" version that cannot be overridden):
    //
    int maxInt = std::numeric_limits<int>::max();
    if (nID == maxInt) {
        if (!(
                nExpiration == maxInt &&
                nCancel == (maxInt-1) &&
                nMinVer == 0 &&
                nMaxVer == maxInt &&
                setSubVer.empty() &&
                nPriority == maxInt &&
                strStatusBar == "URGENT: Alert key compromised, upgrade required"
                )) {
            return false;
        }
    }

    {
        LOCK(CUnsignedAlert::cs_mapAlerts);

        // Cancel previous alerts
        for (std::map<uint256, CAlert>::iterator mi = CAlert::mapAlerts.begin(); mi != CAlert::mapAlerts.end();)
        {
            const CAlert &alert = (*mi).second;
            if (Cancels(alert)) {
                printf("cancelling alert %d\n", alert.nID);
                CClientUIInterface::uiInterface.NotifyAlertChanged((*mi).first, CT_DELETED);
                CAlert::mapAlerts.erase(mi++);
            } else if (! alert.IsInEffect()) {
                printf("expiring alert %d\n", alert.nID);
                CClientUIInterface::uiInterface.NotifyAlertChanged((*mi).first, CT_DELETED);
                CAlert::mapAlerts.erase(mi++);
            } else {
                mi++;
            }
        }

        // Check if this alert has been cancelled
        BOOST_FOREACH(PAIRTYPE(const uint256, CAlert)&item, CAlert::mapAlerts)
        {
            const CAlert &alert = item.second;
            if (alert.Cancels(*this)) {
                printf("alert already cancelled by %d\n", alert.nID);
                return false;
            }
        }

        // Add to mapAlerts
        CAlert::mapAlerts.insert(std::make_pair(GetHash(), *this));

        // Notify UI if it applies to me
        if(AppliesToMe()) {
            CClientUIInterface::uiInterface.NotifyAlertChanged(GetHash(), CT_NEW);
        }
    }

    printf("accepted alert %d, AppliesToMe()=%d\n", nID, AppliesToMe());
    return true;
}
