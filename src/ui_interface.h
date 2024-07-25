// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2012 The Bitcoin developers
// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UI_INTERFACE_H
#define BITCOIN_UI_INTERFACE_H

#include <string>
#include <boost/signals2/signal.hpp>
#include <boost/signals2/last_value.hpp>
#include <util.h>

class CBasicKeyStore;
class CWallet;

//
// General change type (added, updated, removed)
//
enum ChangeType
{
    CT_NEW,
    CT_UPDATED,
    CT_DELETED
};

//
// Signals for UI communication
// Singleton Class
//
class CClientUIInterface
{
private:
    CClientUIInterface() {}

public:
    // Singleton Class
    static CClientUIInterface &get() {
        static CClientUIInterface uiInterface;
        return uiInterface;
    }

    /** Flags for CClientUIInterface::ThreadSafeMessageBox */
    enum MessageBoxFlags
    {
        YES                   = 0x00000002,
        OK                    = 0x00000004,
        NO                    = 0x00000008,
        YES_NO                = (YES|NO),
        CANCEL                = 0x00000010,
        APPLY                 = 0x00000020,
        CLOSE                 = 0x00000040,
        OK_DEFAULT            = 0x00000000,
        YES_DEFAULT           = 0x00000000,
        NO_DEFAULT            = 0x00000080,
        CANCEL_DEFAULT        = 0x80000000,
        ICON_EXCLAMATION      = 0x00000100,
        ICON_HAND             = 0x00000200,
        ICON_WARNING          = ICON_EXCLAMATION,
        ICON_ERROR            = ICON_HAND,
        ICON_QUESTION         = 0x00000400,
        ICON_INFORMATION      = 0x00000800,
        ICON_STOP             = ICON_HAND,
        ICON_ASTERISK         = ICON_INFORMATION,
        ICON_MASK             = (0x00000100|0x00000200|0x00000400|0x00000800),
        FORWARD               = 0x00001000,
        BACKWARD              = 0x00002000,
        RESET                 = 0x00004000,
        HELP                  = 0x00008000,
        MORE                  = 0x00010000,
        SETUP                 = 0x00020000,

        //
        // Force blocking, modal message box dialog (not just OS notification)
        //
        MODAL                 = 0x00040000,

        //
        // Predefined combinations for certain default usage cases
        //
        MSG_INFORMATION = ICON_INFORMATION,
        MSG_WARNING = (ICON_WARNING | OK | MODAL),
        MSG_ERROR = (ICON_ERROR | OK | MODAL),
        MSG_QUESTION = (ICON_QUESTION | YES_NO)
    };

    /** Show message box. */
    // Please use ThreadSafeMessageOk and ThreadSafeMessageAsk only with Qt.
    boost::signals2::signal<void (const std::string &message, const std::string &caption, int style)> ThreadSafeMessageBox;
#ifdef QT_GUI
    boost::signals2::signal<void (const std::string &message, const std::string &caption, const std::string &detail, unsigned int style)> ThreadSafeMessageOk;
    boost::signals2::signal<bool (const std::string &message, const std::string &caption, const std::string &detail, unsigned int style), boost::signals2::last_value<bool> > ThreadSafeMessageAsk;
#endif

    /** Ask the user whether they want to pay a fee or not. */
    boost::signals2::signal<bool (int64_t nFeeRequired, const std::string &strCaption), boost::signals2::last_value<bool> > ThreadSafeAskFee;

    /** Handle a URL passed at the command line. */
    boost::signals2::signal<void (const std::string &strURI)> ThreadSafeHandleURI;

    /** Progress message during initialization. */
    boost::signals2::signal<void (const std::string &message)> InitMessage;

    /** Initiate client shutdown. */
    boost::signals2::signal<void ()> QueueShutdown;

    /** Translate a message to the native language of the user. */
    boost::signals2::signal<std::string (const char *psz)> Translate;

    /** Block chain changed. */
    boost::signals2::signal<void ()> NotifyBlocksChanged;

    /** Number of network connections changed. */
    boost::signals2::signal<void (int newNumConnections)> NotifyNumConnectionsChanged;

    //
    // New, updated or cancelled alert.
    // @note called with lock CUnsignedAlert::cs_mapAlerts held.
    //
    boost::signals2::signal<void (const uint256 &hash, ChangeType status)> NotifyAlertChanged;

    //
    // This is a static method that connects from the CUI.
    // It either writes to the log or does nothing.
    //
    static int noui_ThreadSafeMessageBox(const std::string &message, const std::string &caption, int style);
    static bool noui_ThreadSafeAskFee(int64_t nFeeRequired, const std::string &strCaption);
    //static void noui_ThreadSafeMessageOk(const std::string &message, const std::string &caption, const std::string &detail, unsigned int style);
    //static bool noui_ThreadSafeMessageAsk(const std::string &message, const std::string &caption, const std::string &detail, unsigned int style);
};

//
// Translation function: Call Translate signal on UI interface, which returns a boost::optional result.
// If no translation slot is registered, nothing is returned, and simply return the input.
//
static std::string _(const char *psz)
{
    boost::optional<std::string> rv = CClientUIInterface::get().Translate(psz);
    return rv ? (*rv) : psz;
}

//!
//! This is a class that displays information and warning message boxes.
//! e.g. fMessage ? QMB(QMB::M_ERROR).setText(_("Failed to read from CDataStream.")).exec(): 0;
//!
class QMB
{
public:
    enum status {
        M_INFO,
        M_QUESTION,
        M_ERROR
    };

    QMB() = delete;
    QMB(status s) {
        if(s == M_INFO)
            title = _("Confirmation");
        else if (s == M_QUESTION)
            title = _("Question");
        else if (s == M_ERROR)
            title = _("Error");
        icon = s;
    }

    QMB &setText(const std::string &messageIn, const std::string &detailIn = std::string("")) {
        message = messageIn;
        detail = detailIn;
        return *this;
    }

#ifdef QT_GUI
    int exec() {
        CClientUIInterface::get().ThreadSafeMessageOk(message, title, detail,
        ((icon == M_INFO) ? CClientUIInterface::ICON_INFORMATION : CClientUIInterface::ICON_WARNING) | CClientUIInterface::MODAL);
        return 0;
    }

    bool ask() {
        return CClientUIInterface::get().ThreadSafeMessageAsk(message, title, detail,
        ((icon == M_QUESTION) ? CClientUIInterface::ICON_QUESTION : CClientUIInterface::ICON_WARNING) | CClientUIInterface::MODAL);
    }
#else
    int exec() {
        return 0;
    }

    bool ask() {
        return true;
    }
#endif

private:
    std::string title;
    std::string message;
    std::string detail;
    status icon;
};

#endif
