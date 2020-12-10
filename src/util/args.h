// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ARGS_H
#define BITCOIN_ARGS_H

#include <vector>
#include <set>
#include <file_operate/fs.h>
#include <sync/lsync.h>
#include <thread/threadsafety.h>
#include <const/attributes.h>

enum class OptionsCategory {
    OPTIONS,
    CONNECTION,
    WALLET,
    WALLET_DEBUG_TEST,
    ZMQ,
    DEBUG_TEST,
    CHAINPARAMS,
    NODE_RELAY,
    BLOCK_CREATION,
    RPC,
    GUI,
    COMMANDS,
    REGISTER_COMMANDS,

    HIDDEN // Always the last option to avoid printing these in the help
};

class ArgsManager
{
protected:
    struct Arg {
        std::string m_help_param;
        std::string m_help_text;
        bool m_debug_only;

        Arg(const std::string &help_param, const std::string &help_text, bool debug_only) :
            m_help_param(help_param), m_help_text(help_text), m_debug_only(debug_only) {}
    };

    mutable LCCriticalSection cs_args;
    mutable std::map<std::string, std::vector<std::string> > m_override_args GUARDED_BY(cs_args);
    mutable std::map<std::string, std::vector<std::string> > m_config_args GUARDED_BY(cs_args);
    mutable std::string m_network GUARDED_BY(cs_args);
    mutable std::set<std::string> m_network_only_args GUARDED_BY(cs_args);
    std::map<OptionsCategory, std::map<std::string, Arg>> m_available_args GUARDED_BY(cs_args);
    std::set<std::string> m_config_sections GUARDED_BY(cs_args);

    NODISCARD bool ReadConfigStream(std::istream &stream, std::string &error, bool ignore_invalid_keys = false);

public:
    ArgsManager();
    LCCriticalSection &get_cs_args() const noexcept {return cs_args;}
    std::map<std::string, std::vector<std::string> > &get_override_args() const noexcept {return m_override_args;}
    std::map<std::string, std::vector<std::string> > &get_config_args() const noexcept {return m_config_args;}
    std::string &get_network() const noexcept {return m_network;}
    std::set<std::string> &get_network_only_args() const noexcept {return m_network_only_args;}

    /**
     * Select the network in use
     */
    void SelectConfigNetwork(const std::string &network);

    NODISCARD bool ParseParameters(int argc, const char* const argv[], std::string &error);
    NODISCARD bool ReadConfigFiles(std::string &error, bool ignore_invalid_keys = false) noexcept;

    /**
     * Log warnings for options in m_section_only_args when
     * they are specified in the default section but not overridden
     * on the command line or in a network-specific section in the
     * config file.
     */
    const std::set<std::string> GetUnsuitableSectionOnlyArgs() const;

    /**
     * Log warnings for unrecognized section names in the config file.
     */
    const std::set<std::string> GetUnrecognizedSections() const;

    /**
     * Return a vector of strings of the given argument
     *
     * @param strArg Argument to get (e.g. "-foo")
     * @return command-line arguments
     */
    std::vector<std::string> GetArgs(const std::string &strArg) const;

    /**
     * Return true if the given argument has been manually set
     *
     * @param strArg Argument to get (e.g. "-foo")
     * @return true if the argument has been set
     */
    bool IsArgSet(const std::string &strArg) const;

    /**
     * Return true if the argument was originally passed as a negated option,
     * i.e. -nofoo.
     *
     * @param strArg Argument to get (e.g. "-foo")
     * @return true if the argument was passed negated
     */
    bool IsArgNegated(const std::string &strArg) const;

    /**
     * Return string argument or default value
     *
     * @param strArg Argument to get (e.g. "-foo")
     * @param strDefault (e.g. "1")
     * @return command-line argument or default value
     */
    std::string GetArg(const std::string &strArg, const std::string &strDefault) const;

    /**
     * Return integer argument or default value
     *
     * @param strArg Argument to get (e.g. "-foo")
     * @param nDefault (e.g. 1)
     * @return command-line argument (0 if invalid number) or default value
     */
    int64_t GetArg(const std::string &strArg, int64_t nDefault) const;

    /**
     * Return boolean argument or default value
     *
     * @param strArg Argument to get (e.g. "-foo")
     * @param fDefault (true or false)
     * @return command-line argument or default value
     */
    bool GetBoolArg(const std::string &strArg, bool fDefault) const;

    /**
     * Set an argument if it doesn't already have a value
     *
     * @param strArg Argument to set (e.g. "-foo")
     * @param strValue Value (e.g. "1")
     * @return true if argument gets set, false if it already had a value
     */
    bool SoftSetArg(const std::string &strArg, const std::string &strValue);

    /**
     * Set a boolean argument if it doesn't already have a value
     *
     * @param strArg Argument to set (e.g. "-foo")
     * @param fValue Value (e.g. false)
     * @return true if argument gets set, false if it already had a value
     */
    bool SoftSetBoolArg(const std::string &strArg, bool fValue);

    // Forces an arg setting. Called by SoftSetArg() if the arg hasn't already
    // been set. Also called directly in testing.
    void ForceSetArg(const std::string &strArg, const std::string &strValue);

    /**
     * Looks for -regtest, -testnet and returns the appropriate BIP70 chain name.
     * @return CBaseChainParams::MAIN by default; raises runtime error if an invalid combination is given.
     */
    std::string GetChainName() const;

    /**
     * Add argument
     */
    void AddArg(const std::string &name, const std::string &help, const bool debug_only, const OptionsCategory &cat);

    /**
     * Add many hidden arguments
     */
    void AddHiddenArgs(const std::vector<std::string> &args);

    /**
     * Clear available arguments
     */
    void ClearArgs() {
        LLOCK(cs_args);
        m_available_args.clear();
    }

    /**
     * Get the help string
     */
    std::string GetHelpMessage() const;

    /**
     * Check whether we know of this arg
     */
    bool IsArgKnown(const std::string &key) const;
};

/**
 * @return true if help has been requested via a command-line arg
 */
bool HelpRequested(const ArgsManager &args);

/** Add help options to the args manager */
void SetupHelpOptions(ArgsManager &args);

/**
 * Format a string to be used as group of options in help messages
 *
 * @param message Group name (e.g. "RPC server options:")
 * @return the formatted string
 */
std::string HelpMessageGroup(const std::string &message);

/**
 * Format a string to be used as option description in help messages
 *
 * @param option Option message (e.g. "-rpcuser=<user>")
 * @param message Option description (e.g. "Username for JSON-RPC connections")
 * @return the formatted string
 */
std::string HelpMessageOpt(const std::string &option, const std::string &message);

fs::path GetConfigFile(const std::string &confPath) noexcept;

extern ArgsManager gArgs;
#endif
