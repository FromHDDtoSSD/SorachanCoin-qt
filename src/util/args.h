// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ARGS_H
#define BITCOIN_ARGS_H

//#if defined(HAVE_CONFIG_H)
//# include <config/bitcoin-config.h>
//#endif

#include <vector>
#include <set>
#include <map>
#include <file_operate/fs.h>
#include <sync/lsync.h>
#include <thread/threadsafety.h>
#include <const/attributes.h>
#include <const/no_instance.h>

class bool_arg {
private:
    bool flag;
public:
    explicit bool_arg() : flag(false) {}
    explicit bool_arg(bool b) : flag(b) {}
    bool_arg(const bool_arg &obj) : flag(obj.flag) {}
    bool_arg &operator=(const bool &obj) {
        flag = obj;
        return *this;
    }
    bool_arg &operator=(const bool_arg &obj) {
        flag = obj.flag;
        return *this;
    }
    operator bool() const {
        return flag;
    }
};

namespace args_bool
{
    extern bool_arg fUseMemoryLog; //(false)
    extern bool_arg fConfChange; //(false)
    extern bool_arg fUseFastIndex; //(false)
    extern bool_arg fNoListen; //(false)
    extern bool_arg fDebug; //(false)
    extern bool_arg fDebugNet; //(false)
    extern bool_arg fPrintToConsole; //(false)
    extern bool_arg fPrintToDebugger; //(false)
    extern bool_arg fRequestShutdown; //(false)
    extern bool_arg fShutdown; //(false)
    extern bool_arg fDaemon; //(false)
    extern bool_arg fServer; //(false)
    extern bool_arg fCommandLine; //(false)
    extern bool_arg fTestNet; //(false)
    extern bool_arg fLogTimestamps; //(false)
    extern bool_arg fReopenDebugLog; //(false)
    extern bool_arg fMemoryLockPermissive; //(false)
}

namespace args_uint
{
    extern unsigned int nNodeLifespan; // = 0;
}

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

struct Arg {
    std::string m_help_param;
    std::string m_help_text;
    bool m_debug_only;
    Arg(const std::string &help_param, const std::string &help_text, bool debug_only) :
        m_help_param(help_param), m_help_text(help_text), m_debug_only(debug_only) {}
};

class init : private no_instance
{
protected: // to class config
    static void InterpretNegativeSetting(std::string name, std::map<std::string, std::string> &mapSettingsRet);
};

class config : public init
{
private:
    static std::map<std::string, std::vector<std::string> > GUARDED_BY(cs_args) mapConfigArgs;
    static void createConf();
    static std::string randomStrGen(int length);
protected:    // to class map_arg
    static CCriticalSection cs_args;
    NODISCARD static bool ReadConfigFile(std::map<std::string, std::string> &mapSettingsRet, std::map<std::string, std::vector<std::string> > &mapMultiSettingsRet);
};

// Return : string argument or default(arg) value
class map_arg : public config
{
private:
    static std::map<std::string, std::string> GUARDED_BY(cs_args) mapArgs;
    static std::map<std::string, std::vector<std::string> > GUARDED_BY(cs_args) mapMultiArgs;
    static std::map<OptionsCategory, std::map<std::string, Arg> > GUARDED_BY(cs_args) mapAvailableArgs;

    static bool IsArgKnown(const std::string &key);
public:
    NODISCARD static bool ParseParameters(int argc, const char *const argv[], std::string *error=nullptr);
    NODISCARD static bool ReadConfigFile() {return config::ReadConfigFile(mapArgs, mapMultiArgs);}

    static size_t GetMapArgsCount(const std::string &target) {
        return mapArgs.count(target);
    }
    static std::string GetMapArgsString(const std::string &key) {
        return mapArgs[key];
    }
    static void SetMapArgsString(const std::string &key, const std::string &value) {
        mapArgs[key] = value;
    }

    static std::vector<std::string> GetMapMultiArgsString(const std::string &key) {
        return mapMultiArgs[key];
    }

    /**
    * Return string argument or default value
    *
    * @param strArg Argument to get (e.g. "-foo")
    * @param default (e.g. "1")
    * @return command-line argument or default value
    */
    static std::string GetArg(const std::string &strArg, const std::string &strDefault);

    /**
    * Return 64-bit integer argument or default value
    *
    * @param strArg Argument to get (e.g. "-foo")
    * @param default (e.g. 1)
    * @return command-line argument (0 if invalid number) or default value
    */
    static int64_t GetArg(const std::string &strArg, int64_t nDefault);

    /**
    * Return 32-bit integer argument or default value
    *
    * @param strArg Argument to get (e.g. "-foo")
    * @param default (e.g. 1)
    * @return command-line argument (0 if invalid number) or default value
    */
    static int32_t GetArgInt(const std::string &strArg, int32_t nDefault);

    /**
    * Return 32-bit unsigned integer argument or default value
    *
    * @param strArg Argument to get (e.g. "-foo")
    * @param default (e.g. 1)
    * @return command-line argument (0 if invalid number) or default value
    */
    static uint32_t GetArgUInt(const std::string &strArg, uint32_t nDefault);

    /**
    * Return boolean argument or default value
    *
    * @param strArg Argument to get (e.g. "-foo")
    * @param default (true or false)
    * @return command-line argument or default value
    */
    static bool GetBoolArg(const std::string &strArg, bool fDefault = false);

    /**
    * Set an argument if it doesn't already have a value
    *
    * @param strArg Argument to set (e.g. "-foo")
    * @param strValue Value (e.g. "1")
    * @return true if argument gets set, false if it already had a value
    */
    static bool SoftSetArg(const std::string &strArg, const std::string &strValue);

    /**
    * Set a boolean argument if it doesn't already have a value
    *
    * @param strArg Argument to set (e.g. "-foo")
    * @param fValue Value (e.g. false)
    * @return true if argument gets set, false if it already had a value
    */
    static bool SoftSetBoolArg(const std::string &strArg, bool fValue);

    /**
     * Add argument
     */
    static void AddArg(const std::string &name, const std::string &help, const bool debug_only, const OptionsCategory &cat);

    /**
    * Timing-attack-resistant comparison.
    * Takes time proportional to length
    * of first argument.
    */
    template <typename T>
    static bool TimingResistantEqual(const T &a, const T &b) {
        if (b.size() == 0)
            return a.size() == 0;

        size_t accumulator = a.size() ^ b.size();
        for (size_t i = 0; i < a.size(); ++i)
            accumulator |= a[i] ^ b[i % b.size()];

        return accumulator == 0;
    }
};

class ArgsManager
{
private:
    mutable CCriticalSection cs_args;
    mutable std::map<std::string, std::vector<std::string> > m_override_args GUARDED_BY(cs_args);
    mutable std::map<std::string, std::vector<std::string> > m_config_args GUARDED_BY(cs_args);
    mutable std::string m_network GUARDED_BY(cs_args);
    mutable std::set<std::string> m_network_only_args GUARDED_BY(cs_args);
    std::map<OptionsCategory, std::map<std::string, Arg> > m_available_args GUARDED_BY(cs_args);
    std::set<std::string> m_config_sections GUARDED_BY(cs_args);

    NODISCARD bool ReadConfigStream(std::istream &stream, std::string &error, bool ignore_invalid_keys = false);
    ArgsManager();
    ~ArgsManager();

public:
    /**
     * interface
     */
    CCriticalSection &get_cs_args() const {return cs_args;}
    std::map<std::string, std::vector<std::string>> &get_override_args() const {return m_override_args;}
    std::map<std::string, std::vector<std::string>> &get_config_args() const {return m_config_args;}
    std::string &get_network() const {return m_network;}
    std::set<std::string> &get_network_only_args() const {return m_network_only_args;}

    /**
     * instance
     */
    static ArgsManager &get_instance() {
        static ArgsManager obj;
        return obj;
    }

    /**
     * Select the network in use
     */
    void SelectConfigNetwork(const std::string &network);

    /**
     * Parse args and configure file
     */
    NODISCARD bool ParseParameters(int argc, const char *const argv[], std::string &error);
    NODISCARD bool ReadConfigFiles(std::string &error, bool ignore_invalid_keys = false);

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
        LOCK(cs_args);
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

namespace arginit {
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

    /**
     * Most paths passed as configuration arguments are treated as relative to
     * the datadir if they are not absolute.
     *
     * @return The normalized path.
     */
    fs::path GetConfigFile(const std::string &confPath);

    /**
    * setup logging
    */
    void SetupServerArgs();
} // namespace arginit

#define ARGS ArgsManager::get_instance()

#endif
