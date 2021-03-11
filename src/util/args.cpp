// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <map>
#include <util/args.h>
#include <util/system.h>
#include <const/chainparamsbase.h>
#include <util/strencodings.h>
#include <file_operate/fs.h>
#include <file_operate/iofs.h>
#include <util/c_overload.h>
#include <random/random.h>
#include <debugcs/debugcs.h>

#define ARGS_DEBUG_CS(str) debugcs::instance() << (str) << debugcs::endl()

//
// old core
//

// issue clang: get rid of boost::program_options
#include <boost/program_options/detail/config_file.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/algorithm/string/predicate.hpp> // for startswith() and endswith()

// extern
bool_arg args_bool::fUseMemoryLog(false);
bool_arg args_bool::fConfChange(false);
bool_arg args_bool::fUseFastIndex(false);
bool_arg args_bool::fNoListen(false);
bool_arg args_bool::fDebug(false);
bool_arg args_bool::fDebugNet(false);
bool_arg args_bool::fPrintToConsole(false);
bool_arg args_bool::fPrintToDebugger(false);
bool_arg args_bool::fRequestShutdown(false);
bool_arg args_bool::fShutdown(false);
bool_arg args_bool::fDaemon(false);
bool_arg args_bool::fServer(false);
bool_arg args_bool::fCommandLine(false);
bool_arg args_bool::fTestNet(false);
bool_arg args_bool::fLogTimestamps(false);
bool_arg args_bool::fReopenDebugLog(false);
bool_arg args_bool::fMemoryLockPermissive(false);
unsigned int args_uint::nNodeLifespan = 0;

LCCriticalSection config::cs_args;
std::map<std::string, std::string> map_arg::mapArgs;
std::map<std::string, std::vector<std::string> > map_arg::mapMultiArgs;
std::map<std::string, std::vector<std::string> > config::mapConfigArgs;
std::map<OptionsCategory, std::map<std::string, Arg> > map_arg::mapAvailableArgs;

void init::InterpretNegativeSetting(std::string name, std::map<std::string, std::string> &mapSettingsRet)
{
    // interpret -nofoo as -foo=0 (and -nofoo=0 as -foo=1) as long as -foo not set
    if (name.find("-no") == 0) {
        std::string positive("-");
        positive.append(name.begin() + 3, name.end());
        if (mapSettingsRet.count(positive) == 0) {
            bool value = !map_arg::GetBoolArg(name);
            mapSettingsRet[positive] = (value ? "1" : "0");
        }
    }
}

void config::createConf() {
    std::ofstream pConf;
#if BOOST_FILESYSTEM_VERSION >= 3
    pConf.open(iofs::GetConfigFile().generic_string().c_str());
#else
    pConf.open(iofs::GetConfigFile().string().c_str());
#endif
    pConf << "rpcuser=sora\nrpcpassword="
            + config::randomStrGen(35)
            + "\n\ndaemon=0"
            + "\nserver=0"
            + "\ntestnet=0"
            + "\n\nlisten=1"
            + "\nirc=0"
            + "\n\nrpcallowip=127.0.0.1"
            + "\n";
    pConf.close();
}

std::string config::randomStrGen(int length) {
    static const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

    std::string result;
    result.resize(length);
    for (int32_t i = 0; i < length; ++i) {
        unsigned char bc;
        latest_crypto::random::GetStrongRandBytes(&bc, sizeof(bc));
        result[i] = charset[bc % charset.length()];
        //result[i] = charset[::rand() % charset.length()];
    }
    return result;
}

bool config::ReadConfigFile(std::map<std::string, std::string> &mapSettingsRet, std::map<std::string, std::vector<std::string> > &mapMultiSettingsRet) {
    LLOCK(cs_args);
    fs::ifstream streamConfig(iofs::GetConfigFile());
    if (! streamConfig.good()) {
        config::createConf();
        new(&streamConfig) fs::ifstream(iofs::GetConfigFile());
        if(! streamConfig.good()) {
            return false;
        }
    }

    std::set<std::string> setOptions;
    setOptions.insert("*");

    for (boost::program_options::detail::config_file_iterator it(streamConfig, setOptions), end; it != end; ++it) {
        // Don't overwrite existing settings so command line settings override bitcoin.conf
        std::string strKey = std::string("-") + it->string_key;
        if (mapSettingsRet.count(strKey) == 0) {
            mapSettingsRet[strKey] = it->value[0];
            // interpret nofoo=1 as foo=0 (and nofoo=0 as foo=1) as long as foo not set)
            init::InterpretNegativeSetting(strKey, mapSettingsRet);
        }
        mapMultiSettingsRet[strKey].push_back(it->value[0]);
    }
    return true;
}

bool map_arg::IsArgKnown(const std::string &key) {
    size_t option_index = key.find('.');
    std::string arg_no_net;
    if (option_index == std::string::npos) {
        arg_no_net = key;
    } else {
        arg_no_net = std::string("-") + key.substr(option_index + 1, std::string::npos);
    }

    return true;
    /* after implement AddArg ...
    LLOCK(cs_args);
    for (const auto &arg_map: mapAvailableArgs) {
        if (arg_map.second.count(arg_no_net)) return true;
    }
    return false;
    */
}

bool map_arg::ParseParameters(int argc, const char *const argv[], std::string *error/*=nullptr*/) {
    LLOCK(cs_args);
    mapArgs.clear();
    mapMultiArgs.clear();
    for (int i = 1; i < argc; ++i) {
        std::string str(argv[i]);
        std::string strValue;
        size_t is_index = str.find('=');
        if (is_index != std::string::npos) {
            strValue = str.substr(is_index + 1);
            str = str.substr(0, is_index);
        }
#ifdef WIN32
        std::transform(str.begin(), str.end(), str.begin(), strenc::ToLower);
        if (boost::algorithm::starts_with(str, "/"))
            str = "-" + str.substr(1);
#endif
        if (str[0] != '-')
            break;

        mapArgs[str] = strValue;
        mapMultiArgs[str].push_back(strValue);

        // Check that the arg is known
        if (!(lutil::IsSwitchChar(str[0]) && str.size() == 1)) {
            if (! IsArgKnown(str)) {
                if(error) *error = tfm::format("Invalid parameter %s", str.c_str());
                return false;
            }
        }
    }

    for(const std::pair<std::string,std::string> &entry: mapArgs) {
        std::string name = entry.first;

        //  interpret --foo as -foo (as long as both are not set)
        if (name.find("--") == 0) {
            std::string singleDash(name.begin()+1, name.end());
            if (mapArgs.count(singleDash) == 0) {
                mapArgs[singleDash] = entry.second;
            }
            name = singleDash;
        }

        // interpret -nofoo as -foo=0 (and -nofoo=0 as -foo=1) as long as -foo not set
        init::InterpretNegativeSetting(name, mapArgs);
    }
    return true;
}

std::string map_arg::GetArg(const std::string &strArg, const std::string &strDefault) {
    if (mapArgs.count(strArg)) {
        return mapArgs[strArg];
    }
    return strDefault;
}

int64_t map_arg::GetArg(const std::string &strArg, int64_t nDefault) {
    if (mapArgs.count(strArg)) {
        return strenc::atoi64(mapArgs[strArg]);
    }
    return nDefault;
}

int32_t map_arg::GetArgInt(const std::string &strArg, int32_t nDefault) {
    if (mapArgs.count(strArg)) {
        return strenc::strtol(mapArgs[strArg]);
    }
    return nDefault;
}

uint32_t map_arg::GetArgUInt(const std::string &strArg, uint32_t nDefault) {
    if (mapArgs.count(strArg)) {
        return strenc::strtoul(mapArgs[strArg]);
    }
    return nDefault;
}

bool map_arg::GetBoolArg(const std::string &strArg, bool fDefault /*= false*/) {
    if (mapArgs.count(strArg)) {
        if (mapArgs[strArg].empty()) {
            return true;
        }
        return (strenc::atoi(mapArgs[strArg]) != 0);
    }
    return fDefault;
}

bool map_arg::SoftSetArg(const std::string &strArg, const std::string &strValue) {
    if (mapArgs.count(strArg) || mapMultiArgs.count(strArg)) {
        return false;
    }
    mapArgs[strArg] = strValue;
    mapMultiArgs[strArg].push_back(strValue);
    return true;
}

bool map_arg::SoftSetBoolArg(const std::string &strArg, bool fValue) {
    if (fValue) {
        return map_arg::SoftSetArg(strArg, std::string("1"));
    } else {
        return map_arg::SoftSetArg(strArg, std::string("0"));
    }
}

void map_arg::AddArg(const std::string &name, const std::string &help, const bool debug_only, const OptionsCategory &cat) {
    // Split arg name from its help param
    size_t eq_index = name.find('=');
    if (eq_index == std::string::npos) {
        eq_index = name.size();
    }

    LLOCK(cs_args);
    std::map<std::string, Arg> &arg_map = mapAvailableArgs[cat];
    auto ret = arg_map.emplace(name.substr(0, eq_index), Arg(name.substr(eq_index, name.size() - eq_index), help, debug_only));
    assert(ret.second); // Make sure an insertion actually happened
}

//
// latest core
//

/**
 * Interpret a string argument as a boolean.
 *
 * The definition of atoi() requires that non-numeric string values like "foo",
 * return 0. This means that if a user unintentionally supplies a non-integer
 * argument here, the return value is always false. This means that -foo=false
 * does what the user probably expects, but -foo=true is well defined but does
 * not do what they probably expected.
 *
 * The return value of atoi() is undefined when given input not representable as
 * an int. On most systems this means string value between "-2147483648" and
 * "2147483647" are well defined (this method will return true). Setting
 * -txindex=2147483648 on most systems, however, is probably undefined.
 *
 * For a more extensive discussion of this topic (and a wide range of opinions
 * on the Right Way to change this code), see PR12713.
 */

static bool InterpretBool(const std::string &strValue) {
    if (strValue.empty())
        return true;
    return (::atoi(strValue.c_str()) != 0);
}

/** Internal helper functions for ArgsManager */
class ArgsManagerHelper {
public:
    using MapArgs = std::map<std::string, std::vector<std::string> >;

    /** Determine whether to use config settings in the default section,
     *  See also comments around ArgsManager::ArgsManager() below. */
    static inline bool UseDefaultSection(const ArgsManager &am, const std::string &arg) EXCLUSIVE_LOCKS_REQUIRED(am.cs_args) {
        return (am.get_network() == chainparamsbase::CBaseChainParams::MAIN() || am.get_network_only_args().count(arg) == 0);
    }

    /** Convert regular argument into the network-specific setting */
    static inline std::string NetworkArg(const ArgsManager &am, const std::string &arg) {
        assert(arg.length() > 1 && arg[0] == '-');
        return std::string("-") + am.get_network() + "." + arg.substr(1);
    }

    /** Find arguments in a map and add them to a vector */
    static inline void AddArgs(std::vector<std::string> &res, const MapArgs &map_args, const std::string &arg) {
        auto it = map_args.find(arg);
        if (it != map_args.end()) {
            res.insert(res.end(), it->second.begin(), it->second.end());
        }
    }

    /** Return true/false if an argument is set in a map, and also
     *  return the first (or last) of the possibly multiple values it has
     */
    static inline std::pair<bool,std::string> GetArgHelper(const MapArgs &map_args, const std::string &arg, bool getLast = false) {
        auto it = map_args.find(arg);
        if (it == map_args.end() || it->second.empty()) {
            return std::make_pair(false, std::string());
        }

        if (getLast) {
            return std::make_pair(true, it->second.back());
        } else {
            return std::make_pair(true, it->second.front());
        }
    }

    /* Get the string value of an argument, returning a pair of a boolean
     * indicating the argument was found, and the value for the argument
     * if it was found (or the empty string if not found).
     */
    static inline std::pair<bool, std::string> GetArg(const ArgsManager &am, const std::string &arg) {
        LLOCK(am.get_cs_args());
        std::pair<bool, std::string> found_result(false, std::string());

        // We pass "true" to GetArgHelper in order to return the last
        // argument value seen from the command line (so "bitcoind -foo=bar
        // -foo=baz" gives GetArg(am,"foo")=={true,"baz"}
        found_result = GetArgHelper(am.get_override_args(), arg, true);
        if (found_result.first) {
            return found_result;
        }

        // But in contrast we return the first argument seen in a config file,
        // so "foo=bar \n foo=baz" in the config file gives
        // GetArg(am,"foo")={true,"bar"}
        if (! am.get_network().empty()) {
            found_result = GetArgHelper(am.get_config_args(), NetworkArg(am, arg));
            if (found_result.first) {
                return found_result;
            }
        }

        if (UseDefaultSection(am, arg)) {
            found_result = GetArgHelper(am.get_config_args(), arg);
            if (found_result.first) {
                return found_result;
            }
        }

        return found_result;
    }

    /* Special test for -testnet and -regtest args, because we
     * don't want to be confused by craziness like "[regtest] testnet=1"
     */
    static inline bool GetNetBoolArg(const ArgsManager &am, const std::string &net_arg) EXCLUSIVE_LOCKS_REQUIRED(am.cs_args) {
        std::pair<bool, std::string> found_result(false, std::string());
        found_result = GetArgHelper(am.get_override_args(), net_arg, true);
        if (! found_result.first) {
            found_result = GetArgHelper(am.get_config_args(), net_arg, true);
            if (! found_result.first) {
                return false; // not set
            }
        }
        return InterpretBool(found_result.second); // is set, so evaluate
    }
};

/**
 * Interpret -nofoo as if the user supplied -foo=0.
 *
 * This method also tracks when the -no form was supplied, and if so,
 * checks whether there was a double-negative (-nofoo=0 -> -foo=1).
 *
 * If there was not a double negative, it removes the "no" from the key,
 * and returns true, indicating the caller should clear the args vector
 * to indicate a negated option.
 *
 * If there was a double negative, it removes "no" from the key, sets the
 * value to "1" and returns false.
 *
 * If there was no "no", it leaves key and value untouched and returns
 * false.
 *
 * Where an option was negated can be later checked using the
 * IsArgNegated() method. One use case for this is to have a way to disable
 * options that are not normally boolean (e.g. using -nodebuglogfile to request
 * that debug log output is not sent to any file at all).
 */
static bool InterpretNegatedOption(std::string &key, std::string &val) {
    assert(key[0] == '-');
    size_t option_index = key.find('.');
    if (option_index == std::string::npos) {
        option_index = 1;
    } else {
        ++option_index;
    }
    if (key.substr(option_index, 2) == "no") {
        bool bool_val = InterpretBool(val);
        key.erase(option_index, 2);
        if (!bool_val ) {
            // Double negatives like -nofoo=0 are supported (but discouraged)
            logging::LogPrintf("Warning: parsed potentially confusing double-negative %s=%s\n", key, val);
            val = "1";
        } else {
            return true;
        }
    }
    return false;
}

static bool GetConfigOptions(std::istream &stream, std::string &error, std::vector<std::pair<std::string, std::string> > &options, std::set<std::string> &sections) {
    auto TrimString = [](const std::string &str, const std::string &pattern) {
        std::string::size_type front = str.find_first_not_of(pattern);
        if (front == std::string::npos) {
            return std::string();
        }
        std::string::size_type end = str.find_last_not_of(pattern);
        return str.substr(front, end - front + 1);
    };

    std::string str, prefix;
    std::string::size_type pos;
    int linenr = 1;
    while (std::getline(stream, str)) {
        bool used_hash = false;
        if ((pos = str.find('#')) != std::string::npos) {
            str = str.substr(0, pos);
            used_hash = true;
        }
        const static std::string pattern = " \t\r\n";
        str = TrimString(str, pattern);
        if (! str.empty()) {
            if (*str.begin() == '[' && *str.rbegin() == ']') {
                const std::string section = str.substr(1, str.size() - 2);
                sections.insert(section);
                prefix = section + '.';
            } else if (*str.begin() == '-') {
                error = tfm::format("parse error on line %i: %s, options in configuration file must be specified without leading -", linenr, str);
                return false;
            } else if ((pos = str.find('=')) != std::string::npos) {
                std::string name = prefix + TrimString(str.substr(0, pos), pattern);
                std::string value = TrimString(str.substr(pos + 1), pattern);
                if (used_hash && name.find("rpcpassword") != std::string::npos) {
                    error = tfm::format("parse error on line %i, using # in rpcpassword can be ambiguous and should be avoided", linenr);
                    return false;
                }
                options.emplace_back(name, value);
                if ((pos = name.rfind('.')) != std::string::npos) {
                    sections.insert(name.substr(0, pos));
                }
            } else {
                error = tfm::format("parse error on line %i: %s", linenr, str);
                if (str.size() >= 2 && str.substr(0, 2) == "no") {
                    error += tfm::format(", if you intended to specify a negated option, use %s=1 instead", str);
                }
                return false;
            }
        }
        ++linenr;
    }
    return true;
}

fs::path arginit::GetConfigFile(const std::string &confPath) {
    /**
     * Most paths passed as configuration arguments are treated as relative to
     * the datadir if they are not absolute.
     *
     * @param path The path to be conditionally prefixed with datadir.
     * @param net_specific Forwarded to GetDataDir().
     * @return The normalized path.
     */
    return lutil::AbsPathForConfigVal(fs::path(confPath), false);
}

ArgsManager::ArgsManager() :
    /* These options would cause cross-contamination if values for
     * mainnet were used while running on regtest/testnet (or vice-versa).
     * Setting them as section_only_args ensures that sharing a config file
     * between mainnet and regtest/testnet won't cause problems due to these
     * parameters by accident. */
    m_network_only_args{
      "-addnode", "-connect",
      "-port", "-bind",
      "-rpcport", "-rpcbind",
      "-wallet",
    }
{
    // nothing to do
}

ArgsManager::~ArgsManager() {
    // nothing to do
}

const std::set<std::string> ArgsManager::GetUnsuitableSectionOnlyArgs() const {
    std::set<std::string> unsuitables;
    LLOCK(cs_args);

    // if there's no section selected, don't worry
    if (m_network.empty()) return std::set<std::string> {};

    // if it's okay to use the default section for this network, don't worry
    if (m_network == chainparamsbase::CBaseChainParams::MAIN()) return std::set<std::string> {};

    for (const auto &arg: m_network_only_args) {
        std::pair<bool, std::string> found_result;

        // if this option is overridden it's fine
        found_result = ArgsManagerHelper::GetArgHelper(m_override_args, arg);
        if (found_result.first) continue;

        // if there's a network-specific value for this option, it's fine
        found_result = ArgsManagerHelper::GetArgHelper(m_config_args, ArgsManagerHelper::NetworkArg(*this, arg));
        if (found_result.first) continue;

        // if there isn't a default value for this option, it's fine
        found_result = ArgsManagerHelper::GetArgHelper(m_config_args, arg);
        if (!found_result.first) continue;

        // otherwise, issue a warning
        unsuitables.insert(arg);
    }
    return unsuitables;
}

const std::set<std::string> ArgsManager::GetUnrecognizedSections() const {
    // Section names to be recognized in the config file.
    static const std::set<std::string> available_sections{
        chainparamsbase::CBaseChainParams::REGTEST(),
        chainparamsbase::CBaseChainParams::TESTNET(),
        chainparamsbase::CBaseChainParams::MAIN()
    };
    std::set<std::string> diff;

    LLOCK(cs_args);
    std::set_difference(
        m_config_sections.begin(), m_config_sections.end(),
        available_sections.begin(), available_sections.end(),
        std::inserter(diff, diff.end()));
    return diff;
}

void ArgsManager::SelectConfigNetwork(const std::string &network) {
    LLOCK(cs_args);
    m_network = network;
}

bool ArgsManager::ParseParameters(int argc, const char *const argv[], std::string &error) {
    LLOCK(cs_args);
    m_override_args.clear();
    for (int i = 1; i < argc; ++i) {
        std::string key(argv[i]);
        std::string val;
        size_t is_index = key.find('=');
        if (is_index != std::string::npos) {
            val = key.substr(is_index + 1);
            key.erase(is_index);
        }
#ifdef WIN32
        std::transform(key.begin(), key.end(), key.begin(), strenc::ToLower);
        if (key[0] == '/')
            key[0] = '-';
#endif

        if (key[0] != '-')
            break;

        // Transform --foo to -foo
        if (key.length() > 1 && key[1] == '-')
            key.erase(0, 1);

        // Check for -nofoo
        if (InterpretNegatedOption(key, val)) {
            m_override_args[key].clear();
        } else {
            m_override_args[key].push_back(val);
        }

        // Check that the arg is known
        if (!(lutil::IsSwitchChar(key[0]) && key.size() == 1)) {
            if (! IsArgKnown(key)) {
                error = tfm::format("Invalid parameter %s", key.c_str());
                return false;
            }
        }
    }

    // we do not allow -includeconf from command line, so we clear it here
    auto it = m_override_args.find("-includeconf");
    if (it != m_override_args.end()) {
        if (it->second.size() > 0) {
            for (const auto &ic: it->second) {
                error += "-includeconf cannot be used from commandline; -includeconf=" + ic + "\n";
            }
            return false;
        }
    }
    return true;
}

bool ArgsManager::IsArgKnown(const std::string &key) const {
    size_t option_index = key.find('.');
    std::string arg_no_net;
    if (option_index == std::string::npos) {
        arg_no_net = key;
    } else {
        arg_no_net = std::string("-") + key.substr(option_index + 1, std::string::npos);
    }

    LLOCK(cs_args);
    for (const auto &arg_map: m_available_args) {
        if (arg_map.second.count(arg_no_net))
            return true;
    }
    return false;
}

std::vector<std::string> ArgsManager::GetArgs(const std::string& strArg) const {
    std::vector<std::string> result = {};
    if (IsArgNegated(strArg)) return result; // special case

    LLOCK(cs_args);
    ArgsManagerHelper::AddArgs(result, m_override_args, strArg);
    if (! m_network.empty()) {
        ArgsManagerHelper::AddArgs(result, m_config_args, ArgsManagerHelper::NetworkArg(*this, strArg));
    }
    if (ArgsManagerHelper::UseDefaultSection(*this, strArg)) {
        ArgsManagerHelper::AddArgs(result, m_config_args, strArg);
    }

    return result;
}

bool ArgsManager::IsArgSet(const std::string &strArg) const {
    if (IsArgNegated(strArg)) return true; // special case
    return ArgsManagerHelper::GetArg(*this, strArg).first;
}

bool ArgsManager::IsArgNegated(const std::string &strArg) const {
    LLOCK(cs_args);
    const auto &ov = m_override_args.find(strArg);
    if (ov != m_override_args.end()) return ov->second.empty();

    if (! m_network.empty()) {
        const auto &cfs = m_config_args.find(ArgsManagerHelper::NetworkArg(*this, strArg));
        if (cfs != m_config_args.end()) return cfs->second.empty();
    }

    const auto &cf = m_config_args.find(strArg);
    if (cf != m_config_args.end()) return cf->second.empty();

    return false;
}

std::string ArgsManager::GetArg(const std::string &strArg, const std::string &strDefault) const {
    if (IsArgNegated(strArg)) return "0";
    std::pair<bool,std::string> found_res = ArgsManagerHelper::GetArg(*this, strArg);
    if (found_res.first) return found_res.second;
    return strDefault;
}

int64_t ArgsManager::GetArg(const std::string &strArg, int64_t nDefault) const {
    if (IsArgNegated(strArg)) return 0;
    std::pair<bool, std::string> found_res = ArgsManagerHelper::GetArg(*this, strArg);
    if (found_res.first) return strenc::atoi64(found_res.second);
    return nDefault;
}

bool ArgsManager::GetBoolArg(const std::string &strArg, bool fDefault) const {
    if (IsArgNegated(strArg)) return false;
    std::pair<bool, std::string> found_res = ArgsManagerHelper::GetArg(*this, strArg);
    if (found_res.first) return InterpretBool(found_res.second);
    return fDefault;
}

bool ArgsManager::SoftSetArg(const std::string &strArg, const std::string &strValue) {
    LLOCK(cs_args);
    if (IsArgSet(strArg)) return false;
    ForceSetArg(strArg, strValue);
    return true;
}

bool ArgsManager::SoftSetBoolArg(const std::string &strArg, bool fValue) {
    if (fValue)
        return SoftSetArg(strArg, std::string("1"));
    else
        return SoftSetArg(strArg, std::string("0"));
}

void ArgsManager::ForceSetArg(const std::string &strArg, const std::string &strValue) {
    LLOCK(cs_args);
    m_override_args[strArg] = {strValue};
}

void ArgsManager::AddArg(const std::string &name, const std::string &help, const bool debug_only, const OptionsCategory &cat) {
    // Split arg name from its help param
    size_t eq_index = name.find('=');
    if (eq_index == std::string::npos) {
        eq_index = name.size();
    }

    LLOCK(cs_args);
    std::map<std::string, Arg>& arg_map = m_available_args[cat];
    auto ret = arg_map.emplace(name.substr(0, eq_index), Arg(name.substr(eq_index, name.size() - eq_index), help, debug_only));
    assert(ret.second); // Make sure an insertion actually happened
}

void ArgsManager::AddHiddenArgs(const std::vector<std::string> &names) {
    for (const std::string &name: names) {
        AddArg(name, "", false, OptionsCategory::HIDDEN);
    }
}

std::string ArgsManager::GetHelpMessage() const {
    const bool show_debug = ARGS.GetBoolArg("-help-debug", false);
    std::string usage = "";
    LLOCK(cs_args);
    for (const auto &arg_map: m_available_args) {
        switch(arg_map.first) {
            case OptionsCategory::OPTIONS:
                usage += arginit::HelpMessageGroup("Options:");
                break;
            case OptionsCategory::CONNECTION:
                usage += arginit::HelpMessageGroup("Connection options:");
                break;
            case OptionsCategory::ZMQ:
                usage += arginit::HelpMessageGroup("ZeroMQ notification options:");
                break;
            case OptionsCategory::DEBUG_TEST:
                usage += arginit::HelpMessageGroup("Debugging/Testing options:");
                break;
            case OptionsCategory::NODE_RELAY:
                usage += arginit::HelpMessageGroup("Node relay options:");
                break;
            case OptionsCategory::BLOCK_CREATION:
                usage += arginit::HelpMessageGroup("Block creation options:");
                break;
            case OptionsCategory::RPC:
                usage += arginit::HelpMessageGroup("RPC server options:");
                break;
            case OptionsCategory::WALLET:
                usage += arginit::HelpMessageGroup("Wallet options:");
                break;
            case OptionsCategory::WALLET_DEBUG_TEST:
                if (show_debug) usage += arginit::HelpMessageGroup("Wallet debugging/testing options:");
                break;
            case OptionsCategory::CHAINPARAMS:
                usage += arginit::HelpMessageGroup("Chain selection options:");
                break;
            case OptionsCategory::GUI:
                usage += arginit::HelpMessageGroup("UI Options:");
                break;
            case OptionsCategory::COMMANDS:
                usage += arginit::HelpMessageGroup("Commands:");
                break;
            case OptionsCategory::REGISTER_COMMANDS:
                usage += arginit::HelpMessageGroup("Register Commands:");
                break;
            default:
                break;
        }

        // When we get to the hidden options, stop
        if (arg_map.first == OptionsCategory::HIDDEN) break;

        for (const auto &arg: arg_map.second) {
            if (show_debug || !arg.second.m_debug_only) {
                std::string name;
                if (arg.second.m_help_param.empty()) {
                    name = arg.first;
                } else {
                    name = arg.first + arg.second.m_help_param;
                }
                usage += arginit::HelpMessageOpt(name, arg.second.m_help_text);
            }
        }
    }
    return usage;
}

bool ArgsManager::ReadConfigStream(std::istream &stream, std::string &error, bool ignore_invalid_keys) {
    LLOCK(cs_args);
    std::vector<std::pair<std::string, std::string> > options;
    m_config_sections.clear();
    if (! ::GetConfigOptions(stream, error, options, m_config_sections)) {
        return false;
    }

    ARGS_DEBUG_CS("OK: GetConfigOptions");

    for (const std::pair<std::string, std::string> &option: options) {
        std::string strKey = std::string("-") + option.first;
        std::string strValue = option.second;
        if (InterpretNegatedOption(strKey, strValue)) {
            m_config_args[strKey].clear();
        } else {
            m_config_args[strKey].push_back(strValue);
        }

        ARGS_DEBUG_CS(strKey.c_str());

        // Check that the arg is known
        if (! IsArgKnown(strKey)) {
            if (! ignore_invalid_keys) {
                error = tfm::format("Invalid configuration value %s", option.first.c_str());
                return false;
            } else {
                logging::LogPrintf("Ignoring unknown configuration value %s\n", option.first);
            }
        }
    }
    return true;
}

bool ArgsManager::ReadConfigFiles(std::string &error, bool ignore_invalid_keys/*=false*/) {
    {
        LLOCK(cs_args);
        m_config_args.clear();
    }

    const std::string confPath = GetArg("-conf", lutil::BITCOIN_CONF_FILENAME().c_str());
    fsbridge::ifstream stream(arginit::GetConfigFile(confPath));

    ARGS_DEBUG_CS(arginit::GetConfigFile(confPath.c_str()).string().c_str());

    // ok to not have a config file
    if (stream.good()) {
        if (! ReadConfigStream(stream, error, ignore_invalid_keys)) {
            return false;
        }

        ARGS_DEBUG_CS("OK: ReadConfigStream");

        // if there is an -includeconf in the override args, but it is empty, that means the user
        // passed '-noincludeconf' on the command line, in which case we should not include anything
        bool emptyIncludeConf;
        {
            LLOCK(cs_args);
            emptyIncludeConf = m_override_args.count("-includeconf") == 0;
        }
        if (emptyIncludeConf) {
            std::string chain_id = GetChainName();
            std::vector<std::string> includeconf(GetArgs("-includeconf"));
            {
                // We haven't set m_network yet (that happens in SelectParams()), so manually check
                // for network.includeconf args.
                std::vector<std::string> includeconf_net(GetArgs(std::string("-") + chain_id + ".includeconf"));
                includeconf.insert(includeconf.end(), includeconf_net.begin(), includeconf_net.end());
            }

            // Remove -includeconf from configuration, so we can warn about recursion
            // later
            {
                LLOCK(cs_args);
                m_config_args.erase("-includeconf");
                m_config_args.erase(std::string("-") + chain_id + ".includeconf");
            }

            for (const std::string &to_include: includeconf) {
                fsbridge::ifstream include_config(arginit::GetConfigFile(to_include));
                if (include_config.good()) {
                    if (! ReadConfigStream(include_config, error, ignore_invalid_keys)) {
                        return false;
                    }
                    logging::LogPrintf("Included configuration file %s\n", to_include.c_str());
                } else {
                    error = "Failed to include configuration file " + to_include;
                    return false;
                }
            }

            // Warn about recursive -includeconf
            includeconf = GetArgs("-includeconf");
            {
                std::vector<std::string> includeconf_net(GetArgs(std::string("-") + chain_id + ".includeconf"));
                includeconf.insert(includeconf.end(), includeconf_net.begin(), includeconf_net.end());
                std::string chain_id_final = GetChainName();
                if (chain_id_final != chain_id) {
                    // Also warn about recursive includeconf for the chain that was specified in one of the includeconfs
                    includeconf_net = GetArgs(std::string("-") + chain_id_final + ".includeconf");
                    includeconf.insert(includeconf.end(), includeconf_net.begin(), includeconf_net.end());
                }
            }
            for (const std::string &to_include: includeconf) {
                tfm::format(std::cerr, "warning: -includeconf cannot be used from included files; ignoring -includeconf=%s\n", to_include.c_str());
            }
        }
    }

    // If datadir is changed in .conf file:
    lutil::ClearDatadirCache();
    if (! fs::is_directory(lutil::GetDataDir(false))) {
        error = tfm::format("specified data directory \"%s\" does not exist.", ARGS.GetArg("-datadir", "").c_str());
        return false;
    }
    return true;
}

std::string ArgsManager::GetChainName() const {
    LLOCK(cs_args);
    bool fRegTest = ArgsManagerHelper::GetNetBoolArg(*this, "-regtest");
    bool fTestNet = ArgsManagerHelper::GetNetBoolArg(*this, "-testnet");

    if (fTestNet && fRegTest) {
        throw std::runtime_error("Invalid combination of -regtest and -testnet.");
        return std::string("");
    }
    if (fRegTest)
        return chainparamsbase::CBaseChainParams::REGTEST();
    if (fTestNet)
        return chainparamsbase::CBaseChainParams::TESTNET();
    return chainparamsbase::CBaseChainParams::MAIN();
}

bool arginit::HelpRequested(const ArgsManager &args) {
    return args.IsArgSet("-?") || args.IsArgSet("-h") || args.IsArgSet("-help") || args.IsArgSet("-help-debug");
}

void arginit::SetupHelpOptions(ArgsManager &args) {
    args.AddArg("-?", "Print this help message and exit", false, OptionsCategory::OPTIONS);
    args.AddHiddenArgs({"-h", "-help"});
}

static constexpr int screenWidth = 79;
static constexpr int optIndent = 2;
static constexpr int msgIndent = 7;

std::string arginit::HelpMessageGroup(const std::string &message) {
    return std::string(message) + std::string("\n\n");
}

std::string arginit::HelpMessageOpt(const std::string &option, const std::string &message) {
    return std::string(optIndent,' ') + std::string(option) +
           std::string("\n") + std::string(msgIndent,' ') +
           strenc::FormatParagraph(message, screenWidth - msgIndent, msgIndent) +
           std::string("\n\n");
}
