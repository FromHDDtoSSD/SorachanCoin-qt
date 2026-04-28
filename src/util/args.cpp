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
#include <boost/program_options/detail/config_file.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/algorithm/string/predicate.hpp> // for startswith() and endswith()
//#define ARGS_DEBUG_CS(str) debugcs::instance() << (str) << debugcs::endl()

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
CCriticalSection cs_args;
std::map<std::string, std::string> map_arg::mapArgs;
std::map<std::string, std::vector<std::string> > map_arg::mapMultiArgs;
std::map<std::string, std::vector<std::string> > config::mapConfigArgs;
std::map<OptionsCategory, std::map<std::string, Arg> > map_arg::mapAvailableArgs;

static void InterpretNegativeSetting(std::string name, std::map<std::string, std::string> &mapSettingsRet) {
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

static std::string randomStrGen(int length) {
    static const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

    std::string result;
    result.resize(length);
    for (int32_t i = 0; i < length; ++i) {
        unsigned char bc;
        random::GetStrongRandBytes(&bc, sizeof(bc));
        result[i] = charset[bc % charset.length()];
        //result[i] = charset[::rand() % charset.length()];
    }
    return result;
}

static void createConf() {
    std::ofstream pConf;
#if BOOST_FILESYSTEM_VERSION >= 3
    pConf.open(iofs::GetConfigFile().generic_string().c_str());
#else
    pConf.open(iofs::GetConfigFile().string().c_str());
#endif
    pConf << "rpcuser=sora\nrpcpassword="
            + randomStrGen(35)
            + "\n\ndaemon=0"
            + "\nserver=0"
            + "\ntestnet=0"
            + "\n\nlisten=1"
            + "\nirc=0"
            + "\n\nrpcallowip=127.0.0.1"
            + "\n";
    pConf.close();
}

#ifdef VSTREAM_INMEMORY_MODE
const std::vector<std::string> soraconf_vstream = {
        "rpcuser","sora",
        "rpcpassword","K3qdcr753qhjwqAscwLacwbnm9q52KgwA4J",
        "daemon","0",
        "server","1",
        "testnet","0",
        "listen","1",
        "irc","0",
        "rpcallowip","127.0.0.1",
        "addnode","160.16.110.231",
        "addnode","167.179.108.146",
        };
#endif

bool config::ReadConfigFile(std::map<std::string, std::string> &mapSettingsRet, std::map<std::string, std::vector<std::string> > &mapMultiSettingsRet) {
    LOCK(cs_args);
#ifdef VSTREAM_INMEMORY_MODE
    for(int i=0; i<soraconf_vstream.size(); i+=2) {
        std::string key = std::string("-") + soraconf_vstream[i];
        std::string value = soraconf_vstream[i+1];
        if(mapSettingsRet.count(key)==0) {
            mapSettingsRet[key] = value;
            init::InterpretNegativeSetting(key, mapSettingsRet);
        }
        mapMultiSettingsRet[key].push_back(value);
    }
#else
    fs::ifstream streamConfig(iofs::GetConfigFile());
    if (! streamConfig.good()) {
        createConf();
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
            InterpretNegativeSetting(strKey, mapSettingsRet);
        }
        mapMultiSettingsRet[strKey].push_back(it->value[0]);
    }
#endif

    //debugcs::instance() << "args: " << debugcs::endl();
    for(auto ref: mapSettingsRet) {
        debugcs::instance() << ref.first << " " << ref.second << debugcs::endl();
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
}

static bool IsSwitchChar(char c)
{
#ifdef WIN32
    return c == '-' || c == '/';
#else
    return c == '-';
#endif
}

bool map_arg::ParseParameters(int argc, const char *const argv[], std::string *error/*=nullptr*/) {
    LOCK(cs_args);
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
        if (!(IsSwitchChar(str[0]) && str.size() == 1)) {
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
        InterpretNegativeSetting(name, mapArgs);
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

    LOCK(cs_args);
    std::map<std::string, Arg> &arg_map = mapAvailableArgs[cat];
    auto ret = arg_map.emplace(name.substr(0, eq_index), Arg(name.substr(eq_index, name.size() - eq_index), help, debug_only));
    assert(ret.second); // Make sure an insertion actually happened
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
    } {}

ArgsManager::~ArgsManager() {}

void ArgsManager::AddArg(const std::string &name, const std::string &help, const bool debug_only, const OptionsCategory &cat) {
    // Split arg name from its help param
    size_t eq_index = name.find('=');
    if (eq_index == std::string::npos) {
        eq_index = name.size();
    }

    LOCK(cs_args);
    std::map<std::string, Arg>& arg_map = m_available_args[cat];
    auto ret = arg_map.emplace(name.substr(0, eq_index), Arg(name.substr(eq_index, name.size() - eq_index), help, debug_only));
    assert(ret.second); // Make sure an insertion actually happened
}

void ArgsManager::AddHiddenArgs(const std::vector<std::string> &names) {
    for (const std::string &name: names) {
        AddArg(name, "", false, OptionsCategory::HIDDEN);
    }
}

void arginit::SetupHelpOptions(ArgsManager &args) {
    args.AddArg("-?", "Print this help message and exit", false, OptionsCategory::OPTIONS);
    args.AddHiddenArgs({"-h", "-help"});
}
