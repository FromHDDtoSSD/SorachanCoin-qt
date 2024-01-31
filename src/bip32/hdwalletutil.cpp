// Copyright (c) 2017-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bip32/hdwalletutil.h>
#include <util/logging.h>
#include <util/system.h>
#include <util/args.h>

#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <string>
#include <regex>

namespace rapidsync {

class hash256 {
public:
    void destHash(unsigned char *p) const {
        assert(vch.size()==32);
        ::memcpy(p, vch.data(), 32);
    }

    bool cmpHash(const unsigned char *p) const {
        assert(vch.size()==32);
        return ::memcmp(p, vch.data(), 32) == 0;
    }

    std::vector<unsigned char> getHash() const {
        assert(vch.size()==32);
        return vch;
    }

    unsigned char *begin() {
        vch.resize(32);
        return &vch.front();
    }

private:
    std::vector<unsigned char> vch;
};

bool urlsplit(std::string url, std::string &host, std::string &path) {
    std::regex url_regex("^(?:http[s]?://)?([^/]+)(/.*)?$");
    std::smatch url_match_result;
    if (std::regex_match(url, url_match_result, url_regex)) {
        if (url_match_result.size() == 3) {
            host = url_match_result[1];
            path = url_match_result[2];
        } else
            return false;
    } else
        return false;

    return true;
}

bool GetData(std::string host, std::string path, std::vector<unsigned char> &responseBody, int32_t limit) {
    namespace beast = boost::beast;
    namespace http = beast::http;
    namespace net = boost::asio;
    using tcp = net::ip::tcp;
    namespace ssl = net::ssl;

    try {
        const std::string port = "443";
        int version = 11;

        net::io_context io_context;
        ssl::context ctx(ssl::context::tlsv12_client);
        ctx.set_default_verify_paths();
        ctx.set_verify_mode(ssl::verify_peer);

        tcp::resolver resolver(io_context);
        ssl::stream<tcp::socket> stream(io_context, ctx);
        if(! SSL_set_tlsext_host_name(stream.native_handle(), host.c_str())) {
            beast::error_code ec{static_cast<int>(::ERR_get_error()), net::error::get_ssl_category()};
            throw beast::system_error{ec};
        }

        auto const results = resolver.resolve(host, port);
        boost::asio::connect(stream.next_layer(), results.begin(), results.end());

        stream.handshake(ssl::stream_base::client);
        http::request<http::string_body> req{http::verb::get, path, version};
        req.set(http::field::host, host);
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
        http::write(stream, req);

        beast::flat_buffer buffer;
        http::response<http::dynamic_body> res;
        if(limit != 0) {
            beast::error_code ec;
            while (stream.read_some(buffer.prepare(limit - buffer.size()), ec)) {
                buffer.commit(limit - buffer.size());
                if (buffer.size() >= limit) break;
            }
            if (!ec || ec == http::error::end_of_stream) {
                buffer.commit(buffer.size());
                http::parser<false, http::dynamic_body> parser;
                parser.put(buffer.data(), ec);
                res = parser.release();
            }
        } else {
            http::read(stream, buffer, res);
        }

        responseBody.clear();
        auto &body = res.body();
        for (auto it = body.data().begin(); it != body.data().end(); ++it) {
            const auto &buffer = *it;
            const unsigned char *data = reinterpret_cast<const unsigned char *>(buffer.data());
            responseBody.insert(responseBody.end(), data, data + buffer.size());
        }

        beast::error_code ec;
        stream.shutdown(ec);
        if(ec == net::error::eof) {
            ec = {};
        }
        if(ec) {
            throw beast::system_error{ec};
        }
    } catch(std::exception const &e) {
        //return EXIT_FAILURE;
        return false;
    }

    //return EXIT_SUCCESS;
    return true;
}

} // namespace rapidsync

fs::path hdwalletutil::GetWalletDir() {
    fs::path path;

    if (ARGS.IsArgSet("-walletdir")) {
        path = ARGS.GetArg("-walletdir", "");
        if (! fs::is_directory(path)) {
            // If the path specified doesn't exist, we return the deliberately
            // invalid empty string.
            path = "";
        }
    } else {
        path = lutil::GetDataDir();
        // If a wallets directory exists, use that, otherwise default to GetDataDir
        if (fs::is_directory(path / "wallets")) {
            path /= "wallets";
        }
    }

    return path;
}

static bool IsBerkeleyBtree(const fs::path &path) {
    // A Berkeley DB Btree file has at least 4K.
    // This check also prevents opening lock files.
    boost::system::error_code ec;
    auto size = fs::file_size(path, ec);
    if (ec) logging::LogPrintf("%s: %s %s\n", __func__, ec.message(), path.string());
    if (size < 4096) return false;

    fsbridge::ifstream file(path, std::ios::binary);
    if (! file.is_open()) return false;

    file.seekg(12, std::ios::beg); // Magic bytes start at offset 12
    uint32_t data = 0;
    file.read((char*) &data, sizeof(data)); // Read 4 bytes of file to compare against magic

    // Berkeley DB Btree magic bytes, from:
    //  https://github.com/file/file/blob/5824af38469ec1ca9ac3ffd251e7afe9dc11e227/magic/Magdir/database#L74-L75
    //  - big endian systems - 00 05 31 62
    //  - little endian systems - 62 31 05 00
    return data == 0x00053162 || data == 0x62310500;
}

std::vector<fs::path> hdwalletutil::ListWalletDir() {
    const fs::path wallet_dir = GetWalletDir();
    const size_t offset = wallet_dir.string().size() + 1;
    std::vector<fs::path> paths;
    boost::system::error_code ec;

    for (auto it = fs::recursive_directory_iterator(wallet_dir, ec); it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) {
            logging::LogPrintf("%s: %s %s\n", __func__, ec.message(), it->path().string());
            continue;
        }

        // Get wallet path relative to walletdir by removing walletdir from the wallet path.
        // This can be replaced by boost::filesystem::lexically_relative once boost is bumped to 1.60.
        const fs::path path = it->path().string().substr(offset);

        if (it->status().type() == fs::directory_file && IsBerkeleyBtree(it->path() / "wallet.dat")) {
            // Found a directory which contains wallet.dat btree file, add it as a wallet.
            paths.emplace_back(path);
        } else if (it.level() == 0 && it->symlink_status().type() == fs::regular_file && IsBerkeleyBtree(it->path())) {
            if (it->path().filename() == "wallet.dat") {
                // Found top-level wallet.dat btree file, add top level directory ""
                // as a wallet.
                paths.emplace_back();
            } else {
                // Found top-level btree file not called wallet.dat. Current bitcoin
                // software will never create these files but will allow them to be
                // opened in a shared database environment for backwards compatibility.
                // Add it to the list of available wallets.
                paths.emplace_back(path);
            }
        }
    }

    return paths;
}

hdwalletutil::WalletLocation::WalletLocation(const std::string &name)
    : m_name(name)
    , m_path(fs::absolute(name, GetWalletDir()))
{
}

bool hdwalletutil::WalletLocation::Exists() const {
    return fs::symlink_status(m_path).type() != fs::file_not_found;
}
