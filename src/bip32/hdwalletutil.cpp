// Copyright (c) 2017-2018 The Bitcoin Core developers
// Copyright (c) 2018-2024 The SorachanCoin developers
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
