// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HDCHAIN_H
#define BITCOIN_HDCHAIN_H

#include <hash.h>
#include <cleanse/cleanse.h>
#include <random/random.h>

class SecureBytes {
    SecureBytes()=delete;
    SecureBytes(const SecureBytes &)=delete;
    SecureBytes &operator=(const SecureBytes &)=delete;
public:
    SecureBytes(int8_t sizeIn) {
        _size=sizeIn;
        if(_size>0) {
            _data = new (std::nothrow) unsigned char[_size];
            if(! _data)
                throw std::runtime_error("SecureBytes out of memory");
        }
    }
    SecureBytes(SecureBytes &&obj) {
        operator=(std::move(obj));
    }
    SecureBytes &operator=(SecureBytes &&obj) {
        _size = obj._size;
        _data = obj._data;
        obj._size = 0;
        obj._data = nullptr;
        return *this;
    }
    ~SecureBytes() {
        if(_size>0) {
            cleanse::OPENSSL_cleanse(_data, _size);
            delete [] _data;
        }
    }
    unsigned char *data() {
        return _data;
    }
    int8_t size() {
        return _size;
    }
    operator unsigned char*() {
        return _data;
    }
private:
    int8_t _size;
    unsigned char *_data;
};

static inline SecureBytes token_bytes(int8_t len) {
    SecureBytes buf(len);
    latest_crypto::random::GetStrongRandBytes(buf, len);
    return std::move(buf);
}

#endif
