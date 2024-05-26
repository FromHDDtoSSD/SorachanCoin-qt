// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WITNESS_H
#define BITCOIN_WITNESS_H

#include <vector>
#include <string>
#include <prevector/prevector.h>
#include <script/script.h>

struct CScriptWitness
{
#ifdef CSCRIPT_PREVECTOR_ENABLE
    using valtype = prevector<PREVECTOR_N, uint8_t>;
    using statype = prevector<PREVECTOR_N, prevector<PREVECTOR_N, uint8_t> >;
#else
    using valtype = std::vector<uint8_t>;
    using statype = std::vector<std::vector<uint8_t> >;
#endif
    // Note that this encodes the data elements being pushed, rather than
    // encoding them as a CScript that pushes them.
    statype stack;

    // Some compilers complain without a default constructor
    CScriptWitness() { }

    bool IsNull() const { return stack.empty(); }

    void SetNull() { stack.clear(); stack.shrink_to_fit(); }

    std::string ToString() const;

    //
    // If stack size is 0, building witness field
    //
    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        if(ser_action.ForRead()) {
            int16_t size = 0;
            READWRITE(size);
            if(size > 0) {
                this->stack.resize(size);
                for(auto &vch: this->stack) {
                    READWRITE(vch);
                }
            } else {
                SetNull();
            }
        } else {
            int16_t size = (int16_t)this->stack.size();
            READWRITE(size);
            if(size > 0) {
                for(auto &vch: this->stack) {
                    READWRITE(vch);
                }
            }
        }
    }
};

struct CScriptQai
{
#ifdef CSCRIPT_PREVECTOR_ENABLE
    using valtype = prevector<PREVECTOR_N, uint8_t>;
    using statype = prevector<PREVECTOR_N, prevector<PREVECTOR_N, uint8_t> >;
#else
    using valtype = std::vector<uint8_t>;
    using statype = std::vector<std::vector<uint8_t> >;
#endif
    // Note that this encodes the data elements being pushed, rather than
    // encoding them as a CScript that pushes them.
    statype stack;

    // Some compilers complain without a default constructor
    CScriptQai() { }

    bool IsNull() const { return stack.empty(); }

    void SetNull() { stack.clear(); stack.shrink_to_fit(); }

    std::string ToString() const;

    //
    // If stack size is 0, building witness field
    //
    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        if(ser_action.ForRead()) {
            int16_t size = 0;
            READWRITE(size);
            if(size > 0) {
                this->stack.resize(size);
                for(auto &vch: this->stack) {
                    READWRITE(vch);
                }
            } else {
                SetNull();
            }
        } else {
            int16_t size = (int16_t)this->stack.size();
            READWRITE(size);
            if(size > 0) {
                for(auto &vch: this->stack) {
                    READWRITE(vch);
                }
            }
        }
    }
};

#endif
