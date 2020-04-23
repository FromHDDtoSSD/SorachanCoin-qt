#ifndef JSON_SPIRIT_ERROR_POSITION
#define JSON_SPIRIT_ERROR_POSITION

//          Copyright John W. Wilkinson 2007 - 2009.
// Distributed under the MIT License, see accompanying file LICENSE.txt

// Copyright (c) 2018-2020 The SorachanCoin developers

#include <string>

namespace json_spirit
{
    //
    // An Error_position exception is thrown by the "read_or_throw" functions below on finding an error.
    // Note the "read_or_throw" functions are around 3 times slower than the standard functions "read"
    // functions that return a bool.
    //
    class Error_position
    {
    private:
        unsigned int line_;
        unsigned int column_;
        std::string reason_;
    public:
        Error_position() noexcept : line_(0), column_(0) {}
        Error_position(unsigned int line, unsigned int column, const std::string &reason) noexcept : line_(line), column_(column), reason_(reason) {}
        bool operator==(const Error_position &lhs) const noexcept {
            if(this == &lhs) {return true;}
            return ((reason_ == lhs.reason_) &&
                   (line_ == lhs.line_) &&
                   (column_ == lhs.column_));
        }
    };
}

#endif
