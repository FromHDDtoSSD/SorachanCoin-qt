//          Copyright John W. Wilkinson 2007 - 2009.
// Distributed under the MIT License, see accompanying file LICENSE.txt
//
// Copyright (c) 2018-2021 The SorachanCoin developers
//
// C++11 json_spirit for noexcept
// src/noexcept
// https://github.com/zajo/boost-noexcept

#ifndef JSON_SPIRIT_READ_STREAM
#define JSON_SPIRIT_READ_STREAM

#include <json/json_spirit_reader_template.h>

namespace json_spirit
{
    // these classes allows you to read multiple top level contiguous values from a stream,
    // the normal stream read functions have a bug that prevent multiple top level values
    // from being read unless they are separated by spaces
    template<typename Istream_type, typename Value_type>
    class Stream_reader {
    public:
        Stream_reader(Istream_type &is) noexcept
            : iters_(is)
        {
        }

        bool read_next(Value_type &value, json_flags &status) noexcept {
            return read_range(iters_.begin_, iters_.end_, value, status);
        }

    private:
        using Mp_iters = Multi_pass_iters<Istream_type>;

        Mp_iters iters_;
    };

    template<typename Istream_type, typename Value_type>
    class Stream_reader_thrower {
    public:
        Stream_reader_thrower(Istream_type &is) noexcept
            : iters_(is)
            , posn_begin_(iters_.begin_, iters_.end_)
            , posn_end_(iters_.end_, iters_.end_)
        {
        }

        void read_next(Value_type &value, json_flags &status) noexcept {
            posn_begin_ = read_range_or_throw(posn_begin_, posn_end_, value, status);
        }

    private:
        using Mp_iters = Multi_pass_iters<Istream_type>;
        using Posn_iter_t = spirit_namespace::position_iterator<typename Mp_iters::Mp_iter>;

        Mp_iters iters_;
        Posn_iter_t posn_begin_, posn_end_;
    };
}

#endif
