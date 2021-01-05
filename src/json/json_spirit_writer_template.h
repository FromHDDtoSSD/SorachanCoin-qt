//          Copyright John W. Wilkinson 2007 - 2009.
// Distributed under the MIT License, see accompanying file LICENSE.txt
//
// Copyright (c) 2018-2021 The SorachanCoin developers

#ifndef JSON_SPIRIT_WRITER_TEMPLATE
#define JSON_SPIRIT_WRITER_TEMPLATE

#include <json_spirit_value.h>
#include <cassert>
#include <sstream>
#include <iomanip>

namespace json_spirit
{
    inline char to_hex_char(unsigned int c) noexcept
    {
        assert(c <= 0xF);

        const char ch = static_cast< char >(c);

        if (ch < 10) return '0' + ch;

        return 'A' - 10 + ch;
    }

    template< class String_type >
    String_type non_printable_to_string(unsigned int c) noexcept
    {
        String_type result(6, '\\');

        result[1] = 'u';

        result[5] = to_hex_char(c & 0x000F); c >>= 4;
        result[4] = to_hex_char(c & 0x000F); c >>= 4;
        result[3] = to_hex_char(c & 0x000F); c >>= 4;
        result[2] = to_hex_char(c & 0x000F);

        return result;
    }

    template< typename Char_type, class String_type >
    bool add_esc_char(Char_type c, String_type& s) noexcept
    {
        switch (c)
        {
        case '"':  s += to_str< String_type >("\\\""); return true;
        case '\\': s += to_str< String_type >("\\\\"); return true;
        case '\b': s += to_str< String_type >("\\b"); return true;
        case '\f': s += to_str< String_type >("\\f"); return true;
        case '\n': s += to_str< String_type >("\\n"); return true;
        case '\r': s += to_str< String_type >("\\r"); return true;
        case '\t': s += to_str< String_type >("\\t"); return true;
        }

        return false;
    }

    template< class String_type >
    String_type add_esc_chars(const String_type& s)
    {
        typedef typename String_type::const_iterator Iter_type;
        typedef typename String_type::value_type     Char_type;

        String_type result;

        const Iter_type end(s.end());

        for (Iter_type i = s.begin(); i != end; ++i)
        {
            const Char_type c(*i);

            if (add_esc_char(c, result)) continue;

            // FIXME: This comparison is always true on some platforms
            const wint_t unsigned_c((c >= 0) ? c : 256 + c);

            if (iswprint(unsigned_c))
            {
                result += c;
            }
            else
            {
                result += non_printable_to_string< String_type >(unsigned_c);
            }
        }

        return result;
    }

    // this class generates the JSON text,
    // it keeps track of the indentation level etc.
    template<typename Value_type, typename Ostream_type>
    class Generator {
        using Config_type = typename Value_type::Config_type;
        using String_type = typename Config_type::String_type;
        using Object_type = typename Config_type::Object_type;
        using Array_type = typename Config_type::Array_type;
        using Char_type = typename String_type::value_type;
        using Obj_member_type = typename Object_type::value_type;

    public:
        Generator(const Value_type &value, Ostream_type &os, bool pretty, json_flags &status)
            : os_(os)
            , indentation_level_(0)
            , pretty_(pretty)
        {
            if(! status.fSuccess()) return;
            output(value, status);
        }

    private:
        void output(const Value_type &value, json_flags &status) {
            if(! status.fSuccess()) return;
            switch (value.type())
            {
            case obj_type:   output(value.get_obj(status), status); break;
            case array_type: output(value.get_array(status), status); break;
            case str_type:   output(value.get_str(status), status); break;
            case bool_type:  output(value.get_bool(status), status);  break;
            case int_type:   output_int(value, status); break;

            /// Bitcoin: Added std::fixed and changed precision from 16 to 8
            case real_type:  os_ << std::showpoint << std::fixed << std::setprecision(8) << value.get_real(status); break;

            case null_type:  os_ << "null"; break;
            default: assert(false);
            }
        }

        void output(const Object_type &obj, json_flags &status) {
            if(! status.fSuccess()) return;
            output_array_or_obj(obj, '{', '}', status);
        }

        void output(const Array_type &arr, json_flags &status) {
            if(! status.fSuccess()) return;
            output_array_or_obj(arr, '[', ']', status);
        }

        void output(const Obj_member_type &member, json_flags &status) {
            if(! status.fSuccess()) return;
            output(Config_type::get_name(member), status); space();
            os_ << ':'; space();
            output(Config_type::get_value(member), status);
        }

        void output_int(const Value_type &value, json_flags &status) {
            if(! status.fSuccess()) return;
            if (value.is_uint64())
                os_ << value.get_uint64(status);
            else
                os_ << value.get_int64(status);
        }

        void output(const String_type &s, json_flags &status) {
            if(! status.fSuccess()) return;
            os_ << '"' << add_esc_chars(s) << '"';
        }

        void output(bool b, json_flags &status) {
            if(! status.fSuccess()) return;
            os_ << to_str< String_type >(b ? "true" : "false");
        }

        template<typename T>
        void output_array_or_obj(const T &t, Char_type start_char, Char_type end_char, json_flags &status) {
            if(! status.fSuccess()) return;
            os_ << start_char; new_line();
            ++indentation_level_;
            for (typename T::const_iterator i = t.begin(); i != t.end(); ++i) {
                indent(); output(*i, status);

                typename T::const_iterator next = i;
                if (++next != t.end())
                    os_ << ',';

                new_line();
            }

            --indentation_level_;
            indent(); os_ << end_char;
        }

        void indent() {
            if (!pretty_) return;
            for (int i = 0; i < indentation_level_; ++i)
                os_ << "    ";
        }

        void space() {
            if (pretty_) os_ << ' ';
        }

        void new_line() {
            if (pretty_) os_ << '\n';
        }

        Generator &operator=(const Generator &)=delete; // to prevent "assignment operator could not be generated" warning
        Generator &operator=(Generator &&)=delete;

        Ostream_type& os_;
        int indentation_level_;
        bool pretty_;
    };

    template<typename Value_type, typename Ostream_type>
    void write_stream(const Value_type &value, Ostream_type &os, bool pretty, json_flags &status) {
        Generator< Value_type, Ostream_type >(value, os, pretty, status);
    }

    template<typename Value_type>
    typename Value_type::String_type write_string(const Value_type &value, bool pretty, json_flags &status) {
        using Char_type = typename Value_type::String_type::value_type;

        std::basic_ostringstream<Char_type> os;
        write_stream(value, os, pretty, status);
        return os.str();
    }
}

#endif
