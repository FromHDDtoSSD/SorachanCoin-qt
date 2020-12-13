//          Copyright John W. Wilkinson 2007 - 2009.
// Distributed under the MIT License, see accompanying file LICENSE.txt
//
// Copyright (c) 2018-2021 The SorachanCoin developers

#ifndef JSON_SPIRIT_UTILS
#define JSON_SPIRIT_UTILS

#include <json/json_spirit_value.h>
#include <map>

namespace json_spirit
{
    template<typename Obj_t, typename Map_t>
    void obj_to_map(const Obj_t &obj, Map_t &mp_obj) {
        mp_obj.clear();
        for (typename Obj_t::const_iterator i = obj.begin(); i != obj.end(); ++i)
            mp_obj[i->name_] = i->value_;
    }

    template<typename Obj_t, typename Map_t>
    void map_to_obj(const Map_t &mp_obj, Obj_t &obj) {
        obj.clear();
        for (typename Map_t::const_iterator i = mp_obj.begin(); i != mp_obj.end(); ++i)
            obj.push_back(typename Obj_t::value_type(i->first, i->second));
    }

    using Mapped_obj = std::map<std::string, Value>;

# ifndef BOOST_NO_STD_WSTRING
    using wMapped_obj = std::map<std::wstring, wValue>;
# endif

    template<typename Object_type, typename String_type>
    const typename Object_type::value_type::Value_type &find_value(const Object_type &obj, const String_type &name) {
        for (typename Object_type::const_iterator i = obj.begin(); i != obj.end(); ++i) {
            if (i->name_ == name)
                return i->value_;
        }
        return Object_type::value_type::Value_type::null;
    }
}

#endif
