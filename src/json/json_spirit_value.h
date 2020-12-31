//          Copyright John W. Wilkinson 2007 - 2009.
// Distributed under the MIT License, see accompanying file LICENSE.txt
//
// Copyright (c) 2018-2021 The SorachanCoin developers

#ifndef JSON_SPIRIT_VALUE
#define JSON_SPIRIT_VALUE

#include <vector>
#include <map>
#include <string>
#include <cassert>
#include <sstream>
#include <noexcept/throw.hpp>
#include <noexcept/try.hpp>
#include <boost/config.hpp>
#include <boost/variant.hpp>
#include <debugcs/debugcs.h>

namespace json_spirit
{
    enum Value_type { obj_type, array_type, str_type, bool_type, int_type, real_type, null_type };
    static const char *Value_type_name[] = { "obj", "array", "str", "bool", "int", "real", "null" };

    // error objects
    template <typename Config>
    class ArrayError : public Config::Array_type {
    public:
        template <typename Value_type>
        void push_back(Value_type) {}
        template <typename R>
        R *back() noexcept {return nullptr;}
    };
    template <typename Config>
    class ObjectError : public Config::Object_type {
    public:
        // define here
    };

    // instead of exception
    // execute result are stored to json_flags structure
    struct json_flags {
        enum Status_type { Status_success, Status_error, Status_except };
        mutable Status_type type_;
        mutable std::string e;
        json_flags() noexcept {
            type_=Status_success;
        }
        bool fSuccess() const noexcept {return (type_==Status_success);}
        template <typename T>
        T &JSONError(const char *__e, T *__err) const {
            type_=Status_error;
            if(__e) e = __e;
            return *__err;
        }
        template <typename T=std::string>
        T JSONError() const {
            return e;
        }
        template <typename T=std::string&>
        T JSONError(const T obj) const {
            return obj;
        }
        template <typename B, typename E, typename T=B&>
        T JSONRet(B *__v, E *__err, bool fexcept=true) const {
            if(__v && type_==Status_success) {
                //type_=Status_success;
                return *__v;
            } else {
                type_=fexcept? Status_except: Status_error;
                return *__err;
            }
        }
        void JSONSuccess() const noexcept {
            type_=Status_success;
        }
    };

    // Config determines whether the value uses std::string or std::wstring and
    // whether JSON Objects are represented as vectors or maps
    template<typename Config>
    class Value_impl {
    public:
        using Config_type = Config;
        using String_type = typename Config::String_type;
        using Object = typename Config::Object_type;
        using Array = typename Config::Array_type;
        using Const_str_ptr = typename String_type::const_pointer;  // eg const char *
        Value_impl() noexcept : type_(null_type), is_uint64_(false) {} // creates null value
        Value_impl(Const_str_ptr      value) : type_(str_type), v_(String_type(value)), is_uint64_(false) {}
        Value_impl(const String_type &value) : type_(str_type), v_(value), is_uint64_(false) {}
        Value_impl(const Object      &value) : type_(obj_type), v_(value), is_uint64_(false) {}
        Value_impl(const Array       &value) : type_(array_type), v_(value), is_uint64_(false) {}
        Value_impl(bool               value) noexcept : type_(bool_type), v_(value), is_uint64_(false) {}
        Value_impl(int                value) noexcept : type_(int_type), v_(static_cast<int64_t>(value)), is_uint64_(false) {}
        Value_impl(int64_t            value) noexcept : type_(int_type), v_(value), is_uint64_(false) {}
        Value_impl(uint64_t           value) noexcept : type_(int_type), v_(static_cast<int64_t>(value)), is_uint64_(true) {}
        Value_impl(double             value) noexcept : type_(real_type), v_(value), is_uint64_(false) {}

        Value_impl(const Value_impl &other) noexcept :  type_(other.type()), v_(other.v_), is_uint64_(other.is_uint64_) {}
        Value_impl(const Value_impl &&other) noexcept : type_(other.type_), v_(other.v_), is_uint64_(other.is_uint64_) {}

        bool operator==(const Value_impl &lhs) const noexcept;
        Value_impl &operator=(const Value_impl &lhs);
        Value_type type() const noexcept;
        bool is_uint64() const noexcept;
        bool is_null() const noexcept;

        const String_type &get_str(json_flags &status)    const noexcept;
        const Object      &get_obj(json_flags &status)    const noexcept;
        const Array       &get_array(json_flags &status)  const noexcept;
        bool               get_bool(json_flags &status)   const noexcept;
        int                get_int(json_flags &status)    const noexcept;
        int64_t            get_int64(json_flags &status)  const noexcept;
        uint64_t           get_uint64(json_flags &status) const noexcept;
        double             get_real(json_flags &status)   const noexcept;

        Object            &get_obj(json_flags &status)    noexcept;
        Array             &get_array(json_flags &status)  noexcept;
        template<typename T> T get_value(json_flags &status) const;  // example usage: int    i = value.get_value<int>(status);
                                                                     // or             double d = value.get_value<double>(status);

        static const Value_impl null;

    private:
        void check_type(const Value_type vtype, json_flags &status) const noexcept;
        using Variant = boost::variant<String_type,
            boost::recursive_wrapper<Object>, boost::recursive_wrapper<Array>,
            bool, int64_t, double>;

        Value_type type_;
        Variant v_;
        bool is_uint64_;
    };

    // vector objects
    template<typename Config>
    struct Pair_impl {
        using String_type = typename Config::String_type;
        using Value_type = typename Config::Value_type;

        Pair_impl(const String_type &name, const Value_type &value);

        bool operator==(const Pair_impl& lhs) const noexcept;

        String_type name_;
        Value_type value_;
    };
    template <typename String_type, typename Value_type, typename Pair_type>
    class json_vector : public std::vector<Pair_type> {
    public:
        bool exists(const String_type &name) const {
            for(const Pair_type &data: *this) {
                if(data.name_ == name) return true;
            }
            return false;
        }
        const Value_type &operator[](const String_type &key) const {
            for(const Pair_type &data: *this) {
                if(data.name_ == key) return data.value_;
            }
            return Value_type::null;
        }
        json_vector &operator<<(const json_vector &&)=delete;
        json_vector &operator<<(const json_vector &in) {
            for(const Pair_type &data: in)
                this->push_back(data);
            return *this;
        }
    };
    template<typename String>
    struct Config_vector {
        using String_type = String;
        using Value_type = Value_impl<Config_vector>;
        using Pair_type = Pair_impl<Config_vector>;
        using Array_type = std::vector<Value_type>;
        using Object_type = json_vector<String_type, Value_type, Pair_type>;

        static Value_type &add(Object_type &obj, const String_type &name, const Value_type &value) {
            obj.push_back(Pair_type(name, value));
            return obj.back().value_;
        }

        static String_type get_name(const Pair_type &pair) {
            return pair.name_;
        }

        static Value_type get_value(const Pair_type &pair) {
            return pair.value_;
        }
    };

    // typedefs for ASCII
    using Config = Config_vector<std::string>;
    using Value = Config::Value_type;
    using Pair = Config::Pair_type;
    using Object = Config::Object_type;
    using Array = Config::Array_type;

    // typedefs for Unicode
# ifndef BOOST_NO_STD_WSTRING
    using wConfig = Config_vector<std::wstring>;
    using wValue = wConfig::Value_type;
    using wPair = wConfig::Pair_type;
    using wObject = wConfig::Object_type;
    using wArray = wConfig::Array_type;
# endif

    // map objects
    template<typename String>
    struct Config_map {
        using String_type = String;
        using Value_type = Value_impl<Config_map>;
        using Array_type = std::vector<Value_type>;
        using Object_type = std::map<String_type, Value_type>;
        using Pair_type = typename Object_type::value_type;

        static Value_type &add(Object_type &obj, const String_type &name, const Value_type &value) {
            return obj[name] = value;
        }

        static String_type get_name(const Pair_type &pair) {
            return pair.first;
        }

        static Value_type get_value(const Pair_type &pair) {
            return pair.second;
        }
    };

    // typedefs for ASCII
    using mConfig = Config_map<std::string>;
    using mValue = mConfig::Value_type;
    using mObject = mConfig::Object_type;
    using mArray = mConfig::Array_type;

    // typedefs for Unicode
#ifndef BOOST_NO_STD_WSTRING
    using wmConfig = Config_map<std::wstring>;
    using wmValue = wmConfig::Value_type;
    using wmObject = wmConfig::Object_type;
    using wmArray = wmConfig::Array_type;
#endif

    template<typename Config>
    const Value_impl<Config> Value_impl<Config>::null;
    template<typename Config>
    Value_impl<Config> &Value_impl<Config>::operator=(const Value_impl &lhs) {
        Value_impl tmp(lhs);
        std::swap(type_, tmp.type_);
        std::swap(v_, tmp.v_);
        std::swap(is_uint64_, tmp.is_uint64_);
        return *this;
    }

    template<typename Config>
    bool Value_impl<Config>::operator==(const Value_impl &lhs) const noexcept {
        if (this == &lhs) return true;
        if (type() != lhs.type()) return false;
        return v_ == lhs.v_;
    }

    template<typename Config>
    Value_type Value_impl<Config>::type() const noexcept {
        return type_;
    }

    template<typename Config>
    bool Value_impl<Config>::is_uint64() const noexcept {
        return is_uint64_;
    }

    template<typename Config>
    bool Value_impl<Config>::is_null() const noexcept {
        return type() == null_type;
    }

    template< class Config >
    void Value_impl<Config>::check_type(const Value_type vtype, json_flags &status) const noexcept {
        if (type() != vtype) {
            try {
                std::ostringstream os;
                ///// Bitcoin: Tell the types by name instead of by number
                os << "value is type " << Value_type_name[type()] << ", expected " << Value_type_name[vtype];
                status.JSONError(os.str().c_str());
            } catch (const std::bad_alloc &) {
                status.JSONError("ERROR: check_type failed to allocate memory");
            }
        } else
            status.JSONSuccess();
    }

    template<typename Config>
    const typename Config::String_type &Value_impl<Config>::get_str(json_flags &status) const noexcept {
        static String_type err("");
        check_type(str_type, status);
        if(! status.fSuccess()) return status.JSONError<String_type>(nullptr, &err);
        return status.JSONRet(boost::get<String_type>(&v_), &err);
    }

    template<typename Config>
    const typename Value_impl<Config>::Object &Value_impl<Config>::get_obj(json_flags &status) const noexcept {
        static ObjectError<Config> err; err.clear();
        check_type(obj_type, status);
        if(! status.fSuccess()) return status.JSONError<ObjectError<Config> >(nullptr, &err);
        return status.JSONRet(boost::get<Object>(&v_), &err);
    }

    template<typename Config>
    const typename Value_impl<Config>::Array &Value_impl<Config>::get_array(json_flags &status) const noexcept {
        static ArrayError<Config> err; err.clear();
        check_type(array_type, status);
        if(! status.fSuccess()) return status.JSONError<ArrayError<Config> >(nullptr, &err);
        return status.JSONRet(boost::get<Array>(&v_), &err);
    }

    template<typename Config>
    bool Value_impl<Config>::get_bool(json_flags &status) const noexcept {
        static bool err=false;
        check_type(bool_type, status);
        if(! status.fSuccess()) return status.JSONError<bool>(nullptr, &err);
        //return boost::get< bool >(v_);
        return status.JSONRet(boost::get<bool>(&v_), &err);
    }

    template<typename Config>
    int Value_impl<Config>::get_int(json_flags &status) const noexcept {
        static int err=0;
        check_type(int_type, status);
        if(! status.fSuccess()) return status.JSONError<int>(nullptr, &err);
        return static_cast<int>(get_int64(status));
    }

    template<typename Config>
    int64_t Value_impl<Config>::get_int64(json_flags &status) const noexcept {
        static int64_t err=0;
        check_type(int_type, status);
        if(! status.fSuccess()) return status.JSONError<int64_t>(nullptr, &err);
        //return boost::get< int64_t >(v_);
        return status.JSONRet(boost::get<int64_t>(&v_), &err);
    }

    template<typename Config>
    uint64_t Value_impl<Config>::get_uint64(json_flags &status) const noexcept {
        static uint64_t err=0;
        check_type(int_type, status);
        if(! status.fSuccess()) return status.JSONError<uint64_t>(nullptr, &err);
        return static_cast<uint64_t>(get_int64(status));
    }

    template<typename Config>
    double Value_impl<Config>::get_real(json_flags &status) const noexcept {
        static double err = 0.0;
        if (type() == int_type) {
            return is_uint64() ? static_cast<double>(get_uint64(status))
                               : static_cast<double>(get_int64(status));
        }

        check_type(real_type, status);
        if(! status.fSuccess()) return status.JSONError<double>(nullptr, &err);
        //return boost::get< double >(v_);
        return status.JSONRet(boost::get<double>(&v_), &err);
    }

    template<typename Config>
    typename Value_impl<Config>::Object &Value_impl<Config>::get_obj(json_flags &status) noexcept {
        static ObjectError<Config> err; err.clear();
        check_type(obj_type, status);
        if(! status.fSuccess()) return status.JSONError<ObjectError<Config> >(nullptr, &err);
        return status.JSONRet(boost::get<Object>(&v_), &err);
    }

    template<typename Config>
    typename Value_impl<Config>::Array &Value_impl<Config>::get_array(json_flags &status) noexcept {
        static ArrayError<Config> err; err.clear();
        check_type(array_type, status);
        if(! status.fSuccess()) return status.JSONError<ArrayError<Config> >(nullptr, &err);
        return status.JSONRet(boost::get<Array>(&v_), &err);
    }

    template<typename Config>
    Pair_impl<Config>::Pair_impl(const String_type &name, const Value_type &value)
        : name_(name)
        , value_(value)
    {
    }

    template<typename Config>
    bool Pair_impl<Config>::operator==(const Pair_impl<Config> &lhs) const noexcept {
        if (this == &lhs) return true;
        return (name_ == lhs.name_) && (value_ == lhs.value_);
    }

    // converts a C string, ie. 8 bit char array, to a string object
    //
    template <class String_type>
    String_type to_str(const char *c_str) {
        String_type result;
        for (const char *p = c_str; *p != 0; ++p)
            result += *p;

        return result;
    }

    namespace internal_
    {
        template<typename T>
        struct Type_to_type
        {
        };

        template<typename Value>
        int get_value(const Value &value, Type_to_type<int>, json_flags &status) noexcept
        {
            return value.get_int(status);
        }

        template<typename Value>
        int64_t get_value(const Value &value, Type_to_type<int64_t>, json_flags &status) noexcept
        {
            return value.get_int64(status);
        }

        template<typename Value>
        uint64_t get_value(const Value &value, Type_to_type<uint64_t>, json_flags &status) noexcept
        {
            return value.get_uint64(status);
        }

        template<typename Value>
        double get_value(const Value &value, Type_to_type<double>, json_flags &status) noexcept
        {
            return value.get_real(status);
        }

        template<typename Value>
        typename Value::String_type get_value(const Value &value, Type_to_type<typename Value::String_type>, json_flags &status)
        {
            return value.get_str(status);
        }

        template<typename Value>
        typename Value::Array get_value(const Value &value, Type_to_type<typename Value::Array>, json_flags &status)
        {
            return value.get_array(status);
        }

        template<typename Value>
        typename Value::Object get_value(const Value &value, Type_to_type<typename Value::Object>, json_flags &status)
        {
            return value.get_obj(status);
        }

        template<typename Value>
        bool get_value(const Value &value, Type_to_type<bool>, json_flags &status) noexcept
        {
            return value.get_bool(status);
        }
    }

    template<typename Config>
    template<typename T>
    T Value_impl<Config>::get_value(json_flags &status) const {
        return internal_::get_value(*this, internal_::Type_to_type<T>(), status);
    }
}

#endif
