//          Copyright John W. Wilkinson 2007 - 2009.
// Distributed under the MIT License, see accompanying file LICENSE.txt

#include <json/json_spirit_reader.h>
#include <json/json_spirit_reader_template.h>

using namespace json_spirit;

bool json_spirit::read(const std::string &s, Value &value)
{
    return json_spirit::read_string(s, value);
}

void json_spirit::read_or_throw(const std::string &s, Value &value)
{
    json_spirit::read_string_or_throw(s, value);
}

bool json_spirit::read(std::istream &is, Value &value)
{
    return json_spirit::read_stream(is, value);
}

void json_spirit::read_or_throw(std::istream &is, Value &value)
{
    json_spirit::read_stream_or_throw(is, value);
}

bool json_spirit::read(std::string::const_iterator &begin, std::string::const_iterator end, Value &value)
{
    return json_spirit::read_range(begin, end, value);
}

void json_spirit::read_or_throw(std::string::const_iterator &begin, std::string::const_iterator end, Value &value)
{
    begin = json_spirit::read_range_or_throw(begin, end, value);
}

#ifndef BOOST_NO_STD_WSTRING

bool json_spirit::read(const std::wstring &s, wValue &value)
{
    return json_spirit::read_string(s, value);
}

void json_spirit::read_or_throw(const std::wstring &s, wValue &value)
{
    json_spirit::read_string_or_throw(s, value);
}

bool json_spirit::read(std::wistream &is, wValue &value)
{
    return json_spirit::read_stream(is, value);
}

void json_spirit::read_or_throw(std::wistream &is, wValue &value)
{
    json_spirit::read_stream_or_throw(is, value);
}

bool json_spirit::read(std::wstring::const_iterator &begin, std::wstring::const_iterator end, wValue &value)
{
    return json_spirit::read_range(begin, end, value);
}

void json_spirit::read_or_throw(std::wstring::const_iterator &begin, std::wstring::const_iterator end, wValue &value)
{
    begin = json_spirit::read_range_or_throw(begin, end, value);
}

#endif

bool json_spirit::read(const std::string &s, mValue &value)
{
    return json_spirit::read_string(s, value);
}

void json_spirit::read_or_throw(const std::string &s, mValue &value)
{
    json_spirit::read_string_or_throw(s, value);
}

bool json_spirit::read(std::istream &is, mValue &value)
{
    return json_spirit::read_stream(is, value);
}

void json_spirit::read_or_throw(std::istream &is, mValue &value)
{
    json_spirit::read_stream_or_throw(is, value);
}

bool json_spirit::read(std::string::const_iterator &begin, std::string::const_iterator end, mValue &value)
{
    return json_spirit::read_range(begin, end, value);
}

void json_spirit::read_or_throw(std::string::const_iterator &begin, std::string::const_iterator end, mValue &value)
{
    begin = json_spirit::read_range_or_throw(begin, end, value);
}

#ifndef BOOST_NO_STD_WSTRING

bool json_spirit::read(const std::wstring &s, wmValue &value)
{
    return json_spirit::read_string(s, value);
}

void json_spirit::read_or_throw(const std::wstring &s, wmValue &value)
{
    json_spirit::read_string_or_throw(s, value);
}

bool json_spirit::read(std::wistream &is, wmValue &value)
{
    return json_spirit::read_stream(is, value);
}

void json_spirit::read_or_throw(std::wistream &is, wmValue &value)
{
    json_spirit::read_stream_or_throw(is, value);
}

bool json_spirit::read(std::wstring::const_iterator &begin, std::wstring::const_iterator end, wmValue &value)
{
    return json_spirit::read_range(begin, end, value);
}

void json_spirit::read_or_throw(std::wstring::const_iterator &begin, std::wstring::const_iterator end, wmValue &value)
{
    begin = json_spirit::read_range_or_throw(begin, end, value);
}

#endif
