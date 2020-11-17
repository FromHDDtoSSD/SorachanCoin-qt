//          Copyright John W. Wilkinson 2007 - 2009.
// Distributed under the MIT License, see accompanying file LICENSE.txt
//
// Copyright (c) 2018-2021 The SorachanCoin developers
//
// C++11 json_spirit for noexcept
// src/noexcept
// https://github.com/zajo/boost-noexcept

#include <json/json_spirit_reader_template.h>

std::mutex json_spirit::Json_grammer_ctrl::mutex_;
json_spirit::json_flags json_spirit::Json_grammer_ctrl::status_;
