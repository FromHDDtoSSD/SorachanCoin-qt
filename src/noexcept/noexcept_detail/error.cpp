//Copyright (c) 2017-2018 Emil Dotchevski and Reverge Studios, Inc.

//Distributed under the Boost Software License, Version 1.0. (See accompanying
//file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#include <noexcept/noexcept_detail/error.hpp>

namespace
boost
    {
    namespace
    noexcept_
        {
        namespace
        noexcept_detail
            {
            template <>
            std::exception const *
            error::
            get<std::exception>() const noexcept
                {
                return px_?px_->get_std_exception():0;
                }
            template <>
            std::exception const *
            error::
            get<std::exception const>() const noexcept
                {
                return px_?px_->get_std_exception():0;
                }
            template <>
            std::exception *
            error::
            get<std::exception>() noexcept
                {
                return px_?px_->get_std_exception():0;
                }
            template <>
            std::exception const *
            error::
            get<std::exception const>() noexcept
                {
                return px_?px_->get_std_exception():0;
                }
            template <>
            exception_info const *
            error::
            get<exception_info>() const noexcept
                {
                return px_?px_->get_exception_info():0;
                }
            template <>
            exception_info const *
            error::
            get<exception_info const>() const noexcept
                {
                return px_?px_->get_exception_info():0;
                }
            template <>
            exception_info *
            error::
            get<exception_info>() noexcept
                {
                return px_?px_->get_exception_info():0;
                }
            template <>
            exception_info const *
            error::
            get<exception_info const>() noexcept
                {
                return px_?px_->get_exception_info():0;
                }
            template <class E>
            E const *
            error::
            get() const noexcept
                {
                if( !px_ )
                    return 0;
                else if( void const * e=px_->get_obj(&tid_<E const>) )
                    return reinterpret_cast<E const *>(e);
                else
                    return dynamic<E>::cast(px_);
                }
            template <class E>
            E *
            error::
            get() noexcept
                {
                if( !px_ )
                    return 0;
                if( void * e=px_->get_obj(&tid_<E const>) )
                    return reinterpret_cast<E *>(e);
                else
                    return dynamic<E>::cast(px_);
                }
            }
        }
    }
