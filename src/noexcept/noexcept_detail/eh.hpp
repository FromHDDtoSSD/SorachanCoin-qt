//Copyright (c) 2017-2018 Emil Dotchevski and Reverge Studios, Inc.

//Distributed under the Boost Software License, Version 1.0. (See accompanying
//file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#ifndef UUID_B77EFEB45BBD11E7B59A8BBA7FA7C656
#define UUID_B77EFEB45BBD11E7B59A8BBA7FA7C656

#include <noexcept/noexcept_config/assert.hpp>
#include <noexcept/noexcept_config/rtti.hpp>
#include <noexcept/noexcept_config/throw_exception.hpp>
#ifdef exception_info
#undef exception_info
#endif
#ifdef BOOST_NOEXCEPT_NO_EXCEPTION_INFO
namespace boost { namespace noexcept_ { class exception_info; } }
#else
#include <boost/exception/exception.hpp>
namespace boost { namespace noexcept_ { using exception_info = boost::exception; } }
#endif
#include <type_traits>
#include <exception>
#include <new>

namespace
boost
    {
    namespace
    noexcept_
        {
        namespace
        noexcept_detail
            {
            enum { sizeof_max_error=128 };
            typedef std::aligned_storage<sizeof_max_error>::type error_storage;
            template <class> void tid_();

            class
            error_base
                {
                virtual void throw_exception_() { };
                public:
                BOOST_NOEXCEPT_NORETURN
                void
                throw_exception()
                    {
                    throw_exception_();
                    std::terminate();
                    }
                virtual exception_info * get_exception_info() noexcept { return 0; }
                virtual std::exception * get_std_exception() noexcept=0;
                virtual void * get_obj( void (*typeid_)() ) noexcept=0;
                virtual ~error_base() noexcept { }
                };

            template <class E,
#ifdef BOOST_NOEXCEPT_NO_EXCEPTION_INFO
                bool ExceptionInfoDisabled=true,
#else
                bool DerivesFromExceptionInfo=std::is_base_of<exception_info,E>::value,
#endif
                bool DerivesFromStdException=std::is_base_of<std::exception,E>::value>
            struct class_dispatch;

#ifndef BOOST_NOEXCEPT_NO_EXCEPTION_INFO
            template <class E>
            struct
            class_dispatch<E,false,false>;
            template <class E>
            struct
            class_dispatch<E,false,true>;
#endif

            template <class E>
            struct
            class_dispatch<E,true,false>;
            template <class E>
            struct
            class_dispatch<E,true,true>;

            template <class E,bool IsClass=std::is_class<E>::value> struct wrap;
            template <class E>
            struct wrap<E,false>;
            template <class E>
            struct wrap<E,true>;
            template <class E,bool ErrorTypeTooBig=(sizeof(typename wrap<E>::type)>sizeof_max_error)> struct final_type;
            template <class E>
            struct final_type<E,false>;

            template <class T>
            void move_( void * dst, void * src ) noexcept;
            typedef void (mover_t)( void *, void *);
            void move_error( mover_t * & dst_mvr, void * dst, error_base * & dst_px, mover_t * src_mvr, void * src, error_base * & src_px ) noexcept;
            template <class E>
            typename final_type<E>::type *init_error( E && e, mover_t * & mvr, void * storage ) noexcept;
            }
        }
    }

#endif
