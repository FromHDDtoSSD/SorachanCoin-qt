//Copyright (c) 2017-2018 Emil Dotchevski and Reverge Studios, Inc.

//Distributed under the Boost Software License, Version 1.0. (See accompanying
//file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#ifndef UUID_4074489A481911E7BE231D4A7F4E887A
#define UUID_4074489A481911E7BE231D4A7F4E887A

#include <noexcept/noexcept_detail/eh.hpp>

namespace
boost
    {
    namespace
    noexcept_
        {
        namespace
        noexcept_detail
            {
            class
            error
                {
                error( error const & )=delete;
                error & operator=( error const & )=delete;
                error_storage storage_;
                mover_t * mover_;
                error_base * px_;
                public:
                template <class E>
                explicit
                error( E && e ) noexcept:
                    px_(init_error(std::move(e),mover_,&storage_))
                    {
                    }
                template <class E>
                explicit
                error( E && e, char const * file, int line, char const * function ) noexcept
                    {
                    auto w=init_error(std::move(e),mover_,&storage_);
                    px_=w;
#ifndef BOOST_NOEXCEPT_NO_EXCEPTION_INFO
                    using namespace ::boost::exception_detail;
                    set_info(*w,throw_file(file));
                    set_info(*w,throw_line(line));
                    set_info(*w,throw_function(function));
#endif
                    }
                error( error && x ) noexcept
                    {
                    move_error(mover_,&storage_,px_,x.mover_,&x.storage_,x.px_);
                    BOOST_NOEXCEPT_ASSERT(x.px_==0);
                    }
                error( mover_t * src_mvr, void * src, error_base * & src_px ) noexcept
                    {
                    move_error(mover_,&storage_,px_,src_mvr,src,src_px);
                    }
                void
                move_to( mover_t * & dst_mvr, void * dst, error_base * & dst_px ) noexcept
                    {
                    move_error(dst_mvr,dst,dst_px,mover_,&storage_,px_);
                    BOOST_NOEXCEPT_ASSERT(px_==0);
                    }
                ~error() noexcept
                    {
                    if( px_ )
                        px_->~error_base();
                    }
                BOOST_NOEXCEPT_NORETURN
                void
                throw_exception()
                    {
                    BOOST_NOEXCEPT_ASSERT(px_!=0);
                    px_->throw_exception();
                    }
                template <class E=std::exception> E const * get() const noexcept;
                template <class E=std::exception> E * get() noexcept;
                };
            template <class E,bool IsClass=std::is_class<E>::value> struct dynamic;
            template <class E>
            struct
            dynamic<E,true>
                {
#ifdef BOOST_NOEXCEPT_NO_RTTI
                static E * cast( error_base * ) noexcept { return 0; }
#else
                static E * cast( error_base * px ) noexcept { return dynamic_cast<E *>(px); }
#endif
                };
            template <class E>
            struct
            dynamic<E,false>
                {
                static E * cast( error_base * ) noexcept { return 0; }
                };
            }
        }
    }

#endif
