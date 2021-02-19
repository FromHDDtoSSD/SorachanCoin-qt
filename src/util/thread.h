// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2019-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Server/client environment:
 * thiscall thread wrappers, stdcall thread wrappers
 */
#ifndef SORACHANCOIN_THREAD_H
#define SORACHANCOIN_THREAD_H

#include <stdint.h>
#include <string>
#ifdef WIN32
# include <windows.h>
# include <process.h>
#else
# include <thread>
# include <system_error>
# include <sys/time.h>
# include <sys/resource.h>
#endif
#include <const/no_instance.h>
#include <const/attributes.h>

/**
 * thiscall thread wrappers
 * T: class type
 * Method: start(), stop(), signal(), waitclose()
 */
template <typename T>
class cla_thread final {
public:
    typedef struct _thread_data {
        void *p;
        bool exit_flag;
        size_t nExit;
    } thread_data;
private:
    struct thread_param : public thread_data {
        T *self;
        unsigned int (T::*func)(thread_data *pdata);
    } param;

#ifdef WIN32
    HANDLE hHandle;
#else
    std::thread thread;
#endif

    cla_thread()=delete;
    cla_thread(const cla_thread &)=delete;
    cla_thread &operator=(const cla_thread &)=delete;
    cla_thread(cla_thread &&)=delete;
    cla_thread &operator=(cla_thread &&)=delete;

#ifdef WIN32
    static unsigned int __stdcall _thread(void *p) {
        struct thread_param *tp = reinterpret_cast<struct thread_param *>(p);
        unsigned int ret = (tp->self->*(tp->func))(static_cast<thread_data *>(tp));
        ::_endthreadex((unsigned int)tp->nExit);
        return ret;
    }
#else
    static unsigned int _thread(void *p) {
        struct thread_param *tp = reinterpret_cast<struct thread_param *>(p);
        unsigned int ret = (tp->self->*(tp->func))(static_cast<thread_data *>(tp));
        ::pthread_exit((void *)tp->nExit);
        return ret;
    }
#endif

public:
    explicit cla_thread(unsigned int (T::*_func)(thread_data *pdata)) noexcept {
        param.p = nullptr;
        param.exit_flag = false;
        param.nExit = 0;
        param.self = nullptr;
        param.func = _func;
#ifdef WIN32
        hHandle = nullptr;
#endif
    }
    ~cla_thread() {
        stop();
        waitclose();
    }

    bool start(void *_p, T *_self) noexcept {
        waitclose();

        param.p = _p;
        param.exit_flag = false;
        param.nExit = 0;
        param.self = _self;
#ifdef WIN32
        hHandle = (HANDLE)::_beginthreadex(nullptr, 0, _thread, &param, 0, nullptr);
        return hHandle != nullptr;
#else
        try {
            std::thread tmp(_thread, &param);
            tmp.swap(thread);
            return true;
        } catch (const std::system_error &) {
            return false;
        }
#endif
    }

    void stop(size_t nExitCode=0) noexcept {
        param.exit_flag = true;
        param.nExit = nExitCode;
    }

    bool signal() const noexcept {
#ifdef WIN32
        if(hHandle)
            return (::WaitForSingleObject(hHandle, 0) == WAIT_OBJECT_0) ? true: false;
        else
            return true;
#else
        return (thread.joinable() != true);
#endif
    }

    void waitclose() noexcept {
#ifdef WIN32
        if(hHandle) {
            ::WaitForSingleObject(hHandle, INFINITE);
            ::CloseHandle(hHandle);
            hHandle = nullptr;
        }
#else
        if(thread.joinable())
            thread.join();
#endif
    }
};

/**
 * stdcall thread wrappers
 */
namespace bitthread
{
    extern void thread_error(const std::string &e) noexcept;
    NODISCARD extern bool NewThread(void(*pfn)(void *), void *parg) noexcept;

#ifdef WIN32
    static void SetThreadPriority(int nPriority) noexcept {
        ::SetThreadPriority(::GetCurrentThread(), nPriority);
    }

    static void ExitThread(size_t nExitCode) noexcept {
        ::ExitThread(nExitCode);
    }
#else
# define THREAD_PRIORITY_LOWEST          PRIO_MAX
# define THREAD_PRIORITY_BELOW_NORMAL    2
# define THREAD_PRIORITY_NORMAL          0
# define THREAD_PRIORITY_ABOVE_NORMAL    0
    static void SetThreadPriority(int nPriority) noexcept {
        // It's unclear if it's even possible to change thread priorities on Linux,
        // but we really and truly need it for the generation threads.
# ifdef PRIO_THREAD
        ::setpriority(PRIO_THREAD, 0, nPriority);
# else
        ::setpriority(PRIO_PROCESS, 0, nPriority);
# endif
    }

    static void ExitThread(size_t nExitCode) noexcept {
        ::pthread_exit((void *)nExitCode);
    }
#endif

    static void RenameThread(const char *name) noexcept {
#if defined(PR_SET_NAME)
        // Only the first 15 characters are used (16 - NUL terminator)
        ::prctl(PR_SET_NAME, name, 0, 0, 0);
#elif (defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__))
        ::pthread_set_name_np(::pthread_self(), name);
#elif defined(MAC_OSX)
        ::pthread_setname_np(name);
#else
        // Prevent warnings for unused parameters...
        (void)name;
#endif
    }

    /**
     * .. and a wrapper that just calls func once
     */
    template <typename Callable>
    extern void TraceThread(const char *name, Callable func);
} // namespace bitthread

#endif // SORACHANCOIN_THREAD_H
