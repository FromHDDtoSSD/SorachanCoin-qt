// Copyright (c) 2017-2018 The Bitcoin Core developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_FS_H
#define BITCOIN_FS_H

#include <stdio.h>
#include <string>
#if defined WIN32 && defined __GLIBCXX__
# include <ext/stdio_filebuf.h>
#endif
#include <compat/compat.h>
#include <const/attributes.h>

//! with an upgrade to C++17, where streams can be constructed directly from
// `std::filesystem::path` objects.
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
namespace fs = boost::filesystem;

//! if win32, include windowsAPI
#ifdef WIN32
# include <windows.h>
#endif

/** Bridge operations to C stdio */
namespace fsbridge {
    // FILE *
    FILE *fopen(const fs::path &p, const char *mode);

    // file
    bool file_is(const fs::path &absdir);
    bool file_size(const fs::path &p, size_t *size);
    bool file_copy(const fs::path &src, const fs::path &dest);
    bool file_rename(const fs::path &src, const fs::path &dest);
    bool file_rename(const fs::path &src, const std::string &suffix);
    bool file_exists(const fs::path &abspath);
    bool file_safe_remove(const fs::path &abspath);

    // directory
    bool dir_create(const fs::path &absdir, bool fexists_ok=true);
    bool dir_is(const fs::path &absdir);
    bool dir_exists(const fs::path &absdir);
    bool dir_safe_remove_all(const fs::path &absdir);
    NODISCARD bool dir_size(const fs::path &absdir, size_t *size, bool size_reset=true);

    class FileLock
    {
    private:
        static std::string GetErrorReason();

    public:
        FileLock() = delete;
        FileLock(const FileLock &) = delete;
        FileLock(FileLock &&) = delete;

        explicit FileLock(const fs::path &file);
        ~FileLock();
        bool TryLock();
        std::string GetReason() const { return reason; }

    private:
        std::string reason;
#ifndef WIN32
        int fd = -1;
#else
        //void *hFile = (void *)-1; // INVALID_HANDLE_VALUE
        void *hFile = INVALID_HANDLE_VALUE;
#endif
    };

    //std::string get_filesystem_error_message(const fs::filesystem_error &e);

    // GNU libstdc++ specific workaround for opening UTF-8 paths on Windows.
    //
    // On Windows, it is only possible to reliably access multibyte file paths through
    // `wchar_t` APIs, not `char` APIs. But because the C++ standard doesn't
    // require ifstream/ofstream `wchar_t` constructors, and the GNU library doesn't
    // provide them (in contrast to the Microsoft C++ library, see
    // https://stackoverflow.com/questions/821873/how-to-open-an-stdfstream-ofstream-or-ifstream-with-a-unicode-filename/822032#822032),
    // Boost is forced to fall back to `char` constructors which may not work properly.
    //
    // Work around this issue by creating stream objects with `_wfopen` in
    // combination with `__gnu_cxx::stdio_filebuf`. This workaround can be removed

#if defined WIN32 && defined __GLIBCXX__
    class ifstream : public std::istream {
    public:
        ifstream() = default;
        explicit ifstream(const fs::path &p, std::ios_base::openmode mode = std::ios_base::in) { open(p, mode); }
        ~ifstream() { close(); }
        void open(const fs::path &p, std::ios_base::openmode mode = std::ios_base::in);
        bool is_open() { return m_filebuf.is_open(); }
        void close();
    private:
        __gnu_cxx::stdio_filebuf<char> m_filebuf;
        FILE* m_file = nullptr;
    };
    class ofstream : public std::ostream {
    public:
        ofstream() = default;
        explicit ofstream(const fs::path &p, std::ios_base::openmode mode = std::ios_base::out) { open(p, mode); }
        ~ofstream() { close(); }
        void open(const fs::path &p, std::ios_base::openmode mode = std::ios_base::out);
        bool is_open() { return m_filebuf.is_open(); }
        void close();
    private:
        __gnu_cxx::stdio_filebuf<char> m_filebuf;
        FILE* m_file = nullptr;
    };
#else  // !(WIN32 && __GLIBCXX__)
    typedef fs::ifstream ifstream;
    typedef fs::ofstream ofstream;
#endif // WIN32 && __GLIBCXX__
}

#endif // BITCOIN_FS_H
