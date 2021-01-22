// Copyright (c) 2019-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SORACHANCOIN_CMSTRING_H
#define SORACHANCOIN_CMSTRING_H

#include <string>
#include <stdexcept>
#include <assert.h>
#include <uint256.h>
#include <serialize.h>
#include <util/tinyformat.h> // thanks, tinyformat.
#include <debugcs/debugcs.h> // ::_fprintf_cs(e)
#ifdef WIN32
// # define CMSTRING_WIN32API // defined, using windowsAPI
#endif
#ifdef CMSTRING_WIN32API
# include <windows.h>
#endif

#ifndef WIN32
# ifndef errno_t
  using errno_t = int;
# endif
# ifndef WCHAR
  using WCHAR = wchar_t;
# endif
# ifndef CHAR
  using CHAR = char;
# endif
# ifndef LPSTR
  using LPSTR = char *;
# endif
# ifndef LPWSTR
  using LPWSTR = wchar_t *;
# endif
# ifndef LPCSTR
  using LPCSTR = const char *;
# endif
# ifndef LPCWSTR
  using LPCWSTR = const wchar_t *;
# endif
# ifndef WORD
  using WORD = uint16_t;
# endif
# ifndef DWORD
  using DWORD = uint32_t;
# endif
# ifndef UINT_PTR
  using UINT_PTR = uintptr_t;
# endif
# ifndef INT_PTR
  using INT_PTR = intptr_t;
# endif
static inline errno_t memcpy_s(void *_Dst, size_t _DstSize, const void *_Src, size_t _SrcSize) {
    assert(_DstSize>=_SrcSize);
    ::memcpy(_Dst, _Src, _SrcSize);
    return 0;
}
static inline errno_t strcpy_s(char *_Dst, size_t _DstSize, const char *_Src) {
    (void)_DstSize;
    ::strcpy(_Dst, _Src);
    return 0;
}
static inline errno_t wcscpy_s(wchar_t *_Dst, size_t _DstSize, const wchar_t *_Src) {
    (void)_DstSize;
    ::wcscpy(_Dst, _Src);
    return 0;
}
static inline errno_t wcscat_s(wchar_t *_Dst, size_t _DstSize, const wchar_t *_Src) {
    (void)_DstSize;
    ::wcscat(_Dst, _Src);
    return 0;
}
#endif

class string_error : public std::runtime_error {
public:
    explicit string_error(const char *e) : runtime_error(e) {}
};

class string_error_stream : public std::bad_alloc {
public:
    explicit string_error_stream(const char *) : bad_alloc() {}
};

class string_error_terminate {
public:
    string_error_terminate(const char *e) noexcept {
        ::_fprintf_cs(e);
        std::terminate();
    }
};

//
// string library (char, wchar_t, etc ...)
//
using index_t = int32_t;
class CMString {
private:
    void setnull() noexcept {
        m_lpBuf = nullptr;
        m_cBuf = nullptr;
        m_dwLength = 0;
        m_mask_data = L'\0';
        m_mask_index = 0;
    }
    void release() noexcept {
        if(m_lpBuf) delete [] m_lpBuf;
        if(m_cBuf) delete [] m_cBuf;
        setnull();
    }
    void mem_buffer(const wchar_t *lpStr, size_t len) noexcept { // len: without '\0' e.g., "abcde" => len=5
        assert(lpStr && len>0);
        if (m_dwLength<=len) {
            delete [] m_lpBuf;
            m_dwLength = len+1;
            m_lpBuf = new(std::nothrow) wchar_t[m_dwLength];
            if(!m_lpBuf)
                string_error_terminate("CMString mem_buffer(): MemBuffer ERROR out of memory");
        }
        ::memcpy_s(m_lpBuf, sizeof(wchar_t)*m_dwLength, lpStr, sizeof(wchar_t)*len);
        m_lpBuf[len] = L'\0';
    }
    void splitfast(CMString &dest, wchar_t deli, int offset, int count, int next, bool *p_exist) const {
        if (m_lpBuf==nullptr || p_exist==nullptr) return;
        *p_exist = false;
        int add = next - count;
        assert(add>=0 && count>=0 && offset>=0);
        std::unique_ptr<WCHAR []> string(nullptr);
        if(this==&dest) {
            size_t alloc = this->length() + 1;
            std::unique_ptr<WCHAR []> tmp(new(std::nothrow) WCHAR[alloc]);
            if(!tmp.get())
                string_error_terminate("CMString split_fast(): GetSplitFast ERROR out of memory");
            string=std::move(tmp);
            ::wcscpy_s(string.get(), alloc, (LPCWSTR)(*this));
        }
        count = add;
        const wchar_t *lpStr = nullptr;
        int pick = 0;
        if (count==0) lpStr=(string.get()==nullptr)? m_lpBuf: string.get();
        else {
            const wchar_t *inc = (string.get()==nullptr)? m_lpBuf: string.get();
            inc += offset;
            while (*inc!=L'\0') {
                if (*inc==deli && ++pick==count) {
                    lpStr = inc+1;
                    break;
                }
                ++inc;
            }
        }
        if (lpStr) {
            size_t len = 0;
            const wchar_t *inc = lpStr;
            while (*inc!=L'\0') {
                if (*inc==deli) break;
                ++inc; ++len;
            }
            if (lpStr[0]==L'\0') {
                (string.get()==nullptr)? dest.clear(): (void)0;
                *p_exist = false;
                return;
            } else if (len==0) {
                dest = L'\0';
                *p_exist = true;
                return;
            } else {
                dest.mem_buffer(lpStr, len);
                *p_exist = true;
                return;
            }
        } else {
            (string.get()==nullptr)? dest.clear(): (void)0;
            *p_exist = false;
            return;
        }
    }
public:
    constexpr static int undef_value = -1;
    static LPWSTR wcscasestr(LPCWSTR lpStrA, LPCWSTR lpStrB) noexcept {
        const size_t lengthA = ::wcslen(lpStrA);
        const size_t lengthB = ::wcslen(lpStrB);
        std::unique_ptr<WCHAR []> lpBufA(new(std::nothrow) WCHAR[lengthA+1]);
        std::unique_ptr<WCHAR []> lpBufB(new(std::nothrow) WCHAR[lengthB+1]);
        if(!lpBufA||!lpBufB) return nullptr;
        ::wcscpy_s(lpBufA.get(), lengthA+1, lpStrA);
        ::wcscpy_s(lpBufB.get(), lengthB+1, lpStrB);
        for (int i=0; lpBufA[i]!=L'\0'; ++i) lpBufA[i]=::towlower(lpBufA[i]);
        for (int i=0; lpBufB[i]!=L'\0'; ++i) lpBufB[i]=::towlower(lpBufB[i]);
        UINT_PTR addr = (UINT_PTR)::wcsstr(lpBufA.get(), lpBufB.get());
        if (addr==0) return nullptr;
        else {
            addr-=(UINT_PTR)(&(*(lpBufA.get())));
            addr+=(UINT_PTR)lpStrA;
            return (LPWSTR)addr;
        }
    }
    static void chartowchar(const char *source, std::wstring &dest) {
#ifdef CMSTRING_WIN32API
        int cchWideChar = ::MultiByteToWideChar(CP_ACP, 0, source, -1, nullptr, 0);
        if (cchWideChar == 0) {
            DWORD dwError = ::GetLastError();
            if (dwError == ERROR_INSUFFICIENT_BUFFER || dwError == ERROR_INVALID_FLAGS || dwError == ERROR_INVALID_PARAMETER || dwError == ERROR_NO_UNICODE_TRANSLATION)
                string_error_terminate("CMString chartowchar: ERROR Buffer");
            else {dest = L""; return;}
        }
        dest.resize(cchWideChar, '\0');
        if(::MultiByteToWideChar(CP_ACP, 0, source, -1, &dest.at(0), cchWideChar)<=0)
            string_error_terminate("CMString chartowchar: ERROR MultiByteToWideChar");
#else
        size_t size = ::mbstowcs(nullptr, source, 0);
        if(size == (size_t)-1)
            string_error_terminate("CMString chartowchar: ERROR size");
        dest.resize(size+1, L'\0'); // size is no bytes.
        if(::mbstowcs(&dest.at(0), source, size)==(size_t)-1)
            string_error_terminate("CMString chartowchar: ERROR mbstowcs");
#endif
    }
    static void utoutf8cpy(char *cStr, LPCWSTR lpStr, DWORD *pdwLength) noexcept {
        if (lpStr[0]==L'\0') {
            *pdwLength = 0;
            if (cStr!=nullptr) cStr[0] = '\0';
            return;
        }
#ifdef CMSTRING_WIN32API
        int nLength = ::WideCharToMultiByte(CP_UTF8, 0, lpStr, -1, nullptr, 0, nullptr, nullptr);
        *pdwLength = (DWORD)nLength;
        if (nLength==0) {
            DWORD dwError = ::GetLastError();
            if (dwError == ERROR_INSUFFICIENT_BUFFER || dwError == ERROR_INVALID_FLAGS || dwError == ERROR_INVALID_PARAMETER)
                string_error_terminate("CMString utoutf8cpy: ERROR WideCharToMultiByte");
        }
        if (cStr==nullptr) return;
        else {
            int nMultiLength = ::WideCharToMultiByte(CP_UTF8, 0, lpStr, -1, cStr, nLength, nullptr, nullptr);
            if (nMultiLength<=0)
                string_error_terminate("CMString utoutf8cpy: ERROR WideCharToMultiByte");
            return;
        }
#else
        size_t size = ::wcstombs(nullptr, lpStr, 0) + 1;
        if(size==(size_t)-1)
            string_error_terminate("CMString utoutf8cpy: ERROR size");
        *pdwLength=size;
        if(cStr==nullptr) return;
        cStr[size-1]='\0';
        if(::wcstombs(cStr, lpStr, size-1)==(size_t)-1)
            string_error_terminate("CMString utoutf8cpy: ERROR wcstombs");
#endif
    }
    static void utf8toucpy(wchar_t *lpStr, const char *cStrOrg, DWORD *pdwLength) noexcept {
        if (cStrOrg[0]=='\0') {
            *pdwLength = 0;
            if (lpStr!=nullptr) lpStr[0]=L'\0';
            return;
        }
#ifdef CMSTRING_WIN32API
        int cchWideChar = ::MultiByteToWideChar(CP_UTF8, 0, cStrOrg, -1, nullptr, 0);
        *pdwLength = (DWORD)cchWideChar;
        if (cchWideChar==0) {
            DWORD dwError = ::GetLastError();
            if (dwError == ERROR_INSUFFICIENT_BUFFER || dwError == ERROR_INVALID_FLAGS || dwError == ERROR_INVALID_PARAMETER || dwError == ERROR_NO_UNICODE_TRANSLATION)
                string_error_terminate("CMString utf8toucpy: ERROR MultiByteToWideChar");
        }
        if (lpStr==nullptr) return;
        else {
            int nUnicodeCount = ::MultiByteToWideChar(CP_UTF8, 0, cStrOrg, -1, lpStr, cchWideChar);
            if (nUnicodeCount<=0)
                string_error_terminate("CMString utf8toucpy: ERROR MultiByteToWideChar");
            return;
        }
#else
        size_t size = ::mbstowcs(nullptr, cStrOrg, 0) + 1;
        if(size == (size_t)-1)
            string_error_terminate("CMString utf8toucpy: ERROR size");
        *pdwLength=size;
        if(lpStr==nullptr) return;
        lpStr[size-1] = L'\0';
        if(::mbstowcs(lpStr, cStrOrg, size)==(size_t)-1)
            string_error_terminate("CMString utf8toucpy: ERROR mbstowcs");
#endif
    }

    int replace(WCHAR chOld, WCHAR chNew) noexcept {
        WCHAR strOld[] = {chOld, L'\0'};
        WCHAR strNew[] = {chNew, L'\0'};
        return replace(strOld, strNew);
    }
    int replace(LPCWSTR lpOld, LPCWSTR lpNew) noexcept {
        size_t old_size=::wcslen( lpOld );
        CMString obj;
        if (old_size==0) return undef_value;
        else {
            int rep_num = 0;
            obj.clear();
            LPCWSTR lpTemp = m_lpBuf;
            if(!lpTemp) {
                *this = L"";
                return rep_num;
            }
            while(*lpTemp!=L'\0') {
                if(*lpTemp==lpOld[0]&&::wcsstr(lpTemp, lpOld)==lpTemp) {
                    if (lpNew[0]!=L'\0') obj+=lpNew;
                    lpTemp+=old_size;
                    ++rep_num;
                } else {
                    obj+=*lpTemp;
                    ++lpTemp;
                }
            }
            *this = (LPCWSTR)obj;
            return rep_num;
        }
    }
    int replace_case(LPCWSTR lpOld, LPCWSTR lpNew) noexcept {
        size_t old_size=::wcslen(lpOld);
        CMString obj;
        if (old_size==0) return undef_value;
        else {
            int rep_num = 0;
            obj.clear();
            LPCWSTR lpTemp = m_lpBuf;
            if (!lpTemp) {
                *this = L"";
                return rep_num;
            }
            while(*lpTemp!=L'\0') {
                if(towlower(*lpTemp)==::towlower(lpOld[0])&&wcscasestr(lpTemp, lpOld)==lpTemp) {
                    if (lpNew[0]!=L'\0') obj+=lpNew;
                    lpTemp+=old_size;
                    ++rep_num;
                } else {
                    obj+=*lpTemp;
                    ++lpTemp;
                }
            }
            *this = (LPCWSTR)obj;
            return rep_num;
        }
    }
    int replace_safe(WCHAR chOld, WCHAR chNew, size_t length) noexcept {
        WCHAR strOld[] = {chOld, L'\0'};
        WCHAR strNew[] = {chNew, L'\0'};
        return replace_safe(strOld, strNew, length);
    }
    int replace_safe(LPCWSTR lpOld, LPCWSTR lpNew, size_t length) noexcept {
        size_t old_size=::wcslen(lpOld);
        CMString obj;
        if (old_size==0) return undef_value;
        else {
            int rep_num = 0;
            obj.clear();
            LPCWSTR lpTemp = m_lpBuf;
            if (!lpTemp)    {
                *this = L"";
                return rep_num;
            }
            for(size_t i=0; i<length; ++i) {
                if(*lpTemp==L'\0') break;
                if(*lpTemp==lpOld[0]&&::wcsstr(lpTemp, lpOld)==lpTemp) {
                    if(lpNew[0]!=L'\0') obj += lpNew;
                    lpTemp+=old_size;
                    ++rep_num;
                } else {
                    obj += *lpTemp;
                    ++lpTemp;
                }
            }
            *this = (LPCWSTR)obj;
            return rep_num;
        }
    }

    CMString tokenize(LPCWSTR pszTokens, int &iStart) const noexcept {
        size_t size=::wcslen(pszTokens);
        CMString obj;
        obj.clear();
        if(iStart<0 || m_lpBuf==nullptr) {
            iStart = undef_value;
            return obj;
        } else {
            LPCWSTR lpTemp = m_lpBuf+iStart;
            if (L'\0'==*lpTemp) {
                iStart = undef_value;
                return obj;
            }
            while(*lpTemp!=L'\0') {
                for (int i=0; i<(int)size; ++i) {
                    if (*lpTemp==pszTokens[i]) {
                        iStart += 1;
                        if (0<obj.length()) return obj;
                        else ++lpTemp;
                    }
                }
                obj+=*lpTemp;
                ++lpTemp;
                ++iStart;
            }
            return obj;
        }
    }
    CMString right(int nCount) const {
        CMString obj;
        obj.clear();
        size_t start = length()-1-(nCount-1);
        if(nCount<= 0 || start<=0) return obj;
        else {
            if (nullptr==m_lpBuf) return obj;
            else {
                LPCWSTR p=&m_lpBuf[start];
                for (int i=0; i<nCount; ++i) obj+=*p;
                return obj;
            }
        }
    }
    CMString left(int nCount) const {
        CMString obj;
        obj.clear();
        if(nCount <= 0) return obj;
        else {
            if (nullptr==m_lpBuf) return obj;
            else {
                LPCWSTR p = m_lpBuf;
                for (int i=0; i<nCount; ++i) obj+=*p;
                return obj;
            }
        }
    }
    bool empty() const noexcept {
        return m_lpBuf==nullptr || m_lpBuf[0]==L'\0';
    }

    //
    // CMString += A
    //
    CMString &operator+=(LPCWSTR lpStr) noexcept {
        if (lpStr==nullptr || lpStr[0]==L'\0')
            return *this;
        size_t length = (m_lpBuf!=nullptr)? ::wcslen(m_lpBuf)+::wcslen(lpStr): ::wcslen(lpStr);
        if (m_dwLength<=length) {
            size_t reallocLength = length + 1 + (length>>1);
            wchar_t *new_buf = new(std::nothrow) wchar_t[reallocLength];
            if(! new_buf)
                string_error_terminate("CMString operator+=(LPCWSTR): out of memory");
            m_dwLength = reallocLength;
            if (m_lpBuf) {
                ::wcscpy_s(new_buf, m_dwLength, m_lpBuf);
                ::wcscat_s(new_buf, m_dwLength, lpStr);
                delete [] m_lpBuf;
                m_lpBuf=new_buf;
            } else {
                ::wcscpy_s(new_buf, m_dwLength, lpStr);
                m_lpBuf=new_buf;
            }
        } else (m_lpBuf!=nullptr)? (void)::wcscat_s(m_lpBuf, m_dwLength, lpStr): (void)operator=(lpStr);
        return *this;
    }
    CMString &operator+=(const char *cStr) noexcept {
        if (cStr==nullptr) return *this;
        else {
            std::wstring wstr;
            chartowchar(cStr, wstr);
            return operator+=(wstr.c_str());
        }
    }
    CMString &operator+=(wchar_t wch) noexcept {
        wchar_t str[] = {wch, L'\0'};
        return operator+=( str );
    }
    CMString &operator+=(char cch) noexcept {
        char str[] = {cch, '\0'};
        return operator+=( str );
    }
    CMString &operator+=(int16_t nNum) {
        return operator+=(tfm::format(std::string("%d"), nNum));
    }
    CMString &operator+=(uint16_t nNum) {
        return operator+=(tfm::format(std::string("%d"), nNum));
    }
    CMString &operator+=(int32_t nNum) {
        return operator+=(tfm::format(std::string("%d"), nNum));
    }
    CMString &operator+=(uint32_t nNum) {
        return operator+=(tfm::format(std::string("%d"), nNum));
    }
    CMString &operator+=(int64_t nNum) {
        return operator+=(tfm::format(std::string("%d"), nNum));
    }
    CMString &operator+=(uint64_t nNum) {
        return operator+=(tfm::format(std::string("%d"), nNum));
    }
    CMString &operator+=(float dNum) {
        return operator+=(tfm::format(std::string("%d"), dNum));
    }
    CMString &operator+=(double dNum) {
        return operator+=(tfm::format(std::string("%d"), dNum));
    }
    CMString &operator+=(const CMString &obj) noexcept {
        return operator+=(obj.m_lpBuf);
    }
    CMString &operator+=(const std::string &obj) {
        operator+=(obj.c_str());
        return *this;
    }
    CMString &operator+=(const std::wstring &obj) {
        operator+=(obj.c_str());
        return *this;
    }

    //
    // CMString = A
    //
    CMString &operator=(LPCWSTR lpStr) noexcept {
        if (lpStr==nullptr || lpStr[0]==L'\0') {
            mem_clear(0);
            return *this;
        }
        size_t size = ::wcslen(lpStr);
        if (m_dwLength<=size) {
            size_t reallocLength = size + 1 + (size>>1);
            wchar_t *new_buf = new(std::nothrow) wchar_t[reallocLength];
            if(!new_buf)
                string_error_terminate("CMString operator=(LPCWSTR): out of memory");
            m_dwLength = reallocLength;
            ::wcscpy_s(new_buf, m_dwLength, lpStr);
            delete [] m_lpBuf;
            m_lpBuf = new_buf;
        } else ::wcscpy_s(m_lpBuf, m_dwLength, lpStr);
        return *this;
    }
    CMString &operator=(const char *cStr) noexcept {
        if (cStr==nullptr) return *this;
        else {
            std::wstring wstr;
            chartowchar(cStr, wstr);
            return operator=(wstr.c_str());
        }
    }
    CMString &operator=(wchar_t wch) noexcept {
        wchar_t str[] = {wch, L'\0'};
        return operator=(str);
    }
    CMString &operator=(char cch) noexcept {
        char str[] = {cch, '\0'};
        return operator=(str);
    }
    CMString &operator=(int16_t nNum) noexcept {
        return operator=(tfm::format(std::string("%d"), nNum));
    }
    CMString &operator=(uint16_t nNum) noexcept {
        return operator=(tfm::format(std::string("%d"), nNum));
    }
    CMString &operator=(int32_t nNum) noexcept {
        return operator=(tfm::format(std::string("%d"), nNum));
    }
    CMString &operator=(uint32_t nNum) noexcept {
        return operator=(tfm::format(std::string("%d"), nNum));
    }
    CMString &operator=(int64_t nNum) noexcept {
        return operator=(tfm::format(std::string("%d"), nNum));
    }
    CMString &operator=(uint64_t nNum) noexcept {
        return operator=(tfm::format(std::string("%d"), nNum));
    }
    CMString &operator=(float dNum) noexcept {
        return operator=(tfm::format(std::string("%d"), dNum));
    }
    CMString &operator=(double dNum) noexcept {
        return operator=(tfm::format(std::string("%d"), dNum));
    }
    CMString &operator=(const std::string &obj) {
        return operator=(obj.c_str());
    }
    CMString &operator=(const std::wstring &obj) {
        return operator=(obj.c_str());
    }

    //
    // CMString = A + B
    //
    CMString &operator+(LPCWSTR lpStr) noexcept {
        return (lpStr==m_lpBuf)? *this: operator+=(lpStr);
    }
    CMString &operator+(const char *cStr) noexcept {
        return operator+=(cStr);
    }
    CMString &operator+(wchar_t wch) noexcept {
        return operator+=(wch);
    }
    CMString &operator+(char cch) noexcept {
        return operator+=(cch);
    }
    CMString &operator+(int16_t nNum) {
        return operator+=(tfm::format(std::string("%d"), nNum));
    }
    CMString &operator+(uint16_t nNum) {
        return operator+=(tfm::format(std::string("%d"), nNum));
    }
    CMString &operator+(int32_t nNum) {
        return operator+=(tfm::format(std::string("%d"), nNum));
    }
    CMString &operator+(uint32_t nNum) {
        return operator+=(tfm::format(std::string("%d"), nNum));
    }
    CMString &operator+(int64_t uNum) {
        return operator+=(tfm::format(std::string("%d"), uNum));
    }
    CMString &operator+(uint64_t uNum) {
        return operator+=(tfm::format(std::string("%d"), uNum));
    }
    CMString &operator+(float dNum) {
        return operator+=(tfm::format(std::string("%d"), dNum));
    }
    CMString &operator+(double dNum) {
        return operator+=(tfm::format(std::string("%d"), dNum));
    }
    CMString &operator+(const CMString &obj) noexcept {
        return operator+=(obj.w_str());
    }
    CMString &operator+(const std::string &obj) {
        return operator+=(obj.c_str());
    }
    CMString &operator+(const std::wstring &obj) {
        return operator+=(obj.c_str());
    }

    //
    // like std::string
    //
    const char *c_str() const noexcept {
        if (m_lpBuf==nullptr) return "";
        else {
            if(m_cBuf) delete [] m_cBuf;
            DWORD dwLen;
            utoutf8cpy(nullptr, m_lpBuf, &dwLen);
            m_cBuf = new(std::nothrow) char[dwLen];
            if(! m_cBuf)
                string_error_terminate("CMString c_str(): out of memory");
            utoutf8cpy(m_cBuf, m_lpBuf, &dwLen);
            return m_cBuf;
        }
    }
    LPCWSTR w_str() const noexcept {
        if (m_lpBuf==nullptr) return L"";
        else return m_lpBuf;
    }

    void set_str(const char *utf8) noexcept {
        if (utf8==nullptr) return;
        DWORD dwLength = 0;
        utf8toucpy(nullptr, utf8, &dwLength);
        std::unique_ptr<wchar_t []> str(new(std::nothrow) WCHAR[dwLength]);
        if(!str.get())
            string_error_terminate("SetUtf8 memory allocate failure");
        utf8toucpy(str.get(), utf8, &dwLength);
        *this = str.get();
    }

    size_t bytes(bool fwide) const noexcept {
        if (m_lpBuf==nullptr) return 0;
        if(fwide) {
            c_str();
            return ::strlen(m_cBuf)*sizeof(char);
        } else
            return length()*sizeof(WCHAR);
    }

    bool search(char cch) const noexcept {
        if (m_lpBuf==nullptr) return false;
        else {
            const char *p = c_str();
            while(*p++!='\0') {
                if ( cch == *p ) return true;
            }
            return false;
        }
    }
    bool search(const char *cStr) const noexcept {
        if (cStr==nullptr || m_lpBuf==nullptr) return false;
        else {
            const char *p = c_str();
            return ::strstr(p, cStr)? true: false;
        }
    }
    const char *search_at(char cch) const noexcept {
        if (m_lpBuf==nullptr) return nullptr;
        else {
            bool flag = false;
            const char *p = c_str();
            while (*p++ != '\0') {
                if (*p==cch) {flag = true; break;}
            }
            return (flag)? p: nullptr;
        }
    }

    wchar_t operator[](index_t index) noexcept {
        assert(m_lpBuf && index>=0 && m_dwLength>index);
        //if(m_lpBuf==nullptr) return L'\0';
        return m_lpBuf[index];
    }
    wchar_t operator[](index_t index) const noexcept {
        assert(m_lpBuf && index>=0 && m_dwLength>index);
        if(m_lpBuf==nullptr) return L'\0';
        return m_lpBuf[index];
    }

    char c_at(index_t index) noexcept {
        return c_str()[index];
    }
    char c_at(index_t index) const noexcept {
        return c_str()[index];
    }

    template <typename... Args>
    void format(const wchar_t *lpType, const Args&... args) {
        operator=(tfm::format(CMString(lpType), args...));
    }
    template <typename... Args>
    void format(const char *lpType, const Args&... args) {
        operator=(tfm::format(lpType, args...));
    }
    template <typename... Args>
    void formatcat(const wchar_t *lpType, const Args&... args) {
        operator+=(tfm::format(CMString(lpType), args...));
    }
    template <typename... Args>
    void formatcat(const char *lpType, const Args&... args) {
        operator+=(tfm::format(lpType, args...));
    }

    void tolower() const noexcept {
        if (m_lpBuf) {
            LPWSTR p = m_lpBuf;
            while (*p!=L'\0') {
                *p = ::towlower(*p);
                ++p;
            }
        }
    }
    void toupper() const noexcept {
        if (m_lpBuf) {
            LPWSTR p = m_lpBuf;
            while (*p!=L'\0') {
                *p = ::towupper(*p);
                ++p;
            }
        }
    }

    bool search(wchar_t cch) const noexcept {
        if (m_lpBuf==nullptr) return false;
        else {
            for(size_t i=0; i<m_dwLength; ++i) {
                if (cch==m_lpBuf[i]) return true;
            }
            return false;
        }
    }
    bool search(LPCWSTR lpStr) const noexcept {
        if (lpStr==nullptr || m_lpBuf==nullptr) return false;
        else return (::wcsstr(*this, lpStr))? true: false;
    }
    LPCWSTR search_at(wchar_t cch) const noexcept {
        if (!m_lpBuf) return nullptr;
        else {
            bool flag = false;
            const wchar_t *p = (LPCWSTR)(*this);
            while (*p++!=L'\0') {
                if (*p==cch) {
                    flag = true;
                    break;
                }
            }
            return (flag)? p: nullptr;
        }
    }

    size_t size() const noexcept {return (m_lpBuf==nullptr)? 0: ::wcslen(m_lpBuf);}
    size_t length() const noexcept {return size();}

    bool operator==(const CMString &obj) const noexcept {return (m_lpBuf)? ::wcscmp(*this, (LPCWSTR)obj)==0: false;}
    bool operator<(const CMString &obj) const noexcept  {return 0<::wcscmp((LPCWSTR)obj, (LPCWSTR)*this);}
    bool operator!=(const CMString &obj) const noexcept {return ::wcscmp((LPCWSTR)*this, (LPCWSTR)obj)!=0;}
    bool operator==(LPCWSTR str) const noexcept         {return ::wcscmp((LPCWSTR)*this, str)==0;}
    bool operator!=(LPCWSTR str) const noexcept         {return ::wcscmp((LPCWSTR)*this, str)!=0;}
    bool operator==(LPCSTR str) const noexcept          {return ::strcmp((LPCSTR)*this, str)==0;}
    bool operator!=(LPCSTR str) const noexcept          {return ::strcmp((LPCSTR)*this, str)!=0;}
    bool operator==(char c) const noexcept {
        const char str[] = {c, '\0'};
        return ::strcmp((LPCSTR)*this, str)==0;
    }
    bool operator!=(char c) const noexcept {
        return !(operator==(c));
    }
    bool operator==(wchar_t c) const noexcept {
        const wchar_t str[] = {c, L'\0'};
        return ::wcscmp((LPCWSTR)*this, str)==0;
    }
    bool operator!=(wchar_t c) const noexcept {
        return !(operator==(c));
    }
    bool operator==(int16_t i) const {
        std::string c = tfm::format("%d", i);
        return ::strcmp((LPCSTR)*this, c.c_str())==0;
    }
    bool operator!=(int16_t i) const {
        return !(operator==(i));
    }
    bool operator==(uint16_t i) const {
        std::string c = tfm::format("%d", i);
        return ::strcmp((LPCSTR)*this, c.c_str())==0;
    }
    bool operator!=(uint16_t i) const {
        return !(operator==(i));
    }
    bool operator==(int32_t i) const {
        std::string c = tfm::format("%d", i);
        return ::strcmp((LPCSTR)*this, c.c_str())==0;
    }
    bool operator!=(int32_t i) const {
        return !(operator==(i));
    }
    bool operator==(uint32_t i) const {
        std::string c = tfm::format("%d", i);
        return ::strcmp((LPCSTR)*this, c.c_str())==0;
    }
    bool operator!=(uint32_t i) const {
        return !(operator==(i));
    }
    bool operator==(int64_t i) const {
        std::string c = tfm::format("%d", i);
        return ::strcmp((LPCSTR)*this, c.c_str())==0;
    }
    bool operator!=(int64_t i) const {
        return !(operator==(i));
    }
    bool operator==(uint64_t i) const {
        std::string c = tfm::format("%d", i);
        return ::strcmp((LPCSTR)*this, c.c_str())==0;
    }
    bool operator!=(uint64_t i) const {
        return !(operator==(i));
    }
    bool operator==(float d) const {
        std::string c = tfm::format("%d", d);
        return ::strcmp((LPCSTR)*this, c.c_str())==0;
    }
    bool operator!=(float d) const {
        return !(operator==(d));
    }
    bool operator==(double d) const {
        std::string c = tfm::format("%d", d);
        return ::strcmp((LPCSTR)*this, c.c_str())==0;
    }
    bool operator!=(double d) const {
        return !(operator==(d));
    }
    bool operator==(const uint160 &obj) const noexcept {
        return ::strcmp((LPCSTR)*this, obj.ToString().c_str())==0;
    }
    bool operator!=(const uint160 &obj) const noexcept {
        return !(operator==(obj));
    }
    bool operator==(const uint256 &obj) const noexcept {
        return ::strcmp((LPCSTR)*this, obj.ToString().c_str())==0;
    }
    bool operator!=(const uint256 &obj) const noexcept {
        return !(operator==(obj));
    }
    bool operator==(const uint512 &obj) const noexcept {
        return ::strcmp((LPCSTR)*this, obj.ToString().c_str())==0;
    }
    bool operator!=(const uint512 &obj) const noexcept {
        return !(operator==(obj));
    }
    bool operator==(const uint65536 &obj) const noexcept {
        return ::strcmp((LPCSTR)*this, obj.ToString().c_str())==0;
    }
    bool operator!=(const uint65536 &obj) const noexcept {
        return !(operator==(obj));
    }
    bool operator==(const uint131072 &obj) const noexcept {
        return ::strcmp((LPCSTR)*this, obj.ToString().c_str())==0;
    }
    bool operator!=(const uint131072 &obj) const noexcept {
        return !(operator==(obj));
    }

    void split(CMString *pstr, wchar_t delim, int count, bool *p_exists) const noexcept {
        (pstr)? splitfast(*pstr, delim, 0, 0, count, p_exists): (void)0;
    }
    void split(CMString *pstr, wchar_t delim, int offset, int count, int next, bool *p_exists) const noexcept {
        (pstr)? splitfast(*pstr, delim, offset, count, next, p_exists): (void)0;
    }
    void splitlast(CMString *pstr, wchar_t delim, bool *p_exists) const noexcept {
        (pstr)? splitfast(*pstr, delim, 0, 0, lastadd_delim_count(delim)-1, p_exists): (void)0;
    }
    int delim_count(wchar_t delim) const noexcept {
        if (m_lpBuf==nullptr) return 0;
        else {
            int count=0;
            wchar_t check;
            const wchar_t *inc=m_lpBuf;
            while((check=*inc++)!=L'\0') (check==delim)? ++count: 0;
            return count;
        }
    }
    int lastadd_delim_count(wchar_t delim) const noexcept {
        if (m_lpBuf==nullptr) return 0;
        else {
            int count=0;
            wchar_t check;
            const wchar_t *inc=m_lpBuf;
            while ((check=*inc++)!=L'\0') (check==delim)? ++count: 0;
            --inc;
            (*inc!=delim)? ++count: 0;
            return count;
        }
    }

    void mask_set(size_t index, wchar_t wch) noexcept {
        assert(size()>index && index>=0 && m_mask_data==L'\0');
        if (m_lpBuf==nullptr) return;
        m_mask_data = m_lpBuf[index];
        m_mask_index = index;
        m_lpBuf[index] = wch;
    }
    void mask_release() noexcept {
        if (m_lpBuf==nullptr || m_mask_index<0) return;
        m_lpBuf[m_mask_index] = m_mask_data;
        m_mask_data = L'\0';
    }
    int mask_index() const noexcept {
        return m_mask_index;
    }

    void clear() noexcept {
        if(m_lpBuf) m_lpBuf[0] = L'\0';
    }
    void mem_clear() noexcept {
        mem_clear(0);
    }
    void mem_clear(size_t first_size) noexcept {
        delete [] m_cBuf; m_cBuf=nullptr;
        delete [] m_lpBuf; m_lpBuf=nullptr;
        if (0<first_size) {
            m_dwLength = first_size;
            m_lpBuf = new(std::nothrow) wchar_t[m_dwLength];
            if(!m_lpBuf)
                string_error_terminate("CMString mem_clear(): out of memory");
        } else {
            m_dwLength = 0;
            m_lpBuf = nullptr;
        }
        m_mask_index = 0;
    }

    CMString() noexcept {
        setnull();
    }
    CMString(const wchar_t *lpStr) noexcept {
        setnull();
        operator=(lpStr);
    }
    CMString(const char *cStr) noexcept {
        setnull();
        operator=(cStr);
    }
    CMString(wchar_t wc) noexcept {
        setnull();
        wchar_t str[] = {wc, L'\0'};
        operator=(str);
    }
    CMString(char c) noexcept {
        setnull();
        char str[] = {c, '\0'};
        operator=(str);
    }
    CMString(int16_t n) {
        setnull();
        operator=(tfm::format(std::string("%d"), n));
    }
    CMString(uint16_t n) {
        setnull();
        operator=(tfm::format(std::string("%d"), n));
    }
    CMString(int32_t n) {
        setnull();
        operator=(tfm::format(std::string("%d"), n));
    }
    CMString(uint32_t n) {
        setnull();
        operator=(tfm::format(std::string("%d"), n));
    }
    CMString(int64_t n) {
        setnull();
        operator=(tfm::format(std::string("%d"), n));
    }
    CMString(uint64_t n) {
        setnull();
        operator=(tfm::format(std::string("%d"), n));
    }
    CMString(float d) {
        setnull();
        operator=(tfm::format(std::string("%d"), d));
    }
    CMString(double d) {
        setnull();
        operator=(tfm::format(std::string("%d"), d));
    }
    CMString(const uint160 &obj) {
        setnull();
        operator=(obj.ToString());
    }
    CMString(const uint256 &obj) {
        setnull();
        operator=(obj.ToString());
    }
    CMString(const uint512 &obj) {
        setnull();
        operator=(obj.ToString());
    }
    CMString(const uint65536 &obj) {
        setnull();
        operator=(obj.ToString());
    }
    CMString(const uint131072 &obj) {
        setnull();
        operator=(obj.ToString());
    }
    CMString(const std::string &str) {
        setnull();
        operator=(str.c_str());
    }
    CMString(const std::wstring &str) {
        setnull();
        operator=(str.c_str());
    }
    virtual ~CMString() {
        release();
    }

    //
    // return object
    //
    operator LPCWSTR() const noexcept {
        return w_str();
    }
    operator const char *() const noexcept {
        return c_str();
    }
    std::string str() const {
        return std::string(c_str());
    }
    std::wstring wstr() const {
        return std::wstring(w_str());
    }
    // no defined operator std::string() and operator std::wstring() (because ambiguous)
    // using .str() or .wstr()

    //
    // const CMString + (CMString, primitive or other object)
    //
    friend class CMString operator+(const CMString &s1, const std::string &s2) {
        return CMString(s1)+s2;
    }
    friend class CMString operator+(const CMString &s1, const std::wstring &s2) {
        return CMString(s1)+s2;
    }
    friend class CMString operator+(const CMString &s1, char c2) {
        return CMString(s1)+c2;
    }
    friend class CMString operator+(const CMString &s1, wchar_t c2) {
        return CMString(s1)+c2;
    }
    friend class CMString operator+(const CMString &s1, int16_t i2) {
        return CMString(s1)+i2;
    }
    friend class CMString operator+(const CMString &s1, uint16_t i2) {
        return CMString(s1)+i2;
    }
    friend class CMString operator+(const CMString &s1, int32_t i2) {
        return CMString(s1)+i2;
    }
    friend class CMString operator+(const CMString &s1, uint32_t i2) {
        return CMString(s1)+i2;
    }
    friend class CMString operator+(const CMString &s1, int64_t i2) {
        return CMString(s1)+i2;
    }
    friend class CMString operator+(const CMString &s1, uint64_t i2) {
        return CMString(s1)+i2;
    }
    friend class CMString operator+(const CMString &s1, const uint160 &u2) {
        return CMString(s1).operator+(u2); // if +u2, ISO C++ ambiguous
    }
    friend class CMString operator+(const CMString &s1, const uint256 &u2) {
        return CMString(s1).operator+(u2); // if +u2, ISO C++ ambiguous
    }
    friend class CMString operator+(const CMString &s1, const uint512 &u2) {
        return CMString(s1).operator+(u2); // if +u2, ISO C++ ambiguous
    }
    friend class CMString operator+(const CMString &s1, const uint65536 &u2) {
        return CMString(s1).operator+(u2); // if +u2, ISO C++ ambiguous
    }
    friend class CMString operator+(const CMString &s1, const uint131072 &u2) {
        return CMString(s1).operator+(u2); // if +u2, ISO C++ ambiguous
    }

    //
    // (CMString, primitive or other object) + CMString
    //
    friend class CMString operator+(const std::string &s1, const CMString &s2) {
        return CMString(s1)+s2;
    }
    friend class CMString operator+(const std::wstring &s1, const CMString &s2) {
        return CMString(s1)+s2;
    }
    friend class CMString operator+(char c1, const CMString &s2) {
        return CMString(c1)+s2;
    }
    friend class CMString operator+(wchar_t c1, const CMString &s2) {
        return CMString(c1)+s2;
    }
    friend class CMString operator+(int16_t i1, const CMString &s2) {
        return CMString(i1)+s2;
    }
    friend class CMString operator+(uint16_t i1, const CMString &s2) {
        return CMString(i1)+s2;
    }
    friend class CMString operator+(int32_t i1, const CMString &s2) {
        return CMString(i1)+s2;
    }
    friend class CMString operator+(uint32_t i1, const CMString &s2) {
        return CMString(i1)+s2;
    }
    friend class CMString operator+(int64_t i1, const CMString &s2) {
        return CMString(i1)+s2;
    }
    friend class CMString operator+(uint64_t i1, const CMString &s2) {
        return CMString(i1)+s2;
    }
    friend class CMString operator+(float d1, const CMString &s2) {
        return CMString(d1)+s2;
    }
    friend class CMString operator+(double d1, const CMString &s2) {
        return CMString(d1)+s2;
    }
    friend class CMString operator+(const uint160 &u1, const CMString &s2) {
        return CMString(u1)+s2;
    }
    friend class CMString operator+(const uint256 &u1, const CMString &s2) {
        return CMString(u1)+s2;
    }
    friend class CMString operator+(const uint512 &u1, const CMString &s2) {
        return CMString(u1)+s2;
    }
    friend class CMString operator+(const uint65536 &u1, const CMString &s2) {
        return CMString(u1)+s2;
    }
    friend class CMString operator+(const uint131072 &u1, const CMString &s2) {
        return CMString(u1)+s2;
    }

    //
    // copy and move constructor
    //
    CMString(const CMString &obj) noexcept {
        setnull();
        operator=(obj);
    }
    CMString(CMString &&obj) noexcept {
        setnull();
        operator=(obj);
    }
    CMString &operator=(const CMString &obj) noexcept {
        *this=(LPCWSTR)obj;
        return *this;
    }
    CMString &operator=(CMString &&robj) noexcept {
        this->swap(static_cast<CMString &&>(robj));
        return *this;
    }

    //
    // format constructor
    //
    template <typename... Args>
    CMString(const char *str, const Args&... args) {
        format(str, args...);
    }
    template <typename... Args>
    CMString(LPCWSTR str, const Args&... args) {
        format(str, args...);
    }

    //
    // rvalue operator
    //
    void swap(CMString &&robj) noexcept {
        setnull();
        m_lpBuf = robj.m_lpBuf;
        m_dwLength = robj.m_dwLength;
        m_mask_data = robj.m_mask_data;
        m_mask_index = robj.m_mask_index;
    }

    //
    // CDataStream
    // Serialize, Unserialize
    //
    template <typename Stream>
    inline void Serialize(Stream &s) const {
        const unsigned int len = bytes(false)+sizeof(wchar_t)+sizeof(int);
        compact_size::manage::WriteCompactSize(s, len);
        if(0 < len) {
            s.write((const char *)m_lpBuf, bytes(false));
            s.write((const char *)&m_mask_data, sizeof(wchar_t));
            s.write((const char *)&m_mask_index, sizeof(int));
        }
    }
    template <typename Stream>
    inline void Unserialize(Stream &s) {
        const unsigned int len = compact_size::manage::ReadCompactSize(s);
        if(0 < len) {
            if(m_lpBuf) delete [] m_lpBuf;
            if(m_cBuf) delete [] m_cBuf;
            const size_t size = (len-sizeof(wchar_t)-sizeof(int))/sizeof(wchar_t) + 1; // with '\0'
            m_lpBuf = new(std::nothrow) wchar_t[size];
            if(! m_lpBuf)
                throw string_error_stream("CMString Unserialize(Stream): out of memory"); // catch: try { CDataStream } catch(...) {}
            m_dwLength = size;
            s.read((char *)m_lpBuf, (size-1)*sizeof(wchar_t));
            m_lpBuf[size - 1] = L'\0';
            s.read((char *)&m_mask_data, sizeof(wchar_t));
            s.read((char *)&m_mask_index, sizeof(int));
        }
    }

private:
    wchar_t *m_lpBuf;
    mutable char *m_cBuf;
    size_t m_dwLength; // with '\0'
    wchar_t m_mask_data;
    int m_mask_index;
};

//
// global operator
//
static inline bool operator==(const std::string &s1, const CMString &s2) {
    return (s2==s1);
}

static inline bool operator==(const std::wstring &s1, const CMString &s2) {
    return (s2==s1);
}

static inline bool operator==(char c1, const CMString &s2) {
    return (s2==c1);
}

static inline bool operator==(wchar_t c1, const CMString &s2) {
    return (s2==c1);
}

static inline bool operator==(int16_t i1, const CMString &s2) {
    return (s2==i1);
}

static inline bool operator==(uint16_t i1, const CMString &s2) {
    return (s2==i1);
}

static inline bool operator==(int32_t i1, const CMString &s2) {
    return (s2==i1);
}

static inline bool operator==(uint32_t i1, const CMString &s2) {
    return (s2==i1);
}

static inline bool operator==(int64_t i1, const CMString &s2) {
    return (s2==i1);
}

static inline bool operator==(uint64_t i1, const CMString &s2) {
    return (s2==i1);
}

static inline bool operator==(float d1, const CMString &s2) {
    return (s2==d1);
}

static inline bool operator==(double d1, const CMString &s2) {
    return (s2==d1);
}

static inline bool operator==(const uint160 &u1, const CMString &s2) {
    return (s2==u1);
}

static inline bool operator==(const uint256 &u1, const CMString &s2) {
    return (s2==u1);
}

static inline bool operator==(const uint512 &u1, const CMString &s2) {
    return (s2==u1);
}

static inline bool operator==(const uint65536 &u1, const CMString &s2) {
    return (s2==u1);
}

static inline bool operator==(const uint131072 &u1, const CMString &s2) {
    return (s2==u1);
}

#endif // SORACHANCOIN_CMSTRING_H
