// Copyright (c) 2019-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SORACHANCOIN_CMSTRING_H
#define SORACHANCOIN_CMSTRING_H

#include <string>
#include <stdexcept>
#include <assert.h>
#include <uint256.h>
#include <debugcs/debugcs.h>
#ifdef WIN32
# include <windows.h>
#endif

class string_error : public std::runtime_error {
public:
    explicit string_error(const char *e) : runtime_error(e) {}
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
class CMString {
private:
    void setnull() noexcept {
        m_lpBuf = nullptr;
        m_cBuf = nullptr;
        m_dwLength = 0;
        m_mask_data = L'\0';
        m_mask_index = 0;
    }
    void mem_buffer(const wchar_t *lpStr, size_t len) noexcept { // len: without '\0' e.g., "abcde" => len=5
        assert(lpStr && len>0);
        if (m_dwLength<=len) {
            delete [] m_lpBuf;
            m_dwLength = (DWORD)len+1;
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
            DWORD alloc = this->length() + 1;
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
    static void chartowchar(const char *source, std::wstring &dest) noexcept {
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
    }
    static void utoutf8cpy(char *cStr, LPCWSTR lpStr, DWORD *pdwLength) noexcept {
        if (lpStr[0]==L'\0') {
            *pdwLength = 0;
            if (cStr!=nullptr) cStr[0] = '\0';
            return;
        }
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
    }
    static void utf8toucpy(wchar_t *lpStr, const char *cStrOrg, DWORD *pdwLength) noexcept {
        if (cStrOrg[0]=='\0') {
            *pdwLength = 0;
            if (lpStr!=nullptr) lpStr[0]=L'\0';
            return;
        }
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

    CMString &operator+=(LPCWSTR lpStr) noexcept {
        if (lpStr==nullptr || lpStr[0]==L'\0')
            return *this;
        size_t length = (m_lpBuf!=nullptr)? ::wcslen(m_lpBuf)+::wcslen(lpStr): ::wcslen(lpStr);
        if (m_dwLength<=length) {
            size_t reallocLength = length + 1 + (length>>1);
            wchar_t *new_buf = new(std::nothrow) wchar_t[reallocLength];
            if(!new_buf)
                string_error_terminate("CMString operator+=(LPCWSTR) out of memory");
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
    CMString &operator+=(wchar_t wch) noexcept {
        wchar_t str[] = {wch, L'\0'};
        return operator+=( str );
    }
    CMString &operator+=(char cch) noexcept {
        char str[] = {cch, '\0'};
        return operator+=( str );
    }
    CMString &operator+=(int nNum) noexcept {
        wchar_t szStr[128];
        ::swprintf_s(szStr, 128, L"%d", nNum);
        return operator+=(szStr);
    }
    CMString &operator+=(double dNum) noexcept {
        wchar_t szStr[128];
        ::swprintf_s(szStr, 128, L"%f", dNum);
        return operator+=(szStr);
    }
    CMString &operator+=(int64_t uNum) noexcept {
        wchar_t szStr[128];
        ::swprintf_s(szStr, 128, L"%I64d", uNum);
        return operator+=(szStr);
    }
    CMString &operator+=(const CMString &obj) noexcept {
        return operator+=(obj.m_lpBuf);
    }
    CMString &operator+=(const std::string &obj) noexcept {
        operator+=(obj.c_str());
        return *this;
    }
    CMString &operator+=(const std::wstring &obj) noexcept {
        operator+=(obj.c_str());
        return *this;
    }

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
    CMString &operator=(wchar_t wch) noexcept {
        wchar_t str[] = {wch, L'\0'};
        return operator=(str);
    }
    CMString &operator=(char cch) noexcept {
        char str[] = {cch, '\0'};
        return operator=(str);
    }
    CMString &operator=(int nNum) noexcept {
        wchar_t szStr[128];
        ::swprintf_s(szStr, 128, L"%d", nNum);
        return operator=(szStr);
    }
    CMString &operator=(double dNum) noexcept {
        wchar_t szStr[128]={0};
        ::swprintf_s(szStr, 128, L"%f", dNum);
        return operator=(szStr);
    }
    CMString &operator=(int64_t uNum) noexcept {
        wchar_t szStr[128];
        ::swprintf_s(szStr, 128, L"%I64d", uNum);
        return operator=(szStr);
    }
    CMString &operator=(const CMString &obj) noexcept {
        return operator=(obj.m_lpBuf);
    }

    CMString &operator+(LPCWSTR lpStr) noexcept {
        return (lpStr==m_lpBuf)? *this: operator+=(lpStr);
    }
    CMString &operator+(wchar_t wch) noexcept {
        return operator+=(wch);
    }
    CMString &operator+(const char *cStr) noexcept {
        return operator+=(cStr);
    }
    CMString &operator+(char cch) noexcept {
        return operator+=(cch);
    }
    CMString &operator+(int nNum) noexcept {
        return operator+=(nNum);
    }
    CMString &operator+(double dNum) noexcept {
        return operator+=(dNum);
    }
    CMString &operator+(int64_t uNum) noexcept {
        return operator+=(uNum);
    }
    CMString &operator+(const CMString &obj) noexcept {
        return operator+=(obj.m_lpBuf);
    }

    CMString &operator+=(const char *cStr) noexcept {
        if (cStr==nullptr) return *this;
        else {
            std::wstring wstr;
            chartowchar(cStr, wstr);
            return operator+=(wstr.c_str());
        }
    }
    CMString &operator=(const char *cStr) noexcept {
        if (cStr==nullptr) return *this;
        else {
            std::wstring wstr;
            chartowchar(cStr, wstr);
            return operator=(wstr.c_str());
        }
    }

    const char *c_str() const noexcept {
        if (m_lpBuf==nullptr) return "";
        else {
            delete [] m_cBuf;
            DWORD dwLen;
            utoutf8cpy(nullptr, m_lpBuf, &dwLen);
            m_cBuf = new char[dwLen];
            if(!m_cBuf) string_error_terminate("CMString c_str(): out of memory");
            utoutf8cpy(m_cBuf, m_lpBuf, &dwLen);
            return m_cBuf;
        }
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

    operator const char *() const {
        if (m_lpBuf==nullptr) return "";
        else return c_str();
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

    wchar_t operator[](int index) noexcept {
        return operator[]((size_t)index);
    }
    wchar_t operator[](int index) const noexcept {
        return operator[]((size_t)index);
    }
    wchar_t operator[](size_t index) noexcept {
        assert(m_lpBuf && index>=0 && m_dwLength>index);
        //if(m_lpBuf==nullptr) return L'\0';
        return m_lpBuf[index];
    }
    wchar_t operator[](size_t index) const noexcept {
        assert(m_lpBuf && index>=0 && m_dwLength>index);
        if(m_lpBuf==nullptr) return L'\0';
        return m_lpBuf[index];
    }

    operator LPCWSTR() const noexcept {
        if (m_lpBuf==nullptr) return L"";
        else return m_lpBuf;
    }

    int format(const wchar_t *lpType, ...) noexcept {
        va_list args;
        va_start(args, lpType);
        int length = ::_vscwprintf(lpType, args);
        std::unique_ptr<wchar_t []> str(new(std::nothrow) WCHAR[length+1]);
        if(str.get())
            string_error_terminate("CMString: Format, out of memory");
        int num = ::vswprintf_s(str.get(), length+1, lpType, args);
        operator=(str.get());
        va_end(args);
        return num;
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

    CMString &operator<<(const CMString &obj) noexcept {
        operator+=(obj);
        return *this;
    }
    CMString &operator<<(const std::string &obj) noexcept {
        operator+=(obj.c_str());
        return *this;
    }
    CMString &operator<<(const std::wstring &obj) noexcept {
        operator+=(obj.c_str());
        return *this;
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
    int mask_index() const noexcept {return m_mask_index;}

    void clear() noexcept {if(m_lpBuf) m_lpBuf[0] = L'\0';}
    void mem_clear() noexcept {mem_clear(0);}
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

    CMString() noexcept {setnull();}
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
    CMString(int i) noexcept {
        setnull();
        operator=(i);
    }
    CMString(double d) noexcept {
        setnull();
        operator=(d);
    }
    CMString(int64_t i) noexcept {
        setnull();
        operator=(i);
    }
    CMString(const CMString &obj) noexcept {
        setnull();
        operator=(obj.m_lpBuf);
    }
    CMString(const std::string &str) noexcept {
        setnull();
        operator=(str.c_str());
    }
    CMString(const std::wstring &str) noexcept {
        setnull();
        operator=(str.c_str());
    }

    virtual ~CMString() {
        if(m_cBuf) delete [] m_cBuf;
        if(m_lpBuf) delete [] m_lpBuf;
    }

    std::string str() const noexcept {
        return std::string(c_str());
    }
    std::wstring wstr() const noexcept {
        return std::wstring((LPCWSTR)*this);
    }

private:
    wchar_t *m_lpBuf;
    mutable char *m_cBuf;
    size_t m_dwLength; // with '\0'
    wchar_t m_mask_data;
    int m_mask_index;
};

#endif // SORACHANCOIN_CMSTRING_H
