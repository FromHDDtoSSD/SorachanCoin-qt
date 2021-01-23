// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2019-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MOVESTREAM_H
#define MOVESTREAM_H

#include <serialize.h>

class CMoveStream : public CTypeVersion
{
private:
    // CMoveStream()=delete;
    // CMoveStream(const CMoveStream &)=delete;
    // CMoveStream(CMoveStream &)=delete;
    // CMoveStream &operator=(const CMoveStream &)=delete;
    // CMoveStream &operator=(CMoveStream &&)=delete;

    using vector_type = CSerializeData;
    vector_type *pvch;
    unsigned int nReadPos;
    short state;
    short exceptmask;

    void Init() noexcept {
        pvch = nullptr;
        nReadPos = 0;
        state = 0;
        exceptmask = std::ios::badbit | std::ios::failbit;
    }

    void Alloc() {
        if(! pvch) {
            pvch = new(std::nothrow) vector_type;
            if(! pvch)
                throw std::runtime_error("CMoveStream: out of memory");
        }
    }

    void Release() noexcept {
        if(pvch) delete pvch;
        pvch = nullptr;
    }

public:
    using allocator_type   = vector_type::allocator_type;
    using size_type        = vector_type::size_type;
    using difference_type  = vector_type::difference_type;
    using reference        = vector_type::reference;
    using const_reference  = vector_type::const_reference;
    using value_type       = vector_type::value_type;
    using iterator         = vector_type::iterator;
    using const_iterator   = vector_type::const_iterator;
    using reverse_iterator = vector_type::reverse_iterator;

    CMoveStream(int nType=0, int nVersion=0) : CTypeVersion(nType, nVersion) {
        Init();
        Alloc();
    }

    CMoveStream(CMoveStream &&robj) noexcept : CTypeVersion(robj.GetType(), robj.GetVersion()) {
        Init();
        Swap(static_cast<CMoveStream &&>(robj));
    }

    CMoveStream(const CFlatData &obj, int nType=0, int nVersion=0) : CTypeVersion(nType, nVersion) {
        Init();
        Alloc();
        *this << obj;
    }

    CMoveStream(const_iterator pbegin, const_iterator pend, int nType=0, int nVersion=0) : CTypeVersion(nType, nVersion) {
        Init();
        Alloc();
        pvch->insert(pvch->end(), pbegin, pend);
    }

#if !defined(_MSC_VER) || _MSC_VER >= 1300
    CMoveStream(const char *pbegin, const char *pend, int nType=0, int nVersion=0) : CTypeVersion(nType, nVersion) {
        Init();
        Alloc();
        pvch->insert(pvch->end(), pbegin, pend);
    }
#endif

    CMoveStream(vector_type &&rvch, int nType=0, int nVersion=0) : CTypeVersion(nType, nVersion) {
        Init();
        Alloc();
        Swap(static_cast<vector_type &&>(rvch));
    }

#ifdef DATASTREAM_PREVECTOR_ENABLE
    CMoveStream(const std::vector<char> &vchIn, int nType=0, int nVersion=0) : CTypeVersion(nType, nVersion) {
        Init();
        Alloc();
        pvch->insert(pvch->end(), vchIn.begin(), vchIn.end());
    }
    CMoveStream(const std::vector<unsigned char> &vchIn, int nType=0, int nVersion=0) : CTypeVersion(nType, nVersion) {
        Init();
        Alloc();
        pvch->insert(pvch->end(), vchIn.begin(), vchIn.end());
    }
#endif

    CMoveStream(const datastream_signed_vector &vchIn, int nType=0, int nVersion=0) : CTypeVersion(nType, nVersion) {
        Init();
        Alloc();
        pvch->insert(pvch->end(), vchIn.begin(), vchIn.end());
    }

    CMoveStream(const datastream_vector &vchIn, int nType=0, int nVersion=0) : CTypeVersion(nType, nVersion) {
        Init();
        Alloc();
        pvch->insert(pvch->end(), vchIn.begin(), vchIn.end());
    }

    ~CMoveStream() {
        Release();
    }

    void Swap(CMoveStream &&b) noexcept {
        this->Release();
        this->pvch = b.pvch;
        this->nReadPos = b.nReadPos;
        this->state = b.state;
        this->exceptmask = b.exceptmask;
        b.Init();
    }
    void Swap(vector_type &&b) noexcept {
        this->Release();
        this->Init();
        this->pvch = &b;
    }

    CMoveStream &operator=(CMoveStream &&b) noexcept {
        Swap(static_cast<CMoveStream &&>(b));
        return *this;
    }
    CMoveStream &operator=(vector_type &&b) noexcept {
        Swap(static_cast<vector_type &&>(b));
        return *this;
    }
    CMoveStream &operator+=(const CMoveStream &b) {
        pvch->insert(this->pvch->end(), b.begin(), b.end());
        return *this;
    }

    std::string str() const {
        return (std::string(begin(), end()));
    }

    // Vector subset
    void clear() noexcept { if(pvch) pvch->clear(); nReadPos = 0; }
    const_iterator begin() const noexcept { return pvch ? pvch->begin() + nReadPos: const_iterator(0); }
    iterator begin() noexcept { return pvch ? pvch->begin() + nReadPos: iterator(0); }
    const_iterator end() const noexcept { return pvch ? pvch->end(): const_iterator(0); }
    iterator end() noexcept { return pvch ? pvch->end(): iterator(0); }
    size_type size() const noexcept { return pvch ? pvch->size() - nReadPos: 0; }
    bool empty() const noexcept { return pvch==nullptr || pvch->size()==nReadPos; }
    void resize(size_type n, value_type c = 0) { if(pvch) pvch->resize(n + nReadPos, c); }
    void reserve(size_type n) { if(pvch) pvch->reserve(n + nReadPos); }
    const_reference operator[](size_type pos) const noexcept { return pvch ? (*pvch)[pos + nReadPos]: const_reference(0); }
    reference operator[](size_type pos) noexcept { char lret=0; return pvch ? (*pvch)[pos + nReadPos]: reference(lret); } // Note: reference() require lvalue.
    iterator insert(iterator it, const char &x = char()) { return pvch? pvch->insert(it, x): iterator(0); }
    void insert(iterator it, size_type n, const char &x) { if(pvch) pvch->insert(it, n, x); }
    void push_back(const char &x) {if(pvch) pvch->push_back(x);}
    template <typename... Args>
    void emplace_back(Args&&... args) {
        if(pvch)
            pvch->emplace_back(args...);
    }

#ifdef _MSC_VER
    void insert(iterator it, const_iterator first, const_iterator last) noexcept {
        assert(last - first >= 0);
        if(it == pvch->begin() + nReadPos && (unsigned int)(last - first) <= nReadPos) {
            // special case for inserting at the front when there's room
            nReadPos -= (unsigned int)(last - first);
            std::memcpy(&(*pvch)[nReadPos], &first[0], last - first);
        } else {
            pvch->insert(it, first, last);
        }
    }
#else
    void insert(iterator it, std::vector<char>::const_iterator first, std::vector<char>::const_iterator last) noexcept {
        assert(last - first >= 0);
        if(it == pvch->begin() + nReadPos && (unsigned int)(last - first) <= nReadPos) {
            // special case for inserting at the front when there's room
            nReadPos -= (last - first);
            std::memcpy(&(*pvch)[nReadPos], &first[0], last - first);
        } else {
            pvch->insert(it, first, last);
        }
    }
#endif

#if !defined(_MSC_VER) || _MSC_VER >= 1300
    void insert(iterator it, const char *first, const char *last) noexcept {
        assert(last - first >= 0);
        if(it == pvch->begin() + nReadPos && (unsigned int)(last - first) <= nReadPos) {
            // special case for inserting at the front when there's room
            nReadPos -= (unsigned int)(last - first);
            std::memcpy(&(*pvch)[nReadPos], &first[0], last - first);
        } else {
            pvch->insert(it, first, last);
        }
    }
#endif

    iterator erase(iterator it) noexcept {
        if(it == pvch->begin() + nReadPos) {
            // special case for erasing from the front
            if(++nReadPos >= pvch->size()) {
                // whenever we reach the end, we take the opportunity to clear the buffer
                nReadPos = 0;
                return pvch->erase(pvch->begin(), pvch->end());
            }
            return pvch->begin() + nReadPos;
        } else {
            return pvch->erase(it);
        }
    }

    iterator erase(iterator first, iterator last) noexcept {
        if(first == pvch->begin() + nReadPos) {
            // special case for erasing from the front
            if(last == pvch->end()) {
                nReadPos = 0;
                return pvch->erase(pvch->begin(), pvch->end());
            } else {
                this->nReadPos = (unsigned int)(last - pvch->begin());
                return last;
            }
        } else {
            return pvch->erase(first, last);
        }
    }

    void Compact() noexcept {
        pvch->erase(pvch->begin(), pvch->begin() + nReadPos);
        nReadPos = 0;
    }

    bool Rewind(size_type n) noexcept {
        // Rewind by n characters if the buffer hasn't been compacted yet
        if(n > nReadPos) {
            return false;
        }
        nReadPos -= (unsigned int)n;
        return true;
    }

    //
    // Stream subset
    //
    void setstate(short bits, const char *psz) {
        state |= bits;
        if(state & exceptmask) {
            throw std::ios_base::failure(psz);
        }
    }

    bool eof() const noexcept { return size() == 0; }
    bool fail() const noexcept { return (state & (std::ios::badbit | std::ios::failbit)) != 0; }
    bool good() const noexcept { return !eof() && (state == 0); }
    void clear(short n) noexcept { state = n; }  // name conflict with vector clear()
    short exceptions() noexcept { return exceptmask; }
    short exceptions(short mask) { short prev = exceptmask; exceptmask = mask; setstate(0, "CMoveStream"); return prev; }
    CMoveStream *rdbuf() noexcept { return this; }
    int in_avail() noexcept { return (int)(size()); }

    CMoveStream &read(char *pch, int nSize) {
        // Read from the beginning of the buffer
        assert(nSize >= 0);
        unsigned int nReadPosNext = nReadPos + nSize;
        if(nReadPosNext >= pvch->size()) {
            if(nReadPosNext > pvch->size()) {
                pch ? setstate(std::ios::failbit, "CMoveStream::read() : end of data") : setstate(std::ios::failbit, "CDataStream::ignore() : end of data");
                if(pch) {
                    std::memset(pch, 0, nSize);
                    nSize = (int)(pvch->size() - nReadPos);
                }
            }
            pch ? std::memcpy(pch, &(*pvch)[nReadPos], nSize) : 0;
            nReadPos = 0;
            pvch->clear();
        } else {
            pch ? std::memcpy(pch, &(*pvch)[nReadPos], nSize) : 0;
            nReadPos = nReadPosNext;
        }
        return *this;
    }

    CMoveStream &ignore(int nSize) {
        // Ignore from the beginning of the buffer
        return read(nullptr, nSize);
    }

    CMoveStream &write(const char *pch, int nSize) {
        // Write to the end of the buffer
        assert(nSize >= 0);
        pvch->insert(pvch->end(), pch, pch + nSize);
        return *this;
    }

    template<typename Stream>
    void Serialize(Stream &s) const noexcept {
        // Special case: stream << stream concatenates like stream += stream
        if(! pvch->empty()) {
            s.write((char *)&(*pvch)[0], pvch->size() * sizeof((*pvch)[0]));
        }
    }

    template<typename T>
    unsigned int GetSerializeSize(const T &obj) noexcept {
        // Tells the size of the object if serialized to this stream
        return ::GetSerializeSize(obj, GetVersion());
    }

    // << and >> write and read (Serialize, Unserialize)
    template<typename T>
    CMoveStream &operator<<(const T &obj) {
        // Serialize to this stream
        ::Serialize(*this, obj);
        return *this;
    }

    template<typename T>
    CMoveStream &operator>>(T &obj) {
        // Unserialize from this stream
        ::Unserialize(*this, obj);
        return *this;
    }

    void GetAndClear(CSerializeData &data) noexcept {
        this->pvch->swap(data);
        CSerializeData().swap(*pvch);
    }

    friend CMoveStream operator+(CMoveStream &&a, const CMoveStream &b) {
        CMoveStream obj;
        obj.Swap(static_cast<CMoveStream &&>(a));
        obj += b;
        return obj;
    }

    // XOR the contents of this stream with a certain key.
    // @param[in] key    The key used to XOR the data in this stream.
    void Xor(const datastream_vector &key) {
        if (key.size() == 0)
            return;
        for (size_type i = 0, j = 0; i != size(); ++i) {
            (*pvch)[i] ^= key[j++];

            // This potentially acts on very many bytes of data, so it's
            // important that we calculate `j`, i.e. the `key` index in this
            // way instead of doing a %, which would effectively be a division
            // for each byte Xor'd -- much slower than need be.
            if (j == key.size())
                j = 0;
        }
    }

    template <typename... Args>
    CMoveStream(int nTypeIn, int nVersionIn, Args&&... args) : CTypeVersion(nTypeIn, nVersionIn) {
        Init();
        ::SerializeMany(*this, std::forward<Args>(args)...);
    }
};

#endif // MOVESTREAM_H
