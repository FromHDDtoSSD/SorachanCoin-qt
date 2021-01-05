// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_STREAMS_H
#define BITCOIN_STREAMS_H

#include <serialize.h> // CDataStream, CAutoFile, CBufferedFile
#include <algorithm>
#include <assert.h>
#include <ios>
#include <limits>
#include <map>
#include <set>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <string.h>
#include <utility>
#include <vector>

template<typename Stream>
class OverrideStream : public CTypeVersion
{
    OverrideStream()=delete;
    Stream *stream;
public:
    OverrideStream(Stream *stream_, int nType_, int nVersion_) : stream(stream_), CTypeVersion(nType_, nVersion_) {}

    template<typename T>
    OverrideStream<Stream> &operator<<(const T &obj) {
        // Serialize to this stream
        ::Serialize(*this, obj);
        return (*this);
    }

    template<typename T>
    OverrideStream<Stream> &operator>>(T &&obj) {
        // Unserialize from this stream
        ::Unserialize(*this, obj);
        return (*this);
    }

    void write(const char* pch, size_t nSize) {
        stream->write(pch, nSize);
    }

    void read(char* pch, size_t nSize) {
        stream->read(pch, nSize);
    }

    size_t size() const { return stream->size(); }
};

/* Minimal stream for overwriting and/or appending to an existing byte vector
 *
 * The referenced vector will grow as necessary
 */
template <typename VECTOR>
class CVectorWriter : public CTypeVersion
{
public:

    /*
    * @param[in]  nTypeIn Serialization Type
    * @param[in]  nVersionIn Serialization Version (including any flags)
    * @param[in]  vchDataIn  Referenced byte vector<unsigned char> to overwrite/append
    * @param[in]  nPosIn Starting position. Vector index where writes should start. The vector will initially
    *                     grow as necessary to max(nPosIn, vec.size()). So to append, use vec.size().
    */
    CVectorWriter(int nTypeIn, int nVersionIn, VECTOR &vchDataIn, size_t nPosIn) : CTypeVersion(nTypeIn, nVersionIn), vchData(vchDataIn), nPos(nPosIn) {
        if(nPos > vchData.size())
            vchData.resize(nPos);
    }
    /*
    * (other params same as above)
    * @param[in]  args  A list of items to serialize starting at nPosIn.
    */
    template <typename... Args>
    CVectorWriter(int nTypeIn, int nVersionIn, VECTOR &vchDataIn, size_t nPosIn, Args&&... args) : CVectorWriter(nTypeIn, nVersionIn, vchDataIn, nPosIn) {
        ::SerializeMany(*this, std::forward<Args>(args)...);
    }

    void write(const char *pch, size_t nSize) {
        assert(nPos <= vchData.size());
        size_t nOverwrite = std::min(nSize, vchData.size() - nPos);
        if (nOverwrite) {
            ::memcpy(vchData.data() + nPos, reinterpret_cast<const unsigned char *>(pch), nOverwrite);
        }
        if (nOverwrite < nSize) {
            vchData.insert(vchData.end(), reinterpret_cast<const unsigned char *>(pch) + nOverwrite, reinterpret_cast<const unsigned char *>(pch) + nSize);
        }
        nPos += nSize;
    }

    template<typename T>
    CVectorWriter &operator<<(const T &obj) {
        // Serialize to this stream
        ::Serialize(*this, obj);
        return (*this);
    }
private:
    VECTOR &vchData;
    size_t nPos;
};

/** Minimal stream for reading from an existing vector by reference
 */
template <typename VECTOR>
class VectorReader : public CTypeVersion
{
private:
    const VECTOR &m_data;
    size_t m_pos = 0;

public:
    /**
     * @param[in]  type Serialization Type
     * @param[in]  version Serialization Version (including any flags)
     * @param[in]  data Referenced byte vector to overwrite/append
     * @param[in]  pos Starting position. Vector index where reads should start.
     */
    VectorReader(int type, int version, const VECTOR &data, size_t pos) : CTypeVersion(type, version), m_data(data), m_pos(pos) {
        if (m_pos > m_data.size()) {
            throw std::ios_base::failure("VectorReader(...): end of data (m_pos > m_data.size())");
        }
    }

    /**
     * (other params same as above)
     * @param[in]  args  A list of items to deserialize starting at pos.
     */
    template <typename... Args>
    VectorReader(int type, int version, const VECTOR &data, size_t pos, Args&&... args) : VectorReader(type, version, data, pos) {
        ::UnserializeMany(*this, std::forward<Args>(args)...);
    }

    template<typename T>
    VectorReader &operator>>(T &obj) {
        // Unserialize from this stream
        ::Unserialize(*this, obj);
        return (*this);
    }

    size_t size() const { return m_data.size() - m_pos; }
    bool empty() const { return m_data.size() == m_pos; }
    void read(char *dst, size_t n) {
        if (n == 0) {
            return;
        }

        // Read from the beginning of the buffer
        size_t pos_next = m_pos + n;
        if (pos_next > m_data.size()) {
            throw std::ios_base::failure("VectorReader::read(): end of data");
        }
        ::memcpy(dst, m_data.data() + m_pos, n);
        m_pos = pos_next;
    }
};

template <typename IStream>
class BitStreamReader
{
private:
    IStream &m_istream;

    /// Buffered byte read in from the input stream. A new byte is read into the
    /// buffer when m_offset reaches 8.
    uint8_t m_buffer{0};

    /// Number of high order bits in m_buffer already returned by previous
    /// Read() calls. The next bit to be returned is at this offset from the
    /// most significant bit position.
    int m_offset{8};

public:
    explicit BitStreamReader(IStream& istream) : m_istream(istream) {}

    /** Read the specified number of bits from the stream. The data is returned
     * in the nbits least significant bits of a 64-bit uint.
     */
    uint64_t Read(int nbits) {
        if (nbits < 0 || nbits > 64) {
            throw std::out_of_range("nbits must be between 0 and 64");
        }

        uint64_t data = 0;
        while (nbits > 0) {
            if (m_offset == 8) {
                m_istream >> m_buffer;
                m_offset = 0;
            }

            int bits = std::min(8 - m_offset, nbits);
            data <<= bits;
            data |= static_cast<uint8_t>(m_buffer << m_offset) >> (8 - bits);
            m_offset += bits;
            nbits -= bits;
        }
        return data;
    }
};

template <typename OStream>
class BitStreamWriter
{
private:
    OStream &m_ostream;

    /// Buffered byte waiting to be written to the output stream. The byte is
    /// written buffer when m_offset reaches 8 or Flush() is called.
    uint8_t m_buffer{0};

    /// Number of high order bits in m_buffer already written by previous
    /// Write() calls and not yet flushed to the stream. The next bit to be
    /// written to is at this offset from the most significant bit position.
    int m_offset{0};

public:
    explicit BitStreamWriter(OStream& ostream) : m_ostream(ostream) {}

    ~BitStreamWriter() {
        Flush();
    }

    /** Write the nbits least significant bits of a 64-bit int to the output
     * stream. Data is buffered until it completes an octet.
     */
    void Write(uint64_t data, int nbits) {
        if (nbits < 0 || nbits > 64) {
            throw std::out_of_range("nbits must be between 0 and 64");
        }

        while (nbits > 0) {
            int bits = std::min(8 - m_offset, nbits);
            m_buffer |= (data << (64 - nbits)) >> (64 - 8 + m_offset);
            m_offset += bits;
            nbits -= bits;

            if (m_offset == 8) {
                Flush();
            }
        }
    }

    /** Flush any unwritten bits to the output stream, padding with 0's to the
     * next byte boundary.
     */
    void Flush() {
        if (m_offset == 0) {
            return;
        }

        m_ostream << m_buffer;
        m_buffer = 0;
        m_offset = 0;
    }
};

/** Double ended buffer combining vector and stream-like interfaces.
 * use serialize.h
 *
 * >> and << read and write unformatted data using the above serialization templates.
 * Fills with data in linear time; some stringstream implementations take N^2 time.
 */

/** Non-refcounted RAII wrapper for FILE*
 * use serialize.h
 *
 * Will automatically close the file when it goes out of scope if not null.
 * If you're returning the file pointer, return file.release().
 * If you need to close the file early, use file.fclose() instead of fclose(file).
 */

/** Non-refcounted RAII wrapper around a FILE* that implements a ring buffer to
 * use serialize.h
 *
 *  deserialize from. It guarantees the ability to rewind a given number of bytes.
 *
 *  Will automatically close the file when it goes out of scope if not null.
 *  If you need to close the file early, use file.fclose() instead of fclose(file).
 */

#endif // BITCOIN_STREAMS_H
