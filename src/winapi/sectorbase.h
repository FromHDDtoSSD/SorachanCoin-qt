// Copyright (c) 2019-2021 The SorachanCoin Developers
// Copyright (c) 2019-2021 The Sora neko Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// mt19937: BOOST Library
// xorshift: https://www.jstatsoft.org/article/view/v008i14

#ifndef SORACHANCOIN_SECTORBASE_H
#define SORACHANCOIN_SECTORBASE_H

#include <windows.h>
#include <new>
#include <winapi/drivebase.h>
#include <boost/random.hpp>

constexpr int RAND_GENE_MAX_DEFAULT = 30;

class rand_base
{
    rand_base(const rand_base &)=delete;
    rand_base &operator=(const rand_base &)=delete;
    rand_base(rand_base &&)=delete;
    rand_base &operator=(rand_base &&)=delete;
private:
    std::vector<uint64_t> buf;
    cla_thread<rand_base> thread;
    rand_base *obj;
    int gene_count;

    virtual uint64_t r_func(int i) = 0;
    unsigned int r_thread(cla_thread<rand_base>::thread_data *pdata) {
        if(! obj) { return 1; }
        for(int i=0; i < gene_count; ++i)
        {
            buf.push_back(obj->r_func(i));
            if(pdata->exit_flag) { break; }
        }
        return 1;
    }
protected:
    typedef union _RAND_INTEGER
    {
        struct {
            unsigned long LowPart;
            unsigned long HighPart;
        } u;
        uint64_t QuadPart;
    } RAND_INTEGER;

    bool start(rand_base *_obj) {
        clear();
        obj = _obj;
        return thread.start(nullptr, this);
    }
public:
    rand_base() : thread(&rand_base::r_thread) {
        obj = nullptr;
        gene_count = RAND_GENE_MAX_DEFAULT;
    }
    virtual ~rand_base() {}

    //
    // Method
    //
    void init() {buf.clear();}
    void waitclose() {thread.waitclose();}
    void stop() {thread.stop();}
    bool signal() const {return thread.signal();}
    double getprog() const {return (double)size() / gene_count;}
    size_t size() const {return buf.size();}
    void clear() { buf.clear(); obj = nullptr; }
    void setgenecount(int count) {if(0 < count) {gene_count = count;}}
    uint64_t get(int i) const {return buf[i];}
    const std::vector<uint64_t> &getbuf() const {return buf;}
    virtual void srand() = 0;
    virtual bool create() = 0;
};

class rand_standard final : public rand_base
{
    rand_standard(const rand_standard &)=delete;
    rand_standard &operator=(const rand_standard &)=delete;
    rand_standard(rand_standard &&)=delete;
    rand_standard &operator=(rand_standard &&)=delete;
private:
    randrangebuffer<rand_standard, uint64_t> randrange;
    boost::random::mt19937 gen;
    boost::random::uniform_real_distribution<> urd;

    RAND_INTEGER ri;
    int __RAND_bytes(unsigned char *&buf, int num_unused) { // num is 8.(sizeof(unsigned __int64))
        assert(num_unused == 8);
        boost::random::variate_generator<boost::random::mt19937 &, boost::random::uniform_real_distribution<> > mtrand(gen, urd);
        this->ri.u.LowPart = (unsigned long)mtrand();
        this->ri.u.HighPart = (unsigned long)mtrand();
        buf = (unsigned char *)&this->ri.QuadPart;
        return num_unused;
    }
    uint64_t r_func(int) final override {
        uint64_t rr = randrange.getrand();
        // OK debugcs::instance() << rr << debugcs::endl();
        return rr;
    }
public:
    rand_standard() : randrange(&rand_standard::__RAND_bytes, this), urd(1, (boost::uint32_t)std::numeric_limits<boost::uint32_t>::max()) {
        ::memset(&ri, 0x00, sizeof(RAND_INTEGER));
    }
    ~rand_standard() {}

    //
    // Method
    //
    void srand() final override {
        mcrypto<boost::uint32_t> crypt;
        gen.seed((boost::uint32_t)(crypt >>= crypt));
        std::memset(&ri, 0x00, sizeof(RAND_INTEGER));
        debugcs::instance() << L"[standard Seed Renge]" << (boost::uint32_t)crypt << debugcs::endl();
    }
    bool create() final override {
        return this->start(this);
    }
};

class rand_xorshift final : public rand_base
{
    rand_xorshift(const rand_xorshift &)=delete;
    rand_xorshift &operator=(const rand_xorshift &)=delete;
    rand_xorshift(rand_xorshift &&)=delete;
    rand_xorshift &operator=(rand_xorshift &&)=delete;
private:
    randrangebuffer<rand_xorshift, uint64_t> randrange;
    unsigned long x, y, z, w;
    RAND_INTEGER ri;
    unsigned long xor128() {
        unsigned long t;
        t=(x^(x<<11));x=y;y=z;z=w;
        return( w=(w^(w>>19))^(t^(t>>8)) );
    }

    int __RAND_bytes(unsigned char *&buf, int num_unused) { // num is 8.(sizeof(unsigned __int64))
        assert(num_unused == 8);
        this->ri.u.LowPart = xor128();
        this->ri.u.HighPart = xor128();
        buf = (unsigned char *)&this->ri.QuadPart;
        return num_unused;
    }
    uint64_t r_func(int) final override {
        uint64_t rr = randrange.getrand();
        // OK debugcs::instance() << rr << debugcs::endl();
        return rr;
    }
public:
    rand_xorshift() : randrange(&rand_xorshift::__RAND_bytes, this) {
        x = 123456789;
        y = 362436069;
        z = 521288629;
        w = 88675123;
        std::memset(&ri, 0x00, sizeof(RAND_INTEGER));
    }
    explicit rand_xorshift(unsigned long _x, unsigned long _y, unsigned long _z, unsigned long _w) : randrange(&rand_xorshift::__RAND_bytes, this) {
        x = _x;
        y = _y;
        z = _z;
        w = _w;
        std::memset(&ri, 0x00, sizeof(RAND_INTEGER));
    }
    ~rand_xorshift() {}

    //
    // Method
    //
    void srand() final override {
        mcrypto<unsigned long> crypt;
        x = crypt >>= crypt;
        y = crypt >>= crypt;
        z = crypt >>= crypt;
        w = crypt >>= crypt;
        std::memset(&ri, 0x00, sizeof(RAND_INTEGER));
        //debugcs::instance() << L"[xorshift Seed]" << x << y << z << w << debugcs::endl();
    }
    bool create() final override {
        return this->start(this);
    }
};

class rand_openssl final : public rand_base
{
    rand_openssl(const rand_openssl &)=delete;
    rand_openssl &operator=(const rand_openssl &)=delete;
    rand_openssl(rand_openssl &&)=delete;
    rand_openssl &operator=(rand_openssl &&)=delete;
private:
    uint64_t r_func(int) final override {
        mcrypto<uint64_t> crypt;
        uint64_t rr = crypt >>= crypt;
        // OK debugcs::instance() << rr << debugcs::endl();
        return rr;
    }
public:
    rand_openssl() {}
    ~rand_openssl() {}

    //
    // Method
    //
    void srand() final override {}
    bool create() final override {
        return this->start(this);
    }
};

class rand_pobench final : public rand_base
{
    rand_pobench(const rand_pobench &)=delete;
    rand_pobench &operator=(const rand_pobench &)=delete;
    rand_pobench(rand_pobench &&)=delete;
    rand_pobench &operator=(rand_pobench &&)=delete;
private:
    uint64_t r_func(int) final override { // generate plot information.
        return 0;
    }
public:
    rand_pobench() {}
    ~rand_pobench() {}

    //
    // Method
    //
    void srand() final override {}
    bool create() final override {
        return this->start(this);
    }
};

class sector_base
{
    sector_base(const sector_base &)=delete;
    sector_base &operator=(const sector_base &)=delete;
    sector_base(sector_base &&)=delete;
    sector_base &operator=(sector_base &&)=delete;
public:
    sector_base() {}
    virtual ~sector_base() {}

    //
    // Method
    //
    virtual bool create() = 0;
    virtual void stop() = 0;
    virtual void waitclose() = 0;
    virtual bool signal() const = 0;
    virtual void destroy() = 0;
    virtual double getprog() const = 0;
};

class sector_randbuffer final : public sector_base
{
    sector_randbuffer(const sector_randbuffer &)=delete;
    sector_randbuffer &operator=(const sector_randbuffer &)=delete;
    sector_randbuffer(sector_randbuffer &&)=delete;
    sector_randbuffer &operator=(sector_randbuffer &&)=delete;
private:
    rand_base *target;
public:
    enum RAND_TYPE {
        RAND_GENE_STANDARD = 0,
        RAND_GENE_XORSHIFT,
        RAND_GENE_OPENSSL,
        RAND_GENE_POBENCH,
        RAND_GENE_MAX,
    };

    sector_randbuffer() {
        target = nullptr;
    }
    ~sector_randbuffer() {
        destroy();
    }

    bool settype(RAND_TYPE type) {
        destroy();
        switch (type)
        {
        case RAND_GENE_STANDARD:
            target = new(std::nothrow) rand_standard;
            break;
        case RAND_GENE_XORSHIFT:
            target = new(std::nothrow) rand_xorshift;
            break;
        case RAND_GENE_OPENSSL:
            target = new(std::nothrow) rand_openssl;
            break;
        case RAND_GENE_POBENCH:
            target = new(std::nothrow) rand_pobench;
            break;
        default:
            return false;
        }
        return target != nullptr;
    }
    void destroy() final override {
        if(target) {
            delete target;
            target = nullptr;
        }
    }
    bool create() final override {
        if(target) {
            target->srand();
            return target->create();
        } else {
            return false;
        }
    }
    void stop() final override {
        if(target) {
            target->stop();
        }
    }
    void waitclose() final override {
        if(target) {
            target->waitclose();
        }
    }
    bool signal() const final override {
        if(target) {
            return target->signal();
        } else {
            return true;
        }
    }
    double getprog() const final override {
        if(target) {
            return target->getprog();
        } else {
            return 0.0;
        }
    }
    const std::vector<uint64_t> *getbuf() const {
        if(target) {
            return &target->getbuf();
        } else {
            return nullptr;
        }
    }
    void setgenecount(int count) {
        if(target) {
            target->setgenecount(count);
        }
    }
};

class sector_io final : public sector_base
{
    sector_io(const sector_io &)=delete;
    sector_io &operator=(const sector_io &)=delete;
    sector_io(sector_io &&)=delete;
    sector_io &operator=(sector_io &&)=delete;
private:
    static constexpr DWORD SECTORS_SIZE_SEQ = 100 * 1024 * 1024;
    static constexpr DWORD SECTORS_SIZE_8192KB = 8192 * 1024;
    static constexpr DWORD SECTORS_SIZE_512KB = 512 * 1024;
    static constexpr DWORD SECTORS_SIZE_4KB = 4 * 1024;

    drive_base *drive;
public:
    sector_io() {
        drive = nullptr;
    }
    ~sector_io() {
        destroy();
    }

    enum ACC_TYPE {
        ACC_TYPE_SEQ_READ = 0,
        ACC_TYPE_SEQ_WRITE,
        ACC_TYPE_RANDOM_READ_8192KB,
        ACC_TYPE_RANDOM_WRITE_8192KB,
        ACC_TYPE_RANDOM_READ_512KB,
        ACC_TYPE_RANDOM_WRITE_512KB,
        ACC_TYPE_RANDOM_READ_4KB,
        ACC_TYPE_RANDOM_WRITE_4KB,
        ACC_TYPE_RANDOM_MAX,
    };

    bool settype_io(ACC_TYPE type, int drive_target, const sector_io *instanced = nullptr) {
        if(instanced) {
            return settype(type, drive_target, instanced->drive);
        } else {
            return settype(type, drive_target);
        }
    }

    bool settype(ACC_TYPE type, int drive_target, const drive_base *instanced = nullptr) {
        destroy();
        DWORD sectors_size = 0;
        switch (type)
        {
        case ACC_TYPE_SEQ_READ:
            drive = new(std::nothrow) drive_seqread(drive_target);
            sectors_size = SECTORS_SIZE_SEQ;
            break;
        case ACC_TYPE_SEQ_WRITE:
            drive = new(std::nothrow) drive_seqwrite(drive_target);
            sectors_size = SECTORS_SIZE_SEQ;
            break;
        case ACC_TYPE_RANDOM_READ_8192KB:
            drive = new(std::nothrow) drive_randomread(drive_target);
            sectors_size = SECTORS_SIZE_8192KB;
            break;
        case ACC_TYPE_RANDOM_READ_512KB:
            drive = new(std::nothrow) drive_randomread(drive_target);
            sectors_size = SECTORS_SIZE_512KB;
            break;
        case ACC_TYPE_RANDOM_READ_4KB:
            drive = new(std::nothrow) drive_randomread(drive_target);
            sectors_size = SECTORS_SIZE_4KB;
            break;
        case ACC_TYPE_RANDOM_WRITE_8192KB:
            drive = new(std::nothrow) drive_randomwrite(drive_target);
            sectors_size = SECTORS_SIZE_8192KB;
            break;
        case ACC_TYPE_RANDOM_WRITE_512KB:
            drive = new(std::nothrow) drive_randomwrite(drive_target);
            sectors_size = SECTORS_SIZE_512KB;
            break;
        case ACC_TYPE_RANDOM_WRITE_4KB:
            drive = new(std::nothrow) drive_randomwrite(drive_target);
            sectors_size = SECTORS_SIZE_4KB;
            break;
        default:
            return false;
        }

        if(drive) {
            bool ret = (instanced ? drive->openhandle(instanced): drive->openhandle());
            if(ret) {
                drive->setstep(sectors_size);
            }
            return ret;
        } else {
            return false;
        }
    }
    bool settype_file(ACC_TYPE type, int drive_target, const drive_base *instanced = nullptr) {
        destroy();
        DWORD sectors_size = 0;
        switch (type)
        {
        case ACC_TYPE_SEQ_WRITE:
            drive = new(std::nothrow) drive_datawritelimit(drive_target);
            sectors_size = SECTORS_SIZE_SEQ;
            break;
        case ACC_TYPE_RANDOM_WRITE_8192KB:
            drive = new(std::nothrow) drive_datawritelimit(drive_target);
            sectors_size = SECTORS_SIZE_8192KB;
            break;
        case ACC_TYPE_RANDOM_WRITE_512KB:
            drive = new(std::nothrow) drive_datawritelimit(drive_target);
            sectors_size = SECTORS_SIZE_512KB;
            break;
        case ACC_TYPE_RANDOM_WRITE_4KB:
            drive = new(std::nothrow) drive_datawritelimit(drive_target);
            sectors_size = SECTORS_SIZE_4KB;
            break;
        default:
            return false;
        }

        if(drive) {
            bool ret = (instanced ? drive->openhandle(instanced): drive->openhandle());
            if(ret) {
                drive->setstep(sectors_size);
            }
            return ret;
        } else {
            return false;
        }
    }
    std::wstring getdriveinfo() const {
        if(drive) {
            return drive->getdriveinfo();
        } else {
            return L"";
        }
    }
    void destroy() final override {
        if(drive) {
            delete drive;
            drive = nullptr;
        }
    }
    void setparam(const sector_randbuffer &randbuf) {
        const std::vector<uint64_t> *buf = randbuf.getbuf();
        if(buf && drive) {
            drive->setrand(*buf);
            drive->clearaccpoint();
        }
    }
    // void checkpartition() const {}

    bool create() final override {
        if(drive) {
            drive->clearfailure();
            return drive->scan();
        } else {
            return false;
        }
    }
    void stop() final override {
        if(drive) {
            drive->stop();
        }
    }
    void waitclose() final override {
        if(drive) {
            drive->waitclose();
        }
    }
    bool signal() const final override {
        if(drive) {
            return drive->signal();
        } else {
            return true;
        }
    }
    bool getfailure() const {
        if(drive) {
            return drive->getfailure();
        } else {
            return false;
        }
    }
    double getprog() const final override {
        if(drive) {
            return drive->getprog();
        } else {
            return 0.0;
        }
    }
    double getspeed(double ti) const {
        if(drive) {
            return drive->getspeed(ti);
        } else {
            return 0.0;
        }
    }
};

#endif
