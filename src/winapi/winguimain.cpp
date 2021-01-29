// Copyright (c) 2018-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(QT_GUI) && defined(WIN32)

// prediction system
// windows GUI (win32API and nativeAPI)

#include <winapi/winguimain.h>
#include <sync/lsync.h>
#include <windows.h>
#include <commctrl.h>
#include <string>
#include <sstream>
#include <time.h>
#include <shlobj.h>
#include <util/logging.h>
#include <libstr/cmstring.h>
#include <init.h>

constexpr int THREAD_TIMER_INTERVAL = 500;
constexpr int DISK_MAX = 128;
constexpr int THREAD_MAX = 192; // THREAD_MAX % sector_randbuffer::RAND_GENE_MAX == 0
constexpr int WINDOW_WIDTH = 700;
constexpr int WINDOW_HEIGHT = 550;
constexpr int PROGRESS_NUM = 9;

/////////////////////////////////////////////////////////////////////////
// prediction system LOG (char)
/////////////////////////////////////////////////////////////////////////

namespace {
class logw final : protected drive_util
{
private:
    logw(const logw &)=delete;
    logw &operator=(const logw &)=delete;
    logw(logw &&)=delete;
    logw &operator=(logw &&)=delete;

    mutable drive_datawritefull wobj;
    std::wstring dir;
    std::ostringstream stream;

    bool setbufferwrite() const {
        if(stream.str().size() == 0) { return false; }
        std::vector<BYTE> *pbuf = wobj.setbufferwrite();
        if(! pbuf) { return false; }
        std::string str = stream.str();
        pbuf->resize(str.size(), 0x00);
        ::RtlCopyMemory(&pbuf->at(0), str.c_str(), str.size());
        wobj.setaddr();
        return true;
    }
public:
    logw() {}
    ~logw() {
        clear();
    }

    template <typename T> logw &operator<<(T obj) {
        std::wostringstream source;
        source << obj;

        std::string dest;
        if(! drive_util::wchartochar(source.str().c_str(), dest)) { return *this; }
        stream << dest.c_str();
        return *this;
    }
    void setdir(LPCWSTR _dir) {
        dir = _dir;
    }
    void setdir() {
        std::vector<wchar_t> vwname, vwdir;
        vwname.resize(MAX_PATH, 0x00);
        vwdir.resize(MAX_PATH, 0x00);

        BROWSEINFO bi = { 0 };
        LPITEMIDLIST idl;
        std::wstring title = L"Prediction system Log location";
        bi.hwndOwner = nullptr;
        bi.pidlRoot = nullptr;
        bi.pszDisplayName = &vwname.at(0);
        bi.lpszTitle = title.c_str();
        bi.ulFlags = BIF_RETURNONLYFSDIRS;
        bi.lpfn = nullptr;
        bi.lParam = 0;
        bi.iImage = 0;
        if((idl = ::SHBrowseForFolderW(&bi)) == nullptr) {
            dir.clear();
        } else {
            ::SHGetPathFromIDListW(idl, &vwdir.at(0));
            dir = (LPCWSTR)&vwdir.at(0);
            ::CoTaskMemFree(idl);
        }
    }
    bool output() const {
        if(dir.size() == 0) { return false; }
        if(stream.str().size() == 0) { return false; }
        wobj.waitclose();

        time_t tim = ::time(nullptr);
        struct tm now = { 0 };
        ::localtime_s(&now, &tim);

        std::wstring year = L"year";
        std::wstring mon  = L"mon";
        std::wstring day  = L"day";
        std::wstring hour = L"hour";
        std::wstring min  = L"min";
        std::wstring sec  = L"sec";

        mcrypto<unsigned long> crypt;

        std::wostringstream path;
        path << dir.c_str() << L'\\' << now.tm_year + 1900 << year.c_str() << now.tm_mon + 1 << mon.c_str() << now.tm_mday << day.c_str() << now.tm_hour << hour.c_str() << now.tm_min << min.c_str() << now.tm_sec << sec.c_str() << L'_' << (unsigned long)(crypt >>= crypt) << L".txt";
        wobj.setpath(path.str().c_str());
        return (wobj.openhandle() && setbufferwrite() && wobj.scan());
    }
    bool signal() const {
        return wobj.signal();
    }
    void waitclose() {
        wobj.waitclose();
        clear();
    }
    void clear() {
        stream.str("");
        stream.clear(std::ostringstream::goodbit);
    }
};
} // namespace

/////////////////////////////////////////////////////////////////////////
// STRUCTURE, LOGIC
/////////////////////////////////////////////////////////////////////////

namespace {
typedef struct _progress_info
{
    HWND hProgress;
    WORD id;
    WNDPROC wndproc;
} progress_info;

typedef struct _ctrl_info
{
    const progress_info *pi;
    const HWND *pbench_onoff;
    HWND hStartButton;
    HWND hStopButton;
    HWND hComboDisk;
    HWND hComboThread;
    HWND hComboLoop;
    HWND hComboRand;
} ctrl_info;

class bench_info final
{
private:
    bench_info()=delete;
    bench_info(const bench_info &)=delete;
    bench_info &operator=(const bench_info &)=delete;
    bench_info(bench_info &&)=delete;
    bench_info &operator=(bench_info &&)=delete;

    const ctrl_info *pci;
    logw *plog;
    sector_randbuffer *randbuf; // random generate threads
    sector_io *io_obj; // benchmark threads
    drive_dataread *driveinf; // drive information (locked read)
    bool partition_none;
    int thread_num;

    void set_progmessage(int target, LPCWSTR message, int percent, bool invalid = false) const {
        ::SendMessageW(pci->pi[target].hProgress, PBM_SETPOS, (int)percent, 0L);
        ::SendMessageW(pci->pi[target].hProgress, WM_SET_PROGRESS, (WPARAM)message, (LPARAM)percent);
        invalid ? ::InvalidateRect(pci->pi[target].hProgress, nullptr, TRUE) : false;
    }

    void _threadproc(cla_thread<bench_info>::thread_data *pdata, int prognum, sector_base *base, size_t objsize, LPCWSTR message) const {
        set_progmessage(prognum, message, 0);
        for(;;)
        {
            if(pdata->exit_flag) { return; }

            double ave = 0.0;
            for(int i = 0; i < thread_num; ++i)
            {
                ave += ((sector_base *)(((BYTE *)base + objsize * i)))->getprog();
            }
            ave /= thread_num;
            ave *= 100;
            set_progmessage(prognum, message, (int)ave);

            bool all_signal = true;
            for(int i = 0; i < thread_num; ++i)
            {
                if(!((sector_base *)(((BYTE *)base + objsize * i)))->signal()) {
                    all_signal = false;
                    break;
                }
            }
            if(all_signal) { break; }

            ::Sleep(30);
        }
        set_progmessage(prognum, IDS_BENCHMARK_COMPLETED, (int)100, true);
    }

    bool acc_type(cla_thread<bench_info>::thread_data *pdata, sector_io::ACC_TYPE type) const {
        for(int i = 0; i < thread_num; ++i)
        {
            if(pdata->exit_flag) { return true; }
            io_obj[i].destroy();
        }
        for(int i = 0; i < thread_num; ++i) // Rand Mix
        {
            if(pdata->exit_flag) { return true; }

            /// Note: Data Protection.
            if((!partition_none) &&
                (type == sector_io::ACC_TYPE_RANDOM_WRITE_8192KB ||
                    type == sector_io::ACC_TYPE_RANDOM_WRITE_512KB ||
                    type == sector_io::ACC_TYPE_RANDOM_WRITE_4KB ||
                    type == sector_io::ACC_TYPE_SEQ_WRITE)) {
                if(!io_obj[i].settype_file(type, (int)::SendMessageW(pci->hComboDisk, CB_GETCURSEL, 0L, 0L), driveinf)) {
                    return false;
                }
            } else {
                if(!io_obj[i].settype(type, (int)::SendMessageW(pci->hComboDisk, CB_GETCURSEL, 0L, 0L), driveinf)) {
                    return false;
                }
            }

            io_obj[i].setparam(randbuf[i]);
            if(!io_obj[i].create()) {
                return false;
            }
        }
        return true;
    }

    bool bench_start(cla_thread<bench_info>::thread_data *pdata, sector_io::ACC_TYPE type, int prognum) {
        if(!acc_type(pdata, type)) {
            return false;
        }
        set_progmessage(prognum, IDS_BENCHMARK_DOING, (int)0, true);
        if(!speed_thread.start(nullptr, this)) {
            return false;
        }
        _threadproc(pdata, prognum, io_obj, sizeof(sector_io), IDS_BENCHMARK_DOING);
        {
            speed_thread.waitclose();
            if(pdata->exit_flag) { return true; }
            std::wostringstream stream;
            stream << IDS_BENCHMARK_RESULT << speed_result << L"MB/s  ";
            set_progmessage(prognum, stream.str().c_str(), (int)100, true);

            std::wostringstream logstream;
            logstream << L"* ";
            switch(prognum)
            {
            case PROGRESS_ID(1):
                logstream << IDS_PROGRESSBAR_1 << L"  ";
                break;
            case PROGRESS_ID(2):
                logstream << IDS_PROGRESSBAR_2 << L"   ";
                break;
            case PROGRESS_ID(3):
                logstream << IDS_PROGRESSBAR_3 << L"     ";
                break;
            case PROGRESS_ID(4):
                logstream << IDS_PROGRESSBAR_4 << L" ";
                break;
            case PROGRESS_ID(5):
                logstream << IDS_PROGRESSBAR_5 << L"  ";
                break;
            case PROGRESS_ID(6):
                logstream << IDS_PROGRESSBAR_6 << L"    ";
                break;
            case PROGRESS_ID(7):
                logstream << IDS_PROGRESSBAR_7 << L"     ";
                break;
            case PROGRESS_ID(8):
                logstream << IDS_PROGRESSBAR_8 << L"    ";
                break;
            default:
                break;
            }
            *plog << logstream.str().c_str() << L" " << stream.str().c_str() << L"\r\n";
        }
        return true;
    }

    cla_thread<bench_info> ctrl_thread;
    unsigned int _thread(cla_thread<bench_info>::thread_data *pdata) {
        for(int i = 0; i < PROGRESS_NUM; ++i)
        {
            set_progmessage(i, IDS_BENCHMARK_WAITING, 0, true);
        }

        LPCWSTR sepa = L"=====================================================================";
        std::wstring rand_st, rand_type;
        if((int)::SendMessageW(pci->hComboRand, CB_GETCURSEL, 0L, 0L) == RAND_STRENGTH_LOW) {
            rand_st = IDS_RAND_LOW;
        } else if((int)::SendMessageW(pci->hComboRand, CB_GETCURSEL, 0L, 0L) == RAND_STRENGTH_MID) {
            rand_st = IDS_RAND_MID;
        } else {
            rand_st = IDS_RAND_HIGH;
        }
        if((int)::SendMessageW(pci->pbench_onoff[0], CB_GETCURSEL, 0L, 0L) == RAND_SELECT_MIX) {
            rand_type = IDS_BENCHMARK_RAND_MIX;
        } else if((int)::SendMessageW(pci->pbench_onoff[0], CB_GETCURSEL, 0L, 0L) == RAND_SELECT_MT19937) {
            rand_type = IDS_BENCHMARK_RAND_MT19937;
        } else if((int)::SendMessageW(pci->pbench_onoff[0], CB_GETCURSEL, 0L, 0L) == RAND_SELECT_XORSHIFT) {
            rand_type = IDS_BENCHMARK_RAND_XORSHIFT;
        } else {
            rand_type = IDS_BENCHMARK_RAND_OPENSSL;
        }
        for(;;)
        {
            *plog << L"\r\n" << sepa
                << L"\r\n* " << IDS_APP_TITLE
                << L"\r\n* " << IDS_APP_COPYRIGHT
                << L"\r\n* " << IDS_LOG_PARAM << L" " << ((int)::SendMessageW(pci->hComboThread, CB_GETCURSEL, 0L, 0L) + 1) * sector_randbuffer::RAND_GENE_MAX << IDS_LOG_THREAD << L" " << rand_st.c_str() << L" " << IDS_LOG_RAND << L":" << rand_type.c_str()
                << L"\r\n" << sepa
                << L"\r\n\r\n";

            //
            // 0, RandSeedBuf
            //
            _threadproc(pdata, 0, randbuf, sizeof(sector_randbuffer), IDS_BENCHMARK_GENERATING);
            if(pdata->exit_flag) { return 1; }

            //
            // 1, Random Read 8192KB
            //
            if((int)::SendMessageW(pci->pbench_onoff[1], CB_GETCURSEL, 0L, 0L) == BENCH_SELECT_ON) {
                if(!bench_start(pdata, sector_io::ACC_TYPE_RANDOM_READ_8192KB, 1)) {
                    return 1;
                }
                if(pdata->exit_flag) { return 1; }
            }

            //
            // 2, Random Read 512KB
            //
            if((int)::SendMessageW(pci->pbench_onoff[2], CB_GETCURSEL, 0L, 0L) == BENCH_SELECT_ON) {
                if(!bench_start(pdata, sector_io::ACC_TYPE_RANDOM_READ_512KB, 2)) {
                    return 1;
                }
                if(pdata->exit_flag) { return 1; }
            }

            //
            // 3, Random Read 4KB
            //
            if((int)::SendMessageW(pci->pbench_onoff[3], CB_GETCURSEL, 0L, 0L) == BENCH_SELECT_ON) {
                if(!bench_start(pdata, sector_io::ACC_TYPE_RANDOM_READ_4KB, 3)) {
                    return 1;
                }
                if(pdata->exit_flag) { return 1; }
            }

            //
            // 4, Random Write 8192KB
            //
            if((int)::SendMessageW(pci->pbench_onoff[4], CB_GETCURSEL, 0L, 0L) == BENCH_SELECT_ON) {
                if(!bench_start(pdata, sector_io::ACC_TYPE_RANDOM_WRITE_8192KB, 4)) {
                    return 1;
                }
                if(pdata->exit_flag) { return 1; }
            }

            //
            // 5, Random Write 512KB
            //
            if((int)::SendMessageW(pci->pbench_onoff[5], CB_GETCURSEL, 0L, 0L) == BENCH_SELECT_ON) {
                if(!bench_start(pdata, sector_io::ACC_TYPE_RANDOM_WRITE_512KB, 5)) {
                    return 1;
                }
                if(pdata->exit_flag) { return 1; }
            }

            //
            // 6, Random Write 4KB
            //
            if((int)::SendMessageW(pci->pbench_onoff[6], CB_GETCURSEL, 0L, 0L) == BENCH_SELECT_ON) {
                if(!bench_start(pdata, sector_io::ACC_TYPE_RANDOM_WRITE_4KB, 6)) {
                    return 1;
                }
                if(pdata->exit_flag) { return 1; }
            }

            //
            // 7, Seq Read
            //
            if((int)::SendMessageW(pci->pbench_onoff[7], CB_GETCURSEL, 0L, 0L) == BENCH_SELECT_ON) {
                if(!bench_start(pdata, sector_io::ACC_TYPE_SEQ_READ, 7)) {
                    return 1;
                }
                if(pdata->exit_flag) { return 1; }
            }

            //
            // 8, Seq Write
            //
            if((int)::SendMessageW(pci->pbench_onoff[8], CB_GETCURSEL, 0L, 0L) == BENCH_SELECT_ON) {
                if(!bench_start(pdata, sector_io::ACC_TYPE_SEQ_WRITE, 8)) {
                    return 1;
                }
                if(pdata->exit_flag) { return 1; }
            }

            //
            // log output
            //
            *plog << L"\r\n" << sepa
                << L"\r\n\r\n" << sepa
                << L"\r\n" << IDS_LOG_DRIVEINFO
                << L"\r\n" << sepa
                << L"\r\n\r\n" << driveinf->getdriveinfo().c_str()
                << L"\r\n\r\n" << sepa << L"\r\n\r\n";
            if(plog->output()) {
                plog->waitclose(); // log stream clear
            } else {
                plog->clear();
            }

            if((int)::SendMessageW(pci->hComboLoop, CB_GETCURSEL, 0L, 0L) == LOOP_BENCHMARK_ON) {
                continue;
            } else {
                break;
            }
        }
        return 1;
    }

    cla_thread<bench_info> speed_thread;
    double speed_result;
    unsigned int _speed(cla_thread<bench_info>::thread_data *pdata) {
        cputime time_obj;

        double t1 = time_obj();
        double t2 = 0.0;
        speed_result = 0.0;
        for(;;)
        {
            if(pdata->exit_flag) { return 1; }

            bool all_signal = true;
            for(int i = 0; i < thread_num; ++i)
            {
                if(!io_obj[i].signal()) {
                    all_signal = false;
                    break;
                }
            }

            if(all_signal) {
                t2 = time_obj();
                for(int i = 0; i < thread_num; ++i)
                {
                    // debugcs::instance() << L"[time]" << t2 - t1;
                    speed_result += io_obj[i].getspeed(t2 - t1);
                }
                speed_result /= 1024 * 1024;
                break;
            }
        }
        return 1;
    }

public:
    bench_info(const ctrl_info *p, logw *_plog) : ctrl_thread(&bench_info::_thread), speed_thread(&bench_info::_speed) {
        pci = p;
        plog = _plog;
        randbuf = nullptr;
        io_obj = nullptr;
        driveinf = nullptr;
        thread_num = 0;
        partition_none = false;
        speed_result = 0.0;
    }
    ~bench_info() {
        destroy();
    }

    /// INSTANCE
    bool create() {
        destroy();
        driveinf = new(std::nothrow) drive_dataread((int)::SendMessageW(pci->hComboDisk, CB_GETCURSEL, 0L, 0L));
        if(!driveinf->openhandle()) {
            return false;
        }
        partition_none = checkpartition();
        debugcs::instance() << "[None Partition Flag]" << partition_none;
        thread_num = ((int)::SendMessageW(pci->hComboThread, CB_GETCURSEL, 0L, 0L) + 1) * sector_randbuffer::RAND_GENE_MAX;
        randbuf = new(std::nothrow) sector_randbuffer[thread_num];
        io_obj = new(std::nothrow) sector_io[thread_num];
        return ((driveinf != nullptr) && (randbuf != nullptr) && (io_obj != nullptr));
    }
    std::wstring getdriveinfo() const {
        if(io_obj) {
            return driveinf->getdriveinfo();
        } else {
            return L"";
        }
    }
    void destroy() {
        if(randbuf) {
            delete[] randbuf;
            randbuf = nullptr;
        }
        if(io_obj) {
            delete[] io_obj;
            io_obj = nullptr;
        }
        if(driveinf) {
            delete driveinf;
            driveinf = nullptr;
        }
        thread_num = 0;
        partition_none = false;
    }

    /// Check
    /// true: None partition, false: Exist partition or error.
    bool checkpartition() const {
        if(!driveinf) { return false; }
        if(driveinf->checkdriveletter()) { return false; }

        const DWORD size = 8192; // 16 sectors (or 2 sectors)
        std::vector<sector_t> sectors_addr;
        sectors_addr.push_back(0);
        driveinf->setstep(size);
        driveinf->set(sectors_addr);
        if(!driveinf->scan()) {
            return false;
        }
        driveinf->waitclose();

        const std::vector<BYTE> *pbuf = driveinf->getbufferread();
        if(!pbuf) {
            return false;
        }
        if(pbuf->size() != size) {
            return false;
        }

        for(std::vector<BYTE>::const_iterator ite = pbuf->begin(); ite != pbuf->end(); ++ite)
        {
            if(*ite != 0x00) {
                return false;
            }
        }
        return true;
    }

    /// RAND and SCAN THREAD START
    bool start() {
        if(!randbuf) { return false; }
        const int algo_num = sector_randbuffer::RAND_GENE_MAX;
        int gene_count = RAND_GENE_MAX_DEFAULT;
        if((int)::SendMessageW(pci->hComboRand, CB_GETCURSEL, 0L, 0L) == RAND_STRENGTH_LOW) {
            gene_count *= 1;
        } else if((int)::SendMessageW(pci->hComboRand, CB_GETCURSEL, 0L, 0L) == RAND_STRENGTH_MID) {
            gene_count *= 10;
        } else {
            gene_count *= 100;
        }
        for(int i = 0; i < thread_num; ++i)
        {
            if((int)::SendMessageW(pci->pbench_onoff[0], CB_GETCURSEL, 0L, 0L) == RAND_SELECT_MIX) {
                if(i % algo_num == 0) {
                    if(!randbuf[i].settype(sector_randbuffer::RAND_GENE_STANDARD)) { return false; }
                } else if(i % algo_num == 1) {
                    if(!randbuf[i].settype(sector_randbuffer::RAND_GENE_XORSHIFT)) { return false; }
                } else {
                    if(!randbuf[i].settype(sector_randbuffer::RAND_GENE_OPENSSL)) { return false; }
                }
            } else if((int)::SendMessageW(pci->pbench_onoff[0], CB_GETCURSEL, 0L, 0L) == RAND_SELECT_MT19937) {
                if(!randbuf[i].settype(sector_randbuffer::RAND_GENE_STANDARD)) { return false; }
            } else if((int)::SendMessageW(pci->pbench_onoff[0], CB_GETCURSEL, 0L, 0L) == RAND_SELECT_XORSHIFT) {
                if(!randbuf[i].settype(sector_randbuffer::RAND_GENE_XORSHIFT)) { return false; }
            } else {
                if(!randbuf[i].settype(sector_randbuffer::RAND_GENE_OPENSSL)) { return false; }
            }

            randbuf[i].setgenecount(gene_count);
            if(!randbuf[i].create()) {
                return false;
            }
        }
        return true;
    }

    /// CTRL THREAD START
    bool ctrlthread_start() {
        return ctrl_thread.start(nullptr, this);
    }

    /// THREAD STOP, SIGNAL and WAIT
    void all_stop() {
        if(!randbuf) { return; }
        if(!io_obj) { return; }
        for(int i = 0; i < thread_num; ++i)
        {
            randbuf[i].stop();
        }
        for(int i = 0; i < thread_num; ++i)
        {
            io_obj[i].stop();
        }
        ctrl_thread.stop();
        speed_thread.stop();
    }
    bool all_signal() const {
        if((!randbuf) && (!io_obj)) { return true; }
        for(int i = 0; i < thread_num; ++i)
        {
            if(!randbuf[i].signal()) {
                return false;
            }
        }
        for(int i = 0; i < thread_num; ++i)
        {
            if(!io_obj[i].signal()) {
                return false;
            }
        }

        return ctrl_thread.signal() && speed_thread.signal();
    }
    void all_waitclose() {
        if(!randbuf) { return; }
        if(!io_obj) { return; }
        for(int i = 0; i < thread_num; ++i)
        {
            randbuf[i].waitclose();
        }
        for(int i = 0; i < thread_num; ++i)
        {
            io_obj[i].waitclose();
        }

        ctrl_thread.stop();
        ctrl_thread.waitclose();
        speed_thread.stop();
        speed_thread.waitclose();

        destroy();
    }

    /// Error
    bool getfailure() const {
        if(!io_obj) { return true; }
        for(int i = 0; i < thread_num; ++i)
        {
            if(io_obj[i].getfailure()) {
                return true;
            }
        }
        return false;
    }
};

typedef struct _win_userdata
{
    const ctrl_info *pci;
    bench_info *pbi;
    bool restart;
    logw *plog;
} win_userdata;

} // namespace

/////////////////////////////////////////////////////////////////////////
// OPERATOR
/////////////////////////////////////////////////////////////////////////

namespace {
RECT &operator+=(RECT &rc, const int &d)
{
    rc.top += d;
    rc.bottom += d;
    return rc;
}
} // namespace

/////////////////////////////////////////////////////////////////////////
// FONT
/////////////////////////////////////////////////////////////////////////

namespace {
class font
{
private:
    font(const font &)=delete;
    font &operator=(const font &)=delete;
    font(font &&)=delete;
    font &operator=(font &&)=delete;

    HFONT hFont;
    font() {
        hFont = ::CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_TT_ONLY_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, VARIABLE_PITCH | FF_DONTCARE, nullptr);
        if(! hFont)
            throw std::runtime_error(CMString(IDS_ERROR_FONT));
    }
    ~font() {
        if(hFont) {
            ::DeleteObject(hFont);
            hFont = nullptr;
        }
    }
public:
    static const font &instance() {
        static font fobj;
        return fobj;
    }
    template <typename T> const font &operator()(HDC hDC, RECT rc, const T &obj) const {
        std::wostringstream stream;
        stream << obj;
        HFONT prev = (HFONT)::SelectObject(hDC, hFont);
        ::DrawTextW(hDC, stream.str().c_str(), -1, &rc, DT_WORDBREAK);
        ::SelectObject(hDC, prev);
        return *this;
    }
};
} // namespace

/////////////////////////////////////////////////////////////////////////
// FUNCTION
/////////////////////////////////////////////////////////////////////////

namespace {
namespace ProgressString
{
    static LCCriticalSection cs;
    static std::wstring str[PROGRESS_NUM];

    inline std::wstring GetString(WORD id)
    {
        LLOCK(cs);
        std::wostringstream stream;
        stream << str[id];
        return stream.str();
    }
    inline void SetString(WORD id, LPCWSTR message, int percent)
    {
        LLOCK(cs);
        std::wostringstream stream;
        if(message)
            stream << message << percent << L" %";
        else
            stream << percent << L" %";
        str[id] = stream.str();
    }
    inline void ClearString() {
        for(int i = 0; i < ARRAY_SIZE(ProgressString::str); ++i)
            ProgressString::str[i].clear();
    }
}

static void SetCtrlMenu(HWND hWnd, DWORD idr) {
    HMENU hMenu = ::LoadMenu(::GetModuleHandle(nullptr), MAKEINTRESOURCEW(idr));
    ::SetMenu(hWnd, hMenu);
}

static void SetCtrlWait(HWND hWnd, const ctrl_info *pci) {
    ::EnableWindow(pci->hStartButton, TRUE);
    ::EnableWindow(pci->hStopButton, FALSE);
    ::EnableWindow(pci->hComboDisk, TRUE);
    ::EnableWindow(pci->hComboThread, TRUE);
    ::EnableWindow(pci->hComboLoop, TRUE);
    ::EnableWindow(pci->hComboRand, TRUE);
    for(int i = 0; i < PROGRESS_NUM; ++i)
        ::EnableWindow(pci->pbench_onoff[i], TRUE);
}

static void SetCtrlBenchmark(HWND hWnd, const ctrl_info *pci) {
    ::EnableWindow(pci->hStartButton, FALSE);
    ::EnableWindow(pci->hStopButton, TRUE);
    ::EnableWindow(pci->hComboDisk, FALSE);
    ::EnableWindow(pci->hComboThread, FALSE);
    ::EnableWindow(pci->hComboLoop, FALSE);
    ::EnableWindow(pci->hComboRand, FALSE);
    for(int i = 0; i < PROGRESS_NUM; ++i)
        ::EnableWindow(pci->pbench_onoff[i], FALSE);
}
} // namespace

/////////////////////////////////////////////////////////////////////////
// CALLBACK
/////////////////////////////////////////////////////////////////////////

static LRESULT CALLBACK WindowProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp)
{
    win_userdata *pwu = reinterpret_cast<win_userdata *>(::GetWindowLongPtrW(hWnd, GWLP_USERDATA));
    //std::wstring str;

    switch(msg)
    {
    case WM_CLOSE:
        if(! pwu->pbi->all_signal()) {
            ::MessageBoxW(hWnd, IDS_BENCHMARK_NO_CLOSE, IDS_MESSAGEBOX_INFO, MB_OK | MB_ICONINFORMATION);
            return 0;
        }
        break;
    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC hDC = ::BeginPaint(hWnd, &ps);
        RECT rc = { 2, 60, 430, 95 };
        font::instance()(hDC, rc, IDS_PROGRESSBAR_0);
        for(int i = 1; i < PROGRESS_NUM; ++i)
        {
            std::wostringstream stream;
            switch(i)
            {
            case PROGRESS_ID(1):
                stream << IDS_PROGRESSBAR_1;
                break;
            case PROGRESS_ID(2):
                stream << IDS_PROGRESSBAR_2;
                break;
            case PROGRESS_ID(3):
                stream << IDS_PROGRESSBAR_3;
                break;
            case PROGRESS_ID(4):
                stream << IDS_PROGRESSBAR_4;
                break;
            case PROGRESS_ID(5):
                stream << IDS_PROGRESSBAR_5;
                break;
            case PROGRESS_ID(6):
                stream << IDS_PROGRESSBAR_6;
                break;
            case PROGRESS_ID(7):
                stream << IDS_PROGRESSBAR_7;
                break;
            case PROGRESS_ID(8):
                stream << IDS_PROGRESSBAR_8;
                break;
            default:
                break;
            }
            rc += 45;
            font::instance()(hDC, rc, stream.str());
        }
        ::EndPaint(hWnd, &ps);
    }
    break;
    case WM_COMMAND:
        switch(LOWORD(wp))
        {
        case IDC_BUTTON_START:
            if(! pwu->pbi->all_signal()) {
                ::MessageBoxW(hWnd, IDS_BENCH_START_NO_CLOSE, IDS_MESSAGEBOX_INFO, MB_OK | MB_ICONINFORMATION);
                break;
            }
            if(::MessageBoxW(hWnd, IDS_BENCHMARK_START, IDS_MESSAGEBOX_QUESTION, MB_YESNO | MB_ICONQUESTION) == IDYES) {
                if(pwu->pbi->create()) {
                    std::wostringstream stream;
                    stream << IDS_BENCHMARK_INFO << pwu->pbi->getdriveinfo().c_str() << L"\n\n" << IDS_BENCHMARK_OK;
                    if(::MessageBoxW(hWnd, stream.str().c_str(), IDS_MESSAGEBOX_QUESTION, MB_YESNO | MB_ICONQUESTION) == IDYES) {
                        if(pwu->pbi->start() && pwu->pbi->ctrlthread_start()) {
                            SetCtrlBenchmark(hWnd, pwu->pci);
                            ::SetTimer(hWnd, IDC_THREAD_TIMER, THREAD_TIMER_INTERVAL, nullptr);
                        } else {
                            ::MessageBoxW(hWnd, IDS_ERROR_BENCHMARK_START, IDS_MESSAGEBOX_ERROR, MB_OK | MB_ICONWARNING);
                            pwu->pbi->all_stop();
                            pwu->pbi->all_waitclose();
                        }
                    }
                } else {
                    ::MessageBoxW(hWnd, IDS_ERROR_BENCHMARK_FAILURE, IDS_MESSAGEBOX_ERROR, MB_OK | MB_ICONWARNING);
                    pwu->pbi->all_stop();
                    pwu->pbi->all_waitclose();
                }
            }
            break;
        case IDC_BUTTON_STOP:
            if(pwu->pbi->all_signal()) {
                break;
            }
            if(::MessageBoxW(hWnd, IDS_BENCHMARK_STOP, IDS_MESSAGEBOX_QUESTION, MB_YESNO | MB_ICONQUESTION) == IDYES) {
                pwu->pbi->all_stop();
            }
            break;
        //case IDM_BENCH_LOG:
        //    if(! pwu->pbi->all_signal()) {
        //        ::MessageBoxW(hWnd, IDS_BENCH_LOGSET_NO_CLOSE, IDS_MESSAGEBOX_INFO, MB_OK | MB_ICONINFORMATION);
        //        break;
        //    }
        //    pwu->plog->setdir();
        //    break;
        default:
            break;
        }
        return 0;
    case WM_TIMER:
        if(pwu->pbi->all_signal()) {
            bool failure = pwu->pbi->getfailure();
            pwu->pbi->all_waitclose();
            ::KillTimer(hWnd, IDC_THREAD_TIMER);
            if(failure) {
                ::MessageBoxW(hWnd, IDS_BENCHMARK_RESULT_ERROR, IDS_MESSAGEBOX_ERROR, MB_OK | MB_ICONWARNING);
            }
            SetCtrlWait(hWnd, pwu->pci);
        }
        break;
    default:
        break;
    }

    return ::DefWindowProcW(hWnd, msg, wp, lp);
}

LRESULT CALLBACK ProgressProc(HWND hProgress, UINT msg, WPARAM wp, LPARAM lp)
{
    progress_info *proginfo = reinterpret_cast<progress_info *>(::GetWindowLongPtrW(hProgress, GWLP_USERDATA));
    LRESULT ret = ::CallWindowProcW(proginfo->wndproc, hProgress, msg, wp, lp);

    switch(msg)
    {
    case WM_PAINT:
    {
        HDC hDC = ::GetDC(hProgress);
        RECT rc = { 5, 10, 300, 35 };
        std::wstring str = ProgressString::GetString(proginfo->id);
        font::instance()(hDC, rc, str);
        ::ReleaseDC(hProgress, hDC);
        //::ValidateRect(hProgress, &rc); // Note: ::BeginPaint is called by ::CallWindowProcW in WM_PAINT.
    }
    break;
    case WM_SET_PROGRESS:
        ProgressString::SetString(proginfo->id, (LPCWSTR)wp, (int)lp);
        break;
    default:
        break;
    }

    return ret;
}

//
// extern init.h : called, modeless dialog window
//
predsystem::result predsystem::CreateBenchmark() noexcept
{
    result ret;
    auto unregister_wc = []{::UnregisterClassW(IDS_APP_WINDOWCLASSNAME, ::GetModuleHandleW(nullptr));};
    auto err = [&]{unregister_wc(); ret.ret=ret_code::error_createwindow; return ret;};

    class icon_manage {
    public:
        icon_manage() {
            wchar_t soraPath[MAX_PATH];
            ::GetModuleFileNameW(nullptr, soraPath, MAX_PATH);
            hIcon = ::ExtractIconW(::GetModuleHandleW(nullptr), soraPath, 0);
        }
        ~icon_manage() {
            if(hIcon)
                ::DestroyIcon(hIcon);
        }
        HICON get() const {return hIcon;}
    private:
        HICON hIcon;
    };

    icon_manage icom;
    logw logobj;
    WNDCLASSEX wc = {0};
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WindowProc;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hIcon = wc.hIconSm = icom.get();
    wc.lpszMenuName = nullptr;
    wc.lpszClassName = IDS_APP_WINDOWCLASSNAME;
    if(! ::RegisterClassEx(&wc)) {
        logging::LogPrintf(CMString(IDS_ERROR_CLASSREGISTER)+L"\n");
        return err();
    }

    INT_PTR winmain_ret = 0;
    do
    {
        ProgressString::ClearString();

        const int desktopWidth = ::GetSystemMetrics(SM_CXSCREEN);
        const int desktopHeight = ::GetSystemMetrics(SM_CYSCREEN);
        HWND hWnd = ::CreateWindowExW(
            0,
            IDS_APP_WINDOWCLASSNAME,
            IDS_APP_TITLE,
            WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX,
            (desktopWidth - WINDOW_WIDTH) / 2,
            (desktopHeight - WINDOW_HEIGHT) / 2,
            WINDOW_WIDTH,
            WINDOW_HEIGHT,
            nullptr,
            nullptr,
            ::GetModuleHandleW(nullptr),
            nullptr
        );
        if(!hWnd) {
            logging::LogPrintf(CMString(IDS_ERROR_CREATEWINDOW)+L"\n");
            return err();
        }

        ctrl_info ci;
        {
            HWND hButton = ::CreateWindowExW(
                0,
                L"BUTTON",
                IDS_START,
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                10,
                20,
                100,
                30,
                hWnd,
                (HMENU)IDC_BUTTON_START,
                ::GetModuleHandleW(nullptr),
                nullptr
            );
            if(!hButton) {
                logging::LogPrintf(CMString(IDS_ERROR_CREATEWINDOW)+L"\n");
                return err();
            }
            ci.hStartButton = hButton;
            ::ShowWindow(hButton, SW_SHOW);
        }
        {
            HWND hButton = ::CreateWindowExW(
                0,
                L"BUTTON",
                IDS_STOP,
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                120,
                20,
                100,
                30,
                hWnd,
                (HMENU)IDC_BUTTON_STOP,
                ::GetModuleHandleW(nullptr),
                nullptr
            );
            if(!hButton) {
                logging::LogPrintf(CMString(IDS_ERROR_CREATEWINDOW)+L"\n");
                return err();
            }
            ci.hStopButton = hButton;
            ::ShowWindow(hButton, SW_SHOW);
        }
        {
            HWND hCombo = ::CreateWindowExW(
                0,
                L"COMBOBOX",
                L"",
                WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_TABSTOP | WS_VSCROLL | CBS_HASSTRINGS | CBS_AUTOHSCROLL | CBS_DROPDOWNLIST,
                240,
                15,
                300,
                300,
                hWnd,
                (HMENU)IDC_COMBO_DRIVE,
                ::GetModuleHandleW(nullptr),
                nullptr
            );
            if(!hCombo) {
                logging::LogPrintf(CMString(IDS_ERROR_CREATEWINDOW)+L"\n");
                return err();
            }

            for(int i = 0; i < DISK_MAX; ++i)
            {
                std::wostringstream stream;
                drive_dataread robj(i);
                if(robj.openhandle()) {
                    stream << L"[" << i << L"] " << robj.getdriveinfo(0);
                } else {
                    stream << IDS_DISK << i << L" " << IDS_DISK_NONE;
                }
                ::SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)stream.str().c_str());
            }

            ci.hComboDisk = hCombo;
            ::SendMessageW(hCombo, CB_SETCURSEL, 0, 0);
            ::ShowWindow(hCombo, SW_SHOW);
        }
        {
            HWND hCombo = ::CreateWindowExW(
                0,
                L"COMBOBOX",
                L"",
                WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_TABSTOP | WS_VSCROLL | CBS_HASSTRINGS | CBS_AUTOHSCROLL | CBS_DROPDOWNLIST,
                550,
                15,
                140,
                400,
                hWnd,
                (HMENU)IDC_COMBO_THREAD,
                ::GetModuleHandleW(nullptr),
                nullptr
            );
            if(!hCombo) {
                logging::LogPrintf(CMString(IDS_ERROR_CREATEWINDOW)+L"\n");
                return err();
            }

            for(int i = 0, k = 0; i < THREAD_MAX; ++i)
            {
                if(i % sector_randbuffer::RAND_GENE_MAX == 0) {
                    std::wostringstream stream;
                    stream << (k++ + 1) * sector_randbuffer::RAND_GENE_MAX << IDS_THREADS;
                    ::SendMessageW(hCombo, CB_ADDSTRING, 0L, (LPARAM)stream.str().c_str());
                }
            }

            ci.hComboThread = hCombo;
            ::SendMessageW(hCombo, CB_SETCURSEL, 0, 0);
            ::ShowWindow(hCombo, SW_SHOW);
        }
        {
            HWND hCombo = ::CreateWindowEx(
                0,
                L"COMBOBOX",
                L"",
                WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_TABSTOP | WS_VSCROLL | CBS_HASSTRINGS | CBS_AUTOHSCROLL | CBS_DROPDOWNLIST,
                440,
                470,
                250,
                150,
                hWnd,
                (HMENU)IDC_COMBO_LOOP,
                ::GetModuleHandleW(nullptr),
                nullptr
            );
            if(!hCombo) {
                logging::LogPrintf(CMString(IDS_ERROR_CREATEWINDOW)+L"\n");
                return err();
            }

            ::SendMessageW(hCombo, CB_ADDSTRING, 0L, (LPARAM)IDS_ONCE_BENCHMARK);
            ::SendMessageW(hCombo, CB_ADDSTRING, 0L, (LPARAM)IDS_LOOP_BENCHMARK);

            ci.hComboLoop = hCombo;
            ::SendMessageW(hCombo, CB_SETCURSEL, 0, 0);
            ::ShowWindow(hCombo, SW_SHOW);
        }

        {
            HWND hCombo = ::CreateWindowEx(
                0,
                L"COMBOBOX",
                L"",
                WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_TABSTOP | WS_VSCROLL | CBS_HASSTRINGS | CBS_AUTOHSCROLL | CBS_DROPDOWNLIST,
                210,
                470,
                220,
                150,
                hWnd,
                (HMENU)IDC_COMBO_RAND,
                ::GetModuleHandleW(nullptr),
                nullptr
            );
            if(!hCombo) {
                logging::LogPrintf(CMString(IDS_ERROR_CREATEWINDOW)+L"\n");
                return err();
            }

            ::SendMessageW(hCombo, CB_ADDSTRING, 0L, (LPARAM)IDS_RAND_LOW);
            ::SendMessageW(hCombo, CB_ADDSTRING, 0L, (LPARAM)IDS_RAND_MID);
            ::SendMessageW(hCombo, CB_ADDSTRING, 0L, (LPARAM)IDS_RAND_HIGH);

            ci.hComboRand = hCombo;
            ::SendMessageW(hCombo, CB_SETCURSEL, 0, 0);
            ::ShowWindow(hCombo, SW_SHOW);
        }

        progress_info proginfo[PROGRESS_NUM] = { 0 };
        HWND bench_onoff[PROGRESS_NUM] = { 0 };
        ci.pi = proginfo;
        ci.pbench_onoff = bench_onoff;
        for(int i = 0; i < ARRAY_SIZE(proginfo); ++i)
        {
            proginfo[i].hProgress = ::CreateWindowExW(
                0,
                PROGRESS_CLASSW,
                L"",
                WS_CHILD | WS_BORDER,
                140,
                60 + i * 45,
                550,
                40,
                hWnd,
                (HMENU)PROGRESS_ID(i),
                ::GetModuleHandleW(nullptr),
                nullptr
            );
            if(!proginfo[i].hProgress) {
                logging::LogPrintf(CMString(IDS_ERROR_CREATEWINDOW)+L"\n");
                return err();
            }

            proginfo[i].id = (WORD)PROGRESS_ID(i);
            proginfo[i].wndproc = (WNDPROC)::GetWindowLongPtrW(proginfo[i].hProgress, GWLP_WNDPROC);
            ::SetWindowLongPtrW(proginfo[i].hProgress, GWLP_USERDATA, (LONG_PTR)&proginfo[i]);
            ::SetWindowLongPtrW(proginfo[i].hProgress, GWLP_WNDPROC, (LONG_PTR)ProgressProc);

            ::SendMessageW(proginfo[i].hProgress, PBM_SETRANGE, 0L, MAKELONG(0, 100));
            ::SendMessageW(proginfo[i].hProgress, PBM_SETPOS, 0, 0L);
            ::ShowWindow(proginfo[i].hProgress, SW_SHOW);

            bench_onoff[i] = ::CreateWindowEx(
                0,
                L"COMBOBOX",
                L"",
                WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_TABSTOP | WS_VSCROLL | CBS_HASSTRINGS | CBS_AUTOHSCROLL | CBS_DROPDOWNLIST,
                10,
                80 + i * 45,
                90,
                130,
                hWnd,
                (HMENU)BENCH_ONOFF_ID(i),
                ::GetModuleHandleW(nullptr),
                nullptr
            );
            if(!bench_onoff[i]) {
                logging::LogPrintf(CMString(IDS_ERROR_CREATEWINDOW)+L"\n");
                return err();
            }

            if(i == 0) {
                ::SendMessageW(bench_onoff[i], CB_ADDSTRING, 0L, (LPARAM)IDS_BENCHMARK_RAND_MIX);
                ::SendMessageW(bench_onoff[i], CB_ADDSTRING, 0L, (LPARAM)IDS_BENCHMARK_RAND_MT19937);
                ::SendMessageW(bench_onoff[i], CB_ADDSTRING, 0L, (LPARAM)IDS_BENCHMARK_RAND_XORSHIFT);
                ::SendMessageW(bench_onoff[i], CB_ADDSTRING, 0L, (LPARAM)IDS_BENCHMARK_RAND_OPENSSL);
            } else {
                ::SendMessageW(bench_onoff[i], CB_ADDSTRING, 0L, (LPARAM)IDS_BENCHMARK_ON);
                ::SendMessageW(bench_onoff[i], CB_ADDSTRING, 0L, (LPARAM)IDS_BENCHMARK_OFF);
            }

            if((0 <= i && i <= 3) || i == 7) {
                ::SendMessageW(bench_onoff[i], CB_SETCURSEL, 0, 0L);
            } else {
                ::SendMessageW(bench_onoff[i], CB_SETCURSEL, 1, 0L);
            }
            ::ShowWindow(bench_onoff[i], SW_SHOW);
        }

        bench_info bi(&ci, &logobj);
        win_userdata wu = { &ci, &bi, false, &logobj };
        ::SetWindowLongPtrW(hWnd, GWLP_USERDATA, (LONG_PTR)&wu);
        ::ShowWindow(hWnd, SW_SHOW);
        ::UpdateWindow(hWnd);
        SetCtrlWait(hWnd, wu.pci);

        MSG msg;
        while (::GetMessageW(&msg, nullptr, 0, 0) > 0)
        {
            ::TranslateMessage(&msg);
            ::DispatchMessageW(&msg);
        }
    } while(0); // no loop

    ret.window_ret = winmain_ret;
    unregister_wc();
    return ret;
}

#endif // QT_GUI && WIN32
