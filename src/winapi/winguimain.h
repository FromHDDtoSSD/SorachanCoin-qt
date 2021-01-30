// Copyright (c) 2018-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SORACHANCOIN_WINGUIMAIN_H
#define SORACHANCOIN_WINGUIMAIN_H
#if defined(QT_GUI) && defined(WIN32)

#include <winapi/common.h>
#include <winapi/drivewin.h>
#include <winapi/sectorwin.h>

#define IDS_APP_TITLE                        L"[SORA Network] Drive(HDD/SSD/RAID) Benckmark - on the Blockchain"
#define IDS_APP_WINDOWCLASSNAME              L"prediction-system-window-benchmark"
#define IDS_APP_COPYRIGHT                    L"Copyright (c) 2021 The SorachanCoin Developers."
#define IDS_MESSAGEBOX_OK                    L"OK"
#define IDS_MESSAGEBOX_ERROR                 L"Error"
#define IDS_MESSAGEBOX_QUESTION              L"Question"
#define IDS_MESSAGEBOX_INFO                  L"Info"
#define IDS_PROGRESSBAR_0                    L"RandSeedBuffer"
#define IDS_PROGRESSBAR_1                    L"RandRead (8192KB)"
#define IDS_PROGRESSBAR_2                    L"RandRead (512KB)"
#define IDS_PROGRESSBAR_3                    L"RandRead (4KB)"
#define IDS_PROGRESSBAR_4                    L"RandWrite (8192KB)"
#define IDS_PROGRESSBAR_5                    L"RandWrite (512KB)"
#define IDS_PROGRESSBAR_6                    L"RandWrite (4KB)"
#define IDS_PROGRESSBAR_7                    L"SequentialRead"
#define IDS_PROGRESSBAR_8                    L"SequentialWrite"
#define IDS_LOG_DIR_DIALOG                   L"Please select a storage location for a Prediction-system logs"
#define IDS_LOG_YEAR                         L"y"
#define IDS_LOG_MON                          L"mon"
#define IDS_LOG_DAY                          L"d"
#define IDS_LOG_HOUR                         L"h"
#define IDS_LOG_MIN                          L"min"
#define IDS_LOG_SEC                          L"s"
#define IDS_LOG_DRIVEINFO                    L"[Drive Information]"
#define IDS_LOG_PARAM                        L"Parameter"
#define IDS_LOG_THREAD                       L" threads"
#define IDS_LOG_RAND                         L"RandomType"
#define IDS_START                            L"START"
#define IDS_STOP                             L"STOP"
#define IDS_DISK                             L"disk "
#define IDS_THREADS                          L" threads"
#define IDS_ONCE_BENCHMARK                   L"Once Benchmark"
#define IDS_LOOP_BENCHMARK                   L"Loop benchmark"
#define IDS_DISK_NONE                        L"None"
#define IDS_BENCHMARK_RAND_MIX               L"Mix"
#define IDS_BENCHMARK_RAND_MT19937           L"mt19937"
#define IDS_BENCHMARK_RAND_XORSHIFT          L"Xorshift"
#define IDS_BENCHMARK_RAND_OPENSSL           L"Bitcoin"
#define IDS_BENCHMARK_ON                     L"ON"
#define IDS_BENCHMARK_OFF                    L"OFF"
#define IDS_RAND_LOW                         L"Rand Strength:Low"
#define IDS_RAND_MID                         L"Rand Strength:Mid"
#define IDS_RAND_HIGH                        L"Rand Strength:High"
#define IDS_BENCHMARK_START                  L"Are you sure about that start benchmark?"
#define IDS_BENCHMARK_STOP                   L"Are you sure about that stop benchmark?"
#define IDS_BENCHMARK_INFO                   L"[DRIVE Information]\n\n"
#define IDS_BENCHMARK_OK                     L"Is it OK?"
#define IDS_BENCHMARK_COMPLETED              L"Completed "
#define IDS_BENCHMARK_DOING                  L"Benchmarking ... "
#define IDS_BENCHMARK_RESULT                 L"Result: "
#define IDS_BENCHMARK_WAITING                L"Waiting ... "
#define IDS_BENCHMARK_GENERATING             L"Generating ... "
#define IDS_BENCHMARK_RESULT_ERROR           L"Benchmark failed with the drive error or a memory allocation failure."
#define IDS_BENCHMARK_NO_CLOSE               L"Can not close while benchmark is running."
#define IDS_LANG_NO_CLOSE                    L"Can not change language while benchmark is running."
#define IDS_BENCH_LOGSET_NO_CLOSE            L"Can not set a logs while benchmark is running."
#define IDS_BENCH_START_NO_CLOSE             L"Already, The benchmark has been started."
#define IDS_ERROR_BENCHMARK_START            L"Benchmark starting was failure.\n"
#define IDS_ERROR_BENCHMARK_FAILURE          L"Benchmark starting was failure.\n(out of memory)"

constexpr INT_PTR IDC_BUTTON_START    = 1000;
constexpr INT_PTR IDC_BUTTON_STOP     = 1001;
constexpr INT_PTR IDC_COMBO_DRIVE     = 1100;
constexpr INT_PTR IDC_COMBO_THREAD    = 1101;
constexpr INT_PTR IDC_COMBO_LOOP      = 1200;
constexpr INT_PTR IDC_COMBO_RAND      = 1300;
constexpr INT_PTR IDC_THREAD_TIMER    = 1400;
constexpr int LOOP_BENCHMARK_ON       = 1;
constexpr int RAND_SELECT_MIX         = 0;
constexpr int RAND_SELECT_MT19937     = 1;
constexpr int RAND_SELECT_XORSHIFT    = 2;
constexpr int RAND_SELECT_OPENSSL     = 3;
constexpr int BENCH_SELECT_ON         = 0;
constexpr int BENCH_SELECT_OFF        = 1;
constexpr int RAND_STRENGTH_LOW       = 0;
constexpr int RAND_STRENGTH_MID       = 1;
constexpr int RAND_STRENGTH_HIGH      = 2;

constexpr int THREAD_TIMER_INTERVAL   = 500;
constexpr int DISK_MAX                = 128;
constexpr int THREAD_MAX              = 192; // THREAD_MAX % sector_randbuffer::RAND_GENE_MAX == 0
constexpr int WINDOW_WIDTH            = 700;
constexpr int WINDOW_HEIGHT           = 550;
constexpr int PROGRESS_NUM            = 9;

constexpr int FONT_CHEIGHT            = 16;

#define ICO_MIMI                      100
#define PROGRESS_ID(X)                ((INT_PTR)X)
#define BENCH_ONOFF_ID(X)             ((INT_PTR)X + 1500)
#define WM_SET_PROGRESS               (WM_APP + 0)

#endif
#endif // SORACHANCOIN_WINGUIMAIN_H
