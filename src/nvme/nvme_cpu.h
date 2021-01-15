// libnvme: https://github.com/hgst/libnvme
// Copyright (c) 2019-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <nvme/nvme_common.h>
#include <pthread.h>

/*
 * Maximum number of CPU supported.
 */
constexpr int NVME_CPU_MAX = 64;

/*
 * Undefined CPU ID.
 */
#define NVME_CPU_ID_ANY UINT_MAX

/*
 * Maximum number of sockets supported.
 */
constexpr int NVME_SOCKET_MAX = 32;

/*
 * Undefined SOCKET ID.
 */
#define NVME_SOCKET_ID_ANY UINT_MAX

namespace nvme {

/*
 * System CPU descriptor.
 */
struct nvme_cpu {
    /*
     * CPU ID.
     */
    unsigned int id;

    /*
     * Socket number.
     */
    unsigned int socket;

    /*
     * Core number.
     */
    unsigned int core;

    /*
     * Thread number.
     */
    unsigned int thread;

    /*
     * CPU preset.
     */
    bool present;
};

/*
 * System CPU information.
 */
struct nvme_cpu_info {
    /*
     * Total number of CPUs.
     */
    unsigned int nr_cpus;

    /*
     * CPU information.
     */
    struct nvme_cpu cpu[NVME_CPU_MAX];

    /*
     * Number of sockets.
     */
    unsigned int nr_sockets;

    /*
     * Number of CPU cores.
     */
    unsigned int nr_cores;
};
extern struct nvme_cpu_info cpui;

/*
 * Initialize system CPU information.
 */
extern int nvme_cpu_init();

/*
 * Return the CPU of the caller.
 */
extern struct nvme_cpu *nvme_get_cpu();

/*
 * Return the CPU ID of the caller.
 */
static inline unsigned int nvme_cpu_id()
{
    struct nvme_cpu *cpu = nvme_get_cpu();
    return cpu ? cpu->id : NVME_CPU_ID_ANY;
}

/*
 * Return the Socket ID of the caller.
 */
static inline unsigned int nvme_socket_id()
{
    struct nvme_cpu *cpu = nvme_get_cpu();
    return cpu ? cpu->socket : NVME_SOCKET_ID_ANY;
}

} // namespace nvme

#endif
