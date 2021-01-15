// libnvme: https://github.com/hgst/libnvme
// Copyright (c) 2019-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <nvme/nvme.h>

#ifndef LIBNVME_UNDER_DEVELOPMENT

#include <nvme/nvme_common.h>
#include <nvme/nvme_cpu.h>
#include <dirent.h>

struct nvme::nvme_cpu_info cpui;

/*
 * Check if a cpu is present by the presence
 * of the cpu information for it.
 */
static bool nvme_cpu_present(unsigned int cpu_id)
{
    char path[128];
#ifdef WIN32
    // under development
#else
    ::snprintf(path, sizeof(path),
         "/sys/devices/system/cpu/cpu%u/topology/core_id",
         cpu_id);
#endif
    return ::access(path, F_OK) == 0;
}

/*
 * Count the number of sockets.
 */
static unsigned int nvme_socket_count()
{
    char path[128];
    unsigned int n = 0;
    for (unsigned int socket = 0; socket < NVME_SOCKET_MAX; socket++) {
#ifdef WIN32
    // under development
#else
        ::snprintf(path, sizeof(path),
             "/sys/devices/system/node/node%u",
             socket);
#endif
        if (! access(path, F_OK) == 0)
            break;
        n++;
    }

    return n;
}

/*
 * Get the socket ID (NUMA node) of a CPU.
 */
static unsigned int nvme_cpu_socket_id(unsigned int cpu_id)
{
    char path[128];
    unsigned long id;
#ifdef WIN32
    // under development
#else
    ::snprintf(path, sizeof(path),
        "/sys/devices/system/cpu/cpu%u/topology/physical_package_id",
        cpu_id);
#endif
    if (nvme::nvme_parse_sysfs_value(path, &id) != 0) {
        nvme_err("Parse %s failed\n", path);
        return 0;
    }

    return id;
}

/*
 * Get the core ID of a CPU.
 */
static unsigned int nvme_cpu_core_id(unsigned int cpu_id)
{
    char path[128];
    unsigned long id;
#ifdef WIN32
    // under development
#else
    ::snprintf(path, sizeof(path),
         "/sys/devices/system/cpu/cpu%u/topology/core_id",
         cpu_id);
#endif
    if (nvme::nvme_parse_sysfs_value(path, &id) != 0) {
        nvme_err("Parse %s failed\n", path);
        return 0;
    }

    return id;
}

/*
 * Get the thread ID of a CPU.
 */
static unsigned int nvme_cpu_thread_id(unsigned int cpu_id)
{
    struct nvme_cpu *cpu = &cpui.cpu[cpu_id];
    unsigned int thid = 0;
    for (unsigned int i = 0; i < cpui.nr_cpus; i++) {
        if (cpui.cpu[i].socket == cpu->socket &&
            cpui.cpu[i].core == cpu->core)
            thid++;
    }

    return thid;
}

/*
 * Parse /sys/devices/system/cpu to initialize CPU information.
 */
int nvme::nvme_cpu_init()
{
    struct nvme_cpu *cpu;
    std::memset(&cpui, 0, sizeof(struct nvme_cpu_info));
    cpui.nr_sockets = nvme_socket_count();
    for (unsigned int i = 0; i < NVME_CPU_MAX; i++) {

        cpu = &cpui.cpu[i];
        cpu->id = -1;

        /* init cpuset for per lcore config */
        cpu->present = nvme_cpu_present(i);
        if (! cpu->present) {
            continue;
        }

        cpu->id = i;
        cpu->socket = nvme_cpu_socket_id(i);
        cpu->core = nvme_cpu_core_id(i);
        cpu->thread = nvme_cpu_thread_id(i);

        cpui.nr_cpus++;
        if (cpu->thread == 0)
            cpui.nr_cores++;

        nvme_debug("CPU %02u: socket %02u, core %02u, thread %u\n",
               cpu->id, cpu->socket, cpu->core, cpu->thread);

    }

    nvme_info("Detected %u CPUs: %u sockets, %u cores, %u threads\n",
          cpui.nr_cpus,
          cpui.nr_sockets,
          cpui.nr_cores,
          cpui.nr_cpus);

    return 0;
}

/*
 * Get caller current CPU.
 */
struct nvme_cpu *nvme::nvme_get_cpu()
{
    /*
     * Get current CPU. If trhe caller thread is not pinned down
     * to a particular CPU using sched_setaffinity, this result
     * may be only temporary.
     */
    int cpu = sched_getcpu();
    if (cpu < 0) {
        nvme_err("sched_getcpu failed %d (%s)\n",
             errno, strerror(errno));
        return nullptr;
    }

    if (cpu >= (int)cpui.nr_cpus) {
        nvme_err("Invalid CPU number %d (Max %u)\n",
             cpu, cpui.nr_cpus - 1);
        return nullptr;
    }

    return &cpui.cpu[cpu];
}

#endif // LIBNVME_UNDER_DEVELOPMENT
