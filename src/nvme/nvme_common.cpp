// libnvme: https://github.com/hgst/libnvme
// Copyright (c) 2019-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <nvme/nvme.h>

#ifndef LIBNVME_UNDER_DEVELOPMENT

#include <nvme/nvme_pci.h>
#include <nvme/nvme_common.h>
#include <nvme/nvme_mem.h>
#include <nvme/nvme_cpu.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef WIN32
// under development
#else
#if defined(NVME_ARCH_X86)
# include <sys/io.h>
#endif
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <execinfo.h>
#endif

/*
 * Trim whitespace from a string in place.
 */
void nvme::nvme_str_trim(char *s)
{
    char *p, *q;

    /* Remove header */
    p = s;
    while (*p != '\0' && isspace(*p))
        p++;

    /* Remove tailer */
    q = p + strlen(p);
    while (q - 1 >= p && isspace(*(q - 1))) {
        q--;
        *q = '\0';
    }

    /* if remove header, move */
    if (p != s) {
        q = s;
        while (*p != '\0')
            *q++ = *p++;
        *q = '\0';
    }
}

/*
 * Split string into tokens
 */
int nvme::nvme_str_split(char *string, int stringlen, char **tokens, int maxtokens, char delim)
{
    int i, tok = 0;
    int tokstart = 1;

    if (string == nullptr || tokens == nullptr) {
        errno = EINVAL;
        return -1;
    }

    for (i = 0; i < stringlen; i++) {
        if (string[i] == '\0' || tok >= maxtokens)
            break;
        if (tokstart) {
            tokstart = 0;
            tokens[tok++] = &string[i];
        }
        if (string[i] == delim) {
            string[i] = '\0';
            tokstart = 1;
        }
    }

    return tok;
}

/*
 * Parse a sysfs (or other) file containing one integer value
 */
int nvme::nvme_parse_sysfs_value(const char *filename, unsigned long *val)
{
    FILE *f;
    char buf[BUFSIZ];
    char *end = nullptr;

    if ((f = ::fopen(filename, "r")) == nullptr) {
        nvme_err("%s(): cannot open sysfs value %s\n",
             __func__, filename);
        return -1;
    }

    if (::fgets(buf, sizeof(buf), f) == nullptr) {
        nvme_err("%s(): cannot read sysfs value %s\n",
             __func__, filename);
        fclose(f);
        return -1;
    }
    *val = ::strtoul(buf, &end, 0);
    if ((buf[0] == '\0') || (end == nullptr) || (*end != '\n')) {
        nvme_err("%s(): cannot parse sysfs value %s\n",
             __func__, filename);
        ::fclose(f);
        return -1;
    }
    ::fclose(f);
    return 0;
}

/*
 * Get a block device block size in Bytes.
 */
ssize_t nvme::nvme_dev_get_blocklen(int fd)
{
    uint32_t blocklen = 0;
#ifdef WIN32
    // under development
#else
    if (::ioctl(fd, BLKSSZGET, &blocklen) < 0) {
        nvme_err("iioctl BLKSSZGET failed %d (%s)\n",
             errno,
             strerror(errno));
        return -1;
    }
#endif
    return blocklen;
}

/*
 * Get a file size in Bytes.
 */
uint64_t nvme::nvme_file_get_size(int fd)
{
    struct stat st;
    uint64_t size;

    if (fstat(fd, &st) != 0)
        return 0;

    if (S_ISLNK(st.st_mode))
        return 0;

    if (S_ISBLK(st.st_mode) || S_ISCHR(st.st_mode)) {
        if (ioctl(fd, BLKGETSIZE64, &size) == 0)
            return size;
        else
            return 0;
    }

    if (S_ISREG(st.st_mode))
        return st.st_size;

    /* Not REG, CHR or BLK */
    return 0;
}

/*
 * Dump the stack of the calling core.
 */
static void nvme::nvme_dump_stack(void)
{
    constexpr size_t BACKTRACE_SIZE = 256;
    void *func[BACKTRACE_SIZE];
    int size = backtrace(func, BACKTRACE_SIZE);

    char **symb = backtrace_symbols(func, size);
    if (symb == nullptr)
        return;

    while (size > 0) {
        nvme_crit("%d: [%s]\n", size, symb[size - 1]);
        size--;
    }
    ::free(symb);
}

/**
 * Library initialization: must be run first by any application
 * before calling any libnvme API.
 */
int nvme::nvme_lib_init(enum nvme_log_level level, enum nvme_log_facility facility, const char *path)
{
    /* Set log level and facility first (using LogPrintf) */
    (void)level; (void)facility; (void)path;

    /* Gather CPU information */
    int ret = nvme_cpu_init();
    if (ret != 0) {
        nvme_crit("Failed to gather CPU information\n");
        return ret;
    }

    /* PCI subsystem initialization (libpciaccess) */
    ret = nvme_pci_init();
    if (ret != 0) {
        nvme_crit("PCI subsystem initialization failed\n");
        return ret;
    }

    /* Initialize memory management */
    ret = nvme_mem_init();
    if (ret != 0)
        nvme_crit("Memory management initialization failed\n");

    return ret;
}

/*
 * Close all open controllers on exit.
 */
void nvme::nvme_ctrlr_cleanup(void)
{
    struct nvme_ctrlr *ctrlr;
    while ((ctrlr = LIST_FIRST(&ctrlr_head))) {
        LIST_REMOVE(ctrlr, link);
        nvme_ctrlr_detach(ctrlr);
    }
}

/*
 * Will be executed automatically last on termination of the user application.
 */
class nvme_lib_exit {
public:
    nvme_lib_exit() {}
    ~nvme_lib_exit() {
        nvme::nvme_ctrlr_cleanup();
        nvme::nvme_mem_cleanup();
    }
};
nvme_lib_exit nvme_obj;

#endif // LIBNVME_UNDER_DEVELOPMENT
