// libnvme: https://github.com/hgst/libnvme
// Copyright (c) 2019-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <nvme/nvme.h>

#ifndef LIBNVME_UNDER_DEVELOPMENT

#include <nvme/nvme_common.h>
#include <nvme/nvme_pci.h>
#include <cstring>

/*
 * Initialize PCI subsystem.
 */
int nvme::nvme_pci_init(void)
{
    int ret = pci_system_init();
    if (ret) {
        nvme::nvme_err("pci_system_init failed %d\n", ret);
        return ret;
    }
    return 0;
}

/*
 * Check if a device has a driver binded.
 */
static int nvme::nvme_pci_device_has_kernel_driver(struct pci_device *dev)
{
#ifdef WIN32
    // under development
#else
    char linkname[NVME_PCI_PATH_MAX];
    char driver[NVME_PCI_PATH_MAX];
    ssize_t driver_len;

    ::snprintf(linkname, sizeof(linkname),
         "/sys/bus/pci/devices/%04x:%02x:%02x.%1u/driver",
         dev->domain, dev->bus, dev->dev, dev->func);

    std::memset(driver, 0, sizeof(driver));
    driver_len = ::readlink(linkname, driver, sizeof(driver));
    if ((driver_len <= 0) || (driver_len >= NVME_PCI_PATH_MAX))
        return 0;

    nvme::nvme_log("NVME controller %04x:%02x:%02x.%1u binded to kernel driver %s\n",
         dev->domain, dev->bus, dev->dev, dev->func,
         basename(driver));
#endif

    return 1;
}

/*
 * Search a PCI device and grab it if found.
 */
struct pci_device *nvme::nvme_pci_device_probe(const struct pci_slot_match *slot)
{
    int ret = -ENODEV;
    struct pci_device_iterator *pci_dev_iter = pci_slot_match_iterator_create(slot);
    struct pci_device *pci_dev = pci_device_next(pci_dev_iter);
    if (pci_dev)
        ret = pci_device_probe(pci_dev);
    pci_iterator_destroy(pci_dev_iter);

    if (ret != 0)
        return nullptr;

    if (pci_dev->device_class != NVME_PCI_CLASS) {
        nvme::nvme_err("Device PCI class is not NVME\n");
        pci_dev = nullptr;
    }

    if (nvme_pci_device_has_kernel_driver(pci_dev))
        return nullptr;

    return pci_dev;
}

/*
 * Get a device serial number.
 */
int nvme::nvme_pci_device_get_serial_number(struct pci_device *dev, char *sn, size_t len)
{
    uint32_t header = 0;
    uint32_t i, buf[2];
    if (len < 17)
        return -1;

    int ret = nvme_pcicfg_read32(dev, &header, NVME_PCI_CFG_SIZE);
    if (ret || !header)
        return -1;

    uint32_t pos = NVME_PCI_CFG_SIZE;
    for (;;) {
        if ((header & 0x0000ffff) == NVME_PCI_EXT_CAP_ID_SN && pos != 0) {
            for (i = 0; i < 2; i++) {
                /* skip the header */
                pos += 4;
                ret = nvme_pcicfg_read32(dev, &buf[i], pos);
                if (ret)
                    return -1;
            }
            ::sprintf(sn, "%08x%08x", buf[1], buf[0]);
            return 0;
        }
        pos = (header >> 20) & 0xffc;

        /* 0 if no other items exist */
        if (pos < NVME_PCI_CFG_SIZE)
            return -1;

        ret = nvme_pcicfg_read32(dev, &header, pos);
        if (ret)
            return -1;
    }
    return -1;
}

/*
 * Reset a PCI device.
 */
int nvme::nvme_pci_device_reset(struct pci_device *dev)
{
#ifdef WIN32
    // under development
#else
    char filename[NVME_PCI_PATH_MAX];
    char *buf = "1";

    ::snprintf(filename, sizeof(filename),
         "/sys/bus/pci/devices/%04x:%02x:%02x.%1u/reset",
         dev->domain, dev->bus, dev->dev, dev->func);

    nvme::nvme_debug("Resetting PCI device (%s)\n", filename);
    FILE *fd = ::fopen(filename, "w");
    if (! fd)
        return -1;

    int ret = 0;
    if (::fwrite(buf, strlen(buf), 1, fd) != ::strlen(buf))
        ret = -1;
    else
        ret = 0;

    ::fclose(fd);
    return ret;
#endif
}

#endif // LIBNVME_UNDER_DEVELOPMENT
