// libnvme: https://github.com/hgst/libnvme
// Copyright (c) 2019-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <nvme/nvme.h>

#ifndef LIBNVME_UNDER_DEVELOPMENT

#include <sync/lsync.h>
#include <nvme/nvme_internal.h>

/*
 * List of open controllers
 */
LIST_HEAD(, nvme_ctrlr)	ctrlr_head = LIST_HEAD_INITIALIZER(ctrlr_head);

/*
 * Search for an open controller.
 */
static LCCriticalSection ctrlr_cs;
static struct nvme_ctrlr *nvme_ctrlr_get(struct nvme_ctrlr *ctrlr, bool remove)
{
    struct nvme_ctrlr *c;

    LOCK(ctrlr_cs);
    LIST_FOREACH(c, &ctrlr_head, link) {
        if (c == ctrlr) {
            if (remove)
                LIST_REMOVE(c, link);
            return ctrlr;
        }
    }
    return nullptr;
}

/*
 * Probe a pci device identified by its name.
 * Name should be in the form: [0000:]00:00.0
 * Return NULL if failed
 */
static struct pci_device *nvme_pci_ctrlr_probe(const char *slot_name)
{
    char *domain = nullptr, *bus = nullptr, *dev = nullptr, *func = nullptr, *end = nullptr;
    std::string pciid(slot_name);
    struct pci_slot_match slot;
    struct pci_device *pci_dev = nullptr;
    ::memset(&slot, 0, sizeof(struct pci_slot_match));

    func = ::strrchr(pciid.c_str(), '.');
    if (func) {
        *func = '\0';
        func++;
    }

    dev = ::strrchr(pciid.c_str(), ':');
    if (dev) {
        *dev = '\0';
        dev++;
    }

    bus = ::strrchr(pciid.c_str(), ':');
    if (! bus) {
        domain = nullptr;
        bus = pciid;
    } else {
        domain = pciid;
        *bus = '\0';
        bus++;
    }

    if (!bus || !dev || !func) {
        nvme_err("Malformed PCI device slot name %s\n", slot_name);
        return pci_dev;
    }

    if (domain) {
        slot.domain = (uint32_t)::strtoul(domain, &end, 16);
        if ((end && *end) || (slot.domain > 0xffff)) {
            nvme_err("Invalid domain number: 0x%X\n", slot.domain);
            return nullptr;
        }
    } else {
        slot.domain = PCI_MATCH_ANY;
    }

    slot.bus = (uint32_t)::strtoul(bus, &end, 16);
    if ((end && *end) || (slot.bus > 0xff)) {
        nvme_err("Invalid bus number: 0x%X\n", slot.bus);
        return nullptr;
    }

    slot.dev = ::strtoul(dev, &end, 16);
    if ((end && *end) || (slot.dev > 0x1f)) {
        nvme_err("Invalid device number: 0x%X\n", slot.dev);
        return nullptr;
    }

    slot.func = ::strtoul(func, &end, 16);
    if ((end && *end) || (slot.func > 7)) {
        nvme_err("Invalid function number: 0x%X\n", slot.func);
        return nullptr;
    }

    nvme_debug("PCI URL: domain 0x%X, bus 0x%X, dev 0x%X, func 0x%X\n",
               slot.domain, slot.bus, slot.dev, slot.func);

    pci_dev = nvme_pci_device_probe(&slot);
    if (pci_dev) {
        slot.domain = pci_dev->domain;
        if (slot.domain == PCI_MATCH_ANY)
            slot.domain = 0;
            nvme_info("Found NVMe controller %04x:%02x:%02x.%1u\n",
                      slot.domain,
                      slot.bus,
                      slot.dev,
                      slot.func);
    }

    return pci_dev;
}

/*
 * Open an NVMe controller.
 */
struct nvme_ctrlr *nvme::nvme_ctrlr_open(const char *url, struct nvme_ctrlr_opts *opts)
{
    struct pci_device *pdev;
    struct nvme_ctrlr *ctrlr;
    char *slot;

    /* Check url */
    if (::strncmp(url, "pci://", 6) != 0) {
        nvme_err("Invalid URL %s\n", url);
        return nullptr;
    }

    /* Probe PCI device */
    slot = (char *)url + 6;
    pdev = nvme_pci_ctrlr_probe(slot);
    if (! pdev) {
        nvme_err("Device %s not found\n", url);
        return nullptr;
    }

    LOCK(ctrlr_cs);

    /* Verify that this controller is not already open */
    LIST_FOREACH(ctrlr, &ctrlr_head, link) {
        if (nvme_pci_dev_cmp(ctrlr->pci_dev, pdev) == 0) {
            nvme_err("Controller already open\n");
            return nullptr;
        }
    }

    /* Attach the device */
    ctrlr = nvme_ctrlr_attach(pdev, opts);
    if (! ctrlr) {
        nvme_err("Attach %s failed\n", url);
        return nullptr;
    }

    /* Add controller to the list */
    LIST_INSERT_HEAD(&ctrlr_head, ctrlr, link);

    return ctrlr;
}

/*
 * Close an open controller.
 */
int nvme::nvme_ctrlr_close(struct nvme_ctrlr *ctrlr)
{
    /*
     * Verify that this controller is open.
     * If it is, remove it from the list.
     */
    ctrlr = nvme_ctrlr_get(ctrlr, true);
    if (! ctrlr) {
        nvme_err("Invalid controller\n");
        return -EINVAL;
    }

    nvme_ctrlr_detach(ctrlr);
    return 0;
}

/*
 * Get controller information.
 */
int nvme::nvme_ctrlr_stat(struct nvme_ctrlr *ctrlr, struct nvme_ctrlr_stat *cstat)
{
    struct pci_device *pdev = ctrlr->pci_dev;
    unsigned int i;

    /* Verify that this controller is open */
    ctrlr = nvme_ctrlr_get(ctrlr, false);
    if (! ctrlr) {
        nvme_err("Invalid controller\n");
        return -EINVAL;
    }

    LOCK(ctrlr_cs);
    ::memset(cstat, 0, sizeof(struct nvme_ctrlr_stat));

    /* Controller serial and model number */
    ::strncpy(cstat->sn, (char *)ctrlr->cdata.sn, NVME_SERIAL_NUMBER_LENGTH - 1);
    ::strncpy(cstat->mn, (char *)ctrlr->cdata.mn, NVME_MODEL_NUMBER_LENGTH - 1);

    /* Remove heading and trailling spaces */
    nvme_str_trim(cstat->sn);
    nvme_str_trim(cstat->mn);

    /* PCI device info */
    cstat->vendor_id = pdev->vendor_id;
    cstat->device_id = pdev->device_id;
    cstat->subvendor_id = pdev->subvendor_id;
    cstat->subdevice_id = pdev->subdevice_id;
    cstat->device_class = pdev->device_class;
    cstat->revision = pdev->revision;
    cstat->domain = pdev->domain;
    cstat->bus = pdev->bus;
    cstat->dev = pdev->dev;
    cstat->func = pdev->func;

    /* Maximum transfer size */
    cstat->max_xfer_size = ctrlr->max_xfer_size;

    ::memcpy(&cstat->features, &ctrlr->feature_supported, sizeof(ctrlr->feature_supported));
    ::memcpy(&cstat->log_pages, &ctrlr->log_page_supported, sizeof(ctrlr->log_page_supported));

    cstat->nr_ns = ctrlr->nr_ns;
    for (i = 0; i < ctrlr->nr_ns; i++) {
        cstat->ns_ids[i] = i + 1;
    }

    /* Maximum io qpair possible */
    cstat->max_io_qpairs = ctrlr->max_io_queues;

    /* Constructed io qpairs */
    cstat->io_qpairs = ctrlr->io_queues;

    /* Enabled io qpairs */
    cstat->enabled_io_qpairs = ctrlr->enabled_io_qpairs;

    /* Max queue depth */
    cstat->max_qd = ctrlr->io_qpairs_max_entries;

    return 0;
}

/*
 * Get controller data
 */
int nvme::nvme_ctrlr_data(struct nvme_ctrlr *ctrlr, struct nvme_ctrlr_data *cdata, struct nvme_register_data *rdata)
{
    union nvme_cap_register	cap;

    /* Verify that this controller is open */
    ctrlr = nvme_ctrlr_get(ctrlr, false);
    if (! ctrlr) {
        nvme_err("Invalid controller\n");
        return -EINVAL;
    }

    LOCK(ctrlr_cs);

    /* Controller data */
    if (cdata)
        ::memcpy(cdata, &ctrlr->cdata, sizeof(struct nvme_ctrlr_data));

    /* Read capabilities register */
    if (rdata) {
        cap.raw = nvme_reg_mmio_read_8(ctrlr, cap.raw);
        rdata->mqes = cap.bits.mqes;
    }

    return 0;
}

/*
 * Get qpair information
 */
int nvme::nvme_qpair_stat(struct nvme_qpair *qpair, struct nvme_qpair_stat *qpstat)
{
    struct nvme_ctrlr *ctrlr = qpair->ctrlr;

    /* Verify that this controller is open */
    ctrlr = nvme_ctrlr_get(ctrlr, false);
    if (!ctrlr) {
        nvme_err("Invalid controller\n");
        return -EINVAL;
    }

    LOCK(ctrlr_cs);

    qpstat->id = qpair->id;
    qpstat->qd = qpair->entries;
    qpstat->enabled = qpair->enabled;
    qpstat->qprio = qpair->qprio;

    return 0;
}

#endif // LIBNVME_UNDER_DEVELOPMENT
