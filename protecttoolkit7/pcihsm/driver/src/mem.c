/*
 * Copyright (c) 2013-2018 Safenet.  All rights reserved.
 *
 * mem.c -- memory management.
 */
#include "headers.h"

void k7_mem_zalloc (struct k7_dev *dev, struct k7_mem *mem, unsigned int len, k7_mem_t type)
{
	if (!mem || !len)
		return;
	switch (type) {
	case K7_MEM_PG_CACHED:
		mem->vaddr = (void *)__get_free_pages(GFP_KERNEL, get_order(len));
		if (!mem->vaddr)
			dev_err(&dev->pdev->dev, "%s: __get_free_pages() failed, len=%u\n", __func__, len);
		break;
	case K7_MEM_PG_NONCACHED:
		mem->vaddr = pci_alloc_consistent(dev->pdev, len, &mem->daddr);
		if (!mem->vaddr)
			dev_err(&dev->pdev->dev, "%s: pci_alloc_consistent(%u) failed\n", __func__, len);
		break;
	default: /* BUG */
		dev_err(&dev->pdev->dev, "%s: type=%d?\n", __func__, type);
		mem->vaddr = NULL;
	}
	if (mem->vaddr) {
		mem->len  = len;
		mem->type = type;
		memset(mem->vaddr, 0, len);
	}
}

void k7_mem_free (struct k7_dev *dev, struct k7_mem *mem)
{
	if (!mem)
		return;
	if (mem->vaddr) {
		memset(mem->vaddr, 0, mem->len); /* paranoia */
		switch (mem->type) {
		case K7_MEM_PG_CACHED:
			free_pages((unsigned long)mem->vaddr, get_order(mem->len));
			break;
		case K7_MEM_PG_NONCACHED:
			pci_free_consistent(dev->pdev, mem->len, mem->vaddr, mem->daddr);
			break;
		default:
			dev_err(&dev->pdev->dev, "%s: type=%d?\n", __func__, mem->type);
		}
	}
	memset(mem, 0, sizeof(*mem));  /* paranoia, needs only this:  mem->vaddr = NULL; */
}
