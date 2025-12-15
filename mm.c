
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/dma-mapping.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/mutex.h>
#include <linux/vmalloc.h>

#include "mm.h"

static struct mmapdr_device *g_mdev; 

static void mmapdr_vma_open(struct vm_area_struct *vma)
{
    struct mmapdr_vma_priv *priv = vma->vm_private_data; 
    if(priv)
        atomic_inc(&priv->refcount); 
}

static void mmapdr_vma_close(struct vm_area_struct *vma) 
{
    struct mmapdr_vma_priv *priv = vma->vm_private_data;
    if(!priv)
        return; 

    if(atomic_dec_test(&priv->refcount)){
        kfree(priv); 
    }
    vma->vm_private_data = NULL; 
}

static vm_fault_t mmapdr_map_fault(struct vm_fault *vmf)
{
    struct vm_area_struct *vma = vmf->vma; 
    struct mmapdr_vma_priv *priv = vma->vm_private_data; 
    unsigned long offset = vmf->pgoff << PAGE_SHIFT; 
    unsigned int idx;

    if(!priv || offset >= BUF_SIZE)
        return VM_FAULT_SIGBUS ; 

    idx = offset >> PAGE_SHIFT; 
    if(idx >= g_mdev->nr_pages)
        return VM_FAULT_SIGBUS; 

    page = g_mdev->pages[idx]; 
    get_page(page); 

    if(vmf_insert_page(vma, vmf->address, page)) 
    {
        put_page(page); 
        return VM_FAULT_SIGBUS; 
    }

    atomic64_inc(&g_mdev->fault_count); 
    atomic64_add(PAGE_SIZE, &g_mdev->bytes_mapped); 

    return VM_FAULT_NOPAGE; 
}

static const vm_operations_struct mmapdr_vm_ops = {
    .open = mmapdr_vma_open, 
    .close = mmapdr_vma_close, 
    .fault = mmapdr_map_fault, 
}; 

static int mmapdr_mmap(struct file *filep, struct vm_area_struct *vma)
{
    unsigned long size = vma->vm_end - vma->vm_start;
    unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;

    i(size == 0 || size > BUF_SIZE || offset +
}
