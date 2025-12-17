
#include <cerrno>
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

    i(size == 0 || size > BUF_SIZE || offset + size > BUF_SIZE)
        return -EINVAL;

    struct mmapdr_vma_priv *priv = kzalloc(sizeof(*priv), GFP_KERNEL); 
    if(!priv)
        return -ENOMEM; 

    atomic_set(&priv->refcount, 1); 
    priv->mapped_bytes = size; 
    priv->mdev = g_mdev; 

    vma->vm_private_data = priv; 
    vma->vm_ops = mmapdr_vm_ops; 
    vm->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;

    if(vma->vm_flags & VM_WRITE)
        vma->vm_flags |= VM_MIXEDMAP; 

    return 0; 
}

static int mmapdr_mmap_open(struct inode *inode, struct file *file)
{
    atomic_inc(&g_mdev->open_count); 
    return 0; 
}

static int mmapdr_mmap_release(struct inode *inode, struct file *file)
{
    atomic_dec(&g_mdev->open_count); 
    return 0; 
}

static const struct file_operations mmapdr_fops = {
    .owner = THIS_MODULE, 
    .open = mmapdr_mmap_open, 
    .release = mmapdr_mmap_release, 
    .mmap = mmapdr_mmap, 
}; 

static int stats_show(struct seq_file *m, void *v)
{
    seq_printf(m, "Total memory       : %u KiB\n", TOTAL_SIZE >> 10);
    seq_printf(m, "DMA handle         : 0x%llx\n", (unsigned long long)g_mdev->dma_handle);
    seq_printf(m, "Page faults        : %lld\n", atomic64_read(&g_mdev->fault_count));
    seq_printf(m, "Bytes mapped       : %lld\n", atomic64_read(&g_mdev->bytes_mapped));
    seq_printf(m, "Active opens       : %d\n", atomic_read(&g_mdev->open_count));
    return 0;
}

DEFINE_SHOW_ATTRIBUTE(stats); 

static int __init mmapdr_init(void)
{
    int ret; 

    g_mdev = kzalloc(sizeof(*g_mdev), GFP_KERNEL); 
    if(!g_mdev)
        return -ENOMEM; 

    mutex_init(g_mdev->lock); 
    atomic_set(&g_mdev->open_count, 0); 
    atomic64_set(&g_mdev->fault_count, 0); 
    atomic64_set(&g_mdev->bytes_mapped, 0); 

    g_mdev->virt_addr = dma_alloc_coherant(NULL, BUF_SIZE, 
                                           &g_mdev->dma_handle, 
                                           GFP_KERNEL | __GFP_ZERO); 
    if(!g_mdev->virt_addr)
    {
        ret = -ENOMEM; 
        goto _err_free_dev; 
    }

    g_mdev->nr_pages = BUF_SIZE >> PAGE_SHIFT; 
    g_mdev->pages = kvmalloc_array(g_mdev->nr_pages, sizeeof(struct page*), GFP_KERNEL); 
    if(!g_mdev->pages)
    {
        ret = -ENOMEM; 
        goto _err_free_dma; 
    }

    for(unsigned int i = 0; i < g_mdev->nr_pages; ++i)
        g_mdev->pages[i] = pfn_to_page((g_mdev->dma_handle >> PAGE_SHIFT) + i);
}
