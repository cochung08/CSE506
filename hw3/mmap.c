/* Copyright (c) 1998-2011 Erez Zadok
 * Copyright (c) 2009      Shrikar Archak
 * Copyright (c) 2003-2011 Stony Brook University
 * Copyright (c) 2003-2011 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "wrapfs.h"
#include<linux/pagemap.h>
#include<linux/writeback.h>

static int wrapfs_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
        int err;
        struct file *file, *lower_file;
        const struct vm_operations_struct *lower_vm_ops;
        struct vm_area_struct lower_vma;

        memcpy(&lower_vma, vma, sizeof(struct vm_area_struct));
        file = lower_vma.vm_file;
        lower_vm_ops = WRAPFS_F(file)->lower_vm_ops;
        BUG_ON(!lower_vm_ops);

        lower_file = wrapfs_lower_file(file);
#ifdef DEBUG_SUPPORT
	if(debug_support(lower_file->f_dentry->d_sb,"other"))
		UDBG;
#endif
        /*
         * XXX: vm_ops->fault may be called in parallel.  Because we have to
         * resort to temporarily changing the vma->vm_file to point to the
         * lower file, a concurrent invocation of wrapfs_fault could see a
         * different value.  In this workaround, we keep a different copy of
         * the vma structure in our stack, so we never expose a different
         * value of the vma->vm_file called to us, even temporarily.  A
         * better fix would be to change the calling semantics of ->fault to
         * take an explicit file pointer.
         */
        lower_vma.vm_file = lower_file;
        err = lower_vm_ops->fault(&lower_vma, vmf);
#ifdef DEBUG_SUPPORT
	if(debug_support(lower_file->f_dentry->d_sb,"other"))
		UDBGE(err);
#endif
        return err;
}

int wrapfs_read_lower(char *data, loff_t offset, size_t size, struct file *wrapfs_file)
{
        struct file *lower_file;
        mm_segment_t fs_save;
        ssize_t rc;
        mode_t old_f_mode;
        
	lower_file = wrapfs_lower_file(wrapfs_file);
        if(!lower_file)
                return -EIO;

        fs_save = get_fs();
        set_fs(get_ds());

        old_f_mode = lower_file->f_mode;
        lower_file->f_mode |= FMODE_READ;
        
	rc = vfs_read(lower_file,data,size,&offset);
        lower_file->f_mode = old_f_mode;

        set_fs(fs_save);
        return rc;
}

static int wrapfs_read_lower_page_segment(struct page *page_for_wrapfs, pgoff_t pageindex, size_t offset_in_page, size_t size, struct file *wrapfs_file)
{
        char *virt;
        loff_t offset;
        int rc = -1;
#ifdef WRAPFS_CRYPTO
	struct page *dec_page;
	char *dec_buf;
	dec_page = alloc_page(GFP_USER);
	if(dec_page == NULL ){
		printk("can't alloc page for decryption\n");
		goto out;
	}
#endif	
	offset = ((((loff_t)pageindex)<< PAGE_CACHE_SHIFT) + offset_in_page);
        virt = kmap(page_for_wrapfs);
        rc = wrapfs_read_lower(virt,offset,size,wrapfs_file);
        
	if(rc>0)
                rc =0;
#ifdef WRAPFS_CRYPTO
	rc = wrapfs_decrypt_page(dec_page,page_for_wrapfs,WRAPFS_SB(wrapfs_lower_file(wrapfs_file)->f_dentry->d_sb)->key);
	if(rc<0){
		printk("dec error %d\n",rc);
		goto out;
	}
	dec_buf = kmap(dec_page);
	memcpy(virt,dec_buf,size);
	kunmap(dec_page);
out:
	if(dec_page){
		__free_page(dec_page);
	}
#endif
        kunmap(page_for_wrapfs);
        flush_dcache_page(page_for_wrapfs);
        return rc;
}
static int wrapfs_readpage(struct file *file,struct page *page)
{
        int rc =0;
#ifdef DEBUG_SUPPORT
	if(debug_support(wrapfs_lower_file(file)->f_dentry->d_sb,"address_space"))
		UDBG;
#endif
        rc = wrapfs_read_lower_page_segment(page,page->index,0,PAGE_CACHE_SIZE,file);
        if(rc)
                ClearPageUptodate(page);
        else
                SetPageUptodate(page);
        unlock_page(page);
#ifdef DEBUG_SUPPORT
	if(debug_support(wrapfs_lower_file(file)->f_dentry->d_sb,"address_space"))
		UDBGE(rc);
#endif
        return rc;
}
static int wrapfs_writepage(struct page *page, struct writeback_control *wbc){
        int err = -EIO;
        struct inode *inode;
        struct inode *lower_inode;
        struct page *lower_page;
          struct address_space *lower_mapping; /* lower inode mapping */
        gfp_t mask;
#ifdef DEBUG_SUPPORT
	if(debug_support(wrapfs_lower_inode(page->mapping->host)->i_sb,"address_space"))
		UDBG;
#endif
        BUG_ON(!PageUptodate(page));
        inode = page->mapping->host;
        /* if no lower inode, nothing to do */
        if (!inode || !WRAPFS_I(inode) || WRAPFS_I(inode)->lower_inode) {
                err = 0;
                goto out;
        }
        lower_inode = wrapfs_lower_inode(inode);
        lower_mapping = lower_inode->i_mapping;

        mask = mapping_gfp_mask(lower_mapping) & ~(__GFP_FS);
        lower_page = find_or_create_page(lower_mapping, page->index, mask);
        if (!lower_page) {
                err = 0;
                set_page_dirty(page);
                goto out;
        }

        /* copy page data from our upper page to the lower page */
        copy_highpage(lower_page, page);
        flush_dcache_page(lower_page);
        SetPageUptodate(lower_page);
        set_page_dirty(lower_page);

        BUG_ON(!lower_mapping->a_ops->writepage);
        wait_on_page_writeback(lower_page); /* prevent multiple writers */
        clear_page_dirty_for_io(lower_page); /* emulate VFS behavior */
        err = lower_mapping->a_ops->writepage(lower_page, wbc);
        if (err < 0)
                goto out_release;

        if (err == AOP_WRITEPAGE_ACTIVATE) {
                err = 0;
                unlock_page(lower_page);
        }

        /* all is well */

        /* lower mtimes have changed: update ours */
        fsstack_copy_inode_size(inode,lower_inode);
		        fsstack_copy_attr_times(inode,lower_inode);
#ifdef DEBUG_SUPPORT
	if(debug_support(lower_inode->i_sb,"address_space"))
		UDBGE(err);
#endif
    out_release:
        /* b/c find_or_create_page increased refcnt */
        page_cache_release(lower_page);
    out:
        unlock_page(page);

        return err;
}

int wrapfs_write_lower(struct inode *wrapfs_inode, char *data, loff_t offset, size_t size, struct file *file)
{
        struct file *lower_file;
        mm_segment_t fs_save;
        ssize_t rc;
	unsigned int old_flags;
        
	lower_file = wrapfs_lower_file(file);

        if (!lower_file)
                return -EIO;

	old_flags = lower_file->f_flags;

	if(old_flags & O_APPEND)
		lower_file->f_flags = old_flags ^ O_APPEND;

        fs_save = get_fs();
        set_fs(get_ds());
	//printk("from %d copied %d offset %ld",from,copied,offset);
	rc = vfs_write(lower_file, data, size, &offset);

        set_fs(fs_save);
	lower_file->f_flags = old_flags;
        mark_inode_dirty_sync(wrapfs_inode);
        return rc;
}

static int wrapfs_write_lower_page_segment(struct inode *wrapfs_inode,struct page *page_for_lower,size_t offset_in_page, size_t size,struct file *file)
{
        char *virt;
        loff_t offset;
        int rc = -1;
	struct file *lower_file;
#ifdef WRAPFS_CRYPTO
	char *enc_buf;
	struct page *enc_page;
	enc_page = alloc_page(GFP_USER);
	
#endif
        offset = ((((loff_t)page_for_lower->index) << PAGE_CACHE_SHIFT)
                  + offset_in_page);
        
	virt = kmap(page_for_lower);
	
	lower_file=wrapfs_lower_file(file);
#ifdef WRAPFS_CRYPTO
	enc_buf = kmap(enc_page);
	rc = wrapfs_encrypt_page(enc_page,page_for_lower,WRAPFS_SB(wrapfs_lower_file(file)->f_dentry->d_sb)->key);
	if(rc<0){
		goto out;
	}
	rc = wrapfs_write_lower(wrapfs_inode, enc_buf, offset, size, file);
	kunmap(enc_page);
#else
        rc = wrapfs_write_lower(wrapfs_inode, virt, offset, size, file);
#endif
#ifdef WRAPFS_CRYPTO
out:
#endif
        if (rc > 0)
                rc = 0;
        kunmap(page_for_lower);
#ifdef WRAPFS_CRYPTO
	if(enc_page){
		__free_page(enc_page);	
	}
#endif
        return rc;
}

static int wrapfs_write_begin(struct file *file, struct address_space *mapping, loff_t pos, unsigned len, unsigned flags,struct page **pagep, void **fsdata)
{
        pgoff_t index = pos >> PAGE_CACHE_SHIFT;
        struct page *page;
        loff_t prev_page_end_size;
        int rc = 0;
#ifdef DEBUG_SUPPORT
	if(debug_support(wrapfs_lower_file(file)->f_dentry->d_sb,"address_space"))
		UDBG;
#endif
        page = grab_cache_page_write_begin(mapping, index, flags);
        if (!page)
            return -ENOMEM;
        *pagep = page;

        prev_page_end_size = ((loff_t)index << PAGE_CACHE_SHIFT);
        if (!PageUptodate(page)) {

            rc = wrapfs_read_lower_page_segment( page, index, 0, PAGE_CACHE_SIZE, file);//mapping->host);
            if (rc) {
			                printk(KERN_ERR "%s: Error attemping to read "
                                        "lower page segment; rc = [%d]\n",
                                        __func__, rc);
                ClearPageUptodate(page);
                                goto out;
            } else
                SetPageUptodate(page);
        }

        /* Writing to a new page, and creating a small hole from start
         * of page?  Zero it out. */
        if ((i_size_read(mapping->host) == prev_page_end_size)
            && (pos != 0))
                zero_user(page, 0, PAGE_CACHE_SIZE);
out:
        if (unlikely(rc)) {
                unlock_page(page);
                page_cache_release(page);
                *pagep = NULL;
        }
#ifdef DEBUG_SUPPORT
	if(debug_support(wrapfs_lower_file(file)->f_dentry->d_sb,"address_space"))
		UDBGE(rc);
#endif
        return rc;
}

static int wrapfs_write_end(struct file *file,struct address_space *mapping,loff_t pos, unsigned len, unsigned copied, struct page *page, void *fsdata)
{
        //pgoff_t index = pos >> PAGE_CACHE_SHIFT;
	unsigned from = pos & (PAGE_CACHE_SIZE - 1);
        unsigned to = from + copied;
        struct inode *wrapfs_inode = mapping->host;
        int rc;
        int need_unlock_page = 1;
#ifdef DEBUG_SUPPORT
	if(debug_support(wrapfs_lower_file(file)->f_dentry->d_sb,"address_space"))
		UDBG;
#endif

        rc = wrapfs_write_lower_page_segment(wrapfs_inode ,page ,0 ,to ,file);

        if (!rc) {
                rc = copied;
                fsstack_copy_inode_size(wrapfs_inode,wrapfs_lower_inode(wrapfs_inode));
        }
	else
        	goto out;
out:
        if (need_unlock_page)
                unlock_page(page);
        page_cache_release(page);
#ifdef DEBUG_SUPPORT
	if(debug_support(wrapfs_lower_file(file)->f_dentry->d_sb,"address_space"))
		UDBGE(rc);
#endif
        return rc;
}

/*
 * XXX: the default address_space_ops for wrapfs is empty.  We cannot set
 * our inode->i_mapping->a_ops to NULL because too many code paths expect
 * the a_ops vector to be non-NULL.
 */
 const struct address_space_operations wrapfs_aops = {
        /* empty on purpose */
        .readpage    = wrapfs_readpage,
        .writepage   = wrapfs_writepage,
        .write_begin = wrapfs_write_begin,
        .write_end   = wrapfs_write_end,
};

const struct vm_operations_struct wrapfs_vm_ops = {
        .fault          = wrapfs_fault,
};
