/*
 * Copyright (c) 1998-2011 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2011 Stony Brook University
 * Copyright (c) 2003-2011 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "wrapfs.h"
#ifdef WRAPFS_CRYPTO
static int no_key_func(char *key)
{
	int t;
	for(t=0;t<strlen(key);t++)
	{
		if(key[t]!='0')
			return 0;
	}
	if(t == strlen(key))
		return 1;
	return 1;
}
#endif
static ssize_t wrapfs_read(struct file *file, char __user *buf,
			   size_t count, loff_t *ppos)
{
	int err;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;
#ifdef WRAPFS_CRYPTO
	char nokey[KEY_LENGTH]={0,};
#endif
	lower_file = wrapfs_lower_file(file);
#ifdef DEBUG_SUPPORT
	if(debug_support(lower_file->f_dentry->d_sb,"file"))
		UDBG;
#endif
	if(WRAPFS_SB(lower_file->f_path.dentry->d_sb)->mount_options.mmap == 1)
	{
#ifdef WRAPFS_CRYPTO		
		if(!strcmp(WRAPFS_SB(lower_file->f_dentry->d_sb)->key,nokey) || no_key_func(WRAPFS_SB(lower_file->f_dentry->d_sb)->key))
		{
			printk("No Key entered. Encrypt operations cannot be done\n");
			return -ENOKEY;
		}
#endif
		err = do_sync_read(file, buf, count, ppos);
	}
	else
		err = vfs_read(lower_file, buf, count, ppos);
	/* update our inode atime upon a successful lower read */
	if (err >= 0)
		fsstack_copy_attr_atime(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);
#ifdef DEBUG_SUPPORT
	if(debug_support(lower_file->f_dentry->d_sb,"file"))
		UDBGE(err);
#endif
	return err;
}

static ssize_t wrapfs_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	int err = 0;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;
	loff_t pos,lpos;
#ifdef WRAPFS_CRYPTO
	char nokey[KEY_LENGTH] = {0,};
#endif
	lower_file = wrapfs_lower_file(file);
#ifdef DEBUG_SUPPORT
	if(debug_support(lower_file->f_dentry->d_sb,"file"))
		UDBG;
#endif
	lpos = lower_file->f_pos;	
	pos = file->f_pos;
	if(WRAPFS_SB(lower_file->f_path.dentry->d_sb)->mount_options.mmap == 1)
        {
#ifdef WRAPFS_CRYPTO
		if(!strcmp(WRAPFS_SB(lower_file->f_dentry->d_sb)->key,nokey)|| no_key_func(WRAPFS_SB(lower_file->f_dentry->d_sb)->key))
		{
			printk("No key is entered. Encryption operations cannot be done\n");
			return -ENOKEY;
		}
#endif
                err = do_sync_write(file, buf, count, ppos);
        }
        else
        {
                err = vfs_write(lower_file, buf, count, ppos);
        }

	/* update our inode times+sizes upon a successful lower write */
	if (err >= 0) {
		fsstack_copy_inode_size(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);
		fsstack_copy_attr_times(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);
	}
	//dump_stack();
#ifdef DEBUG_SUPPORT
	if(debug_support(lower_file->f_dentry->d_sb,"file"))
		UDBGE(err);
#endif
	return err;
}

static int wrapfs_readdir(struct file *file, void *dirent, filldir_t filldir)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = wrapfs_lower_file(file);
#ifdef DEBUG_SUPPORT
	if(debug_support(lower_file->f_dentry->d_sb,"file"))
		UDBG;
#endif
	err = vfs_readdir(lower_file, filldir, dirent);
	file->f_pos = lower_file->f_pos;
	if (err >= 0)		/* copy the atime */
		fsstack_copy_attr_atime(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);
#ifdef DEBUG_SUPPORT
	if(debug_support(lower_file->f_dentry->d_sb,"file"))
		UDBGE(err);
#endif
	return err;
}

static long wrapfs_unlocked_ioctl(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;
#ifdef WRAPFS_CRYPTO
	char *key = kmalloc(KEY_LENGTH+1,GFP_KERNEL);
	char nokey[KEY_LENGTH]={0,};
	long rc = 0;
	//char hex[CHKSUM_SIZE*2 + 1];
#endif
	lower_file = wrapfs_lower_file(file);
#ifdef DEBUG_SUPPORT
	if(debug_support(lower_file->f_dentry->d_sb,"file"))
		UDBG;
#endif
	/* XXX: use vfs_ioctl if/when VFS exports it */
#ifdef WRAPFS_CRYPTO
	if(cmd == IOCTL_KEY)
	{
		if(key == NULL)
		{
			err = -ENOMEM;
			goto end;
		}
		if(copy_from_user(key,(char*)arg,KEY_LENGTH))
		{
			err = -EFAULT;
			goto end;
		}
		if(key == NULL)
		{
			printk("No key is entered. No encryption will be done\n");
			goto end;
		}
		key[strlen((char*)arg)] ='\0';
		if(no_key_func(key))
		{
			printk("All Zeros are not allowed\n");
			rc = -EPERM;
			goto end;
		}
		if(WRAPFS_SB(lower_file->f_dentry->d_sb)->mount_options.mmap == 1 && strcmp(WRAPFS_SB(lower_file->f_dentry->d_sb)->key,nokey))
		{
			printk("Only one key per instance of mount\n");
			rc = -EPERM;
			goto end;
			
		}
		strcpy(WRAPFS_SB(lower_file->f_dentry->d_sb)->key, key);
		//if(calculate_key(key,WRAPFS_SB(lower_file->f_dentry->d_sb)->key,CHKSUM_SIZE))
		//	goto out;

		//for(t=0;t<CHKSUM_SIZE;t++)
		//	sprintf(&hex[t*2],"%.2x",(unsigned char)WRAPFS_SB(lower_file->f_dentry->d_sb)->key[t]);	
		
		//strcpy(WRAPFS_SB(lower_file->f_dentry->d_sb)->key,hex);
	}
end:
#endif
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->unlocked_ioctl)
		err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);

out:
#ifdef WRAPFS_CRYPTO
	if(rc == -EPERM)
		err =rc;
	if(key!=NULL)
		kfree(key);	
#endif
#ifdef DEBUG_SUPPORT
	if(debug_support(lower_file->f_dentry->d_sb,"file"))
		UDBGE((int)err);
#endif
	return err;
}

#ifdef CONFIG_COMPAT
static long wrapfs_compat_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = wrapfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
	return err;
}
#endif

static int wrapfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;
	bool willwrite;
	struct file *lower_file;
	const struct vm_operations_struct *saved_vm_ops = NULL;
#ifdef DEBUG_SUPPORT
	if(debug_support(wrapfs_lower_file(file)->f_dentry->d_sb,"file"))
		UDBG;
#endif
	/* this might be deferred to mmap's writepage */
	willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

	/*
	 * File systems which do not implement ->writepage may use
	 * generic_file_readonly_mmap as their ->mmap op.  If you call
	 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
	 * But we cannot call the lower ->mmap op, so we can't tell that
	 * writeable mappings won't work.  Therefore, our only choice is to
	 * check if the lower file system supports the ->writepage, and if
	 * not, return EINVAL (the same error that
	 * generic_file_readonly_mmap returns in that case).
	 */
	lower_file = wrapfs_lower_file(file);
	if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
		err = -EINVAL;
		printk(KERN_ERR "wrapfs: lower file system does not "
		       "support writeable mmap\n");
		goto out;
	}

	/*
	 * find and save lower vm_ops.
	 *
	 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
	 */
	if (!WRAPFS_F(file)->lower_vm_ops) {
		err = lower_file->f_op->mmap(lower_file, vma);
		if (err) {
			printk(KERN_ERR "wrapfs: lower mmap failed %d\n", err);
			goto out;
		}
		saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
		err = do_munmap(current->mm, vma->vm_start,
				vma->vm_end - vma->vm_start);
		if (err) {
			printk(KERN_ERR "wrapfs: do_munmap failed %d\n", err);
			goto out;
		}
	}

	/*
	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
	 * don't want its test for ->readpage which returns -ENOEXEC.
	 */
	file_accessed(file);
	vma->vm_ops = &wrapfs_vm_ops;
	vma->vm_flags |= VM_CAN_NONLINEAR;

	file->f_mapping->a_ops = &wrapfs_aops; /* set our aops */
	if (!WRAPFS_F(file)->lower_vm_ops) /* save for our ->fault */
		WRAPFS_F(file)->lower_vm_ops = saved_vm_ops;

out:
#ifdef DEBUG_SUPPORT
	if(debug_support(lower_file->f_dentry->d_sb,"file"))
		UDBGE(err);
#endif
	return err;
}

static int wrapfs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct path lower_path;
#ifdef DEBUG_SUPPORT
	if(debug_support(wrapfs_lower_inode(inode)->i_sb,"file"))
		UDBG;
#endif
	/* don't open unhashed/deleted files */
	if (d_unhashed(file->f_path.dentry)) {
		err = -ENOENT;
		goto out_err;
	}

	file->private_data =
		kzalloc(sizeof(struct wrapfs_file_info), GFP_KERNEL);
	if (!WRAPFS_F(file)) {
		err = -ENOMEM;
		goto out_err;
	}
	/* open lower object and link wrapfs's file struct to lower's */
	wrapfs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_file = dentry_open(lower_path.dentry, lower_path.mnt,
				 file->f_flags, current_cred());
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		lower_file = wrapfs_lower_file(file);
		if (lower_file) {
			wrapfs_set_lower_file(file, NULL);
			fput(lower_file); /* fput calls dput for lower_dentry */
		}
	} else {
		wrapfs_set_lower_file(file, lower_file);
	}

	if (err)
		kfree(WRAPFS_F(file));
	else
		fsstack_copy_attr_all(inode, wrapfs_lower_inode(inode));
out_err:
#ifdef DEBUG_SUPPORT
	if(debug_support(wrapfs_lower_inode(inode)->i_sb,"file"))
		UDBGE(err);
#endif
	return err;
}

static int wrapfs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = wrapfs_lower_file(file);
#ifdef DEBUG_SUPPORT
	if(debug_support(lower_file->f_dentry->d_sb,"file"))
		UDBG;
#endif
	if (lower_file && lower_file->f_op && lower_file->f_op->flush)
		err = lower_file->f_op->flush(lower_file, id);
#ifdef DEBUG_SUPPORT
	if(debug_support(lower_file->f_dentry->d_sb,"file"))
		UDBGE(err);
#endif
	return err;
}

/* release all lower object references & free the file info structure */
static int wrapfs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;

	lower_file = wrapfs_lower_file(file);
	if (lower_file) {
		wrapfs_set_lower_file(file, NULL);
		fput(lower_file);
	}

	kfree(WRAPFS_F(file));
	return 0;
}

static int wrapfs_fsync(struct file *file, loff_t start, loff_t end,
			int datasync)
{
	int err;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;

	err = generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	lower_file = wrapfs_lower_file(file);
	wrapfs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	wrapfs_put_lower_path(dentry, &lower_path);
out:
	return err;
}

static int wrapfs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = wrapfs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

	return err;
}

const struct file_operations wrapfs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= wrapfs_read,
	.aio_read	= generic_file_aio_read,
	.write		= wrapfs_write,
	.aio_write	= generic_file_aio_write,
	.unlocked_ioctl	= wrapfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= wrapfs_compat_ioctl,
#endif
	.mmap		= wrapfs_mmap,
	.open		= wrapfs_open,
	.flush		= wrapfs_flush,
	.release	= wrapfs_file_release,
	.fsync		= wrapfs_fsync,
	.fasync		= wrapfs_fasync,
};

/* trimmed directory options */
const struct file_operations wrapfs_dir_fops = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.readdir	= wrapfs_readdir,
	.unlocked_ioctl	= wrapfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= wrapfs_compat_ioctl,
#endif
	.open		= wrapfs_open,
	.release	= wrapfs_file_release,
	.flush		= wrapfs_flush,
	.fsync		= wrapfs_fsync,
	.fasync		= wrapfs_fasync,
};
