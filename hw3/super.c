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
#ifdef DEBUG_SUPPORT
#include<linux/module.h>
#include<linux/parser.h>
#endif
/*
 * The inode cache is used with alloc_inode for both our inode info and the
 * vfs inode.
 */
static struct kmem_cache *wrapfs_inode_cachep;
#ifdef DEBUG_SUPPORT
enum{   wrapfs_option_mmap,
        wrapfs_option_debug,
        wrapfs_opt_err
};

static const match_table_t tokens = {
        {wrapfs_option_mmap, "mmap"},
        {wrapfs_option_debug, "debug=%d"},
        {wrapfs_opt_err,NULL}
};
static int wrapfs_parsing_debug(struct super_block *sb, char *options)
{
        char *p;
        int token;
        substring_t args[MAX_OPT_ARGS];
	int db_flg;
        char *debug_flg;
        WRAPFS_SB(sb)->mount_options.debug_flag = 0;
        if(options!=NULL){
                while((p = strsep(&options,","))!= NULL){
                        if(!*p)
                                continue;

                        token = match_token(p,tokens,args);
                        switch(token){
                                case wrapfs_option_debug:
                                        debug_flg = args[0].from;
                                        db_flg = (int)simple_strtol(debug_flg,&debug_flg,0);
                                        WRAPFS_SB(wrapfs_lower_super(sb))->mount_options.debug_flag = db_flg;
                                        break;
                                default:
                                        printk(KERN_WARNING
                                                "%s: wrapfs: unrecognized option [%s]\n",__func__,p);
                        }
                }
        }
        if(options)
        {
                kfree(options);
                options = NULL;
        }
        return 0;
}
#endif
/* final actions when unmounting a file system */
static void wrapfs_put_super(struct super_block *sb)
{
	struct wrapfs_sb_info *spd;
	struct super_block *s;
#ifdef DEBUG_SUPPORT
	int db_flg =0;
	if(debug_support(wrapfs_lower_super(sb),"superblock"))
	{
		UDBG;
		db_flg =1;
	}
#endif
	spd = WRAPFS_SB(sb);
	if (!spd)
		return;

	/* decrement lower super references */
	s = wrapfs_lower_super(sb);

	wrapfs_set_lower_super(sb, NULL);
	atomic_dec(&s->s_active);
	
	kfree(spd);
	sb->s_fs_info = NULL;
#ifdef DEBUG_SUPPORT
	if(db_flg ==1)
		UDBGE(err);
#endif
}

static int wrapfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	int err;
	struct path lower_path;

	wrapfs_get_lower_path(dentry, &lower_path);
	err = vfs_statfs(&lower_path, buf);
	wrapfs_put_lower_path(dentry, &lower_path);

	/* set return buf to our f/s to avoid confusing user-level utils */
	buf->f_type = WRAPFS_SUPER_MAGIC;

	return err;
}

/*
 * @flags: numeric mount options
 * @options: mount options string
 */
static int wrapfs_remount_fs(struct super_block *sb, int *flags, char *options)
{
	int err = 0;
#ifdef DEBUG_SUPPORT
	wrapfs_parsing_debug(sb,options);
#endif
	/*
	 * The VFS will take care of "ro" and "rw" flags among others.  We
	 * can safely accept a few flags (RDONLY, MANDLOCK), and honor
	 * SILENT, but anything else left over is an error.
	 */
	if ((*flags & ~(MS_RDONLY | MS_MANDLOCK | MS_SILENT)) != 0) {
		printk(KERN_ERR
		       "wrapfs: remount flags 0x%x unsupported\n", *flags);
		err = -EINVAL;
	}

	return err;
}

/*
 * Called by iput() when the inode reference count reached zero
 * and the inode is not hashed anywhere.  Used to clear anything
 * that needs to be, before the inode is completely destroyed and put
 * on the inode free list.
 */
static void wrapfs_evict_inode(struct inode *inode)
{
	struct inode *lower_inode;

	truncate_inode_pages(&inode->i_data, 0);
	end_writeback(inode);
	/*
	 * Decrement a reference to a lower_inode, which was incremented
	 * by our read_inode when it was created initially.
	 */
	lower_inode = wrapfs_lower_inode(inode);
	wrapfs_set_lower_inode(inode, NULL);
	iput(lower_inode);
}

static struct inode *wrapfs_alloc_inode(struct super_block *sb)
{
	struct wrapfs_inode_info *i;

	i = kmem_cache_alloc(wrapfs_inode_cachep, GFP_KERNEL);
	if (!i)
		return NULL;

	/* memset everything up to the inode to 0 */
	memset(i, 0, offsetof(struct wrapfs_inode_info, vfs_inode));

	i->vfs_inode.i_version = 1;
	return &i->vfs_inode;
}

static void wrapfs_destroy_inode(struct inode *inode)
{
	kmem_cache_free(wrapfs_inode_cachep, WRAPFS_I(inode));
}

/* wrapfs inode cache constructor */
static void init_once(void *obj)
{
	struct wrapfs_inode_info *i = obj;

	inode_init_once(&i->vfs_inode);
}

int wrapfs_init_inode_cache(void)
{
	int err = 0;

	wrapfs_inode_cachep =
		kmem_cache_create("wrapfs_inode_cache",
				  sizeof(struct wrapfs_inode_info), 0,
				  SLAB_RECLAIM_ACCOUNT, init_once);
	if (!wrapfs_inode_cachep)
		err = -ENOMEM;
	return err;
}

/* wrapfs inode cache destructor */
void wrapfs_destroy_inode_cache(void)
{
	if (wrapfs_inode_cachep)
		kmem_cache_destroy(wrapfs_inode_cachep);
}

/*
 * Used only in nfs, to kill any pending RPC tasks, so that subsequent
 * code can actually succeed and won't leave tasks that need handling.
 */
static void wrapfs_umount_begin(struct super_block *sb)
{
	struct super_block *lower_sb;

	lower_sb = wrapfs_lower_super(sb);
	if (lower_sb && lower_sb->s_op && lower_sb->s_op->umount_begin)
		lower_sb->s_op->umount_begin(lower_sb);
}

/*static int wrapfs_show_options(struct seq_file *m, struct vfsmount *mnt)
{
	printk("honey bunny\n");
	generic_show_options(m,mnt);
}*/
const struct super_operations wrapfs_sops = {
	.put_super	= wrapfs_put_super,
	.statfs		= wrapfs_statfs,
	.remount_fs	= wrapfs_remount_fs,
	.evict_inode	= wrapfs_evict_inode,
	.umount_begin	= wrapfs_umount_begin,
	.show_options	= generic_show_options,
	.alloc_inode	= wrapfs_alloc_inode,
	.destroy_inode	= wrapfs_destroy_inode,
	.drop_inode	= generic_delete_inode,
};
