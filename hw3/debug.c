#include "wrapfs.h"

int debug_support(struct super_block *sb, char *ops)
{
#ifdef DEBUG_SUPPORT
	int debug_flag;

	debug_flag = WRAPFS_SB(sb)->mount_options.debug_flag;
	if((!strcmp(ops,"file") && (debug_flag & WRAPFS_DEBUG_FILE_OP))
	|| (!strcmp(ops,"dentry") && (debug_flag & WRAPFS_DEBUG_DENTRY_OP))
	|| (!strcmp(ops,"inode") && (debug_flag & WRAPFS_DEBUG_INODE_OP))
	|| (!strcmp(ops,"superblock") && (debug_flag & WRAPFS_DEBUG_SUPERBLOCK_OP))
	||(!strcmp(ops,"address_space") && (debug_flag & WRAPFS_DEBUG_ADDRESS_SPACE_OP))
	||(!strcmp(ops,"other") && (debug_flag & WRAPFS_DEBUG_OTHER_OP))
	)
		return 1;
	else
#endif
		return 0;
			

}
