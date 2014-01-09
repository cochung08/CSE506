#include "wrapfs.h"
#include<linux/xattr.h>
#include<linux/dcache.h>
#include<linux/file.h>
#include<linux/fcntl.h>
#include<linux/fs.h>
#include<linux/crypto.h>
#include<linux/scatterlist.h>
#include<linux/string.h>

int calculate_checksum(struct file *lower_file, void *chkbuf, int len);
void bin_to_hex(char *dst,char *src,size_t len);

#ifdef EXTRA_CREDIT
int get_chksum_size(char *algorithm_name);
int get_default_chksum_size(struct dentry *dentry,char *default_algo,int *size);
#endif

ssize_t wrapfs_getxattr(struct dentry *dentry, const char *name, void *value,size_t size)
{
	struct dentry *lower_dentry = NULL;
	struct path lower_path;
	int err = -EOPNOTSUPP;
	
	wrapfs_get_lower_path(dentry,&lower_path);
	lower_dentry = lower_path.dentry;

	err = vfs_getxattr(lower_dentry, name, value, size);

	wrapfs_put_lower_path(dentry,&lower_path);
	return err;
}
int wrapfs_setxattr(struct dentry *dentry, const char *name,const void *value, size_t size, int flags)
{
	struct dentry *lower_dentry = NULL;
	struct path lower_path;
	int err = - EOPNOTSUPP;
	
	char *chkbuf;
#ifdef EXTRA_CREDIT
	char *algo;
	int CHKSUM_SIZE =0;
	int *algo_len;
	char *h_i;
	int h=0;
#endif
	wrapfs_get_lower_path(dentry,&lower_path);
        lower_dentry = lower_path.dentry;

#ifdef EXTRA_CREDIT
	algo = kmalloc(sizeof(char)*10,GFP_KERNEL);
	algo_len = kmalloc(sizeof(int)*1,GFP_KERNEL);
	h_i = kmalloc(sizeof(char)*1,GFP_KERNEL);
	CHKSUM_SIZE = get_chksum_size((char*)value);
	if(!CHKSUM_SIZE)
		CHKSUM_SIZE = 16;
	printk("chksum size%d\n",CHKSUM_SIZE);			
#endif
	chkbuf = kmalloc(sizeof(char)*CHKSUM_SIZE,GFP_KERNEL);
	if(NULL == chkbuf)
	{
		err = -ENOMEM;
		goto out;

	}	

	if(current_cred()->uid < 0 && !(strcmp(name,XATTR_HAS_INTEGRITY) || strcmp(name,XATTR_INTEGRITY_VAL)))
	{
		printk("Only root has permission\n");
		err = -EPERM;
		goto out;
	}

	if(!strcmp(name,XATTR_INTEGRITY_VAL))
	{	err = -EPERM;
		goto out;
	}
	
	if(!strcmp(name,XATTR_HAS_INTEGRITY))
	{
		if((memcmp((char*)value,"1",1) &&  memcmp((char*)value,"0",1)) || size > 1)
		{
			printk("Has_integrity can have only 1 or 0\n");
			err = -EPERM;
			goto out;
		}
	}
#ifdef EXTRA_CREDIT
	if(!strcmp(name,XATTR_INTEGRITY_TYPE))
	{
		if(0 == get_chksum_size((char*)value))
		{
			printk("This algorithm is not supported \n");
			err = -EOPNOTSUPP;
			goto out;
		}
	}
	h = vfs_getxattr(lower_dentry,XATTR_HAS_INTEGRITY,h_i,1);
#endif	
	if((!strcmp(name,XATTR_HAS_INTEGRITY) && !memcmp((char*)value,"1",1) && !S_ISDIR(lower_dentry->d_inode->i_mode))
#ifdef EXTRA_CREDIT
	   || (!(strcmp(name,XATTR_INTEGRITY_TYPE)) && h>0 && !memcmp(h_i,"1",1) && !S_ISDIR(lower_dentry->d_inode->i_mode))
#endif
	 )
	{
		struct file *lower_file = NULL;
		int err_chksum;
#ifdef EXTRA_CREDIT
		vfs_setxattr(lower_dentry,XATTR_INTEGRITY_TYPE,value,size,flags);
#endif		
		lower_file = dentry_open(lower_path.dentry,lower_path.mnt,O_RDONLY,current_cred());
		err_chksum = calculate_checksum(lower_file,chkbuf,CHKSUM_SIZE);
		err = vfs_setxattr(lower_dentry,XATTR_INTEGRITY_VAL,chkbuf,CHKSUM_SIZE,flags);
	}
	else if(!strcmp(name,XATTR_HAS_INTEGRITY) && !memcmp((char*)value,"0",1) && !S_ISDIR(lower_dentry->d_inode->i_mode))
		err = vfs_removexattr(lower_dentry,XATTR_INTEGRITY_VAL);

	err = vfs_setxattr(lower_dentry,name,value,size,flags);

out:	
	wrapfs_put_lower_path(dentry,&lower_path);
	
	kfree(chkbuf);	
#ifdef EXTRA_CREDIT
	kfree(algo);
	kfree(algo_len);
#endif
	return err;
}
ssize_t wrapfs_listxattr(struct dentry *dentry, char *list, size_t size)
{
	struct dentry *lower_dentry = NULL;
	struct path lower_path;
	int err = -EOPNOTSUPP;

	wrapfs_get_lower_path(dentry,&lower_path);
	lower_dentry = lower_path.dentry;

	err = vfs_listxattr(lower_dentry,list,size);

	wrapfs_put_lower_path(dentry,&lower_path);

	return err;
}
int wrapfs_removexattr(struct dentry *dentry, const char *name)
{
	struct dentry *lower_dentry = NULL;
	struct path lower_path;
	int err = -EOPNOTSUPP;

        if(current_cred()->uid < 0 && !(strcmp(name,XATTR_HAS_INTEGRITY) || strcmp(name,XATTR_INTEGRITY_VAL)))
        {
                printk("Only root has permission\n");
                err = -EPERM;
                return err;
        }

	if(!strcmp(name,XATTR_INTEGRITY_VAL))
	{
		printk("NO permission to remove integral val attribute\n");
                err = -EPERM;
		return err;
	}

	wrapfs_get_lower_path(dentry,&lower_path);
	lower_dentry = lower_path.dentry;

	if(!strcmp(name,XATTR_HAS_INTEGRITY))
		err = vfs_removexattr(lower_dentry,XATTR_INTEGRITY_VAL);

	err = vfs_removexattr(lower_dentry,name);

	wrapfs_put_lower_path(dentry,&lower_path);

	return err;
}

int calculate_checksum(struct file *filp, void *chkbuf, int len)
{
        mm_segment_t oldfs;
        char *buf;
	//char *temp_chkbuf;
        int bytes = -1;
        int rc = 0;
#ifdef EXTRA_CREDIT
	char *algorithm_name  = kmalloc(sizeof(char)*10,GFP_KERNEL);
	int *algo_len = kmalloc(sizeof(int)*1,GFP_KERNEL);
#endif
        struct scatterlist sg;
        struct hash_desc desc;
        desc.flags = 0;

        if(!filp->f_op->read)
                return -2;

        buf =  kmalloc(sizeof(char)*PAGE_SIZE,GFP_KERNEL);
	if(!buf)
	{
		bytes = -ENOMEM;
		goto out;
	}
	//temp_chkbuf = kmalloc(sizeof(char)*CHKSUM_SIZE,GFP_KERNEL);
#ifdef EXTRA_CREDIT
	get_default_chksum_size(filp->f_path.dentry,algorithm_name,algo_len);
	algorithm_name[(*algo_len)]='\0';
	printk("Algorithm used is %s%d\n",algorithm_name,strlen(algorithm_name));
	desc.tfm = crypto_alloc_hash(algorithm_name,0,CRYPTO_ALG_ASYNC);
#else
        desc.tfm = crypto_alloc_hash("md5",0,CRYPTO_ALG_ASYNC);
#endif

        if(IS_ERR(desc.tfm))
        {
                rc = PTR_ERR(desc.tfm);
                goto out;
        }
        if(crypto_hash_init(&desc))
                goto out;

        filp->f_pos = 0;
        oldfs = get_fs();
        set_fs(KERNEL_DS);
        do
        {
                bytes = filp->f_op->read(filp, buf,PAGE_SIZE, &filp->f_pos);
                sg_init_one(&sg,(u8*)buf,bytes);
                crypto_hash_update(&desc,&sg,bytes);
        }
        while(bytes == PAGE_SIZE);
        set_fs(oldfs);
        crypto_hash_final(&desc,chkbuf);
	//bin_to_hex(chkbuf,temp_chkbuf,CHKSUM_SIZE);
out:
	kfree(buf);
	//kfree(temp_chkbuf);
#ifdef EXTRA_CREDIT
	kfree(algorithm_name);
	kfree(algo_len);
#endif
	return bytes;
}
void bin_to_hex(char *dst,char *src,size_t len)
{
	int i;
	for(i =0;i<len;i++)
		sprintf(&dst[i*2],"%.2x",(unsigned char)src[i]);
}

#ifdef EXTRA_CREDIT
int get_chksum_size(char *algorithm_name)
{
	if(!memcmp(algorithm_name,"MD5",3) || !memcmp(algorithm_name,"md5",3))
		return 16;

	else if(!memcmp(algorithm_name,"SHA1",4) || !memcmp(algorithm_name,"sha1",4))
		return 20;

	else if(!memcmp(algorithm_name,"SHA224",6) || !memcmp(algorithm_name,"sha224",6))
		return 28;

	else if(!memcmp(algorithm_name,"SHA256",6) || !memcmp(algorithm_name,"sha256",6))
		return 32;

	else
		return 0;
}
int get_default_chksum_size(struct dentry *dentry,char *default_algo,int *len)
{
	int size;
	char *algo = kmalloc(sizeof(char)*10,GFP_KERNEL);
	if(vfs_getxattr(dentry,XATTR_INTEGRITY_TYPE,algo,10)>0)
	{
		size = get_chksum_size(algo);
		if(size == 16)
		{
			memcpy(default_algo,algo,3);
			*len = 3;
		}
		else if(size == 20)
		{
			memcpy(default_algo,algo,4);
			*len = 4;
		}
		else if(size == 28 || size == 32)
		{
			memcpy(default_algo,algo,6);
			*len = 6;
		}
	}
	else
	{
		size = 16;
		memcpy(default_algo,"md5",3);
		*len = 3;
	}
	kfree(algo);
	return size;
}
#endif
