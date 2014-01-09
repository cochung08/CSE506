#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/syscalls.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/security.h>
#include <linux/xattr.h>
#include <linux/file.h>
#include "sys_xargs.h"

asmlinkage extern long (*sysptr)(void *arg);
int calculate_checksum (const char *filename, void *chkbuf, int len);
void bin_to_hex(char *dst, char *src, size_t len);

asmlinkage long xintegrity(void *arg)
{
	int rc = 0;
	int filestr_len;
	unsigned char mode= 0;
	struct file *filp = NULL;
	struct Args_mode1 *mykptr1 = NULL;
	struct Args_mode2 *mykptr2 = NULL;
	struct Args_mode3 *mykptr3 = NULL;

	if(!access_ok(VERIFY_READ, mode, sizeof(unsigned char)))
	{
		rc = -EFAULT;
		goto END;
	} 
	rc = copy_from_user(&mode, arg,sizeof(unsigned char));
	if(rc)
	{
		rc = -EFAULT;
		goto END;
	}
	switch(mode)
	{
		case '1':
		{
			if(!access_ok(VERIFY_READ, mykptr1, sizeof(struct Args_mode1*)))
			{
				rc = -EFAULT;
				goto END;
			}
			mykptr1 = kmalloc(sizeof(struct Args_model*), GFP_KERNEL);
			if(mykptr1 == NULL)
			{
				rc = -ENOMEM;
				goto END;
			}
			
			if(copy_from_user(&(*mykptr1),arg,sizeof(struct Args_mode1*)))
			{
				rc = -EFAULT;
				goto END;
			}

			filestr_len = strlen(((struct Args_mode1*)arg)->filename);
			mykptr1->filename = kmalloc(sizeof(char)*filestr_len,GFP_KERNEL);
			if(mykptr1->filename == NULL)
			{
				rc = -ENOMEM;
				goto END;
			}
			
			mykptr1->ilen = CHKSUM_SIZE;
			if(!mykptr1->ilen)
			{
				rc = -ENOMEM;
				goto END;
			}
			mykptr1->ibuf = kmalloc(sizeof(unsigned char)*mykptr1->ilen,GFP_KERNEL);
			if(mykptr1->ibuf == NULL)
			{
				rc = -ENOMEM;
				goto END;
			}
			
			mykptr1->filename = getname(((struct Args_mode1*)arg)->filename);
			if(IS_ERR(mykptr1->filename))
				goto END;

			filp = filp_open(mykptr1->filename,O_RDONLY,0);

			if(!filp || IS_ERR(filp))
			{
				rc = -ENOENT;
				goto END1;
			}
			if(!filp->f_op->read)
			{
				rc = -EACCES;
				goto END1;
			}
			else
			{
				if(generic_getxattr(filp->f_dentry,XATTR_CHK_SUM,mykptr1->ibuf,2*CHKSUM_SIZE)<0)
				{
					if(rc == -ERANGE)
						printk("BAD TYPE LENGTH ERROR\n");
					else
						printk("Can't read checksum of the file\n");
					rc = -EINVAL;	
				}
				else
				{
					if(copy_to_user(((struct Args_mode1*)arg)->ibuf,mykptr1->ibuf,2*CHKSUM_SIZE))
						rc = -EFAULT;
				}
				filp_close(filp,NULL);	
			}
END1:			
			filp = NULL;
			putname(mykptr1->filename);
			break;
		}
		case '2':
		{
			int credlen;
			if(!access_ok(VERIFY_READ,mykptr2,sizeof(struct Args_mode2*)))
			{
				rc = -EFAULT;
				goto END;
			}
			mykptr2 = kmalloc(sizeof(struct Args_mode2*),GFP_KERNEL);
			if(NULL == mykptr2)
			{
				rc = -EFAULT;
				goto END;
			}
			if( copy_from_user(&(*mykptr2),arg,sizeof(struct Args_mode2*)))
			{
				rc = -EFAULT;
				goto END;
			}
			
			filestr_len = strlen(((struct Args_mode2*)arg)->filename);
			mykptr2->ilen = CHKSUM_SIZE;
			if(!mykptr2->ilen)
			{
				rc = -ENOMEM;
				goto END;
			}
			mykptr2->ibuf = kmalloc(sizeof(char)*mykptr2->ilen,GFP_KERNEL);
			if(NULL == mykptr2->ibuf)
			{
				rc = -ENOMEM;
				goto END;
			}
			credlen =strlen(((struct Args_mode2*)arg)->credbuf);
			mykptr2->credbuf = kmalloc(sizeof(char)*credlen,GFP_KERNEL);
			if(NULL == mykptr2->credbuf)
			{
				rc = -ENOMEM;
				goto END;
			}
			mykptr2->credbuf = getname(((struct Args_mode2*)arg)->credbuf);
			if(IS_ERR(mykptr2->credbuf))
			{
				rc = -EPERM;
				goto END;
			}
			if(strcmp(mykptr2->credbuf,PASSWORD))
			{
				printk("password not matching %s %s\n",mykptr2->credbuf,PASSWORD);
				rc = -EPERM;
				putname(mykptr2->credbuf);
				goto END;
			}
			else
			{
				putname(mykptr2->credbuf);
				mykptr2->filename = getname(((struct Args_mode2*)arg)->filename);
				if(IS_ERR(mykptr2->filename))
				{
					rc = -ENOMEM;
					goto END;
				}				
				rc = calculate_checksum(mykptr2->filename,mykptr2->ibuf,CHKSUM_SIZE);
				if(rc<0)
				{
					putname(mykptr2->filename);
					goto END;
				}
				else
				{	filp = filp_open(mykptr2->filename, O_RDONLY, 0);
					if(!filp || IS_ERR(filp))
					{
						rc = -ENOENT;
						putname(mykptr2->filename);
						goto END;
					}
					if(!filp->f_op->read)
					{
						rc = -EACCES;
						putname(mykptr2->filename);
						goto END;
					}
					else
					{
						rc = generic_setxattr(filp->f_path.dentry,XATTR_CHK_SUM,mykptr2->ibuf,2*CHKSUM_SIZE,XATTR_CREATE);
						if(rc < 0 && rc== -EEXIST)
							rc = generic_setxattr(filp->f_path.dentry,XATTR_CHK_SUM,mykptr2->ibuf,2*CHKSUM_SIZE,XATTR_REPLACE);
					}
					filp_close(filp,NULL);
				}
				putname(mykptr2->filename);
			}
			filp = NULL;
			break;
		}
		case '3':
		{
			int fd=0;
			struct file *fp;
			char *calchkbuf = kmalloc(sizeof(char)*CHKSUM_SIZE,GFP_KERNEL);
			int errcal=0,errchk=0;
			char *getchkbuf = kmalloc(sizeof(char)*CHKSUM_SIZE,GFP_KERNEL);
			if(!access_ok(VERIFY_READ,mykptr3,sizeof(struct Args_mode3*)))
			{
				rc = -EFAULT;
				goto END;
			}
			mykptr3 = kmalloc(sizeof(struct Args_mode3*),GFP_KERNEL);
			if(NULL == mykptr3)
			{
				rc = -ENOMEM;
				goto END;
			}
			rc = copy_from_user(&(*mykptr3),arg,sizeof(struct Args_mode3*));
			if(rc)
			{
				rc = -EFAULT;
				goto END;
			}
			mykptr3->oflag = ((struct Args_mode3*)arg)->oflag;
			mykptr3->mode = ((struct Args_mode3*)arg)->mode;
			filestr_len = strlen(((struct Args_mode3*)arg)->filename);
			mykptr3->filename = kmalloc(sizeof(char)*filestr_len,GFP_KERNEL);
			if(mykptr3->filename == NULL)
			{
				rc = -ENOMEM;
				goto END;
			}
			mykptr3->filename = getname(((struct Args_mode3*)arg)->filename);
			if(!IS_ERR(mykptr3->filename))
			{
					errcal = calculate_checksum(mykptr3->filename,calchkbuf,CHKSUM_SIZE);
					fd = get_unused_fd();
					if(fd>=0)
					{	
						fp = filp_open(mykptr3->filename,mykptr3->oflag,mykptr3->mode);
						if(!fp || IS_ERR(fp))
						{
							rc = -ENOENT;
							goto END3;
						}
						if((mykptr3->oflag == O_WRONLY && !filp->f_op->write)||
						   (mykptr3->oflag == O_RDONLY && !filp->f_op->read))
						{
							rc = -EPERM;
							goto END3;
						}
						if(!IS_ERR(fp))
							fd_install(fd,fp);
						if(!IS_ERR(fp)&& errcal>=0)
						{	
							errchk = generic_getxattr(fp->f_path.dentry,XATTR_CHK_SUM,getchkbuf,2*CHKSUM_SIZE);
							if(!memcmp(calchkbuf,getchkbuf,CHKSUM_SIZE)&& errchk >=0)
								rc = fd;
							else
								rc = -EPERM;
						}
					}
			}
				
END3:
			putname(mykptr3->filename);
			if(calchkbuf!=NULL)
				kfree(calchkbuf);
			if(getchkbuf!=NULL)
				kfree(getchkbuf);
			break;
		}
		default:
		{	rc = -1;
			break;
		}
	}
END:
	if(mykptr1!=NULL)
		kfree(mykptr1);
	if(mykptr2!= NULL)
		kfree(mykptr2);
	if(mykptr3!=NULL)
		kfree(mykptr3);
	return rc;
}

int calculate_checksum(const char *filename, void *chkbuf, int len)
{
	struct file *filp;
	mm_segment_t oldfs;	
	char *buf,*temp_chkbuf;
	int bytes = -1;
	int rc = 0;
	struct scatterlist sg;
	struct hash_desc desc;
	desc.flags = 0;
	
	filp = filp_open(filename, O_RDONLY, 0);
	if(!filp || IS_ERR(filp))
	{
		printk("File Read Error with %d\n",(int)PTR_ERR(filp));
		return -1;
	}

	if(!filp->f_op->read)
		return -2;
	buf =  kmalloc(sizeof(char)*PAGE_SIZE,GFP_KERNEL);
	temp_chkbuf = kmalloc(sizeof(char)*CHKSUM_SIZE,GFP_KERNEL);
	desc.tfm = crypto_alloc_hash("md5",0,CRYPTO_ALG_ASYNC);
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
	crypto_hash_final(&desc,temp_chkbuf);
	bin_to_hex(chkbuf,temp_chkbuf,CHKSUM_SIZE);
out:
	if(buf!=NULL)
		kfree(buf);
	if(temp_chkbuf!=NULL)
		kfree(temp_chkbuf);
	filp_close(filp,NULL);
	return  bytes;
}

void bin_to_hex(char *dst,char *src, size_t len)
{
	int i;
	for(i = 0;i < len; i++)
		sprintf(&dst[i*2],"%.2x",(unsigned char)src[i]);
}
static int __init init_sys_xintegrity(void)
{
	printk("installed new sys_xintegrity module\n");
	if (sysptr == NULL)
		sysptr = xintegrity;
	return 0;
}
static void  __exit exit_sys_xintegrity(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk("removed sys_xintegrity module\n");
}
module_init(init_sys_xintegrity);
module_exit(exit_sys_xintegrity);
MODULE_LICENSE("GPL");
