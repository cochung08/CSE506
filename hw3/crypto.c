#include "wrapfs.h"
#include<linux/crypto.h>
#include<linux/scatterlist.h>
#include<linux/string.h>
#include<linux/pagemap.h>

int wrapfs_decrypt_page(struct page *dst_page,struct page *src_page, char *key)
{
	int ret = 0;
	struct crypto_blkcipher *tfm = NULL;
	 struct blkcipher_desc desc;
	const char *algo = "ctr(aes)";
	 struct scatterlist src_sg, dst_sg;
	 sg_init_table(&src_sg, 1);
        sg_init_table(&dst_sg, 1);

        sg_set_page(&src_sg, src_page, PAGE_CACHE_SIZE, 0);
        sg_set_page(&dst_sg, dst_page, PAGE_CACHE_SIZE, 0);


	tfm = crypto_alloc_blkcipher(algo,0,CRYPTO_ALG_ASYNC);
	if(IS_ERR(tfm)){
		printk(KERN_ERR "AES: cipher: Failed to load transform for %ld\n",PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}
	

	desc.tfm = tfm;
        desc.flags = 0;


	ret = crypto_blkcipher_setkey(tfm,key,32);
	ret = crypto_blkcipher_decrypt(&desc, &dst_sg, &src_sg, PAGE_CACHE_SIZE);
        if (ret) {
                printk(KERN_ERR "Error encrypting\n");
                goto out;
        }
out:
	crypto_free_blkcipher(tfm);
	return ret;
}

int wrapfs_encrypt_page(struct page *dst_page, struct page *src_page, char *key)
{
	int ret = 0;
	struct crypto_blkcipher *tfm = NULL;
	 struct blkcipher_desc desc;
	const char *algo = "ctr(aes)";
	 struct scatterlist src_sg, dst_sg;

	sg_init_table(&src_sg, 1);
        sg_init_table(&dst_sg, 1);

        sg_set_page(&src_sg, src_page, PAGE_CACHE_SIZE, 0);
        sg_set_page(&dst_sg, dst_page, PAGE_CACHE_SIZE, 0);


	tfm = crypto_alloc_blkcipher(algo,0,CRYPTO_ALG_ASYNC);
	if(IS_ERR(tfm)){
		printk(KERN_ERR "AES: cipher: Failed to load transform for %ld\n",PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}
	

	desc.tfm = tfm;
        desc.flags = 0;


	ret = crypto_blkcipher_setkey(tfm,key,32);
	ret = crypto_blkcipher_encrypt(&desc, &dst_sg, &src_sg, PAGE_CACHE_SIZE);
        if (ret) {
                printk(KERN_ERR "Error encrypting\n");
                goto out;
        }

out:
	crypto_free_blkcipher(tfm);
	return ret;
}

int calculate_key(char *key,char *chksum,int len)
{
	int rc =0;
	struct scatterlist sg;
	struct hash_desc desc;
	desc.flags = 0;
	desc.tfm = crypto_alloc_hash("md5",0,CRYPTO_ALG_ASYNC);
	if(IS_ERR(desc.tfm))
	{
		rc = PTR_ERR(desc.tfm);
		goto out;
	}
	if(crypto_hash_init(&desc))
		goto out;
	
	sg_init_one(&sg,(u8*)key,len);
	crypto_hash_update(&desc,&sg,len);
	crypto_hash_final(&desc,chksum);
out:
	return rc;
}
