//#ifndef EXTRA_CREDIT
//#define EXTRA_CREDIT
//#endif
#if !defined(EXTRA_CREDIT)
#define CHKSUM_SIZE 16
#endif
#define PATH_FILENAME_MAX 4096
#define XATTR_CHK_SUM "user.md5sum"
#define PASSWORD "passwd"
struct Args_mode1
{
	unsigned char flag;
	char *filename;
	unsigned char *ibuf;
	unsigned int ilen;
};

struct Args_mode2
{
	unsigned char flag;
	char *filename;
	unsigned char *ibuf;
	unsigned int ilen;
	unsigned char *credbuf;
	unsigned int clen;;
};

struct Args_mode3
{
	unsigned char flag;
	const char *filename;
	int oflag;
	int mode;
};
