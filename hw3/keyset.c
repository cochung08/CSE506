#include<sys/ioctl.h>
#include<linux/fs.h>
#include<fcntl.h>
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

#define IOCTL_KEY 6767

int main(int argc, char *argv[])
{
	int fd;

	if(argc == 1)
	{
		printf("\n Enter the key\n");
		return 0;
	}

	fd = open("/tmp/",O_RDONLY);
	if(fd == -1)
	{
		printf("Device not found/mounted\n");
		return 0;
	}
	else
	{
		ioctl(fd,IOCTL_KEY,argv[1]);
		close(fd);
	}
	return 0;
}
