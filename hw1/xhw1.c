#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "sys_xargs.h"

#define __NR_xintegrity	349	/* our private syscall number */

int main(int argc, char *argv[])
{
	int rc;
	if(argc == 3 && argv[1][0] == '1')
	{
		struct Args_mode1 myuptr;
				
		myuptr.flag =  argv[1][0];
		myuptr.filename = (char *)malloc(sizeof(char)*PATH_FILENAME_MAX);
		if(NULL == myuptr.filename)
			return -ENOMEM;
		strcpy(myuptr.filename,argv[2]);
				
		myuptr.ilen = CHKSUM_SIZE;
		myuptr.ibuf = (unsigned char *)malloc(sizeof(unsigned char)*CHKSUM_SIZE*2);
		if(NULL == myuptr.ibuf)
			return -ENOMEM;

  		rc = syscall(__NR_xintegrity,(void*)&myuptr);
		if(!rc)
			printf("%s\n",myuptr.ibuf);
		free(myuptr.ibuf);
		free(myuptr.filename);
		goto EXIT;
	}
	else if(argc == 4 && argv[1][0] == '2')
	{
		struct Args_mode2 myuptr;
		myuptr.flag = argv[1][0];
		myuptr.filename = argv[2];
		myuptr.credbuf  = (unsigned char*)argv[3];
		myuptr.clen = strlen((char*)myuptr.credbuf);
		myuptr.ilen = CHKSUM_SIZE;
		myuptr.ibuf = (unsigned char*)malloc(sizeof(unsigned char)*CHKSUM_SIZE);
		if(NULL == myuptr.ibuf)
			return -ENOMEM;
		rc = syscall(__NR_xintegrity,(void*)&myuptr);
		free(myuptr.ibuf);
		goto EXIT;
	}
	else if(argc == 5 && argv[1][0] == '3')
	{
		struct Args_mode3 myuptr;
		myuptr.flag = argv[1][0];
		myuptr.filename = argv[2];
		myuptr.oflag = atoi(argv[3]);
		myuptr.mode = atoi(argv[4]);
		
		rc = syscall(__NR_xintegrity,(void*)&myuptr);
		if(rc>=0)
			close(rc);
		goto EXIT;
	}
	else
	{
		printf("INVALID MODE OR INVALID NUMBER OF ARGUMENTS\n");
		exit(-1);
	}
EXIT:
	if (rc == 0)
		printf("syscall returned %d\n", rc);
	else
		printf("syscall returned %d (errno=%d)\n", rc, errno);
	perror("");

	exit(rc);
}
