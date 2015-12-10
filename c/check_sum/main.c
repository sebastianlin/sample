
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#define ERROR(s)	{printf("%s ", s); puts("Quit."); exit(1);}

int have_table = 0;
uint table[256];
uint POLYNOMIAL = 0xEDB88320L;
void make_table()
{
	int i, j ;
	have_table = 1 ;
	for (i = 0 ; i < 256 ; i++)
		for (j = 0, table[i] = i ; j < 8 ; j++)
			table[i] = (table[i]>>1)^((table[i]&1)?POLYNOMIAL:0) ;
}

uint crc32(uint crc, unsigned char *buff, int len)
{
	if (!have_table) make_table() ;
	crc = ~crc;
	for (int i = 0; i < len; i++)
		crc = (crc >> 8) ^ table[(crc ^ buff[i]) & 0xff];
	return ~crc;
}

int main(int argc, char **argv)
{
	char *file_name=NULL;
	int c;
	int fd;
	int ret;
	struct stat sb;
	unsigned char *ptr;

	while ((c = getopt (argc, argv, "f:")) != -1) {
		switch (c)
		{
			case 'f':
				file_name = optarg;
				break;
			default:
				ERROR("Unknown parameters!");
		}
	}

	if(!file_name)
		ERROR("Parameter error!");

	if((fd = open(file_name, O_RDONLY))<0)
		ERROR("File open error!");
	
	if((ret=fstat(fd, &sb))<0)
		ERROR("fstat open error!");

	ptr=(unsigned char *)mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	printf("%p %u\n", ptr, crc32(0, ptr, sb.st_size));

	munmap(ptr, sb.st_blksize);
	close(fd);
}



