#include <sys/mman.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>


void anonymous_mapping()
{
	unsigned char *ADDR; 

	// We can omit lock and fixed flags
	ADDR = (unsigned char*)mmap(NULL,0x1000,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS|MAP_LOCKED,-1,0);
	printf("Mapping address = %p\n", ADDR);
	*(volatile unsigned int *)(ADDR + 0x00) = 0x1;
	*(volatile unsigned int *)(ADDR + 0x04) = 0x1;
	munmap(ADDR,0x1000);
}

void file_mapping()
{
	unsigned char *ADDR; 
	int device_pointer;
	device_pointer = open("./map_file",O_RDWR);
	if (device_pointer < 0){
		printf("device file open error !\n");
		return ;
	}

	ADDR = (unsigned char*)mmap(0,0x1000,PROT_READ|PROT_WRITE,MAP_SHARED,device_pointer,0x1000);
	printf("Mapping address = %p\n", ADDR);
	printf("Origin value: %x\n", *(volatile unsigned int *)(ADDR + 0x00));
	*(volatile unsigned int *)(ADDR + 0x00) = rand();
	printf("Current value: %x\n", *(volatile unsigned int *)(ADDR + 0x00));
	munmap(ADDR,0x1000);
	close(device_pointer);
}

int main(int argc, char *argv[])
{
	srand(time(NULL));
	printf("Try anonyous mapping...\n");
	anonymous_mapping();
	printf("Try file mapping...\n");
	file_mapping();
	return 0;
}


