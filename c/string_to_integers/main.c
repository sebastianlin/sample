// Parse string input and convert it into a serial of integers

#include <string.h>
#include <stdio.h>

#define PARAM_COUNT	3

char test[][128] = {"1 2 3", "1 2 3 ", " 1 2 3", "1 2 ", "1 2", " 1 2", "1 2 3 4", "1x 2 3", "1 2 3x"};


int str_to_ints(char *buffer, int *input_array)
{
    char *token_ptr, *p, *endptr;
	int i=0;

	while(1) {
		token_ptr = strsep(&buffer, " ");
    
		if(!token_ptr) {
			if(i==PARAM_COUNT)
				break;
			else {
				printf("Input error. Not enough items.\n");
		        return -1;
			}
		}

		if(*token_ptr == 0)
			continue;

		if(i==PARAM_COUNT) {
			printf("Input error. More than %d items.\n", i);
			return -1;
		}
	    
	    input_array[i++] = strtoul(token_ptr, &endptr, 16);
	    if(*endptr != 0) {
			printf("Input error. Contain non-digital char.\n");
	        return -1;
		}
	}

	return 0;
}

int main(void)
{
	unsigned int input_array[PARAM_COUNT];
	int i;
	
	for(i=0; i<sizeof(test)/sizeof(test[0]); i++) {
		printf("\"%s\" test: ", test[i]);
		if(!str_to_ints(test[i], input_array))
			printf("\"%d\" \"%d\" \"%d\"\n", input_array[0], input_array[1], input_array[2]);
	}
}

