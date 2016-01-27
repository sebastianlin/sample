

#include <string.h>
#include <pthread.h>
#include <stdio.h>

//The function we want to make the thread run.
void task(void *msg)
{
	printf("%s running.\n", (char*)msg);
	while(1);
}

int main()
{
	int ret;
	pthread_t id1, id2;
	char *data1="Task1", *data2="Task2";

	// Constructs the new thread and runs it. Does not block execution.
	ret=pthread_create(&id1, NULL, (void *) &task, (void *) data1);
	ret=pthread_create(&id2, NULL, (void *) &task, (void *) data2);
	
	//Makes the main thread wait for the new thread to finish execution, therefore blocks its own execution.
	pthread_join(id1, NULL);
	pthread_join(id2, NULL);
}



