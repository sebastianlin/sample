

#include <stdio.h>
#include <unistd.h>

int spawn(char *prog, char **arg_list)
{
	pid_t child;

	child = fork();

	if (child != 0) {
		return child;
	} else {
		execvp(prog, arg_list);
		fprintf(stderr, "spawn error\n");
		return -1;
	}
}

int main()
{
	char *arg_list[] = {
		(char*)"ls",
		(char*)"-l",
		(char*)"/tmp",
		NULL };

	spawn((char*)"ls", arg_list);
}



