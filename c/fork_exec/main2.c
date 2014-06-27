

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

// dir: Change directory to "dir" and then execute the program
// wait_child: If parent should wait child.
int spawn(char *dir, char *prog, char **arg_list, int wait_child)
{
	pid_t child;

	child = fork();

	if (child != 0) {
		int status;
		if(wait_child)
			waitpid(child, &status, 0);
		if(WIFEXITED(status))
			return WEXITSTATUS(status);
		else
			return -1;
	} else {
		chdir(dir);
		execvp(prog, arg_list);
		fprintf(stderr, "spawn error\n");
		exit(-1);
	}
}

int main()
{
	char *arg_list[] = {
		(char*)"sleep",
		(char*)"5",
		NULL };

	spawn((char*)".", (char*)"sleep", arg_list, 0);
	puts("Parent print.");
}



