

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

void sig_handler(int signo)
{
	if (signo == SIGCHLD)
		wait(NULL);
}

int spawn(char *prog, char **arg_list)
{
	pid_t child;

	child = fork();

	if (child != 0) {
		return child;
	} else {
		execvp(prog, arg_list);
		fprintf(stderr, "spawn error\n");
		perror("");
		exit(-1);
	}
}

int main()
{
	char *arg_list[] = {
		(char*)"ls",
		(char*)"-l",
		(char*)"/tmp",
		NULL };

	if (signal(SIGCHLD, sig_handler) == SIG_ERR) {
		printf("\ncan't register SIGCHLD\n");
		exit(-1);
	}

	spawn((char*)"ls", arg_list);
	puts("Parent end.");
}



