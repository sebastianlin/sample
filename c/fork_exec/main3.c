

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

#define BUF_SIZE 16

void sig_handler(int signo)
{
	if (signo == SIGCHLD)
		wait(NULL);
}

// dir: Change directory to "dir" and then execute the program
// wait_child: If parent should wait child.
// pfd: parent process can build pipe with child process's stdin/stdout.
int spawn(char *dir, char *prog, char **arg_list, int wait_child, int in_pfd[2], int out_pfd[2])
{
	pid_t child;

	child = fork();

	if (child != 0) {
		int status=0;

		if(in_pfd)
			close(in_pfd[0]);
		if(out_pfd)
			close(out_pfd[1]);

		if(wait_child)
			waitpid(child, &status, 0);
		if(WIFEXITED(status))
			return WEXITSTATUS(status);
		else
			return -1;
	} else {
		chdir(dir);
		if(in_pfd) {
			dup2(in_pfd[0], STDIN_FILENO);
			close(in_pfd[0]);
			close(in_pfd[1]);
		}
		if(out_pfd) {
			dup2(out_pfd[1], STDOUT_FILENO);
			close(out_pfd[0]);
			close(out_pfd[1]);
		}
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
		(char*)"-la",
		(char*)"/tmp",
		NULL };
	int pfd[2];
	int i, len, status;
	char buf[BUF_SIZE];

	if (signal(SIGCHLD, sig_handler) == SIG_ERR) {
		printf("\ncan't register SIGCHLD\n");
		exit(-1);
	}

	if(pipe(pfd)<0)
		exit(-1);
	spawn((char*)".", (char*)"ls", arg_list, 0, NULL, pfd);
	while((len = read(pfd[0], buf, BUF_SIZE))>0)
			for(i=0; i<len; i++)
				printf("_%c", buf[i]);
	wait(&status);
}



