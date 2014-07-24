#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

int main(void)
{
	fd_set rfds;
	struct timeval tv;
	int retval;

	// Turn off stream cache and "select" whould be precise.
	setvbuf(stdin, NULL, _IONBF, 0);

	while(1) {
		/* Watch stdin (fd 0) to see when it has input. */
		FD_ZERO(&rfds);
		FD_SET(0, &rfds);
	
		tv.tv_sec = 0;
		tv.tv_usec = 0;
		// The above lines should be executed in front of every "select"

		retval = select(1, &rfds, NULL, NULL, &tv);
		/* Don't rely on the value of tv now! */

		if (retval == -1)
			perror("select()");
		else if (retval) {
			getchar();
			fflush(stdout);
			/* FD_ISSET(0, &rfds) will be true. */
		} else {
			printf(".");
			fflush(stdout);
		}
		sleep(1);
	}
	
	exit(EXIT_SUCCESS);
}

