#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <termios.h>

static struct termios orig_termios;  /* TERMinal I/O Structure */

void tty_raw(int fd)
{
	struct termios raw;

	raw = orig_termios;  /* copy original and then modify below */

	/* input modes - clear indicated ones giving: no break, no CR to NL, 
	no parity check, no strip char, no start/stop output (sic) control */
	raw.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);

	/* output modes - clear giving: no post processing such as NL to CR+NL */
	raw.c_oflag &= ~(OPOST);

	/* control modes - set 8 bit chars */
	raw.c_cflag |= (CS8);

	/* local modes - clear giving: echoing off, canonical off (no erase with 
	backspace, ^U,...),  no extended functions, no signal chars (^Z,^C) */
	raw.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);

	/* control chars - set return condition: min number of bytes and timer */
	raw.c_cc[VMIN] = 5; raw.c_cc[VTIME] = 8; /* after 5 bytes or .8 seconds
						after first byte seen      */
	raw.c_cc[VMIN] = 0; raw.c_cc[VTIME] = 0; /* immediate - anything       */
	raw.c_cc[VMIN] = 2; raw.c_cc[VTIME] = 0; /* after two bytes, no timer  */
	raw.c_cc[VMIN] = 0; raw.c_cc[VTIME] = 8; /* after a byte or .8 seconds */

	/* put terminal in raw mode after flushing */
	if (tcsetattr(fd,TCSAFLUSH,&raw) < 0) puts("can't set raw mode");
}

int main(void)
{
	fd_set rfds;
	struct timeval tv;
	int retval;

	// Turn off stream buffer and "select" whould be precise.
	setvbuf(stdin, NULL, _IONBF, 0);
	// Switch tty from line mode to raw mode and then every input char can be detected by select.
	tty_raw(0);

	while(1) {
		/* Watch stdin (fd 0) to see when it has input. */
		FD_ZERO(&rfds);
		FD_SET(0, &rfds);
	
		tv.tv_sec = 0;
		tv.tv_usec = 0;
		// The above lines should be executed in front of every "select"

		retval = select(1, &rfds, NULL, NULL, &tv);
		/* Don't rely on the value of tv now! */

		if (retval == -1) {
			perror("select()");
			exit(-1);
		} else if (retval) {
			printf("%c", getchar());
			fflush(stdout);
			/* FD_ISSET(0, &rfds) will be true. */
		} else {
			printf(".");
			fflush(stdout);
			sleep(1);
		}
	}
	
	exit(EXIT_SUCCESS);
}

