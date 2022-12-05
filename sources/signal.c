#include "../headers/malcolm.h"
#include "../headers/options.h"

/* Control-C */
void  inthandler(int sig)
{
	g_data.loop = 0;

	/* Restoring old MAC */
	/* TODO: Must not restore by default (subject restriction) */

	if (sig == SIGINT) {
		if (g_data.opt & OPT_VERBOSE)
			printf("\n[*] CTRL+C Pressed\n");
		else
			printf("\b\b  ");
	}
	else if (sig == SIGALRM) {
	}
	printf("\b \rQUITTING!\n");
}
