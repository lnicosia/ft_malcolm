#include "../headers/malcolm.h"

/* Control-C */
void  inthandler(int sig)
{
	g_data.loop = 0;

	/* Restoring old MAC */
	/* TODO: Must not restore by default (subject restriction) */

	if (sig == SIGINT)
		printf("\b\b  ");
	printf("\b \rQUITTING!\n");
}
