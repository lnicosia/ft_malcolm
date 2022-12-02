#include "../headers/malcolm.h"

/* Control-C */
void  inthandler(int sig)
{
	(void)sig;

	g_data.loop = 0;

	/* Restoring old MAC */
	/* TODO: Must not restore by default (subject restriction) */

	close(g_data.sockfd);

	printf("\rQUITTING!\n");
}
