#include "../headers/malcolm.h"

/* Control-C */
void  inthandler(int sig)
{
	(void)sig;

	printf("\rQUITTING!\n");
	g_data.loop = 0;
	
}