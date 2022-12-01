#include "../headers/malcolm.h"

/* Control-C */
void  inthandler(int sig)
{
	(void)sig;

	printf("\rQUITTING!");
	loop = 0;
	
}
