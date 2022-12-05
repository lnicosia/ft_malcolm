#include "../headers/malcolm.h"
#include "../headers/options.h"

t_data	g_data;

/* TODO: Check allowed functions and fd leaks */
int main(int ac, char **av)
{
	/* g_data default values */
	ft_bzero(&g_data, sizeof(g_data));
	g_data.frequency = 2; /* 2 Seconds */
	g_data.loop = 1; /* The loop is started by default */
	g_data.wait_loop_len = 4;
	g_data.wait_loop = "/|\\|";

	if (parse_option_line(ac, av))
		return -1;

	/* Permissions check */
	if (getuid() != 0) {
		fprintf(stderr, "%s must be run as root\nQUITTING!\n", av[0]);
		return 1;
	}

	/* TODO: Must handle error cases for arguments (emptys, etc...) */
	ft_malcolm();
	return 0;
}
