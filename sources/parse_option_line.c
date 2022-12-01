#include "libft.h"
#include <stdio.h>

void	print_usage(FILE *f)
{
	fprintf(f, "Usage:\n");
}

void	print_version(FILE *f)
{
	fprintf(f, "ft_malcolm version 0.1\n");
}

int	parse_option_line(int ac, char **av)
{
	int	opt, option_index = 0;
	char		*optarg = NULL;
	const char	*optstring = "hV";
	static struct option long_options[] = {
		{"help",		0,					0, 'h'},
		{"version",		0,					0, 'V'},
		{0,				0,					0,	0 }
	};
	while ((opt = ft_getopt_long(ac, av, optstring, &optarg,
					long_options, &option_index)) != -1) {
		switch (opt) {
			case 0:
				break;
			case 'h':
				print_usage(stdout);
				return 1;
			case 'V':
				print_version(stdout);
				return 1;
			default:
				return 1;
		}
	}
	return 0;
}
