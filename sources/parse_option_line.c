#include "libft.h"
#include "malcolm.h"
#include "options.h"
#include <stdio.h>
#include <stdlib.h>

int		ft_atom(char *str, uint8_t *dest)
{
	char **split = ft_strsplit(str, ':');
	if (!split) {
		fprintf(stderr, "ft_strsplit fail\n");
	}
	int byte = 0;
	char **tmp = split;
	while (tmp && *tmp) {
		if (byte >= 6) {
			fprintf(stderr, "\nInvalid mac address %s (too many bytes)\n", str);
			free(split);
			return 1;
		}
		dest[byte] = ft_atoi_base(*tmp, "0123456789ABCDEF");
		byte++;
		tmp++;
	}
	printf("\n");
	free(split);
	return 0;
}

int		parse_option_line(int ac, char **av)
{
	int	opt, option_index = 0;
	char		*optarg = NULL;
	const char	*optstring = "hVpvcnd:f:";
	static struct option long_options[] = {
		{"help",		0,					0, 'h'},
		{"version",		0,					0, 'V'},
		{"proxy",		0,					0, 'p'},
		{"verbose",		0,					0, 'v'},
		{"consistent",	0,					0, 'c'},
		{"numeric",		0,					0, 'n'},
		{"duration",	required_argument,	0, 'd'},
		{"frequency",	required_argument,	0, 'f'},
		{0,				0,					0, 0}
	};
	while ((opt = ft_getopt_long(ac, av, optstring, &optarg,
					long_options, &option_index)) != -1) {
		switch (opt) {
			case 0:
				break;
			case 'h':
				print_help();
				return 1;
			case 'V':
				print_version();
				return 1;
			case 'p':
				g_data.opt |= OPT_PROXY;
				break;
			case 'v':
				g_data.opt |= OPT_VERBOSE;
				break;
			case 'c':
				g_data.opt |= OPT_CONSISTENT;
				break;
			case 'n':
				g_data.opt |= OPT_NUMERIC;
				break;
			case 'd':
				g_data.opt |= OPT_DURATION;
				break;
			case 'f':
				g_data.opt |= OPT_FREQUENCY;
				/* TODO: Must take value between 0-20 seconds*/
				break;
			default:
				return 1;
		}
	}
	int arg_count = 0;
	for (int i = 1; i < ac; i++) {
		if (!is_arg_an_opt(av, i, optstring, long_options)) {
			switch (arg_count) {
				case 0:
					{
						in_addr_t ip = inet_addr(av[i]);
						uint8_t *ptr = (uint8_t*)&ip;
						g_data.source_ip[0] = ptr[0];
						g_data.source_ip[1] = ptr[1];
						g_data.source_ip[2] = ptr[2];
						g_data.source_ip[3] = ptr[3];
						printf("Source ip = %s",
								inet_ntoa(*(struct in_addr*)&g_data.source_ip));
						arg_count++;
						break;
					}
				case 1:
					{
						if (ft_atom(av[i], g_data.source_mac))
							return 1;
						printf("Source mac = ");
						print_mac(g_data.source_mac);
						printf("\n");
						arg_count++;
						break;
					}
				case 2:
					{
						in_addr_t ip = inet_addr(av[i]);
						uint8_t *ptr = (uint8_t*)&ip;
						g_data.target_ip[0] = ptr[0];
						g_data.target_ip[1] = ptr[1];
						g_data.target_ip[2] = ptr[2];
						g_data.target_ip[3] = ptr[3];
						printf("Target ip = %s",
								inet_ntoa(*(struct in_addr*)&g_data.target_ip));
						arg_count++;
						break;
					}
				case 3:
					{
						if (ft_atom(av[i], g_data.target_mac))
							return 1;
						printf("Target mac = ");
						print_mac(g_data.target_mac);
						printf("\n");
						arg_count++;
						break;
					}
				default:
					break;
			}
		}
	}
	if (arg_count != 4) {
	}
	return 0;
}
