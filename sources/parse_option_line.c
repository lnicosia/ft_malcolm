#include "../libft/libft.h"
#include "../headers/malcolm.h"
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
	int i = 0;
	while (split[i])
		free(split[i++]);
	free(split);
	return 0;
}

int		parse_mac(int *arg_count, char *arg)
{
	switch (*arg_count) {
		case 0:
			{
				in_addr_t ip = inet_addr(arg);
				uint8_t *ptr = (uint8_t*)&ip;
				g_data.source_ip[0] = ptr[0];
				g_data.source_ip[1] = ptr[1];
				g_data.source_ip[2] = ptr[2];
				g_data.source_ip[3] = ptr[3];
				(*arg_count)++;
			break;
			}
		case 1:
			{
				if (ft_atom(arg, g_data.source_mac))
					return 1;
				(*arg_count)++;
				break;
			}
		case 2:
			{
				in_addr_t ip = inet_addr(arg);
				uint8_t *ptr = (uint8_t*)&ip;
				g_data.target_ip[0] = ptr[0];
				g_data.target_ip[1] = ptr[1];
				g_data.target_ip[2] = ptr[2];
				g_data.target_ip[3] = ptr[3];
				(*arg_count)++;
				break;
			}
		case 3:
			{
				if (ft_atom(arg, g_data.target_mac))
					return 1;
				(*arg_count)++;
				break;
			}
		default:
			(*arg_count)++;
			break;
	}
	return 0;
}

int		parse_proxy(int *arg_count, char *arg)
{
	switch (*arg_count) {
		case 0:
			{
				in_addr_t ip = inet_addr(arg);
				uint8_t *ptr = (uint8_t*)&ip;
				g_data.source_ip[0] = ptr[0];
				g_data.source_ip[1] = ptr[1];
				g_data.source_ip[2] = ptr[2];
				g_data.source_ip[3] = ptr[3];
				(*arg_count)++;
				break;
			}
		case 1:
			{
				in_addr_t ip = inet_addr(arg);
				uint8_t *ptr = (uint8_t*)&ip;
				g_data.target_ip[0] = ptr[0];
				g_data.target_ip[1] = ptr[1];
				g_data.target_ip[2] = ptr[2];
				g_data.target_ip[3] = ptr[3];
				(*arg_count)++;
				break;
			}
		default:
			(*arg_count)++;
			break;
	}
	return 0;
}

int		parse_option_line(int ac, char **av)
{
	int	opt, option_index = 0;
	char		*optarg = NULL;
	const char	*optstring = "hVpvPnd:f:i:";
	static struct option long_options[] = {
		{"help",		0,					0, 'h'},
		{"version",		0,					0, 'V'},
		{"proxy",		0,					0, 'P'},
		{"verbose",		0,					0, 'v'},
		{"persistent",	0,					0, 'p'},
		{"numeric",		0,					0, 'n'},
		{"duration",	required_argument,	0, 'd'},
		{"frequency",	required_argument,	0, 'f'},
		{"interface",	required_argument,	0, 'i'},
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
			case 'i':
				g_data.opt |= OPT_INTERFACE;
				g_data.interface = optarg;
				break;
			case 'P':
				g_data.opt |= OPT_PROXY;
				g_data.opt &= ~OPT_PERSISTENT;
				break;
			case 'v':
				g_data.opt |= OPT_VERBOSE;
				break;
			case 'p':
				g_data.opt |= OPT_PERSISTENT;
				g_data.opt &= ~OPT_PROXY;
				break;
			case 'n':
				g_data.opt |= OPT_NUMERIC;
				break;
			case 'd':
				g_data.opt |= OPT_DURATION;
				int tmp_duration = ft_atoi(optarg);
				if (tmp_duration < 0) {
					fprintf(stderr, "Duration must be positive\n");
					return 1;
				}
				g_data.duration = tmp_duration;
				break;
			case 'f':
				g_data.opt |= OPT_FREQUENCY;
				int tmp_frequency = ft_atoi(optarg);
				if (tmp_frequency < 0 || tmp_frequency > 20) {
					fprintf(stderr, "Frequency must be between 0 and 20 seconds\n");
					return 1;
				}
				g_data.frequency = tmp_frequency;
				break;
			default:
				return 1;
		}
	}

	if (g_data.opt & OPT_PROXY && !(g_data.opt & OPT_INTERFACE)) {
		fprintf(stderr,
			"You must select an interface for proxying between 2 hosts\n"
			"QUITTING!\n"
		);
		return 1;
	}

	int arg_count = 0;
	for (int i = 1; i < ac; i++) {
		if (!is_arg_an_opt(av, i, optstring, long_options)) {
			if (g_data.opt & OPT_PROXY)
				parse_proxy(&arg_count, av[i]);
			else
				parse_mac(&arg_count, av[i]);
		}
	}
	if (g_data.opt & OPT_PROXY) {
		if (arg_count != 2) {
			print_usage(stderr);
			return 1;
		}
	}
	else if (arg_count != 4) {
		print_usage(stderr);
		return 1;
	}
	return 0;
}
