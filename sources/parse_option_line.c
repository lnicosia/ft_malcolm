#include "../libft/libft.h"
#include "../headers/malcolm.h"
#include "options.h"
#include <stdio.h>
#include <stdlib.h>

static int		invalid_ip(char *str)
{
	char **split;
	int i = 0;
	int j = 0;
	int k = 0;
	int ret = 0;
	int byte = 0;
	int check = 0;

	while (str[k]) {
		if (str[k] == '.')
			check++;
		k++;
	}

	if (check != IP_ADDR_LEN-1) {
		fprintf(stderr, "Invalid IP address %s (invalid number of bytes)\n", str);
		return 1;
	}

	split = ft_strsplit(str, '.');
	if (!split) {
		fprintf(stderr, "ft_strsplit fail\n");
		return 1;
	}

	byte = 0;

	char **tmp = split;
	int len;
	int nb;
	while (tmp && *tmp) {
		j = 0;
		len = ft_strlen(*tmp);
		if (len < 1 || len > 3) {
			fprintf(stderr, "Invalid IP address %s (invalid format)\n", str);
			ret = 1;
			break;
		}
		nb = ft_atoi(*tmp);
		if (nb < 0 || nb > 255) {
			fprintf(stderr, "Invalid IP address %s (value error)\n", str);
			ret = 1;
			break;
		}
		while (j < len) {
			if (!ft_isdigit((*tmp)[j])) {
				fprintf(stderr, "Invalid IP address %s (invalid character)\n", str);
				ret = 1;
				break;
			}
			j++;
		}
		tmp++;
		byte++;
	}

	if (!ret && byte != IP_ADDR_LEN) {
		fprintf(stderr, "Invalid IP address %s (invalid number of bytes)\n", str);
		ret = 1;
	}

	while (split[i])
		free(split[i++]);
	free(split);

	return ret;
}

static int		ft_atom(char *str, uint8_t *dest)
{
	char **split = ft_strsplit(str, ':');
	int i = 0;
	int ret = 0;

	if (!split) {
		fprintf(stderr, "ft_strsplit fail\n");
		return 1;
	}

	int byte = 0;
	char **tmp = split;
	while (tmp && *tmp) {
		if (ft_strlen(*tmp) != 2) {
			fprintf(stderr, "Invalid mac address %s (invalid format)\n", str);
			ret = 1;
			break;
		}
		if (byte >= ETH_ADDR_LEN) {
			fprintf(stderr, "Invalid mac address %s (too many bytes)\n", str);
			ret = 1;
			break;
		}
		int j = 0;
		while ((*tmp)[j]) {
			(*tmp)[j] = ft_toupper((*tmp)[j]);
			if (!(((*tmp)[j] >= '0' && (*tmp)[j] <= '9') ||
				((*tmp)[j] >= 'A' && (*tmp)[j] <= 'F')))
			{
				fprintf(stderr, "Invalid mac address %s (bad value)\n", str);
				ret = 1;
				break;
			}
			j++;
		}
		dest[byte] = ft_atoi_base(*tmp, "0123456789ABCDEF");
		byte++;
		tmp++;
	}

	while (split[i])
		free(split[i++]);
	free(split);

	return ret;
}

static int		parse_manual(int *arg_count, char *arg)
{
	switch (*arg_count) {
		case 0:
			{
				if (invalid_ip(arg))
					return 1;
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
				if (invalid_ip(arg))
					return 1;
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

static int		parse_proxy(int *arg_count, char *arg)
{
	switch (*arg_count) {
		case 0:
			{
				if (invalid_ip(arg))
					return 1;
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
				if (g_data.opt & OPT_BROADCAST) {
					g_data.interface = arg;
					(*arg_count)++;
					break;
				}
				if (invalid_ip(arg))
					return 1;
				in_addr_t ip = inet_addr(arg);
				uint8_t *ptr = (uint8_t*)&ip;
				g_data.target_ip[0] = ptr[0];
				g_data.target_ip[1] = ptr[1];
				g_data.target_ip[2] = ptr[2];
				g_data.target_ip[3] = ptr[3];
				(*arg_count)++;
				break;
			}
		case 2:
			{
				g_data.interface = arg;
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
	const char	*optstring = "hVvsmbnd:f:";
	static struct option long_options[] = {
		{"help",			0,					0, 'h'},
		{"version",			0,					0, 'V'},
		{"verbose",			0,					0, 'v'},
		{"numeric",			0,					0, 'n'},
		{"manual",			0,					0, 'm'},
		{"sniff",			0,					0, 's'},
		{"broadcast",		0,					0, 'b'},
		{"duration",		required_argument,	0, 'd'},
		{"frequency",		required_argument,	0, 'f'},
		{"deny",			0,					0, 0},
		{"no-persistency",	0,					0, 0},
		{0,					0,					0, 0}
	};
	while ((opt = ft_getopt_long(ac, av, optstring, &optarg,
					long_options, &option_index)) != -1) {
		switch (opt) {
			case 0:
				if (ft_strequ(long_options[option_index].name, "no-persistency"))
					 g_data.opt |= OPT_NO_PERSISTENCY;
				else if (ft_strequ(long_options[option_index].name, "deny"))
					g_data.opt |= OPT_DENY;
				break;
			case 'h':
				print_help();
				return 1;
			case 'V':
				print_version();
				return 1;
			case 'm':
				g_data.opt |= OPT_MANUAL;
				break;
			case 'b':
				g_data.opt |= OPT_BROADCAST;
				break;
			case 's':
				g_data.opt |= OPT_SNIFF;
				break;
			case 'v':
				g_data.opt |= OPT_VERBOSE;
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

	int arg_count = 0;
	for (int i = 1; i < ac; i++) {
		if (!is_arg_an_opt(av, i, optstring, long_options)) {
			if (g_data.opt & OPT_MANUAL) {
				if (parse_manual(&arg_count, av[i]))
					return 1;
			}
			else {
				if (parse_proxy(&arg_count, av[i]))
					return 1;
			}
		}
	}
	if (!(g_data.opt & OPT_MANUAL)) {
		if (!(g_data.opt & OPT_BROADCAST) && arg_count != 3) {
			print_dusage(stderr);
			return 1;
		}
		else if (g_data.opt & OPT_BROADCAST && arg_count != 2) {
			print_busage(stderr);
			return 1;
		}
		if (g_data.opt & OPT_NO_PERSISTENCY) {
			fprintf(stderr,
				"--no-persistency is only available when manual mode is selected, QUITTING!\n");
			print_dusage(stderr);
			return 1;
		}
	}
	else {
		if (arg_count != 4) {
			print_musage(stderr);
			return 1;
		}
		if (g_data.opt & OPT_DENY) {
			fprintf(stderr,
				"--deny is not available when manual mode is selected, QUITTING!\n");
			print_musage(stderr);
			return 1;
		}
		if (g_data.opt & OPT_BROADCAST) {
			fprintf(stderr,
				"--broadcast -b is not available when manual mode is selected, QUITTING!\n");
			print_musage(stderr);
			return 1;
		}
		if (g_data.opt & OPT_SNIFF) {
			fprintf(stderr,
				"--sniffing -s is not available when manual mode is selected, QUITTING!\n");
			print_musage(stderr);
			return 1;
		}
	}
	return 0;
}
