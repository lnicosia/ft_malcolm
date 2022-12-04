#include "../headers/malcolm.h"
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>

static void		print_art(char *path)
{
	int fd = open(path, O_RDONLY);
	char *buf;

	if (fd == -1)
		return;

	while (get_next_line(fd, &buf) > 0) {
		printf("%s\n", buf);
		free(buf);
	}

	close(fd);
}

static void		print_random_art()
{
	int rand = ft_random(1, 4096);

	if (rand % 2)
		print_art(ASCII1);
	else
		print_art(ASCII2);
}

void		print_version(void)
{
	printf("lumenthi and lnicosia's ft_malcolm version 1.0 (https://github.com/lnicosia/ft_malcolm)\n"
			"This program is free software; you may redistribute it\n"
			"This program has absolutely no warranty\n"
	);
}

void		print_usage(FILE *f)
{
	fprintf(f,
		"USAGE:\n"
		"  ft_malcolm [Source IP] [Source MAC] [Target IP] [Target MAC] [Options]\n"
	);
}

static void examples()
{
	printf("EXAMPLES:\n"
			"  sudo ./ft_malcolm 172.17.0.1 66:66:66:66:66:66 172.17.0.2 02:42:ac:11:00:02\n"
			"  sudo ./ft_malcolm -P 172.17.0.2 172.17.0.3 -i docker0\n"
			"  sudo ./ft_malcolm -P 192.168.1.20 192.168.1.34 -i eth0 -d 60 -f 1\n"
			"  sudo ./ft_malcolm 110.24.10.5 54:10:78:ab:45:60 110.24.10.17 41:64:25:11:00:02 -p\n"
	);
}

static void source_specification()
{
	printf("SOURCE SPECIFICATION:\n"
			"  Source IP is the IPv4 address of the host you wish to intercept packets for\n"
			"  Source MAC is the hardware address of the host you wish to redirect packets to\n"
	);
}

static void target_specification()
{
	printf("TARGET SPECIFICATION:\n"
		"  Target IP is the IPv4 address of the host to poison\n"
		"  Target MAC is the MAC address of the host to poison\n"
	);
}

static void formatting()
{
	printf("FORMATTING:\n"
			"  IPv4 addresses must be valid IPs under this format: 172.17.0.1\n"
			"  Hardware addresses must be valid MACs under this format: 12:34:56:78:9a:bc\n"
	);
}

void		print_help()
{
	/* Header with ascii art and usage */
	print_random_art();
	print_usage(stdout);
	printf("\n");

	/* Content */
	source_specification();
	target_specification();
	formatting();
	examples();

	/* Footer with version */
	printf("\n");
	print_version();
}
