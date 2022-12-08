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

void		print_dusage(FILE *f)
{
	fprintf(f,
		"DEFAULT USAGE:\n"
		"  ft_malcolm [Source IP] [Target IP] [Interface] [Options]\n"
	);
}

void		print_musage(FILE *f)
{
	fprintf(f,
		"MANUAL USAGE:\n"
		"  ft_malcolm --manual [Source IP] [Source MAC] [Target IP] [Target MAC] [Options]\n"
	);
}

void		print_busage(FILE *f)
{
	fprintf(f,
		"BROADCAST USAGE:\n"
		"  ft_malcolm --broadcast [Source IP] [Interface] [Options]\n"
	);
}

void		print_usage(FILE *f)
{
	print_dusage(f);
	print_busage(f);
	print_musage(f);
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

static void modes()
{
	printf("MODES:\n"
			"  DEFAULT:\n"
			"    ft_malcolm [Source IP] [Target IP] [Interface] [Options]: Monitor/Proxy the communication between source and target host\n"
			"    Default mode will send ARP requests to get MAC addresses for both hosts\n"
			"    Both hosts will be spoofed persistently to redirect packets to us\n"
			"    You must only give IPv4 addresses when this option is active\n"
			"    Specifying an interface is mandatory for this mode\n"
			"    Note that persistency is always active (you can't specify --no-persistency)\n"
			"    At the end of the process, ARP cache of targets will be reset so it will work normally again\n"
			"    Be sure to enable kernel IP forwarding to allow packets redistribution: sysctl -w net.ipv4.ip_forward=1\n"
			"      EXEMPLE: ./ft_malcolm 172.17.0.1 172.17.0.3 eth0\n"
			"  BROADCAST:\n"
			"    ft_malcolm --broadcast [Source IP] [Interface] [Options]: Proxy the whole network\n"
			"    Works like the default's mode but spoof all machines within the network\n"
			"    You must only give the source IP since the target will be the broadcast\n"
			"    This mode will own the addresses of the broadcast address automatically\n"
			"    At the end of the process, ARP cache of the whole network will be reset so it will work normally again\n"
			"      EXEMPLE: ./ft_malcolm 172.17.0.1 eth0 -b\n"
			"  MANUAL:\n"
			"    ft_malcolm --manual [Source IP] [Source MAC] [Target IP] [Target MAC] [Options]\n"
			"    In this mode, malcolm won't send ARP requests to resolve IPs\n"
			"    You have control over MAC addresses by specifying them\n"
			"    When manual mode is selected, malcolm will wait for an ARP request to start the spoof process\n"
			"    Selecting an interface is not necessary, the interface will be set to the good one automatically\n"
			"    Malcolm won't spoof both hosts but only the target\n"
			"    By default, manual mode will spoof the target consistently, change this behavior with --no-persistency\n"
			"    EXEMPLE: ./ft_malcolm -m 172.17.0.1 66:66:66:66:66:66 172.17.0.2 02:42:ac:11:00:02\n"
	);
}

static void persistency()
{
	printf("PERSISTENCY:\n"
			"  --no-persistency: Do not keep the spoofing alive\n"
			"  By default, malcolm keeps the spoofing alive by resending ARP requests every 2 seconds (2 seconds by default)\n"
			"  The request rate can be changed with the option -f --frequency [time (in second)]\n"
			"  The no persistency option denies this behavior by only responding to ARP request once\n"
			"  Note that the --no-persistency option is only available with the -m --manual mode\n"
	);
}

static void duration()
{
	printf("DURATION:\n"
			"  -d --duration [time (in seconds)]: Duration of the spoofing process\n"
			"  Note that this option will be taken in consideration only when the persistency is enabled\n"
	);
}

static void misc()
{
	printf("MISC:\n"
			"  -i --interface [Interface Name]: Select the interface to use, only works with proxy mode\n"
			"  -f --frequency [Time]: Select (in seconds) the rate for ARP replies in --persistent and --proxy mode\n"
			"  -v --verbose: Displays informations about what ft_malcolm is doing\n"
			"  -h --help: Display the help menu\n"
			"  -V --version: Output the current version of this software\n"
			"  ft_malcolm requires root's privileges in order to open raw sockets\n"
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
	modes();
	persistency();
	duration();
	misc();
	examples();

	/* Footer with version */
	printf("\n");
	print_version();
}
