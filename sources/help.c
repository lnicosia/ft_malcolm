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
	printf("ft_malcolm version 1.0\n");
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

void		print_help()
{
	/* Header with ascii art and usage */
	print_random_art();
	print_usage(stdout);
	printf("\n");

	/* Content */
	examples();

	/* Footer with version */
	printf("\n");
	print_version();
}
