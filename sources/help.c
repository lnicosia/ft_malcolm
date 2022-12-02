#include "malcolm.h"
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

void		print_random_art()
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
		"  ft_malcolm [Target(s)] [Options]\n"
	);
}

void		print_help()
{
	/* Header with ascii art and usage */
	print_random_art();
	print_usage(stdout);
	printf("\n");

	/* Content */

	/* Footer with version */
	printf("\n");
	print_version();
}
