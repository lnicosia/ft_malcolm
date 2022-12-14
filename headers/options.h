#ifndef OPTIONS_H
# define OPTIONS_H

#include <getopt.h>

# define OPT_VERBOSE		(1UL << 0)
# define OPT_MANUAL			(1UL << 1)
# define OPT_NO_PERSISTENCY	(1UL << 2)
# define OPT_NUMERIC		(1UL << 3)
# define OPT_DURATION		(1UL << 4)
# define OPT_FREQUENCY		(1UL << 5)
# define OPT_SNIFF			(1UL << 6)
# define OPT_BROADCAST		(1UL << 7)
# define OPT_DENY			(1UL << 8)

#endif
