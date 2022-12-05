#include "libft.h"
#include "malcolm.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>

int		resolve_hostname(char *hostname, uint8_t *dest_ip)
{
	int		ret;

	struct addrinfo *ai;
	struct addrinfo hints;
	ft_bzero(&hints, sizeof(hints));
	ai = NULL;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_flags = AI_CANONNAME;
	if ((ret = getaddrinfo(hostname, NULL, &hints, &ai)))
	{
		dprintf(STDERR_FILENO, "ft_ping: %s: %s\n",
			hostname, gai_strerror(ret));
		return 1;
	}
	struct addrinfo *tmp = ai;
	while (tmp)
	{
		if (tmp->ai_family == AF_INET)
		{
			struct sockaddr_in *ip4 = (struct sockaddr_in*)tmp->ai_addr;
			ft_memcpy(dest_ip, &ip4->sin_addr, sizeof(*ip4));
			break;
		}
		else if (tmp->ai_family == AF_INET6)
		{
		}
		tmp = tmp->ai_next;
	}
	freeaddrinfo(ai);
	return 0;
}
