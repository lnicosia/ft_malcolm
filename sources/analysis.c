#include "../headers/malcolm.h"

static int sniff_traffic(void *osef)
{
	/* TODO: Verbose */
	(void)osef;
	int l2fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	int len = 65535;
	char buffer[len];
	int ret;
	struct sockaddr_ll src_addr;
	socklen_t addr_len = sizeof(struct sockaddr_ll);

	ft_bzero(buffer, len);

	if (l2fd < 0)
		fprintf(stderr, "[!] Failed to open layer 2 socket\n");

	while (g_data.loop) {
		ret = recvfrom(l2fd, buffer, len, MSG_DONTWAIT,
			(struct sockaddr *)&src_addr, &addr_len);
		if (ret > 0) {
			ft_bzero(buffer, len);
			printf("\rRECEIVED      \n");
		}
	}

	close(l2fd);

	return 0;
}

int launch_thread(pthread_t *thread)
{
	if (pthread_create(thread, NULL,
		(void*)sniff_traffic, NULL) != 0)
	{
		return -1;
	}

	return 0;
}
