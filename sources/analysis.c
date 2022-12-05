#include "../headers/malcolm.h"

static int sniff_traffic(void *osef)
{
	/* TODO: Verbose */
	(void)osef;
	int tcpfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	int udpfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	int icmpfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

	int len = 65535;
	char buffer[len];
	int ret;
	struct sockaddr_ll src_addr;
	socklen_t addr_len = sizeof(struct sockaddr_ll);

	ft_bzero(buffer, len);

	if (tcpfd < 0)
		fprintf(stderr, "[!] Failed to open TCP socket\n");
	if (udpfd < 0)
		fprintf(stderr, "[!] Failed to open UDP socket\n");
	if (icmpfd < 0)
		fprintf(stderr, "[!] Failed to open ICMP socket\n");

	while (g_data.loop) {
		ret = recvfrom(tcpfd, buffer, len, MSG_DONTWAIT,
			(struct sockaddr *)&src_addr, &addr_len);
		if (ret > 0) {
			ft_bzero(buffer, len);
		}
		ret = recvfrom(udpfd, buffer, len, MSG_DONTWAIT,
			(struct sockaddr *)&src_addr, &addr_len);
		if (ret > 0) {
			ft_bzero(buffer, len);
		}
		ret = recvfrom(icmpfd, buffer, len, MSG_DONTWAIT,
			(struct sockaddr *)&src_addr, &addr_len);
		if (ret > 0) {
			ft_bzero(buffer, len);
		}
	}

	close(tcpfd);
	close(udpfd);
	close(icmpfd);

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
