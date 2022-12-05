#include "../headers/malcolm.h"
#include <netinet/ip_icmp.h>

static void print_icmp(struct icmphdr *icmp)
{
	printf("TYPE: %d\n", icmp->type);
	printf("CODE: %d\n", icmp->code);
	printf("CHECKSUM: %x\n", ft_htons(icmp->checksum));
}

static int sniff_traffic(void *osef)
{
	/* TODO: Verbose */
	(void)osef;
	int l2fd;
	struct ethernet_hdr *ethernet;
	struct iphdr *ip;
	int len = 65535;
	char buffer[len];
	int ret;
	struct sockaddr_ll src_addr;
	socklen_t addr_len = sizeof(struct sockaddr_ll);

	ft_bzero(buffer, len);

	l2fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (l2fd < 0)
		fprintf(stderr, "[!] Failed to open layer 2 socket\n");

	while (g_data.loop) {
		ret = recvfrom(l2fd, buffer, len, MSG_DONTWAIT,
			(struct sockaddr *)&src_addr, &addr_len);
		if (ret > 0) {
			if (!filter_out(g_data.source_mac, src_addr.sll_addr, ETH_ADDR_LEN) ||
				!filter_out(g_data.target_mac, src_addr.sll_addr, ETH_ADDR_LEN)) {
				ethernet = (struct ethernet_hdr *)buffer;
				print_mac(src_addr.sll_addr);
				if (ft_htons(ethernet->type) == ETHERTYPE_IP) {
					ip = (struct iphdr *)(buffer + sizeof(struct ethernet_hdr));
					if (ip->protocol == IPPROTO_ICMP)
						print_icmp((struct icmphdr *)(buffer+(sizeof(struct ethernet_hdr)+sizeof(struct iphdr))));
				}

				fflush(stdout);
				printf("\n");
				ft_bzero(buffer, len);
			}
		}
	}

	(void)print_icmp;

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
