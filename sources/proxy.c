#include "../headers/malcolm.h"
#include <sys/ioctl.h>
#include <net/if.h>

static int interface_index(char *name)
{
	int sockfd;
	struct ifreq if_idx;

	/* Open RAW socket to send on */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
		perror("socket");
		return -1;
	}

	ft_bzero(&if_idx, sizeof(struct ifreq));
	ft_strncpy(if_idx.ifr_name, name, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
		perror("SIOCGIFINDEX");
		return -1;
	}

	return if_idx.ifr_ifindex;
}

int ft_proxy(uint8_t *source_ip, uint8_t *target_ip)
{
	(void)source_ip;
	(void)target_ip;

	int len = sizeof(struct ethernet_hdr) + sizeof(struct arp_hdr);
	char buffer[len];
	int ret;
	struct sockaddr_ll src_addr;
	int if_idx;
	socklen_t addr_len = sizeof(struct sockaddr_ll);

	if ((if_idx = interface_index(g_data.interface)) < 0)
		return 1;

	printf("%s has index %d\n", g_data.interface, if_idx);

	ret = recvfrom(g_data.sockfd, buffer, len, 0,
		(struct sockaddr *)&src_addr, &addr_len);

	(void)ret;

	printf("PROTO: %d\n", ft_htons(src_addr.sll_protocol));
	printf("INDEX: %d\n", ft_htons(src_addr.sll_ifindex));
	printf("HATYPE: %d\n", src_addr.sll_hatype);
	printf("PKTTYPE: %d\n", src_addr.sll_pkttype);
	printf("HALEN: %d\n", src_addr.sll_halen);

	return 0;
}
