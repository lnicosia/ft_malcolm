#include "../headers/malcolm.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_arp.h>

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
	ft_strncpy(if_idx.ifr_name, name, IFNAMSIZ - 1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
		perror("SIOCGIFINDEX");
		return -1;
	}

	return if_idx.ifr_ifindex;
}

static uint8_t interface_mac(char *name)
{
	struct ifreq if_mac;

	ft_bzero(&if_mac, sizeof(struct ifreq));
	ft_strncpy(if_mac.ifr_name, name, IFNAMSIZ - 1);
	if (ioctl(sock, SIOCGIFHWADDR, &if_mac) < 0) {
		perror("SIOCGIFHWADDR");
		return -1;
	}

	return 0;
}

static int arp_request(uint8_t *ip, struct sockaddr_ll sockaddr)
{
	socklen_t addr_len = sizeof(struct sockaddr_ll);
	struct arp_packet packet = {0};

	/* Set the ARP opcode to reply */
	packet.arp.op = ft_htons(ARP_REPLY);

	/* Changing MAC addresses */
	ft_memcpy(packet.ethernet.dmac, packet.ethernet.smac, ETH_ADDR_LEN);
	ft_memcpy(packet.ethernet.smac, g_data.source_mac, ETH_ADDR_LEN);
	ft_memcpy(packet.arp.tha, packet.arp.sha, ETH_ADDR_LEN);
	ft_memcpy(packet.arp.sha, g_data.source_mac, ETH_ADDR_LEN);

	/* Swapping IP addresses */
	ft_memcpy(tmp_ip, packet.arp.sip, IP_ADDR_LEN);
	ft_memcpy(packet.arp.sip, packet.arp.tip, IP_ADDR_LEN);
	ft_memcpy(packet.arp.tip, tmp_ip, IP_ADDR_LEN);

	/* debug_packet(&packet.ethernet, &packet.arp); */

	ret = sendto(g_data.sockfd, &packet, sizeof(struct arp_packet), 0,
		(struct sockaddr *)&src_addr, addr_len);

	return 0;
}

int ft_proxy(uint8_t *source_ip, uint8_t *target_ip)
{
	// char buffer[len];
	int ret;
	struct sockaddr_ll sockaddr;
	int if_idx;

	ft_bzero(&sockaddr, sizeof(struct sockaddr_ll));

	if ((if_idx = interface_index(g_data.interface)) < 0)
		return 1;

	printf("%s has index %d\n", g_data.interface, if_idx);

	/* ret = recvfrom(g_data.sockfd, buffer, len, 0,
		(struct sockaddr *)&sockaddr, &addr_len); */

	(void)ret;

	/* Filling sockaddr_ll */
	sockaddr.sll_family = AF_PACKET;
	sockaddr.sll_protocol = htons(ETH_P_ALL);
	sockaddr.sll_ifindex = if_idx;
	sockaddr.sll_hatype = ARPHRD_ETHER;
	sockaddr.sll_pkttype = PACKET_HOST;

	arp_request(source_ip, sockaddr);
	arp_request(target_ip, sockaddr);

	return 0;
}