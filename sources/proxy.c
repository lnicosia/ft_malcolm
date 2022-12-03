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
		close(sockfd);
		return -1;
	}

	close(sockfd);
	return if_idx.ifr_ifindex;
}

static int interface_mac(char *name, uint8_t *ret)
{
	int sockfd;
	struct ifreq if_mac;
	struct sockaddr sockaddr;

	/* Open RAW socket to send on */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
		perror("socket");
		return -1;
	}

	ft_bzero(&if_mac, sizeof(struct ifreq));
	ft_strncpy(if_mac.ifr_name, name, IFNAMSIZ - 1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0) {
		perror("SIOCGIFHWADDR");
		close(sockfd);
		return -1;
	}
	sockaddr = *(struct sockaddr *)&if_mac.ifr_hwaddr;
	ft_memcpy(ret, sockaddr.sa_data, ETH_ADDR_LEN);

	close(sockfd);
	return 0;
}

static int interface_ip(char *name, uint8_t *ret)
{
	int sockfd;
	struct ifreq if_ip;
	struct sockaddr_in sockaddr;

	/* Open RAW socket to send on */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
		perror("socket");
		return -1;
	}

	ft_bzero(&if_ip, sizeof(struct ifreq));
	ft_strncpy(if_ip.ifr_name, name, IFNAMSIZ - 1);
	if (ioctl(sockfd, SIOCGIFADDR, &if_ip) < 0) {
		perror("SIOCGIFADDR");
		close(sockfd);
		return -1;
	}
	sockaddr = *(struct sockaddr_in *)&if_ip.ifr_addr;
	ft_memcpy(ret, (uint8_t*)&sockaddr.sin_addr, IP_ADDR_LEN);

	close(sockfd);
	return 0;
}

static int arp_request(uint8_t *tip, struct sockaddr_ll sockaddr,
	uint8_t *if_mac, uint8_t *if_ip)
{
	socklen_t addr_len = sizeof(struct sockaddr_ll);
	struct arp_packet packet = {0};
	int ret;
	/* TODO: Parse dynamically the broadcast MAC address ? */
	/* We assume the broadcast is always ff:ff:ff:ff:ff:ff */
	uint8_t brdcst[ETH_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

	/* Setting ETHERNET flags */
	packet.ethernet.type = ft_ntohs(ETH_P_ARP);

	/* Setting ARP flags */
	packet.arp.hrd = ft_htons(HARDWARE_ETHERNET);
	packet.arp.hln = ETH_ADDR_LEN;
	packet.arp.pln = IP_ADDR_LEN;
	packet.arp.pro = ft_htons(ETH_P_IP);
	packet.arp.op = ft_htons(ARP_REQUEST);

	/* Setting MAC addresses */
	/* Ethernet */
	ft_memcpy(packet.ethernet.dmac, brdcst, ETH_ADDR_LEN);
	ft_memcpy(packet.ethernet.smac, if_mac, ETH_ADDR_LEN);
	/* ARP */
	ft_memcpy(packet.arp.sha, if_mac, ETH_ADDR_LEN);

	/* Setting IP addresses */
	ft_memcpy(packet.arp.sip, if_ip, IP_ADDR_LEN);
	ft_memcpy(packet.arp.tip, tip, IP_ADDR_LEN);

	debug_packet(&packet.ethernet, &packet.arp);

	ret = sendto(g_data.sockfd, &packet, sizeof(struct arp_packet), 0,
		(struct sockaddr *)&sockaddr, addr_len);
	(void)ret;

	return 0;
}

int ft_proxy(uint8_t *source_ip, uint8_t *target_ip)
{
	// char buffer[len];
	struct sockaddr_ll sockaddr;
	int if_idx;
	uint8_t if_mac[ETH_ADDR_LEN] = {0};
	uint8_t if_ip[IP_ADDR_LEN] = {0};

	ft_bzero(&sockaddr, sizeof(struct sockaddr_ll));

	/* Getting interface informations */
	if ((if_idx = interface_index(g_data.interface)) < 0)
		return 1;
	if (interface_mac(g_data.interface, if_mac) < 0)
		return 1;
	if (interface_ip(g_data.interface, if_ip) < 0)
		return 1;

	/* Debug prints */
	/* printf("%s has index %d with MAC address ", g_data.interface, if_idx);
	print_mac(if_mac);
	printf(" and IP address ");
	fflush(stdout);
	print_ip(STDOUT_FILENO, if_ip);
	printf("\n"); */

	/* ret = recvfrom(g_data.sockfd, buffer, len, 0,
		(struct sockaddr *)&sockaddr, &addr_len); */

	/* Filling sockaddr_ll */
	sockaddr.sll_family = AF_PACKET;
	sockaddr.sll_protocol = htons(ETH_P_ALL);
	sockaddr.sll_ifindex = if_idx;
	sockaddr.sll_hatype = ARPHRD_ETHER;
	sockaddr.sll_pkttype = ARPHRD_NETROM;

	arp_request(source_ip, sockaddr, if_mac, if_ip);
	arp_request(target_ip, sockaddr, if_mac, if_ip);

	return 0;
}
