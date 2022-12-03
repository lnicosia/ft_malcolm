#include "../headers/malcolm.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_arp.h>

int interface_index(char *name)
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

int interface_mac(char *name, uint8_t *ret)
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

int interface_ip(char *name, uint8_t *ret)
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
