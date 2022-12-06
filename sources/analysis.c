#include "../headers/malcolm.h"
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

static void	print_tcp_flags(struct tcphdr *header)
{
	int	count;
	int	first;

	count = 0;
	if (header->th_flags & TH_FIN)
		count++;
	if (header->th_flags & TH_SYN)
		count++;
	if (header->th_flags & TH_RST)
		count++;
	if (header->th_flags & TH_PUSH)
		count++;
	if (header->th_flags & TH_ACK)
		count++;
	if (header->th_flags & TH_URG)
		count++;
	first = 0;
	if (header->th_flags & TH_FIN) {
		if (first > 0)
			dprintf(STDOUT_FILENO, "|");
		dprintf(STDOUT_FILENO, "FIN");
		first++;
	}
	if (header->th_flags & TH_SYN) {
		if (first > 0)
			dprintf(STDOUT_FILENO, "|");
		dprintf(STDOUT_FILENO, "SYN");
		first++;
	}
	if (header->th_flags & TH_RST) {
		if (first > 0)
			dprintf(STDOUT_FILENO, "|");
		dprintf(STDOUT_FILENO, "RST");
		first++;
	}
	if (header->th_flags & TH_PUSH) {
		if (first > 0)
			dprintf(STDOUT_FILENO, "/");
		dprintf(STDOUT_FILENO, "PUSH");
		first++;
	}
	if (header->th_flags & TH_ACK) {
		if (first > 0)
			dprintf(STDOUT_FILENO, "|");
		dprintf(STDOUT_FILENO, "ACK");
		first++;
	}
	if (header->th_flags & TH_URG) {
		if (first > 0)
			dprintf(STDOUT_FILENO, "|");
		dprintf(STDOUT_FILENO, "URG");
		first++;
	}
}

static void print_icmp(struct icmphdr *icmp, struct iphdr *ip)
{
	dprintf(STDOUT_FILENO, "%s:", inet_ntoa(*(struct in_addr*)&ip->saddr));
	if (icmp->type == ICMP_ECHOREPLY)
		dprintf(STDOUT_FILENO, " ICMP Reply to ");
	else if (icmp->type == ICMP_ECHO)
		dprintf(STDOUT_FILENO, " ICMP Request to ");
	else
		dprintf(STDOUT_FILENO, " ICMP Code %d to ", icmp->code);	
	dprintf(STDOUT_FILENO, "%s\n", inet_ntoa(*(struct in_addr*)&ip->daddr));
}

static void print_tcp(struct tcphdr *tcp, struct iphdr *ip, ssize_t payload_size)
{
	(void)print_tcp_flags;
	(void)ip;
	/*dprintf(STDOUT_FILENO, "%d TCP", ft_ntohs(tcp->th_sport));
	//print_tcp_flags(tcp);
	dprintf(STDOUT_FILENO, " to %s:%d",
		inet_ntoa(*(struct in_addr*)&ip->daddr), ft_ntohs(tcp->th_dport));*/
	if (payload_size > 0) {
		char *payload = (char*)(tcp + 1);
		char *location = ft_strstr(payload, "Location");
		if (location) {
			char *endl = ft_strchr(location, '\n');
			if (endl)
				*endl = 0;
			dprintf(STDOUT_FILENO, "Accessing %s\n", location);
		}
	}
	/*ssize_t i = 0;
	char *payload = (char*)(tcp + 1);
	while (i < payload_size) {
		if (ft_isprint(payload[i]))
			dprintf(STDOUT_FILENO, "%c", payload[i]);
		i++;
	}*/
}

static void print_udp(struct udphdr *udp, struct iphdr *ip)
{
	dprintf(STDOUT_FILENO, "%s:", inet_ntoa(*(struct in_addr*)&ip->saddr));
	dprintf(STDOUT_FILENO, "%d UDP", ft_ntohs(udp->uh_sport));
	dprintf(STDOUT_FILENO, " to %s:%d\n",
		inet_ntoa(*(struct in_addr*)&ip->daddr), ft_ntohs(udp->uh_dport));
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
				//print_mac(src_addr.sll_addr);
				if (ft_htons(ethernet->type) == ETHERTYPE_IP) {
					ip = (struct iphdr *)(buffer + sizeof(struct ethernet_hdr));
					void *layer4 = buffer + sizeof(struct ethernet_hdr)
						+ sizeof(struct iphdr);
					if (ip->protocol == IPPROTO_ICMP)
						print_icmp(layer4, ip);
					else if (ip->protocol == IPPROTO_TCP)
						print_tcp(layer4, ip, ret - sizeof(struct ethernet_hdr) + sizeof(struct iphdr) + sizeof(struct tcphdr));
					//else if (ip->protocol == IPPROTO_UDP)
					//	print_udp(layer4, ip);
					(void)print_udp;
				}

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
