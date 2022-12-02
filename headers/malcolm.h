#ifndef MALCOLM_H
# define MALCOLM_H

#include "libft.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

/* ASCII ART */
#define DB_PATH "ascii/"
/* ******* */
#define ONE_FILENAME "1.ascii"
#define ASCII1 DB_PATH ONE_FILENAME
/* ******* */
#define TWO_FILENAME "2.ascii"
#define ASCII2 DB_PATH TWO_FILENAME

#define IP_ADDR_LEN		4	/* in bytes */
#define ETH_ADDR_LEN	6	/* in bytes */

/* Ethernet header */
struct ethernet_hdr {
	uint8_t		dmac[ETH_ADDR_LEN];	/* Destination mac address */
	uint8_t		smac[ETH_ADDR_LEN];	/* Source mac address */
	u_int16_t	type;				/* Ethertype: arp, rarp, ip ... */
};

#define HARDWARE_ETHERNET 0x1	/* Ethernet type */

#define ARP_REQUEST 1	/* ARP Request */
#define ARP_REPLY 2		/* ARP Reply */

/* Ethernet ARP packet from RFC 826 */
struct arp_hdr {
	uint16_t	hrd;				/* Hardware type */
	uint16_t	pro;				/* Protocol type */
	uint8_t		hln;				/* Length of hardware address */
	uint8_t		pln;				/* Length of protocol address */
	uint16_t	op;					/* ARP opcode (command) */
	uint8_t		sha[ETH_ADDR_LEN];	/* Sender hardware address */
	uint8_t		sip[IP_ADDR_LEN];	/* Sender IP address */
	uint8_t		tha[ETH_ADDR_LEN];	/* Target hardware address */
	uint8_t		tip[IP_ADDR_LEN];	/* Target IP address */
};

/* Full ARP packet over Ethernet */
struct arp_packet {
	struct ethernet_hdr ethernet;
	struct arp_hdr arp;
};

/* sockaddr_ll content */
/*
struct sockaddr_ll {
	unsigned short	sll_family;
	__be16		sll_protocol;
	int		sll_ifindex;
	unsigned short	sll_hatype;
	unsigned char	sll_pkttype;
	unsigned char	sll_halen;
	unsigned char	sll_addr[8];
};
*/

typedef struct	s_data
{
	uint8_t		source_ip[4];
	uint8_t		source_mac[6];
	uint8_t		target_ip[4];
	uint8_t		target_mac[6];
	uint8_t		original_mac[6]; /* Original mac of the target */

	uint8_t		loop;
	uint64_t	opt;

	int			sockfd;

	uint32_t	frequency; /* In seconds */
	uint32_t	duration; /* In seconds */
}				t_data;

extern t_data	g_data;

/* Macro functions */
#define ft_ntohs(netshort) (swap_uint16(netshort))
#define ft_htons(netshort) (swap_uint16(netshort))

/* signal.c */
void		inthandler(int sig);

/* print.c */
void		debug_packet(struct ethernet_hdr *ethernet, struct arp_hdr *arp);
void		print_ip(int fd, uint8_t *ip_address);
void		print_mac(uint8_t *mac);

/* help.c */
void		print_help();
void		print_usage(FILE *f);
void		print_version(void);

/* parse_option_line.c */
int			parse_option_line(int ac, char **av);


#endif
