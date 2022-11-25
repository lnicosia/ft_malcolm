#ifndef MALCOLM_H
# define MALCOLM_H

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>

#define IP_ADDR_LEN		4	/* in bytes */
#define ETH_ADDR_LEN	6	/* in bytes */

/* Ethernet header */
struct ethernet_hdr {
	u_char		ether_dmac[ETH_ADDR_LEN];	/* Destination mac address */
	u_char		ether_smac[ETH_ADDR_LEN];	/* Source mac address */
	u_int16_t	ether_type;					/* Ethertype: arp, rarp, ip ... */
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

#endif
