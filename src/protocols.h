/*
    voiphopper - VoIP Hopper
    Copyright (C) 2012 Jason Ostrom <jpo@pobox.com>

    This file is part of VoIP Hopper.

    VoIP Hopper is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    VoIP Hopper is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/


#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>

/* ************************************************************
 * Ethernet Frames
 * ************************************************************/
typedef struct {
    struct ether_addr   daddr;
    struct ether_addr   saddr;
    u_int16_t           length;
} etherIIhdr_t;

/* IEEE 802.3, LLC related structs */
struct eth_ieee802_3 {
    struct ether_addr   daddr;
    struct ether_addr   saddr;
    u_int16_t           length;
};

/* Ethernet II, for spoofing LLDP */
struct eth_lldp {
    struct ether_addr	daddr;
    struct ether_addr	saddr;
    u_int16_t		type;
};

struct eth_LLC {
    u_int8_t            DSAP;
    u_int8_t            SSAP;
    u_int8_t            Control;
    u_int8_t            orgcode[3];
    u_int16_t           proto;
};

struct eth_LLC_short {
    u_int8_t            DSAP;
    u_int8_t            SSAP;
    u_int8_t            Control;
    u_int8_t            orgcode[3];
    u_int16_t           proto;
};

/* ************************************************************
 * CDP frames
 * ************************************************************/

/* LLDP Chassis Subtype */
struct lldpchassisid {
    u_int8_t	tlvtype;
    u_int8_t	tlvlength;
    u_char	value[7];
};

struct lldpportid {
    u_int8_t    tlvtype;
    u_int8_t    tlvlength;
    u_char      value[16];
};

struct lldpportid_a {
    u_int8_t    tlvtype;
    u_int8_t    tlvlength;
    u_char      value[7];
};

struct lldpttl {
    u_int8_t    tlvtype;
    u_int8_t    tlvlength;
    u_int16_t   value;
};

struct lldpendpdu {
    u_int8_t    tlvtype;
    u_int8_t    tlvlength;
};

struct lldpportdesc {
    u_int8_t    tlvtype;
    u_int8_t    tlvlength;
    u_char      value[7];
};

struct lldpsname {
    u_int8_t    tlvtype;
    u_int8_t    tlvlength;
    u_char      value[25];
};

struct lldpcaps {
    u_int8_t    tlvtype;
    u_int8_t    tlvlength;
    u_char      value[4];
};

struct lldpmacphy {
    u_int8_t    tlvtype;
    u_int8_t    tlvlength;
    u_char      value[9];
};

struct lldpmediacaps {
    u_int8_t    tlvtype;
    u_int8_t    tlvlength;
    u_char      value[7];
};

struct lldpnetworkpolicy {
    u_int8_t    tlvtype;
    u_int8_t    tlvlength;
    u_char      value[8];
};

//struct lldpextpvm { /* TIA Extended Power-via-MDI */
struct lldpextpvm {
    u_int8_t    tlvtype;
    u_int8_t    tlvlength;
    u_char      value[7];
};

//struct inventoryhr { /* TIA - Inventory - Hardware Revision */
struct lldpinventoryhr {
    u_int8_t    tlvtype;
    u_int8_t    tlvlength;
    u_char      value[5];
}; 

struct lldpinventoryfr { /* TIA - Inventory - Firmware Revision */
    u_int8_t    tlvtype;
    u_int8_t    tlvlength;
    u_char      value[24];
};

struct lldpinventorysr { /* TIA - Inventory - Software Revision */
    u_int8_t    tlvtype;
    u_int8_t    tlvlength;
    u_char      value[20];
};

struct lldpinventorysn { /* TIA - Inventory - Serial Number */
    u_int8_t    tlvtype;
    u_int8_t    tlvlength;
    u_char      value[15];
};

struct lldpinventorymn { /* TIA - Inventory - Manufacturer Name */
    u_int8_t    tlvtype;
    u_int8_t    tlvlength;
    u_char      value[23];
};

struct lldpinventorymodelname { /* TIA - Inventory - Model Name */
    u_int8_t    tlvtype;
    u_int8_t    tlvlength;
    u_char      value[15];
};

struct lldpinventoryai { /* TIA - Inventory - Asset ID */
    u_int8_t    tlvtype;
    u_int8_t    tlvlength;
    u_char      value[4];
};

/* CDP header */
struct cdphdr {
    u_int8_t            version;
    u_int8_t            ttl;
    u_int16_t           checksum;
};
/* CDP sections */
#define TYPE_DEVICE_ID          0x0001
#define TYPE_ADDRESS            0x0002
#define TYPE_PORT_ID            0x0003
#define TYPE_CAPABILITIES       0x0004
#define TYPE_IOS_VERSION        0x0005
#define TYPE_PLATFORM           0x0006
#define TYPE_VOIPVLANQUERY      0x000f
#define TYPE_DUPLEX             0x000b
#define TYPE_POWER              0x0010

struct cdp_device {
    u_int16_t           type;           /* 0x0001 */
    u_int16_t           length;
    u_char              device;         /* pointer to device name */
};

struct cdp_address {
    u_int16_t           type;           /* 0x0002 */
    u_int16_t           length;
    u_int32_t           number;         /* number of addresses */
};

struct cdp_address_entry {
    u_int8_t            proto_type;     /* 0x1 for NLPID */
    u_int8_t            length;         /* 0x1 for IP */
    u_int8_t            proto;          /* 0xCC for IP */
    u_int8_t            addrlen[2];
    u_char              addr;
};

struct cdp_port {
    u_int16_t           type;           /* 0x0003 */
    u_int16_t           length;
    u_char              port;           /* pointer to port name */
};

#define CDP_CAP_LEVEL1          0x40
#define CDP_CAP_FORWARD_IGMP    0x20
#define CDP_CAP_NETWORK_LAYER   0x10
#define CDP_CAP_LEVEL2_SWITCH   0x08
#define CDP_CAP_LEVEL2_SRB      0x04
#define CDP_CAP_LEVEL2_TRBR     0x02
#define CDP_CAP_LEVEL3_ROUTER   0x01
struct cdp_capabilities {
    u_int16_t           type;           /* 0x0004 */
    u_int16_t           length;         /* is 8 */
    u_int32_t           capab;
};

struct cdp_software {
    u_int16_t           type;           /* 0x0005 */
    u_int16_t           length;
    u_char              software;       /* pointer to software string */
};

struct cdp_platform {
    u_int16_t           type;           /* 0x0006 */
    u_int16_t           length;
    u_char              platform;       /* pointer to platform string */
};
 
struct cdp_vvlanquery {
    u_int16_t           type;
    u_int16_t           length;
    u_char              vvlanquery;       /* pointer to voip vlan query string */
};

struct cdp_duplex {
    u_int16_t           type;         
    u_int16_t           length;
    u_char              duplex;       /* pointer to duplex byte */
};

struct cdp_power {
    u_int16_t           type;        
    u_int16_t           length;
    u_char              powerstring;       /* pointer to power string */
};



/* ************************************************************
 * ARP version 4
 * ************************************************************/
#define ARPOP_REQUEST   1               /* ARP request.  */
#define ARPOP_REPLY     2               /* ARP reply.  */
#define ARPOP_RREQUEST  3               /* RARP request.  */
#define ARPOP_RREPLY    4               /* RARP reply.  */
typedef struct {
    u_int16_t	hardware;
    u_int16_t	protocol;
    u_int8_t	hw_size;
    u_int8_t	proto_size;
    u_int16_t	opcode;
    u_int8_t	sha[ETH_ALEN];   	/* Sender hardware address.  */
    u_int8_t 	sip[4];	          	/* Sender IP address.  */
    u_int8_t 	tha[ETH_ALEN];   	/* Target hardware address.  */
    u_int8_t 	tip[4];          	/* Target IP address.  */
} arphdr_t;


/* ************************************************************
 * IP version 4
 * ************************************************************/
#define IPPROTO_IGRP    0x09
#define IPPROTO_EIGRP	0x58
#define IPPROTO_OSPF	0x59

#define IP_ADDR_LEN	4
typedef struct {
        u_int8_t        ihl:4,          /* header length */
                        version:4;      /* version */
        u_int8_t        tos;            /* type of service */
        u_int16_t       tot_len;        /* total length */
        u_int16_t       id;             /* identification */
        u_int16_t       off;            /* fragment offset field */
        u_int8_t        ttl;            /* time to live */
        u_int8_t        protocol;       /* protocol */
        u_int16_t       check;          /* checksum */
        struct in_addr  saddr;
        struct in_addr  daddr;  	/* source and dest address */
} iphdr_t;

/* ************************************************************
 * TCP
 * ************************************************************/
typedef struct {
    u_int16_t th_sport;         /* source port */
    u_int16_t th_dport;         /* destination port */
    u_int32_t th_seq;             /* sequence number */
    u_int32_t th_ack;             /* acknowledgement number */
#if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t th_x2:4;           /* (unused) */
    u_int8_t th_off:4;          /* data offset */
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t th_off:4;          /* data offset */
    u_int8_t th_x2:4;           /* (unused) */
#endif
    u_int8_t th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
    u_int16_t th_win;           /* window */
    u_int16_t th_sum;           /* checksum */
    u_int16_t th_urp;           /* urgent pointer */
} tcphdr_t;

struct pseudohdr {
    struct in_addr saddr;
    struct in_addr daddr;
    u_char zero;
    u_char protocol;
    u_short length;
    tcphdr_t tcpheader;
};

/* ************************************************************
 * UDP
 * ************************************************************/
typedef struct {
    u_int16_t	sport			__attribute__ ((packed));
    u_int16_t	dport			__attribute__ ((packed));
    u_int16_t	length			__attribute__ ((packed));
    u_int16_t	checksum		__attribute__ ((packed));
} udphdr_t;


/* ************************************************************
 * ICMP
 * ************************************************************/
#define ICMP_ECHOREPLY          0       /* Echo Reply                   */
#define ICMP_DEST_UNREACH       3       /* Destination Unreachable      */
#define ICMP_SOURCE_QUENCH      4       /* Source Quench                */
#define ICMP_REDIRECT           5       /* Redirect (change route)      */
#define ICMP_ECHO               8       /* Echo Request                 */
#define ICMP_ROUTER_ADVERT	9	/* router advertisement 	*/
#define ICMP_SOLICITATION	10	/* router solicitation		*/
#define ICMP_TIME_EXCEEDED      11      /* Time Exceeded                */
#define ICMP_PARAMETERPROB      12      /* Parameter Problem            */
#define ICMP_TIMESTAMP          13      /* Timestamp Request            */
#define ICMP_TIMESTAMPREPLY     14      /* Timestamp Reply              */
#define ICMP_INFO_REQUEST       15      /* Information Request          */
#define ICMP_INFO_REPLY         16      /* Information Reply            */
#define ICMP_ADDRESS            17      /* Address Mask Request         */
#define ICMP_ADDRESSREPLY       18      /* Address Mask Reply           */
/* Codes for REDIRECT. */
#define ICMP_REDIR_NET          0       /* Redirect Net                 */
#define ICMP_REDIR_HOST         1       /* Redirect Host                */
#define ICMP_REDIR_NETTOS       2       /* Redirect Net for TOS         */
#define ICMP_REDIR_HOSTTOS      3       /* Redirect Host for TOS        */
/* codes for unreach */
#define ICMP_UNREACH_NET	0
#define ICMP_UNREACH_HOST	1
#define ICMP_UNREACH_PROTO	2	/* protocol unreachable 	*/
#define ICMP_UNREACH_PORT	3	/* port unreachable 		*/
#define ICMP_UNREACH_FRAG	4	/* fragmentation needed and DF	*/
#define ICMP_UNREACH_SOURCE	5	/* source route failed 		*/
#define ICMP_UNREACH_ADMIN1	9	/* administratively prohibited	*/
#define ICMP_UNREACH_TOS	11	/* unreach fro TOS		*/
#define ICMP_UNREACH_FIREWALL	13	/* port filtered 		*/
