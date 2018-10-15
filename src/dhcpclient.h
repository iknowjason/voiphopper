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

#ifndef CLIENT_H
#define CLIENT_H

#ifdef __GLIBC__
#include <net/ethernet.h>
#include <linux/types.h>
#include <netinet/if_tr.h>
#else
#include <netinet/if_ether.h>
#define ETHERTYPE_IP		0x0800
#define ETHERTYPE_ARP		0x0806
#endif

#define IPPACKET_SIZE		1500
#define MAGIC_COOKIE		0x63825363
#define BROADCAST_FLAG		0x8000
#define MAC_BCAST_ADDR		"\xff\xff\xff\xff\xff\xff"
#ifndef AF_PACKET
#define AF_PACKET		17	/* should have been in socketbits.h */
#endif
#define CLASS_ID_MAX_LEN	48
#define CLIENT_ID_MAX_LEN	48
#define HOSTNAME_MAX_LEN	64
#define HWADDR_TRIES		3

/* UDP port numbers for DHCP */
#define	DHCP_SERVER_PORT	67	/* from client to server */
#define DHCP_CLIENT_PORT	68	/* from server to client */

/* DHCP message OP code */
#define DHCP_BOOTREQUEST	1
#define DHCP_BOOTREPLY		2

/* DHCP message type */
#define	DHCP_DISCOVER		1
#define DHCP_OFFER		2
#define	DHCP_REQUEST		3
#define	DHCP_DECLINE		4
#define	DHCP_ACK		5
#define DHCP_NAK		6
#define	DHCP_RELEASE		7
#define DHCP_INFORM		8
/* DHCP RETRANSMISSION TIMEOUT (microseconds) */
#define DHCP_INITIAL_RTO	(4*1000000)
#define DHCP_MAX_RTO		(64*1000000)

/* DHCP option and value (cf. RFC1533) */
enum
{
  padOption				=	0,
  subnetMask				=	1,
  timerOffset				=	2,
  routersOnSubnet			=	3,
  timeServer				=	4,
  nameServer				=	5,
  dns					=	6,
  logServer				=	7,
  cookieServer				=	8,
  lprServer				=	9,
  impressServer				=	10,
  resourceLocationServer		=	11,
  hostName				=	12,
  bootFileSize				=	13,
  meritDumpFile				=	14,
  domainName				=	15,
  swapServer				=	16,
  rootPath				=	17,
  extentionsPath			=	18,
  IPforwarding				=	19,
  nonLocalSourceRouting			=	20,
  policyFilter				=	21,
  maxDgramReasmSize			=	22,
  defaultIPTTL				=	23,
  pathMTUagingTimeout			=	24,
  pathMTUplateauTable			=	25,
  ifMTU					=	26,
  allSubnetsLocal			=	27,
  broadcastAddr				=	28,
  performMaskDiscovery			=	29,
  maskSupplier				=	30,
  performRouterDiscovery		=	31,
  routerSolicitationAddr		=	32,
  staticRoute				=	33,
  trailerEncapsulation			=	34,
  arpCacheTimeout			=	35,
  ethernetEncapsulation			=	36,
  tcpDefaultTTL				=	37,
  tcpKeepaliveInterval			=	38,
  tcpKeepaliveGarbage			=	39,
  nisDomainName				=	40,
  nisServers				=	41,
  ntpServers				=	42,
  vendorSpecificInfo			=	43,
  netBIOSnameServer			=	44,
  netBIOSdgramDistServer		=	45,
  netBIOSnodeType			=	46,
  netBIOSscope				=	47,
  xFontServer				=	48,
  xDisplayManager			=	49,
  dhcpRequestedIPaddr			=	50,
  dhcpIPaddrLeaseTime			=	51,
  dhcpOptionOverload			=	52,
  dhcpMessageType			=	53,
  dhcpServerIdentifier			=	54,
  dhcpParamRequest			=	55,
  dhcpMsg				=	56,
  dhcpMaxMsgSize			=	57,
  dhcpT1value				=	58,
  dhcpT2value				=	59,
  dhcpClassIdentifier			=	60,
  dhcpClientIdentifier			=	61,
  dhcpOption43				=	43,
  dhcpOption176				=	176,
  dhcpOption191				=	191,
  dhcpOption242				=	242,
  endOption				=	255
};

typedef struct dhcpInterface
{
  unsigned char	version[11];
  int		ciaddr;
  int		siaddr;
  int		class_len;
  int		client_len;
  unsigned int	xid;
  unsigned char	shaddr[ETH_ALEN];
  unsigned char	class_id[CLASS_ID_MAX_LEN];
  unsigned char	client_id[CLIENT_ID_MAX_LEN];
#if 0
  unsigned char chaddr[ETH_ALEN];
#endif
} dhcpInterface;

typedef struct dhcpMessage
{
  u_char  op;		/* message type */
  u_char  htype;	/* hardware address type */
  u_char  hlen;		/* hardware address length */
  u_char  hops;		/* should be zero in client's message */
  u_int   xid;		/* transaction id */
  u_short secs;		/* elapsed time in sec. from trying to boot */
  u_short flags;
  u_int   ciaddr;	/* (previously allocated) client IP address */
  u_int	  yiaddr;	/* 'your' client IP address */
  u_int	  siaddr;	/* should be zero in client's messages */
  u_int	  giaddr;	/* should be zero in client's messages */
  u_char  chaddr[16];	/* client's hardware address */
  u_char  sname[64];	/* server host name, null terminated string */
  u_char  file[128];	/* boot file name, null terminated string */
  u_char  options[312];	/* message options */
} __attribute__((packed)) dhcpMessage;

struct packed_ether_header {
  u_int8_t  ether_dhost[ETH_ALEN];      /* destination eth addr */
  u_int8_t  ether_shost[ETH_ALEN];      /* source ether addr    */
  u_int16_t ether_type;                 /* packet type ID field */
} __attribute__((packed));

typedef struct udpipMessage
{
  struct packed_ether_header	ethhdr;
  char	udpipmsg[IPPACKET_SIZE];
  char	pad_for_tokenring_header[sizeof(struct trh_hdr) + sizeof(struct trllc)];
} __attribute__((packed)) udpipMessage;

typedef struct dhcpOptions
{
  u_char num;
  u_char len[256];
  void   *val[256];
} __attribute__((packed)) dhcpOptions;

int peekfd(int s,int tv_usec);
void *dhcpReboot();
void *dhcpStart();
void *dhcpInit();
void *dhcpRequest(unsigned xid,void (*buildDhcpMsg)(unsigned));
void *dhcpBound();
void *dhcpRenew();
void *dhcpRebind();
void *dhcpRelease();
void *dhcpStop();
void *dhcpInform();
#ifdef ARPCHECK
void *dhcpDecline();
#endif

#endif
