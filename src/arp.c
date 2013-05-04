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

#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <string.h>
#include <syslog.h>
#include "dhcpclient.h"

typedef struct arpMessage
{
  struct packed_ether_header	ethhdr;
  u_short htype;	/* hardware type (must be ARPHRD_ETHER) */
  u_short ptype;	/* protocol type (must be ETHERTYPE_IP) */
  u_char  hlen;		/* hardware address length (must be 6) */
  u_char  plen;		/* protocol address length (must be 4) */
  u_short operation;	/* ARP opcode */
  u_char  sHaddr[ETH_ALEN];	/* sender's hardware address */
  u_char  sInaddr[4];	/* sender's IP address */
  u_char  tHaddr[ETH_ALEN];	/* target's hardware address */
  u_char  tInaddr[4];	/* target's IP address */
  u_char  pad[18];	/* pad for min. Ethernet payload (60 bytes) */
} __attribute__((packed)) arpMessage;

#define BasicArpLen(A) (sizeof(A) - (sizeof(A.ethhdr) + sizeof(A.pad)))

extern	char		*IfName;
extern	int		IfName_len;
extern	int		DebugFlag;
extern	int		dhcpSocket;
extern	int		TokenRingIf;
extern	dhcpInterface	DhcpIface;
extern	unsigned char	ClientHwAddr[ETH_ALEN];

int eth2tr(struct packed_ether_header *frame, int datalen);
int tr2eth(struct packed_ether_header *frame);

const int inaddr_broadcast = INADDR_BROADCAST;
/*****************************************************************************/
#ifdef ARPCHECK
int arpCheck()
{
  arpMessage ArpMsgSend,ArpMsgRecv;
  struct sockaddr addr;
  int j,i=0,len=0;

  memset(&ArpMsgSend,0,sizeof(arpMessage));
  memcpy(ArpMsgSend.ethhdr.ether_dhost,MAC_BCAST_ADDR,ETH_ALEN);
  memcpy(ArpMsgSend.ethhdr.ether_shost,ClientHwAddr,ETH_ALEN);
  ArpMsgSend.ethhdr.ether_type = htons(ETHERTYPE_ARP);

  ArpMsgSend.htype	= (TokenRingIf) ? htons(ARPHRD_IEEE802_TR) : htons(ARPHRD_ETHER);
  ArpMsgSend.ptype	= htons(ETHERTYPE_IP);
  ArpMsgSend.hlen	= ETH_ALEN;
  ArpMsgSend.plen	= 4;
  ArpMsgSend.operation	= htons(ARPOP_REQUEST);
  memcpy(ArpMsgSend.sHaddr,ClientHwAddr,ETH_ALEN);
  memcpy(&ArpMsgSend.tInaddr,&DhcpIface.ciaddr,4);

  if ( DebugFlag ) syslog(LOG_DEBUG,
    "broadcasting ARPOP_REQUEST for %u.%u.%u.%u\n",
    ArpMsgSend.tInaddr[0],ArpMsgSend.tInaddr[1],
    ArpMsgSend.tInaddr[2],ArpMsgSend.tInaddr[3]);
  do
    {
      do
    	{
      	  if ( i++ > 4 ) return 0; /*  5 probes  */
      	  memset(&addr,0,sizeof(struct sockaddr));
      	  memcpy(addr.sa_data,IfName,IfName_len);
	  if ( TokenRingIf )
	    len = eth2tr(&ArpMsgSend.ethhdr,BasicArpLen(ArpMsgSend));
	  else
	    len = sizeof(arpMessage);
	  if ( sendto(dhcpSocket,&ArpMsgSend,len,0,
		&addr,sizeof(struct sockaddr)) == -1 )
	    {
	      syslog(LOG_ERR,"arpCheck: sendto: %m\n");
	      return -1;
	    }
    	}
      while ( peekfd(dhcpSocket,50000) ); /* 50 msec timeout */
      do
    	{
      	  memset(&ArpMsgRecv,0,sizeof(arpMessage));
      	  j=sizeof(struct sockaddr);
      	  if ( recvfrom(dhcpSocket,&ArpMsgRecv,sizeof(arpMessage),0,
		    (struct sockaddr *)&addr,&j) == -1 )
    	    {
      	      syslog(LOG_ERR,"arpCheck: recvfrom: %m\n");
      	      return -1;
    	    }
	  if ( TokenRingIf )
	    {
	      if ( tr2eth(&ArpMsgRecv.ethhdr) )  continue;
	    }
	  if ( ArpMsgRecv.ethhdr.ether_type != htons(ETHERTYPE_ARP) )
	    continue;
      	  if ( ArpMsgRecv.operation == htons(ARPOP_REPLY) )
	    {
	      if ( DebugFlag ) syslog(LOG_DEBUG,
	      "ARPOP_REPLY received from %u.%u.%u.%u for %u.%u.%u.%u\n",
	      ArpMsgRecv.sInaddr[0],ArpMsgRecv.sInaddr[1],
	      ArpMsgRecv.sInaddr[2],ArpMsgRecv.sInaddr[3],
	      ArpMsgRecv.tInaddr[0],ArpMsgRecv.tInaddr[1],
	      ArpMsgRecv.tInaddr[2],ArpMsgRecv.tInaddr[3]);
	    }
      	  else
	    continue;
      	  if ( memcmp(ArpMsgRecv.tHaddr,ClientHwAddr,ETH_ALEN) )
	    {
	      if ( DebugFlag )
	    	syslog(LOG_DEBUG,
	    	"target hardware address mismatch: %02X.%02X.%02X.%02X.%02X.%02X received, %02X.%02X.%02X.%02X.%02X.%02X expected\n",
	    	ArpMsgRecv.tHaddr[0],ArpMsgRecv.tHaddr[1],ArpMsgRecv.tHaddr[2],
	    	ArpMsgRecv.tHaddr[3],ArpMsgRecv.tHaddr[4],ArpMsgRecv.tHaddr[5],
	    	ClientHwAddr[0],ClientHwAddr[1],
	        ClientHwAddr[2],ClientHwAddr[3],
		ClientHwAddr[4],ClientHwAddr[5]);
	      continue;
	    }
      	  if ( memcmp(&ArpMsgRecv.sInaddr,&DhcpIface.ciaddr,4) )
	    {
	      if ( DebugFlag )
	    	syslog(LOG_DEBUG,
	    	"sender IP address mismatch: %u.%u.%u.%u received, %u.%u.%u.%u expected\n",
	    	ArpMsgRecv.sInaddr[0],ArpMsgRecv.sInaddr[1],ArpMsgRecv.sInaddr[2],ArpMsgRecv.sInaddr[3],
	    	((unsigned char *)&DhcpIface.ciaddr)[0],
	    	((unsigned char *)&DhcpIface.ciaddr)[1],
	    	((unsigned char *)&DhcpIface.ciaddr)[2],
	    	((unsigned char *)&DhcpIface.ciaddr)[3]);
	      continue;
	    }
      	  return 1;
    	}
      while ( peekfd(dhcpSocket,50000) == 0 );
    }
  while ( 1 );
  return 0;
}
#endif
/*****************************************************************************/
int arpRelease()  /* sends UNARP message, cf. RFC1868 */
{
  arpMessage ArpMsgSend;
  struct sockaddr addr;
  int len;

/* build Ethernet header */
  memset(&ArpMsgSend,0,sizeof(arpMessage));
  memcpy(ArpMsgSend.ethhdr.ether_dhost,MAC_BCAST_ADDR,ETH_ALEN);
  memcpy(ArpMsgSend.ethhdr.ether_shost,ClientHwAddr,ETH_ALEN);
  ArpMsgSend.ethhdr.ether_type = htons(ETHERTYPE_ARP);

/* build UNARP message */
  ArpMsgSend.htype	= (TokenRingIf) ? htons(ARPHRD_IEEE802_TR) : htons(ARPHRD_ETHER);
  ArpMsgSend.ptype	= htons(ETHERTYPE_IP);
  ArpMsgSend.plen	= 4;
  ArpMsgSend.operation	= htons(ARPOP_REPLY);
  memcpy(&ArpMsgSend.sInaddr,&DhcpIface.ciaddr,4);
  memcpy(&ArpMsgSend.tInaddr,&inaddr_broadcast,4);
 
  memset(&addr,0,sizeof(struct sockaddr));
  memcpy(addr.sa_data,IfName,IfName_len);
  if ( TokenRingIf )
    len = eth2tr(&ArpMsgSend.ethhdr,BasicArpLen(ArpMsgSend));
  else
    len = sizeof(arpMessage);
  if ( sendto(dhcpSocket,&ArpMsgSend,len,0,
	      &addr,sizeof(struct sockaddr)) == -1 )
    {
      syslog(LOG_ERR,"arpRelease: sendto: %m\n");
      return -1;
    }
  return 0;
}
/*****************************************************************************/
int arpInform()
{
  arpMessage ArpMsgSend;
  struct sockaddr addr;
  int len;

  memset(&ArpMsgSend,0,sizeof(arpMessage));
  memcpy(ArpMsgSend.ethhdr.ether_dhost,MAC_BCAST_ADDR,ETH_ALEN);
  memcpy(ArpMsgSend.ethhdr.ether_shost,ClientHwAddr,ETH_ALEN);
  ArpMsgSend.ethhdr.ether_type = htons(ETHERTYPE_ARP);

  ArpMsgSend.htype	= (TokenRingIf) ? htons(ARPHRD_IEEE802_TR) : htons(ARPHRD_ETHER);
  ArpMsgSend.ptype	= htons(ETHERTYPE_IP);
  ArpMsgSend.hlen	= ETH_ALEN;
  ArpMsgSend.plen	= 4;
  ArpMsgSend.operation	= htons(ARPOP_REPLY);
  memcpy(ArpMsgSend.sHaddr,ClientHwAddr,ETH_ALEN);
  memcpy(ArpMsgSend.tHaddr,DhcpIface.shaddr,ETH_ALEN);
  memcpy(ArpMsgSend.sInaddr,&DhcpIface.ciaddr,4);
  memcpy(ArpMsgSend.tInaddr,&inaddr_broadcast,4);
 
  memset(&addr,0,sizeof(struct sockaddr));
  memcpy(addr.sa_data,IfName,IfName_len);
  if ( TokenRingIf )
    len = eth2tr(&ArpMsgSend.ethhdr,BasicArpLen(ArpMsgSend));
  else
    len = sizeof(arpMessage);
  if ( sendto(dhcpSocket,&ArpMsgSend,len,0,
	      &addr,sizeof(struct sockaddr)) == -1 )
    {
      syslog(LOG_ERR,"arpInform: sendto: %m\n");
      return -1;
    }
  return 0;
}
