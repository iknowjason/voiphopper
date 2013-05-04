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

#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include "dhcpclient.h"
#include "udpipgen.h"

extern int avaya_yes;
extern int nortel_yes;
extern int alcatel_yes;
extern	dhcpMessage	*DhcpMsgSend;
extern	dhcpOptions	DhcpOptions;
extern  dhcpInterface   DhcpIface;
extern	char		*HostName;
extern	int		HostName_len;
extern	int		DebugFlag;
extern	int		BeRFC1541;
extern	unsigned	LeaseTime;
extern	int		TokenRingIf;
extern	unsigned char	ClientHwAddr[6];
extern  udpipMessage	UdpIpMsgSend;
extern  int 		magic_cookie;
extern  unsigned short  dhcpMsgSize;
extern  unsigned        nleaseTime;
extern  int             BroadcastResp;
extern  struct in_addr  inform_ipaddr;
extern  char		*set_mac;
extern  int		macy;

/*****************************************************************************/
void buildDhcpDiscover(xid)
unsigned xid;
{

  register unsigned char *p = DhcpMsgSend->options + 4;

  /* build Ethernet header */
  memset(&UdpIpMsgSend,0,sizeof(udpipMessage));
  memcpy(UdpIpMsgSend.ethhdr.ether_dhost,MAC_BCAST_ADDR,ETH_ALEN);
  memcpy(UdpIpMsgSend.ethhdr.ether_shost,ClientHwAddr,ETH_ALEN);
  UdpIpMsgSend.ethhdr.ether_type = htons(ETHERTYPE_IP);

  DhcpMsgSend->op	=	DHCP_BOOTREQUEST;
  DhcpMsgSend->htype	=	(TokenRingIf) ? ARPHRD_IEEE802_TR : ARPHRD_ETHER;
  DhcpMsgSend->hlen	=	ETH_ALEN;
  DhcpMsgSend->xid	=	xid;
  DhcpMsgSend->secs	=       htons(10);
  if ( BroadcastResp )
    DhcpMsgSend->flags	=	htons(BROADCAST_FLAG);
#if 0
  memcpy(DhcpMsgSend->chaddr,DhcpIface.chaddr,ETH_ALEN);
#else
  memcpy(DhcpMsgSend->chaddr,ClientHwAddr,ETH_ALEN);
#endif
  memcpy(DhcpMsgSend->options,&magic_cookie,4);
  *p++ = dhcpMessageType;
  *p++ = 1;
  *p++ = DHCP_DISCOVER;
  if(alcatel_yes != 1) {
    /* If this is true, the Alcatel Option was not specified */
    *p++ = dhcpMaxMsgSize;
    *p++ = 2;
    memcpy(p,&dhcpMsgSize,2);
    p += 2;
    if ( DhcpIface.ciaddr )
      {
        if ( BeRFC1541 )
          DhcpMsgSend->ciaddr = DhcpIface.ciaddr;
        else
          {
            *p++ = dhcpRequestedIPaddr;
            *p++ = 4;
            memcpy(p,&DhcpIface.ciaddr,4);
            p += 4; 
          }
      }
    *p++ = dhcpIPaddrLeaseTime;
    *p++ = 4;
    memcpy(p,&nleaseTime,4);
    p += 4;
    *p++ = dhcpParamRequest;
    int prlength;
    if(avaya_yes == 1) {
  	  prlength = 17;
     } else if(nortel_yes == 1) {
  	  prlength = 16;
     } else {
          prlength = 15;
     }
    *p++ = prlength;
    *p++ = subnetMask;
    *p++ = routersOnSubnet;
    *p++ = dns;
    *p++ = hostName;
    *p++ = domainName;
    *p++ = rootPath;
    *p++ = defaultIPTTL;
    *p++ = broadcastAddr;
    *p++ = performMaskDiscovery;
    *p++ = performRouterDiscovery;
    *p++ = staticRoute;
    *p++ = nisDomainName;
    *p++ = nisServers;
    *p++ = ntpServers;
    if(avaya_yes == 1){
       *p++ = dhcpOption176;
       *p++ = dhcpOption242;
    }
    if(nortel_yes == 1){
       *p++ = dhcpOption191;
    }
    if ( HostName )
    {
      *p++ = hostName;
      *p++ = HostName_len;
      memcpy(p,HostName,HostName_len);
      p += HostName_len;
    }
    *p++ = dhcpClassIdentifier;

    // Had to temporarily remove this because it's causing the request
    // to be generated as Option 28, with a length of 76
    /*
    *p++ = DhcpIface.class_len;
    memcpy(p,DhcpIface.class_id,DhcpIface.class_len);
    p += DhcpIface.class_len;
    memcpy(p,DhcpIface.client_id,DhcpIface.client_len);
    p += DhcpIface.client_len;*/
    *p = endOption;

  } else {
	/* Build special DISCOVER for Alcatel IP Phone */
   	/***********************************************/

	/* DHCP Option 43 */
        *p++ = dhcpOption43;
        *p++ = 5;
        *p++ = 0x3a;
        *p++ = 0x2b;
        *p++ = 0xff;
        *p++ = 0xff;
        *p++ = 0xff;
	/* End of DHCP Option 43 */

        /* Option 55 (Parameter Request List) */
        *p++ = dhcpParamRequest;
        *p++ = 7;
        *p++ = subnetMask;
        *p++ = routersOnSubnet;
        *p++ = broadcastAddr;
        *p++ = ntpServers;
        *p++ = dhcpOption43;
        *p++ = dhcpT1value;
        *p++ = dhcpT2value;
        /* End of Option 55 (Parameter Request List) */

	/* Option 12 (Host Name) */

	/* If MAC Address spoofing is enabled (-m), then change Option 12 Host Name to be 
	   supplied  parameter of MAC, like 00:50:60:03:99:CB */
	if(macy == 1) {
		/* True, so spoof HostName */
		unsigned char *tmpMac1;
		unsigned char tmpMac2[12];
		tmpMac1 = set_mac;
		/* A loop below to remove ':' char */ 
		int i;
		int y = 0;
		for (i = 0; i < 17; i++) {

			if(tmpMac1[i] == ':') {
			} else {
				tmpMac2[y] = tmpMac1[i];
				y++;
			}

		}

		tmpMac2[y] = '\0';
		char testStr[28];
		sprintf(testStr,"ALCATEL-iptouch-%s",tmpMac2);
		HostName = testStr;
	} else {
		/* MAC Spoofing not enabled, so use hard coded value */
        	HostName = "ALCATEL-iptouch-00809fad4242";
	}
        HostName_len = strlen(HostName);
        if ( HostName )
        {
          *p++ = hostName;
          *p++ = HostName_len;
          memcpy(p,HostName,HostName_len);
          p += HostName_len;
        }
	/* End of Option 12 (Host Name) */

	/* Option 60 (Vendor class identifier) */
        DhcpIface.class_len = 13;
        memcpy(DhcpIface.class_id, "alcatel.noe.0", DhcpIface.class_len);
        *p++ = dhcpClassIdentifier;
        *p++ = DhcpIface.class_len;
        memcpy(p,DhcpIface.class_id,DhcpIface.class_len);
        p += DhcpIface.class_len;
	/* End of Option 60 (Vendor class identifier) */

	/* Option 61 (Client identifier) */

        /* If MAC Address spoofing is enabled (-m), then change Option 61 Client identifier to be 
           supplied  parameter of MAC, like 00:50:60:03:99:CB */
        if(macy == 1) {

                /* True, so spoof Client identifier */
                unsigned char *tmpMac1;
                unsigned char tmpMac2[28];
                tmpMac1 = set_mac;

                /* A loop below to remove ':' char */
                int i;
                int y = 0;
                for (i = 0; i < 17; i++) {

                        if(tmpMac1[i] == ':') {
                        } else {
                                        tmpMac2[y] = tmpMac1[i];
                                        y++;
                        }

                }
                /* End of loop to remove ':' char */

                tmpMac2[y] = '\0';

                /* Convert all characters to upper case */
                for (y = 0; y < strlen(tmpMac2); y++) {
                        tmpMac2[y] = toupper(tmpMac2[y]);
                }
                /* End of Convert all characters to upper case */

                /* Function to take two ASCII represented characters and output 1 hex byte representation */
                uint8_t* hex_decode(const char *in, size_t len, uint8_t *out) {

                        unsigned int i, t, hn, ln;

                        for(t = 0, i = 0; i < len; i+=2, ++t) {

                                hn = in[i] > '9' ? in[i] - 'A' + 10 : in[i] - '0';
                                ln = in[i+1] > '9' ? in[i+1] - 'A' + 10 : in[i+1] - '0';

                                out[t] = (hn << 4 ) | ln;
                        }

                        return out;
                }

                /* Take two ASCII represented characters and output 1 hex byte representation */
                uint8_t output[6];
                hex_decode(tmpMac2,strlen(tmpMac2), output);

                /* First byte is 0x01 */
                u_char clientIDbuf[7];
                clientIDbuf[0] = 0x01;

                /* copy to a new array */
                int j, e = 1;
                for(j = 0; j < 6; j++) {
                        clientIDbuf[e] = output[j];
                        e++;
                }

                DhcpIface.client_len = 7;
                memcpy(DhcpIface.client_id, clientIDbuf, DhcpIface.client_len);
                *p++ = dhcpClientIdentifier;
                *p++ = DhcpIface.client_len;
                memcpy(p,DhcpIface.client_id,DhcpIface.client_len);
                p += DhcpIface.client_len;

        } else {
                /* MAC Spoofing not enabled, so use hard coded value */
                DhcpIface.client_len = 7;
                memcpy(DhcpIface.client_id, "\x01\x00\x80\x9f\xad\x42\x42", DhcpIface.client_len);
                *p++ = dhcpClientIdentifier;
                *p++ = DhcpIface.client_len;
                memcpy(p,DhcpIface.client_id,DhcpIface.client_len);
                p += DhcpIface.client_len;
        }
        /* End of Option 61 (Client identifier) */

        *p = endOption;
  }

/* build UDP/IP header */
  udpipgen((udpiphdr *)UdpIpMsgSend.udpipmsg,0,INADDR_BROADCAST,
  htons(DHCP_CLIENT_PORT),htons(DHCP_SERVER_PORT),sizeof(dhcpMessage));
}
/*****************************************************************************/
void buildDhcpRequest(xid)
unsigned xid;
{

  register unsigned char *p = DhcpMsgSend->options + 4;
 
/* build Ethernet header */
  memset(&UdpIpMsgSend,0,sizeof(udpipMessage));
  memcpy(UdpIpMsgSend.ethhdr.ether_dhost,MAC_BCAST_ADDR,ETH_ALEN);
  memcpy(UdpIpMsgSend.ethhdr.ether_shost,ClientHwAddr,ETH_ALEN);
  UdpIpMsgSend.ethhdr.ether_type = htons(ETHERTYPE_IP);

  DhcpMsgSend->op	=	DHCP_BOOTREQUEST;
  DhcpMsgSend->htype	=	(TokenRingIf) ? ARPHRD_IEEE802_TR : ARPHRD_ETHER;
  DhcpMsgSend->hlen	=	ETH_ALEN;
  DhcpMsgSend->xid	=	xid;
  DhcpMsgSend->secs	=	htons(10);
  if ( BroadcastResp )
    DhcpMsgSend->flags	=	htons(BROADCAST_FLAG);
#if 0
  memcpy(DhcpMsgSend->chaddr,DhcpIface.chaddr,ETH_ALEN);
#else
  memcpy(DhcpMsgSend->chaddr,ClientHwAddr,ETH_ALEN);
#endif
  memcpy(DhcpMsgSend->options,&magic_cookie,4);
  *p++ = dhcpMessageType;
  *p++ = 1;
  *p++ = DHCP_REQUEST;
  if(alcatel_yes != 1) {
    /* If this is true, the Alcatel Option was not specified */
    *p++ = dhcpMaxMsgSize;
    *p++ = 2;
    memcpy(p,&dhcpMsgSize,2);
    p += 2;
    *p++ = dhcpServerIdentifier;
    *p++ = 4;
    memcpy(p,DhcpOptions.val[dhcpServerIdentifier],4);
    p += 4;
    if ( BeRFC1541 )
      DhcpMsgSend->ciaddr = DhcpIface.ciaddr;
    else
      {
        *p++ = dhcpRequestedIPaddr;
        *p++ = 4;
        memcpy(p,&DhcpIface.ciaddr,4);
        p += 4;
      }
    if ( DhcpOptions.val[dhcpIPaddrLeaseTime] )
    {
      *p++ = dhcpIPaddrLeaseTime;
      *p++ = 4;
      memcpy(p,DhcpOptions.val[dhcpIPaddrLeaseTime],4);
      p += 4;
    }
    *p++ = dhcpParamRequest;
    int prlength;
    if(avaya_yes == 1) {
        prlength = 17;
     } else if(nortel_yes == 1) {
        prlength = 16;
     } else {
        prlength = 15;
     }
    *p++ = prlength;
    *p++ = subnetMask;
    *p++ = routersOnSubnet;
    *p++ = dns;
    *p++ = hostName;
    *p++ = domainName;
    *p++ = rootPath;
    *p++ = defaultIPTTL;
    *p++ = broadcastAddr;
    *p++ = performMaskDiscovery;
    *p++ = performRouterDiscovery;
    *p++ = staticRoute;
    *p++ = nisDomainName;
    *p++ = nisServers;
    *p++ = ntpServers;
    if(avaya_yes == 1){
  	*p++ = dhcpOption176;
  	*p++ = dhcpOption242;
    }
    if(nortel_yes == 1){
	*p++ = dhcpOption191;
    }
    if ( HostName )
    {
      *p++ = hostName;
      *p++ = HostName_len;
      memcpy(p,HostName,HostName_len);
      p += HostName_len;
    }
    *p++ = dhcpClassIdentifier;

  /*
  *p++ = DhcpIface.class_len;
  memcpy(p,DhcpIface.class_id,DhcpIface.class_len);
  p += DhcpIface.class_len;
  memcpy(p,DhcpIface.client_id,DhcpIface.client_len);
  p += DhcpIface.client_len;*/
    *p = endOption;
  } else {

        /* Build special REQUEST for Alcatel IP Phone */
        /***********************************************/
        
        /* Option 50 (Requested IP Address) */
        if ( BeRFC1541 )
          DhcpMsgSend->ciaddr = DhcpIface.ciaddr;
        else
        {
          *p++ = dhcpRequestedIPaddr;
          *p++ = 4;
          memcpy(p,&DhcpIface.ciaddr,4);
          p += 4;
        }
        /* End of Option 50 (Requested IP Address) */

        /* Option 54 (DHCP Server Identifier) */
        *p++ = dhcpServerIdentifier;
        *p++ = 4;
        memcpy(p,DhcpOptions.val[dhcpServerIdentifier],4);
        p += 4;
        /* End of Option 54 (DHCP Server Identifier) */

        /* DHCP Option 43 */
        *p++ = dhcpOption43;
        *p++ = 5;
        *p++ = 0x3a;
        *p++ = 0x2b;
        *p++ = 0xff;
        *p++ = 0xff;
        *p++ = 0xff;
        /* End of DHCP Option 43 */

        /* Option 55 (Parameter Request List) */
        *p++ = dhcpParamRequest;
        *p++ = 7;
        *p++ = subnetMask;
        *p++ = routersOnSubnet;
        *p++ = broadcastAddr;
        *p++ = ntpServers;
        *p++ = dhcpOption43;
        *p++ = dhcpT1value;
        *p++ = dhcpT2value;
        /* End of Option 55 (Parameter Request List) */

        /* Option 12 (Host Name) */

        /* If MAC Address spoofing is enabled (-m), then change Option 12 Host Name to be 
           supplied  parameter of MAC, like 00:50:60:03:99:CB */
        if(macy == 1) {
                /* True, so spoof HostName */
                unsigned char *tmpMac1;
                unsigned char tmpMac2[12];
                tmpMac1 = set_mac;
                /* A loop below to remove ':' char */
                int i;
                int y = 0;
                for (i = 0; i < 17; i++) {

                        if(tmpMac1[i] == ':') {
                        } else {
                                tmpMac2[y] = tmpMac1[i];
                                y++;
                        }

                }

                tmpMac2[y] = '\0';
                char testStr[28];
                sprintf(testStr,"ALCATEL-iptouch-%s",tmpMac2);
                HostName = testStr;
        } else {
                /* MAC Spoofing not enabled, so use hard coded value */
                HostName = "ALCATEL-iptouch-00809fad4242";
        }
        /* End of Option 12 (Host Name) */

        /* Option 60 (Vendor class identifier) */
        DhcpIface.class_len = 13;
        memcpy(DhcpIface.class_id, "alcatel.noe.0", DhcpIface.class_len);
        *p++ = dhcpClassIdentifier;
        *p++ = DhcpIface.class_len;
        memcpy(p,DhcpIface.class_id,DhcpIface.class_len);
        p += DhcpIface.class_len;
        /* End of Option 60 (Vendor class identifier) */

        /* Option 61 (Client identifier) */

        if(macy == 1) {

                /* True, so spoof Client identifier */
                unsigned char *tmpMac1;
                unsigned char tmpMac2[28];
                tmpMac1 = set_mac;

                /* A loop below to remove ':' char */
                int i;
                int y = 0;
                for (i = 0; i < 17; i++) {

                        if(tmpMac1[i] == ':') {
                        } else {
                                        tmpMac2[y] = tmpMac1[i];
                                        y++;
                        }

                }
                /* End of loop to remove ':' char */

                tmpMac2[y] = '\0';

		/* Convert all characters to upper case */
                for (y = 0; y < strlen(tmpMac2); y++) {
                        tmpMac2[y] = toupper(tmpMac2[y]);
                }
		/* End of Convert all characters to upper case */

		/* Function to take two ASCII represented characters and output 1 hex byte representation */
                uint8_t* hex_decode(const char *in, size_t len, uint8_t *out) {

                        unsigned int i, t, hn, ln;

                        for(t = 0, i = 0; i < len; i+=2, ++t) {

                                hn = in[i] > '9' ? in[i] - 'A' + 10 : in[i] - '0';
                                ln = in[i+1] > '9' ? in[i+1] - 'A' + 10 : in[i+1] - '0';

                                out[t] = (hn << 4 ) | ln;
                        }

                        return out;
                }

		/* Take two ASCII represented characters and output 1 hex byte representation */
                uint8_t output[6];
                hex_decode(tmpMac2,strlen(tmpMac2), output);

		/* First byte is 0x01 */
                u_char clientIDbuf[7];
                clientIDbuf[0] = 0x01;

		/* copy to a new array */
                int j, e = 1;
                for(j = 0; j < 6; j++) {
                        clientIDbuf[e] = output[j];
                        e++;
                }

                DhcpIface.client_len = 7;
                memcpy(DhcpIface.client_id, clientIDbuf, DhcpIface.client_len);
                *p++ = dhcpClientIdentifier;
                *p++ = DhcpIface.client_len;
                memcpy(p,DhcpIface.client_id,DhcpIface.client_len);
                p += DhcpIface.client_len;

        } else {
                /* MAC Spoofing not enabled, so use hard coded value */
                DhcpIface.client_len = 7;
                memcpy(DhcpIface.client_id, "\x01\x00\x80\x9f\xad\x42\x42", DhcpIface.client_len);
                *p++ = dhcpClientIdentifier;
                *p++ = DhcpIface.client_len;
                memcpy(p,DhcpIface.client_id,DhcpIface.client_len);
                p += DhcpIface.client_len;
        }
        /* End of Option 61 (Client identifier) */

        *p = endOption;
  }

 /* build UDP/IP header */
  udpipgen((udpiphdr *)UdpIpMsgSend.udpipmsg,0,INADDR_BROADCAST,
  htons(DHCP_CLIENT_PORT),htons(DHCP_SERVER_PORT),sizeof(dhcpMessage));
}
/*****************************************************************************/
void buildDhcpRenew(xid)
unsigned xid;
{
  //printf("Inside of buildDhcpRenew\n");
  register unsigned char *p = DhcpMsgSend->options + 4;
  memset(&UdpIpMsgSend,0,sizeof(udpipMessage));
  memcpy(UdpIpMsgSend.ethhdr.ether_dhost,DhcpIface.shaddr,ETH_ALEN);
  memcpy(UdpIpMsgSend.ethhdr.ether_shost,ClientHwAddr,ETH_ALEN);
  UdpIpMsgSend.ethhdr.ether_type = htons(ETHERTYPE_IP);

  DhcpMsgSend->op	=	DHCP_BOOTREQUEST;
  DhcpMsgSend->htype	=	(TokenRingIf) ? ARPHRD_IEEE802_TR : ARPHRD_ETHER;
  DhcpMsgSend->hlen	=	ETH_ALEN;
  DhcpMsgSend->xid	=	xid;
  DhcpMsgSend->secs	=	htons(10);
  if ( BroadcastResp )
    DhcpMsgSend->flags	=	htons(BROADCAST_FLAG);
  DhcpMsgSend->ciaddr   =       DhcpIface.ciaddr;
#if 0
  memcpy(DhcpMsgSend->chaddr,DhcpIface.chaddr,ETH_ALEN);
#else
  memcpy(DhcpMsgSend->chaddr,ClientHwAddr,ETH_ALEN);
#endif
  memcpy(DhcpMsgSend->options,&magic_cookie,4);
  *p++ = dhcpMessageType;
  *p++ = 1;
  *p++ = DHCP_REQUEST;
  *p++ = dhcpMaxMsgSize;
  *p++ = 2;
  memcpy(p,&dhcpMsgSize,2);
  p += 2;
#if 0
  if ( DhcpOptions.val[dhcpIPaddrLeaseTime] )
    {
      *p++ = dhcpIPaddrLeaseTime;
      *p++ = 4;
      memcpy(p,DhcpOptions.val[dhcpIPaddrLeaseTime],4);
      p += 4;
    }
#endif
  *p++ = dhcpParamRequest;
  int prlength;
  if(avaya_yes == 1) {
        prlength = 17;
   } else if(nortel_yes == 1) {
        prlength = 16;
   } else {
        prlength = 15;
   }
  *p++ = prlength;
  *p++ = subnetMask;
  *p++ = routersOnSubnet;
  *p++ = dns;
  *p++ = hostName;
  *p++ = domainName;
  *p++ = rootPath;
  *p++ = defaultIPTTL;
  *p++ = broadcastAddr;
  *p++ = performMaskDiscovery;
  *p++ = performRouterDiscovery;
  *p++ = staticRoute;
  *p++ = nisDomainName;
  *p++ = nisServers;
  *p++ = ntpServers;
  if(avaya_yes == 1){
  	*p++ = dhcpOption176;
  	*p++ = dhcpOption242;
  }
  if(nortel_yes == 1){
  	*p++ = dhcpOption191;
  } 
  if ( HostName )
    {
      *p++ = hostName;
      *p++ = HostName_len;
      memcpy(p,HostName,HostName_len);
      p += HostName_len;
    }
  *p++ = dhcpClassIdentifier;

  // Had to temporarily remove this because it's causing the request
  // to be generated as Option 28, with a length of 76
  /**p++ = DhcpIface.class_len;
  memcpy(p,DhcpIface.class_id,DhcpIface.class_len);
  p += DhcpIface.class_len;
  memcpy(p,DhcpIface.client_id,DhcpIface.client_len);
  p += DhcpIface.client_len;
  */
  *p = endOption;

  udpipgen((udpiphdr *)UdpIpMsgSend.udpipmsg,
  DhcpIface.ciaddr,DhcpIface.siaddr,
  htons(DHCP_CLIENT_PORT),htons(DHCP_SERVER_PORT),sizeof(dhcpMessage));
}
/*****************************************************************************/
void buildDhcpRebind(xid)
unsigned xid;
{
  register unsigned char *p = DhcpMsgSend->options + 4;
  memset(&UdpIpMsgSend,0,sizeof(udpipMessage));
  memcpy(UdpIpMsgSend.ethhdr.ether_dhost,MAC_BCAST_ADDR,ETH_ALEN);
  memcpy(UdpIpMsgSend.ethhdr.ether_shost,ClientHwAddr,ETH_ALEN);
  UdpIpMsgSend.ethhdr.ether_type = htons(ETHERTYPE_IP);

  DhcpMsgSend->op	=	DHCP_BOOTREQUEST;
  DhcpMsgSend->htype	=	(TokenRingIf) ? ARPHRD_IEEE802_TR : ARPHRD_ETHER;
  DhcpMsgSend->hlen	=	ETH_ALEN;
  DhcpMsgSend->xid	=	xid;
  DhcpMsgSend->secs	=	htons(10);
  if ( BroadcastResp )
    DhcpMsgSend->flags	=	htons(BROADCAST_FLAG);
  DhcpMsgSend->ciaddr   =       DhcpIface.ciaddr;
#if 0
  memcpy(DhcpMsgSend->chaddr,DhcpIface.chaddr,ETH_ALEN);
#else
  memcpy(DhcpMsgSend->chaddr,ClientHwAddr,ETH_ALEN);
#endif
  memcpy(DhcpMsgSend->options,&magic_cookie,4);
  *p++ = dhcpMessageType;
  *p++ = 1;
  *p++ = DHCP_REQUEST;
  *p++ = dhcpMaxMsgSize;
  *p++ = 2;
  memcpy(p,&dhcpMsgSize,2);
  p += 2;
  if ( DhcpOptions.val[dhcpIPaddrLeaseTime] )
    {
      *p++ = dhcpIPaddrLeaseTime;
      *p++ = 4;
      memcpy(p,DhcpOptions.val[dhcpIPaddrLeaseTime],4);
      p += 4;
    }
  *p++ = dhcpParamRequest;
  int prlength;
  if(avaya_yes == 1) {
        prlength = 17;
   } else if(nortel_yes == 1) {
        prlength = 16;
   } else {
        prlength = 15;
   }
  *p++ = prlength;
  *p++ = subnetMask;
  *p++ = routersOnSubnet;
  *p++ = dns;
  *p++ = hostName;
  *p++ = domainName;
  *p++ = rootPath;
  *p++ = defaultIPTTL;
  *p++ = broadcastAddr;
  *p++ = performMaskDiscovery;
  *p++ = performRouterDiscovery;
  *p++ = staticRoute;
  *p++ = nisDomainName;
  *p++ = nisServers;
  *p++ = ntpServers;
  if(avaya_yes == 1){
  	*p++ = dhcpOption176;
  	*p++ = dhcpOption242;
  }
  if(nortel_yes == 1){
  	*p++ = dhcpOption191;
  }
  if ( HostName )
    {
      *p++ = hostName;
      *p++ = HostName_len;
      memcpy(p,HostName,HostName_len);
      p += HostName_len;
    }
  *p++ = dhcpClassIdentifier;

  // Had to temporarily remove this because it's causing the request
  // to be generated as Option 28, with a length of 76
  /**p++ = DhcpIface.class_len;
  memcpy(p,DhcpIface.class_id,DhcpIface.class_len);
  p += DhcpIface.class_len;
  memcpy(p,DhcpIface.client_id,DhcpIface.client_len);
  p += DhcpIface.client_len;*/
  *p = endOption;

  udpipgen((udpiphdr *)UdpIpMsgSend.udpipmsg,
  DhcpIface.ciaddr,INADDR_BROADCAST,
  htons(DHCP_CLIENT_PORT),htons(DHCP_SERVER_PORT),sizeof(dhcpMessage));
}
/*****************************************************************************/
void buildDhcpReboot(xid)
unsigned xid;
{
  register unsigned char *p = DhcpMsgSend->options + 4;

  //printf("Inside of buildDhcpReboot\n");
 
/* build Ethernet header */
  memset(&UdpIpMsgSend,0,sizeof(udpipMessage));
  memcpy(UdpIpMsgSend.ethhdr.ether_dhost,MAC_BCAST_ADDR,ETH_ALEN);
  memcpy(UdpIpMsgSend.ethhdr.ether_shost,ClientHwAddr,ETH_ALEN);
  UdpIpMsgSend.ethhdr.ether_type = htons(ETHERTYPE_IP);

  DhcpMsgSend->op	=	DHCP_BOOTREQUEST;
  DhcpMsgSend->htype	=	(TokenRingIf) ? ARPHRD_IEEE802_TR : ARPHRD_ETHER;
  DhcpMsgSend->hlen	=	ETH_ALEN;
  DhcpMsgSend->xid	=	xid;
  DhcpMsgSend->secs	=	htons(10);
  if ( BroadcastResp )
    DhcpMsgSend->flags	=	htons(BROADCAST_FLAG);
#if 0
  memcpy(DhcpMsgSend->chaddr,DhcpIface.chaddr,ETH_ALEN);
#else
  memcpy(DhcpMsgSend->chaddr,ClientHwAddr,ETH_ALEN);
#endif
  memcpy(DhcpMsgSend->options,&magic_cookie,4);

  *p++ = dhcpMessageType;
  *p++ = 1;
  *p++ = DHCP_REQUEST;
  *p++ = dhcpMaxMsgSize;
  *p++ = 2;
  memcpy(p,&dhcpMsgSize,2);
  p += 2;
  if ( BeRFC1541 )
    DhcpMsgSend->ciaddr = DhcpIface.ciaddr;
  else
    {
      *p++ = dhcpRequestedIPaddr;
      *p++ = 4;
      memcpy(p,&DhcpIface.ciaddr,4);
      p += 4;
    }
  *p++ = dhcpIPaddrLeaseTime;
  *p++ = 4;
  memcpy(p,&nleaseTime,4);
  p += 4;
  *p++ = dhcpParamRequest;
  int prlength;
  if(avaya_yes == 1) {
        prlength = 17;
   } else if(nortel_yes == 1) {
        prlength = 16;
   } else {
        prlength = 15;
   }
  *p++ = prlength;
  *p++ = subnetMask;
  *p++ = routersOnSubnet;
  *p++ = dns;
  *p++ = hostName;
  *p++ = domainName;
  *p++ = rootPath;
  *p++ = defaultIPTTL;
  *p++ = broadcastAddr;
  *p++ = performMaskDiscovery;
  *p++ = performRouterDiscovery;
  *p++ = staticRoute;
  *p++ = nisDomainName;
  *p++ = nisServers;
  *p++ = ntpServers;
  if(avaya_yes == 1){
  	*p++ = dhcpOption176;
  	*p++ = dhcpOption242;
  }
  if(nortel_yes == 1){
  	*p++ = dhcpOption191;
  }
  if ( HostName )
    {
      *p++ = hostName;
      *p++ = HostName_len;
      memcpy(p,HostName,HostName_len);
      p += HostName_len;
    }
  *p++ = dhcpClassIdentifier;

  // Had to temporarily remove this because it's causing the request
  // to be generated as Option 28, with a length of 76
  /**p++ = DhcpIface.class_len;
  printf("class_len value:  %d\n",DhcpIface.class_len);
  memcpy(p,DhcpIface.class_id,DhcpIface.class_len);
  p += DhcpIface.class_len;
  memcpy(p,DhcpIface.client_id,DhcpIface.client_len);
  p += DhcpIface.client_len;*/
  *p = endOption;

  udpipgen((udpiphdr *)UdpIpMsgSend.udpipmsg,0,INADDR_BROADCAST,
  htons(DHCP_CLIENT_PORT),htons(DHCP_SERVER_PORT),sizeof(dhcpMessage));
  
  printf("End of build message\n");
}


void buildDhcpRelease(xid)
unsigned xid;
{
  register unsigned char *p = DhcpMsgSend->options + 4;
  memset(&UdpIpMsgSend,0,sizeof(udpipMessage));
  memcpy(UdpIpMsgSend.ethhdr.ether_dhost,DhcpIface.shaddr,ETH_ALEN);
  memcpy(UdpIpMsgSend.ethhdr.ether_shost,ClientHwAddr,ETH_ALEN);
  UdpIpMsgSend.ethhdr.ether_type = htons(ETHERTYPE_IP);

  DhcpMsgSend->op	=	DHCP_BOOTREQUEST;
  DhcpMsgSend->htype	=	(TokenRingIf) ? ARPHRD_IEEE802_TR : ARPHRD_ETHER;
  DhcpMsgSend->hlen	=	ETH_ALEN;
  DhcpMsgSend->xid	=	xid;
  DhcpMsgSend->ciaddr	=	DhcpIface.ciaddr;
#if 0
  memcpy(DhcpMsgSend->chaddr,DhcpIface.chaddr,ETH_ALEN);
#else
  memcpy(DhcpMsgSend->chaddr,ClientHwAddr,ETH_ALEN);
#endif
  memcpy(DhcpMsgSend->options,&magic_cookie,4);
  *p++ = dhcpMessageType;
  *p++ = 1;
  *p++ = DHCP_RELEASE;
  *p++ = dhcpServerIdentifier;
  *p++ = 4;
  memcpy(p,DhcpOptions.val[dhcpServerIdentifier],4);
  p += 4;
  memcpy(p,DhcpIface.client_id,DhcpIface.client_len);
  p += DhcpIface.client_len;
  *p = endOption;

  udpipgen((udpiphdr *)UdpIpMsgSend.udpipmsg,DhcpIface.ciaddr,
  DhcpIface.siaddr,htons(DHCP_CLIENT_PORT),htons(DHCP_SERVER_PORT),
  sizeof(dhcpMessage));
}
/*****************************************************************************/
#ifdef ARPCHECK
void buildDhcpDecline(xid)
unsigned xid;
{
  register unsigned char *p = DhcpMsgSend->options + 4;
  memset(&UdpIpMsgSend,0,sizeof(udpipMessage));
  memcpy(UdpIpMsgSend.ethhdr.ether_dhost,DhcpIface.shaddr,ETH_ALEN);
  memcpy(UdpIpMsgSend.ethhdr.ether_shost,ClientHwAddr,ETH_ALEN);
  UdpIpMsgSend.ethhdr.ether_type = htons(ETHERTYPE_IP);

  DhcpMsgSend->op	=	DHCP_BOOTREQUEST;
  DhcpMsgSend->htype	=	(TokenRingIf) ? ARPHRD_IEEE802_TR : ARPHRD_ETHER;
  DhcpMsgSend->hlen	=	ETH_ALEN;
  DhcpMsgSend->xid	=	xid;
#if 0
  memcpy(DhcpMsgSend->chaddr,DhcpIface.chaddr,ETH_ALEN);
#else
  memcpy(DhcpMsgSend->chaddr,ClientHwAddr,ETH_ALEN);
#endif
  memcpy(DhcpMsgSend->options,&magic_cookie,4);
  *p++ = dhcpMessageType;
  *p++ = 1;
  *p++ = DHCP_DECLINE;
  *p++ = dhcpServerIdentifier;
  *p++ = 4;
  memcpy(p,DhcpOptions.val[dhcpServerIdentifier],4);
  p += 4;
  if ( BeRFC1541 )
    DhcpMsgSend->ciaddr = DhcpIface.ciaddr;
  else
    {
      *p++ = dhcpRequestedIPaddr;
      *p++ = 4;
      memcpy(p,&DhcpIface.ciaddr,4);
      p += 4;
    }
  memcpy(p,DhcpIface.client_id,DhcpIface.client_len);
  p += DhcpIface.client_len;
  *p = endOption;

  udpipgen((udpiphdr *)UdpIpMsgSend.udpipmsg,0,
  DhcpIface.siaddr,htons(DHCP_CLIENT_PORT),htons(DHCP_SERVER_PORT),
  sizeof(dhcpMessage));
}
#endif
/*****************************************************************************/
void buildDhcpInform(xid)
unsigned xid;
{
  register unsigned char *p = DhcpMsgSend->options + 4;

  memset(&UdpIpMsgSend,0,sizeof(udpipMessage));
  memcpy(UdpIpMsgSend.ethhdr.ether_dhost,MAC_BCAST_ADDR,ETH_ALEN);
  memcpy(UdpIpMsgSend.ethhdr.ether_shost,ClientHwAddr,ETH_ALEN);
  UdpIpMsgSend.ethhdr.ether_type = htons(ETHERTYPE_IP);

  DhcpMsgSend->op	=	DHCP_BOOTREQUEST;
  DhcpMsgSend->htype	=	(TokenRingIf) ? ARPHRD_IEEE802_TR : ARPHRD_ETHER;
  DhcpMsgSend->hlen	=	ETH_ALEN;
  DhcpMsgSend->xid	=	xid;
  DhcpMsgSend->secs	=       htons(10);
  if ( BroadcastResp )
    DhcpMsgSend->flags	=	htons(BROADCAST_FLAG);
#if 0
  memcpy(DhcpMsgSend->chaddr,DhcpIface.chaddr,ETH_ALEN);
#else
  memcpy(DhcpMsgSend->chaddr,ClientHwAddr,ETH_ALEN);
#endif
  DhcpMsgSend->ciaddr = inform_ipaddr.s_addr;
  memcpy(DhcpMsgSend->options,&magic_cookie,4);
  *p++ = dhcpMessageType;
  *p++ = 1;
  *p++ = DHCP_INFORM;
  *p++ = dhcpMaxMsgSize;
  *p++ = 2;
  memcpy(p,&dhcpMsgSize,2);
  p += 2;
  *p++ = dhcpParamRequest;
  int prlength;
  if(avaya_yes == 1) {
        prlength = 17;
   } else if(nortel_yes == 1) {
        prlength = 16;
   } else {
        prlength = 15;
   }
  *p++ = prlength;
  *p++ = subnetMask;
  *p++ = routersOnSubnet;
  *p++ = dns;
  *p++ = hostName;
  *p++ = domainName;
  *p++ = rootPath;
  *p++ = defaultIPTTL;
  *p++ = broadcastAddr;
  *p++ = performMaskDiscovery;
  *p++ = performRouterDiscovery;
  *p++ = staticRoute;
  *p++ = nisDomainName;
  *p++ = nisServers;
  *p++ = ntpServers;
  if(avaya_yes == 1){
  	*p++ = dhcpOption176;
  	*p++ = dhcpOption242;
  }
  if(nortel_yes == 1){
  	*p++ = dhcpOption191;
  }
  if ( HostName )
    {
      *p++ = hostName;
      *p++ = HostName_len;
      memcpy(p,HostName,HostName_len);
      p += HostName_len;
    }
  *p++ = dhcpClassIdentifier;

  // Had to temporarily remove this because it's causing the request
  // to be generated as Option 28, with a length of 76
  /*
  *p++ = DhcpIface.class_len;
  memcpy(p,DhcpIface.class_id,DhcpIface.class_len);
  p += DhcpIface.class_len;
  memcpy(p,DhcpIface.client_id,DhcpIface.client_len);
  p += DhcpIface.client_len;*/
  *p = endOption;

  udpipgen((udpiphdr *)UdpIpMsgSend.udpipmsg,0,INADDR_BROADCAST,
  htons(DHCP_CLIENT_PORT),htons(DHCP_SERVER_PORT),sizeof(dhcpMessage));
}
