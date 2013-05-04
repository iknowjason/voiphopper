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


typedef struct {
        /* Ethernet address of the interface */
        struct ether_addr	eth;
	/* IPv4 address of the interface */
	struct in_addr		ip;
	struct in_addr		bcast;
	/* Maximum transfer unit for this interface */
	unsigned int		mtu;
} packet_ifconfig_t;


extern packet_ifconfig_t	 packet_ifconfig;


void    	*smalloc(size_t size);

/* network init */
int     	init_socket_eth(char *device);
int     	init_socket_IP4(char *device, int broadcast);

/* network sending */
int     	sendpack_IP4(int sfd, u_char *packet,int plength);
int     	sendpack_eth(char *device, int atsock,
			u_char *frame, int frame_length);

/* checksum */
u_int16_t 	chksum(u_char *data, unsigned long count);

/* ping */
int     	icmp_ping(struct in_addr *t,int timeout,int verbose);
void		makenonblock(int s);
int		makebcast(int s);
