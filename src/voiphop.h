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

int avaya_yes = 0;
int alcatel_yes = 0;
int assessment_mode = 0;
int nortel_yes;
int cdpmode;

struct ethernet_header {
        u_char  ether_dhost[6];
        //u_char  ether_dhost[ETHER_ADDR_LEN];
        //u_char  ether_shost[ETHER_ADDR_LEN];
        u_char  ether_shost[6];
        u_short type_length;
};

struct logical_link_control {
        u_char  dsapigbit[1];
        u_char  ssapcrbit[1];
        u_char  controlfield[1];
        u_char  organizationc[3];
        u_char  pid[2];
};

struct vlan_header {
        u_char  other[2];
        u_short length;
};


int dhcpclientcall(char *);
void create_vlan_interface(char *,int);
void cdp_mode(int,char*);
unsigned int mk_spoof_cdp(char *,char *,char *,char *,char *,char *);
int get_cdp(u_char *, const struct pcap_pkthdr *, const u_char *);
void vlan_hop(int,char*);
