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
#include "udpipgen.h"

unsigned short ip_id;
/*****************************************************************************/
unsigned short in_cksum(addr,len)
unsigned short *addr;
int len;
{
  register int sum = 0;
  register u_short *w = addr;
  register int nleft = len;
  while ( nleft > 1 )
    {
      sum += *w++;
      nleft -= 2;
    }
  if ( nleft == 1 )
    {
      u_char a = 0;
      memcpy(&a,w,1);
      sum += a;
    }
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ~sum;
}
/*****************************************************************************/
void udpipgen(udpip,saddr,daddr,sport,dport,msglen)
udpiphdr *udpip;
unsigned int saddr,daddr;
unsigned short sport,dport,msglen;
{
  /* Use local copy because udpip->ip is not aligned.  */
  struct ip ip_local;
  struct ip *ip=&ip_local;
  struct ipovly *io=(struct ipovly *)udpip->ip;
  struct udphdr *udp=(struct udphdr *)udpip->udp;

  io->ih_next = io->ih_prev = 0;
  io->ih_x1 = 0;
  io->ih_pr = IPPROTO_UDP;
  io->ih_len = htons(msglen + sizeof(struct udphdr));
  io->ih_src.s_addr = saddr;
  io->ih_dst.s_addr = daddr;
  udp->uh_sport = sport;
  udp->uh_dport = dport;
  udp->uh_ulen = io->ih_len;
  udp->uh_sum = 0;
  udp->uh_sum=in_cksum((unsigned short *)udpip,msglen+sizeof(udpiphdr));
  if ( udp->uh_sum == 0 ) udp->uh_sum = 0xffff;
  memcpy(ip,(struct ip *)udpip->ip,sizeof(ip_local));
  ip->ip_hl = 5;
  ip->ip_v = IPVERSION;
  ip->ip_tos = 0;	/* normal service */
  ip->ip_len = htons(msglen + sizeof(udpiphdr));
  ip->ip_id = htons(ip_id); ip_id++;
  ip->ip_off = 0;
  ip->ip_ttl = IPDEFTTL; /* time to live, 64 by default */
  ip->ip_p = IPPROTO_UDP;
  ip->ip_src.s_addr = saddr;
  ip->ip_dst.s_addr = daddr;
#ifdef __GLIBC__
  ip->ip_sum = 0;
  memcpy(udpip->ip,ip,sizeof(ip_local));
  ip->ip_sum = in_cksum((unsigned short *)&ip_local,sizeof(struct ip));
#else
  ip->ip_csum = 0;
  memcpy(udpip->ip,ip,sizeof(ip_local));
  ip->ip_csum = in_cksum((unsigned short *)&ip_local,sizeof(struct ip));
#endif
  memcpy(udpip->ip,ip,sizeof(ip_local));
}
/*****************************************************************************/
int udpipchk(udpip)
udpiphdr *udpip;
{
  int hl;
  struct ip save_ip;
  struct ip *ip=(struct ip *)udpip->ip;
  struct ipovly *io=(struct ipovly *)udpip->ip;
  struct udphdr *udp=(struct udphdr *)udpip->udp;
  udpiphdr *nudpip = udpip;

  hl = ip->ip_hl<<2;
  if ( in_cksum((unsigned short *)udpip,hl) ) return -1;
  memcpy(&save_ip, udpip->ip, sizeof(struct ip));
  hl -= sizeof(struct ip);
  if ( hl )
    { /* thrash IP options */
      nudpip = (udpiphdr *)((char *)udpip+hl);
      memmove((char *)nudpip,udpip,sizeof(struct ip));
      io=(struct ipovly *)nudpip->ip;
      ip=(struct ip *)nudpip->ip;
      udp=(struct udphdr *)nudpip->udp;
    }
  if ( udp->uh_sum == 0 ) return 0; /* no checksum has been done by sender */
  io->ih_next = io->ih_prev = 0;
  io->ih_x1 = 0;
  io->ih_len = udp->uh_ulen;
  hl = ntohs(udp->uh_ulen)+sizeof(struct ip);
  if ( in_cksum((unsigned short *)nudpip,hl) ) return -2;
  memcpy(udpip->ip, &save_ip, sizeof(struct ip));
  return 0;
}
