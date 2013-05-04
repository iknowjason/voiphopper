/*
    voiphopper - VoIP Hopper
    Copyright (C) 2010 Jason Ostrom <jpo@pobox.com>

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

#ifndef __MAC_CHANGER_NETINFO_H__
#define __MAC_CHANGER_NETINFO_H__

#include <net/if.h>
#include "mac.h"


typedef struct {
	   int sock;
	   struct ifreq dev;
} net_info_t;



net_info_t *mc_net_info_new     (const char *device);
void        mc_net_info_free    (net_info_t *);

mac_t      *mc_net_info_get_mac (const net_info_t *);
int         mc_net_info_set_mac (net_info_t *, const mac_t *);


#endif /* __MAC_CHANGER_NETINFO_H__ */
