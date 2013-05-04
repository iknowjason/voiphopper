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

#ifndef __MAC_CHANGER_LIST_H__
#define __MAC_CHANGER_LIST_H__

#include "mac.h"

typedef struct {
	char  *name;
	unsigned char byte[3];
} card_mac_list_item_t;

#define LIST_LENGHT(l)   ((sizeof(l) / sizeof(card_mac_list_item_t))-1)
#define CARD_NAME(x)     mc_maclist_get_cardname_with_default(x, "unknown")

int    mc_maclist_init  (void);
void   mc_maclist_free  (void);

const char * mc_maclist_get_cardname_with_default (const mac_t *, const char *);
void         mc_maclist_set_random_vendor         (mac_t *, mac_type_t);
int          mc_maclist_is_wireless               (const mac_t *);
void         mc_maclist_print                     (const char *keyword);

#endif /* __MAC_CHANGER_LIST_H__ */
