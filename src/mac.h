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

#ifndef __MAC_CHANGER_MAC_H__
#define __MAC_CHANGER_MAC_H__


typedef struct {
	unsigned char byte[6];
} mac_t;

typedef enum {
	mac_is_anykind,
	mac_is_wireless,
	mac_is_others
} mac_type_t;



int     mc_mac_read_string (mac_t *, char *);
void    mc_mac_into_string (const mac_t *, char *);

int     mc_mac_equal       (const mac_t *, const mac_t *);
mac_t  *mc_mac_dup         (const mac_t *);
void    mc_mac_free        (mac_t *);
void    mc_mac_random      (mac_t *, unsigned char last_n_bytes);
void    mc_mac_next        (mac_t *);

#endif /* __MAC_CHANGER_LISTA_H__ */
