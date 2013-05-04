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

#ifndef DHCPCD_H
#define DHCPCD_H

#ifndef PACKAGE
#define PACKAGE 		"dhcpcd"
#endif
#define PROGRAM_NAME		PACKAGE

#ifndef VERSION
#define VERSION			"1.3.22-pl4"
#endif


#define DEFAULT_IFNAME		"eth0"
#define DEFAULT_IFNAME_LEN	4
#define DEFAULT_TIMEOUT		60
#define DEFAULT_LEASETIME	0xffffffff	/* infinite lease time */

#endif
