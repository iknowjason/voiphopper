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

#ifndef BUILDMSG_H
#define BUILDMSG_H

void buildDhcpDiscover(unsigned);
void buildDhcpRequest(unsigned);
void buildDhcpRenew(unsigned);
void buildDhcpRebind(unsigned);
void buildDhcpReboot(unsigned);
void buildDhcpRelease(unsigned);
void buildDhcpDecline(unsigned);
void buildDhcpInform(unsigned);

#endif
