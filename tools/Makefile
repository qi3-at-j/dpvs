#
# DPVS is a software load balancer (Virtual Server) based on DPDK.
#
# Copyright (C) 2021 iQIYI (www.iqiyi.com).
# All Rights Reserved.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#

#
# Makefile for tools
#
SUBDIRS = dpip ud_sock vty

all:
	for i in $(SUBDIRS); do $(MAKE) -C $$i || exit 1; done

clean:
	for i in $(SUBDIRS); do $(MAKE) -C $$i clean || exit 1; done

install:
	install -m 744 dpip/build/dpip $(INSDIR)/dpip
	install -m 744 ud_sock/build/test_tyflow_ud_sock $(INSDIR)/test_tyflow_ud_sock
	install -m 744 vty/build/vty $(INSDIR)/vty
