# Copyright (C) CERT Polska - NASK PIB
# Author: Michał Leszczyński <michal.leszczynski@cert.pl>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; under version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS  += -Werror
CFLAGS  += $(CFLAGS_libxenevtchn)
CFLAGS  += $(CFLAGS_libxenctrl)
LDLIBS  += $(LDLIBS_libxenctrl)
LDLIBS  += $(LDLIBS_libxenevtchn)
LDLIBS  += $(LDLIBS_libxenforeignmemory)

.PHONY: all
all: build

.PHONY: build
build: proctrace

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(sbindir)
	$(INSTALL_PROG) proctrace $(DESTDIR)$(sbindir)/proctrace

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(sbindir)/proctrace

.PHONY: clean
clean:
	$(RM) -f proctrace $(DEPS_RM)

.PHONY: distclean
distclean: clean

-include $(DEPS_INCLUDE)
