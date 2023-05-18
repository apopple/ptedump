KDIR ?= /lib/modules/`uname -r`/build

default: ptedump_user
	$(MAKE) -C $(KDIR) M=$$PWD

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean

ptedump_user: CFLAGS = -Wall -O3 -DTEST
ptedump_user: ptedump_user.c
