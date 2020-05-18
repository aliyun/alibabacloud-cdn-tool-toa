MODULE_NAME := tcp_toa
$(MODULE_NAME)-objs := toa.o
obj-m += $(MODULE_NAME).o

KVER := $(shell uname -r)
KDIR := /usr/src/kernels/$(KVER)
PWD := $(shell pwd)

default:
	make -C $(KDIR) M=$(PWD) modules

debug:
	make -C $(KDIR) M=$(PWD) EXTRA_CFLAGS="-DTOA_DEBUG_ENABLE" modules

clean:
	rm -f .*.cmd *.o *.ko *.mod.c modules.order Module.symvers
	rm -rf .tmp_versions
