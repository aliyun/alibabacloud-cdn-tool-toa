MODULE_NAME := tcp_toa
$(MODULE_NAME)-objs := toa.o
obj-m += $(MODULE_NAME).o

KVER := $(shell uname -r)
KDIR := /usr/src/kernels/$(KVER)
PWD := $(shell pwd)

MD5_ERR := Y

default: verify
	make -C $(KDIR) M=$(PWD) modules

debug: verify
	make -C $(KDIR) M=$(PWD) EXTRA_CFLAGS="-DTOA_DEBUG_ENABLE" modules

clean:
	rm -f .*.cmd *.o *.ko *.mod.c modules.order Module.symvers
	rm -rf .tmp_versions

verify:
	@md5sum --check checksum.txt --status || { echo -e "\033[0;31mSource file MD5 mismatch. For details, run 'md5sum --check checksum.txt'\033[0m"; [ $(MD5_ERR) != "Y" ]; }
