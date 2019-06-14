obj-m += netlink_module.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules CHECK="cc -E"
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

