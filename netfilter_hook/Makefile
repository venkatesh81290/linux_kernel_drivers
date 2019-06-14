obj-m += my_nf_hook.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules CHECK="cc -E"
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

