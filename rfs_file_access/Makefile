obj-m += rfs_file_access.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules CHECK="cc -E"
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

