obj-m += fsops.o

all:
	make CFLAGS_MODULE=-Wno-error -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
