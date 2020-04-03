obj-m := snapshotko.o
snapshotko-objs := associated_data.o snapshot.o hook.o module.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
