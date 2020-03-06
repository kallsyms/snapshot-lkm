obj-m := snapshotko.o
snapshotko-objs := associated_data.o snapshot.o hooks.o hook.o module.o

all:
	make -C $(HOME)/src/linux/ M=$(PWD) modules
	#make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C $(HOME)/src/linux/ M=$(PWD) clean
	#make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
