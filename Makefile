KERNEL_SRC:= /home/manviknanda/uiuc/cs423/linux-5.15.165
SUBDIR= $(PWD)
GCC:=gcc
RM:=rm

.PHONY : clean

all: clean modules app

obj-m:= mp2.o

modules:
	$(MAKE) -C $(KERNEL_SRC) M=$(SUBDIR) modules

app: userapp.c userapp.h
	$(GCC) -o userapp userapp.c

clean:
	$(RM) -f userapp *~ *.ko *.o *.mod.c Module.symvers modules.order
