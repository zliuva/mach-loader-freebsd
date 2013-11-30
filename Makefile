CC = clang
AS = as
CPPFLAGS = -I./include
CPPFLAGS += -DUSE_BSD_LIBS
CFLAGS = -std=c99
LDFLAGS = -lm -lpthread

.if defined(DEBUG) || make(debug)
CFLAGS += -O0 -g
.else
CFLAGS += -O3 -DNDEBUG
.endif

debug: all
all: loader

loader: loader.c osx_compat.h boot.o dyld_stub_binder.o set_proc_comm.o
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< boot.o dyld_stub_binder.o set_proc_comm.o

set_proc_comm.o: set_proc_comm.s
boot.o: boot.s
	$(AS) -o $@ $<

dyld_stub_binder.o: dyld_stub_binder.S
	$(CC) -c -o $@ $<

run: loader
	./loader test/hello_asm

run_c: loader
	./loader test/hello

run_all: loader
	-@for BIN in test/*; do\
		if [ -x $$BIN ]; then\
			echo "Testing $$BIN...";\
			./loader $$BIN;\
			echo "";\
		fi\
	done

kmod:
	make -f loader.kmod.mk

run_kmod: kmod
	-kldunload ./imgact_mach.ko
	-kldload ./imgact_mach.ko
	-test/hello_asm
	-kldunload ./imgact_mach.ko

clean:
	rm -f loader
	rm -f *.o
	rm -f *.core
	make -f loader.kmod.mk clean

