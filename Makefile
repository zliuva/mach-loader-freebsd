CC = clang
AS = as
CPPFLAGS = -I./include
CFLAGS = -std=c99

.if defined(DEBUG) || make(debug)
CFLAGS += -O0 -g
.else
CFLAGS += -O3 -DNDEBUG
.endif

debug: all
all: loader

loader: loader.c boot.o dyld_stub_binder.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< boot.o dyld_stub_binder.o

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

clean:
	rm -f loader
	rm -f *.o
	rm -f *.core

