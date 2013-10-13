CC = clang
CPPFLAGS = -I./include
CFLAGS = -std=c99

.if defined(DEBUG) || make(debug)
CFLAGS += -O0 -g
.else
CFLAGS += -O3 -fno-omit-frame-pointer -DNDEBUG
.endif

debug: all
all: loader

loader: loader.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

run: loader
	./loader test/hello_mach

run_c: loader
	./loader test/hello_c_mach

run_all: loader
	@for BIN in test/*; do\
		if [ -x $$BIN ]; then\
			echo "Testing $$BIN...";\
			./loader $$BIN;\
			echo "";\
		fi\
	done

clean:
	rm -f loader
	rm -f *.core

