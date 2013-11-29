CC = cc
CFLAGS = -mmacosx-version-min=10.8
LDFLAGS = -macosx_version_min 10.7
AS = as
LD = ld

C_BINS = hello getpid args return_val
ASM_BINS = hello_asm

all: $(C_BINS) $(ASM_BINS) test_dylib

$(C_BINS):
	$(CC) $(CFLAGS) -o $@ $<

$(ASM_BINS):
	$(LD) $(LDFLAGS) -o $@ $<

%.o: %.S
	$(AS) -o $@ $<

test_dylib: test_dylib.c libmy.dylib
	$(CC) $(CFLAGS) -lmy -L. -o $@ $<

libmy.dylib: mylib.c
	$(CC) -install_name "@executable_path/$@" -o $@ -dynamiclib mylib.c

clean:
	rm -f $(C_BINS) $(ASM_BINS) *.o

hello: hello.c
getpid: getpid.c
args: args.c
return_val: return_val.c
hello_asm: hello.o
hello.o: hello.S

