CC = cc
CFLAGS = -mmacosx-version-min=10.7
LDFLAGS = -macosx_version_min 10.7
AS = as
LD = ld

C_BINS = hello getpid
ASM_BINS = hello_asm

all: $(C_BINS) $(ASM_BINS)

$(C_BINS):
	$(CC) $(CFLAGS) -o $@ $<

$(ASM_BINS):
	$(LD) $(LDFLAGS) -o $@ $<

%.o: %.S
	$(AS) -o $@ $<

clean:
	rm -f $(C_BINS) $(ASM_BINS) *.o

hello: hello.c
getpid: getpid.c
hello_asm: hello.o
hello.o: hello.S

