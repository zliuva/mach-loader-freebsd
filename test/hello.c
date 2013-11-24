#include <stdio.h>

int main(int argc, char **argv) {
	// lazy bind here, dyld_stub_binder will be called
	printf("Hello, World!\n");

	// the second call to printf should not have to jump to dyld_stub_binder
	printf("Hello, World!\n");

	if (argc > 1) {
		// if no additional arguments are supplied, _puts should not be bound
		puts(argv[1]);
	}
}

