#include <stdio.h>

int main(void) {
	// lazy bind here, dyld_stub_binder will be called
	printf("Hello, World!\n");

	// the second call to printf should not have to jump to dyld_stub_binder
	printf("Hello, World!\n");
}

