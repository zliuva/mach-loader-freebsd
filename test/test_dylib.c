#include <stdio.h>

extern int foo(void);

int main(void) {
	printf("%d\n", foo());
}

