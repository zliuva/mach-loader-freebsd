#include <stdio.h>

int main(int argc, char **argv, char **envp, char **apple) {
	for (int i = 0; i < argc; i++) {
		printf("argv[%d]: %s\n", i, argv[i]);
	}

	char **p = envp;
	int i = 0;
	while (*p) {
		printf("envp[%d]: %s\n", i++, *p++);
	}
	
	p = apple;
	i = 0;
	while (*p) {
		printf("apple[%d]: %s\n", i++, *p++);
	}
}

