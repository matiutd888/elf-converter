#include <stdio.h>

extern long long buf[];
extern long long size;
extern int check();

int real_main() {
	for (long long i = 0; i < size; i++)
		buf[i] = i;
	if (check() != 0)
		return -1;
	printf("OK\n");
	return 0;
}

