#include <stdio.h>
#define MAXDEPTH 4
int r_x86_64(int, int*);

int is_16_aligned(int* ptr) {
	return !(((long) ptr) & 0xf);
}

int r_aarch64(int depth) {
	int test __attribute__((aligned(16)));

	if (depth == MAXDEPTH) {
		return 0;
	} else
		return r_x86_64(depth + 1, &test);
}

int real_main() {
	if(r_aarch64(0) != 0)
		return -1;

	printf("OK\n");
	return 0;
}

