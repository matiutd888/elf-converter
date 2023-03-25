#include <stdio.h>

int answer = 3;

extern int set_answer();

int real_main() {
	set_answer();
	if (answer != 42)
		return -1;
	printf("OK\n");
	return 0;
}

