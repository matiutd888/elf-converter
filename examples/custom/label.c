#include <stdio.h>

int main() {
    if (2 + 2 == 4) {
        goto x;
    } else {
        goto y;
    }
x: 
    printf("x\n");
    goto exit;
y:
    printf("y\n");
exit:
    ;
}
