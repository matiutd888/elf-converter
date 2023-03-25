#include <stdio.h>

int main() {
    int x;
    scanf("%d", &x);
    if (x % 2) {
        printf("Liczba jest nieparzysta\n");
    } else {
        printf("Liczba jest parzysta\n");
    }
}
