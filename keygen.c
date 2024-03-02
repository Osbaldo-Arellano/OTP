#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s keylength\n", argv[0]);
        return 1;
    }

    int keylength = atoi(argv[1]);
    if (keylength <= 0) {
        fprintf(stderr, "Error: keylength must be a positive integer\n");
        return 1;
    }

    // Generate random number from 0 to 27
    // Source: https://www.tutorialspoint.com/c_standard_library/c_function_srand.htm
    srand(time(NULL));
    char characters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ ";
    for (int i = 0; i < keylength; i++) {
        int index = rand() % 27;
        putchar(characters[index]);
    }
    putchar('\n');

    return 0;
}
