#include <stdio.h> // for puts
#include <stdlib.h> // for EXIT_FAILURE
#include <string.h> // for strlen, strcat

int main(int argc, char const *const *const argv) {
    size_t len = 0;
    for (int i = 1; i < argc; i++) {
        len += strlen(argv[i]);
        len += 1; // for ' ' if not last, '\0' if last
    }

    char *const s = malloc(len);
    if (!s) {
        return EXIT_FAILURE;
    }
    *s = '\0';
    for (int i = 1; i < argc; i++) {
        if (i != 1) {
            strcat(s, " ");
        }
        strcat(s, argv[i]);
    }
    puts(s);
}
