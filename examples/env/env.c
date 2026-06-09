#include <stdio.h>  // for puts

int main(int, char **, char const *const *envp) {
    while (*envp) {
        puts(*envp);
        envp++;
    }
}
