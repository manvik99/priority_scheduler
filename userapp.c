#include "userapp.h"
#include <stdio.h>
#include <unistd.h>

#define PROC_FILE "/proc/mp2/status"

int main(int argc, char *argv[]){
    pid_t pid;
    pid = getpid();

    /* Writing to the proc file */
    FILE *proc_file;

    proc_file = fopen(PROC_FILE, "w");
    if (proc_file == NULL) {
        perror("Failed to open proc file");
        printf("There is an error");
        return 1;
    }
    char a[] = "R,1,2,3\n";
    char b[] = "R,4,5,6\n";
    char c[] = "R,7,8,9\n";
    char d[] = "D,4\n";
    fprintf(proc_file, "%s", a);
    fprintf(proc_file, "%s", b);
    fprintf(proc_file, "%s", c);
    fprintf(proc_file, "%s", d);
    fclose(proc_file);

    // Please tweak the iteration counts to make this calculation run long enough
    // volatile long long unsigned int sum = 0;
    // for (int i = 0; i < 100000000; i++) {
    //     volatile long long unsigned int fac = 1;
    //     for (int j = 1; j <= 50; j++) {
    //         fac *= j;
    //     }
    //     sum += fac;
    // }
    return 0;
}

