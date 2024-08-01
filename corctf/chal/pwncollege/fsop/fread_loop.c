#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv){

    char buf[0x1000];
    FILE *file = fopen("/dev/urandom","r");
    for (int i = 0; i < 50000; i++){
        fread(buf, 1, 0x20, file);
    }

    return 0;

}