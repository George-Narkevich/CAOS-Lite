#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define PROC_FILE "/proc/moex_stocks"
#define BUFFER_SIZE 1024

int main() {
    int fd;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    if ((fd = open(PROC_FILE, O_RDONLY)) < 0) {
        perror("Failed to open proc file");
        return EXIT_FAILURE;
    }

    memset(buffer, 0, BUFFER_SIZE);
    if ((bytes_read = read(fd, buffer, BUFFER_SIZE-1)) < 0) {
        perror("Failed to read data");
        close(fd);
        return EXIT_FAILURE;
    }

    close(fd);

    if (bytes_read == 0) {
        printf("No data available\n");
        return EXIT_SUCCESS;
    }

    printf("=== Moscow Exchange Data ===\n");
    printf("%s\n", buffer);
    
    return EXIT_SUCCESS;
}
