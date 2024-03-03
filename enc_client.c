#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define BUF_SIZE 500

int validate(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Could not open file: %s\n", filename);
        return -1;
    }

    int c;
    while ((c = fgetc(file)) != EOF) {
        if ((c < 'A' || c > 'Z') && c != ' ' && c != '\n') {
            fclose(file);
            fprintf(stderr, "Invalid character found: %d\n", c);
            return 0;
        }
    }

    fclose(file);
    return 1;
}

ssize_t readFile(const char *filename, char **buffer) {
    FILE *file = fopen(filename, "r");
    if (!file) return -1;

    // Go to the end of the file and get the length from that
    fseek(file, 0, SEEK_END);
    long length = ftell(file);

    // Go back to the start of the file
    fseek(file, 0, SEEK_SET);

    if (buffer != NULL) {
        *buffer = malloc(length + 1);
        if (!*buffer) {
            fclose(file);
            return -1;
        }

        fread(*buffer, 1, length, file);
        (*buffer)[length] = '\0';
    }

    fclose(file);
    return length;
}

ssize_t sendAll(int sockfd, const char *data, size_t length) {
    size_t total_sent = 0;
    while (total_sent < length) {
        ssize_t sent = send(sockfd, data + total_sent, length - total_sent, 0);
        if (sent == -1){
            return -1;
        } 
        total_sent += sent;
    }
    return total_sent;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s plaintext key port\n", argv[0]);
        exit(1);
    }

    if (validate(argv[1]) != 1 || validate(argv[2]) != 1) {
        exit(1);
    }

    long pt_length = readFile(argv[1], NULL);
    long key_length = readFile(argv[2], NULL);
    if (pt_length > key_length || pt_length == -1 || key_length == -1) {
        fprintf(stderr, "Error: key ‘myshortkey’ is too short\n");
        exit(1);
    }

    char *plaintext, *key;
    readFile(argv[1], &plaintext);
    readFile(argv[2], &key);

    struct addrinfo hints, *servinfo, *p;
    int rv, sockfd;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo("localhost", argv[3], &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        exit(2);
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) continue;
        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            continue;
        }
        break;
    }

    if (p == NULL) {
        fprintf(stderr, "client: failed to connect\n");
        exit(2);
    }

    freeaddrinfo(servinfo);

    // Send validation string to server
    char *valdidationString = "enc_client";
    if (sendAll(sockfd, valdidationString, strlen(valdidationString)) == -1) {
        perror("send magic string");
        close(sockfd);
        exit(2);
    }

    ssize_t plainTextCheck = sendAll(sockfd, plaintext, pt_length);
    ssize_t delimCheck = sendAll(sockfd, "@", 1);
    ssize_t keyTextCheck = sendAll(sockfd, key, pt_length);
    ssize_t delimCheck2 = sendAll(sockfd, "@", 1);

    if (plainTextCheck == -1 || keyTextCheck== -1 || delimCheck == -1 || delimCheck2== -1) {
        perror("send");
        exit(1);
    }

    shutdown(sockfd, SHUT_WR); // Signal the end of communication

    char buf[BUF_SIZE];
    memset(buf, 0, sizeof buf);
    ssize_t numbytes = recv(sockfd, buf, sizeof buf, 0);
    if (numbytes == -1) {
        fprintf(stderr, "Error: could not contact enc_server on port %s\n", argv[3]); 
        exit(2);
    }

    int nread = read(sockfd, buf, BUF_SIZE);   
    if (nread == -1) {
        perror("read");
        exit(EXIT_FAILURE);
    }

    fwrite(buf, 1, numbytes, stdout);

    close(sockfd);
    free(plaintext);
    free(key);

    exit(0);
}