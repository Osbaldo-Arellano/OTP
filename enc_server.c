/*
ADAPTED FROM getaddrinfo(3)
SOURCE: https://linux.die.net/man/3/getaddrinfo
*/

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>

#define BUF_SIZE 5000000
#define SECRET "enc_client"

struct addrinfo hints, *result, *rp;
int sfd, s; // Server file descriptor
struct sockaddr_storage peer_addr;
socklen_t peer_addr_len;
int cfd; // Client file descriptor

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

void performOneTimePadEncryption(int cfd, const char* plaintext, const char* key, size_t plaintextLen) {
    if (!plaintext || !key) {
        perror("Plaintext or key is NULL");
        return;
    }

    char *cypherText = malloc(plaintextLen); // Handling binary data, no +1 for null terminator

    if (!cypherText) {
        perror("Failed to allocate memory for cypherText");
        return;
    }

    for (size_t i = 0; i < plaintextLen; i++) {
        int plaintextChar, keyChar;

        // Convert plaintext characters to numerical values
        if (plaintext[i] == ' ') {
            plaintextChar = 26;
        } else {
            plaintextChar = plaintext[i] - 'A';
        }
        // Convert key characters to numerical values
        if (key[i] == ' ') {
            keyChar = 26;
        } else {
            keyChar = key[i] - 'A';
        }

        // Encryption formula
        int cypherVal = (plaintextChar + keyChar) % 27;
        if (cypherVal == 26) {
            cypherText[i] = ' ';
        } else {
            cypherText[i] = 'A' + cypherVal;
        }
    }   

    // Send the cypherText back to the client
    ssize_t sentBytes = send(cfd, cypherText, plaintextLen, 0);
    if (sentBytes == -1) {
        perror("send");
    } else {
        printf("Sent %zd bytes\n", sentBytes);
    }

    free(cypherText);
}

void handler(int cfd) {
    char buf[BUF_SIZE];
    ssize_t nread;

    char *receivedData = malloc(BUF_SIZE);
    if (!receivedData) {
        perror("Failed to allocate memory");
        close(cfd);
        return;
    }

    size_t receivedLen = 0;
    while ((nread = recv(cfd, buf, BUF_SIZE, 0)) > 0) {
        if (receivedLen + nread > BUF_SIZE) {
            fprintf(stderr, "Error: Buffer overflow detected.\n");
            free(receivedData);
            close(cfd);
            return;
        }
        memcpy(receivedData + receivedLen, buf, nread);
        receivedLen += nread;
    }

    if (nread < 0) {
        perror("Failed to receive data");
        free(receivedData);
        close(cfd);
        return;
    }

    if (strncmp(receivedData, SECRET, strlen(SECRET)) != 0) {
        fprintf(stderr, "Secret string mismatch\n");
        free(receivedData);
        close(cfd);
        return;
    }

    char *plaintextStart = receivedData + strlen(SECRET) + 1;
    char *keyStart = strchr(plaintextStart, '@') + 1;
    if (!keyStart) {
        fprintf(stderr, "Malformed message: Key not found\n");
        free(receivedData);
        close(cfd);
        return;
    }

    *strchr(plaintextStart, '@') = '\0'; // Null-terminate the plaintext
    char *end = strchr(keyStart, '@');
    if (!end) {
        fprintf(stderr, "Malformed message: End of key not found\n");
        free(receivedData);
        close(cfd);
        return;
    }
    *end = '\0'; // Null-terminate the key

    // Call the one-time pad encryption function
    size_t plainTextLen = strlen(plaintextStart) - 1;
    performOneTimePadEncryption(cfd, plaintextStart, keyStart, plainTextLen);

    // Clean up and close the client socket
    free(receivedData);
    close(cfd);
}


int main(int argc, char *argv[]) {

    if (argc != 2) {
        fprintf(stderr, "Usage: %s port\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    s = getaddrinfo(NULL, argv[1], &hints, &result);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        exit(EXIT_FAILURE);
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1) continue;

        if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0) break; // Success

        close(sfd);
    }

    if (rp == NULL) {
        fprintf(stderr, "Could not bind\n");
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(result);

    if (listen(sfd, 5) == -1) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    // Ignore SIGCHLD to prevent zombie processes
    signal(SIGCHLD, SIG_IGN);

    for (;;) {
        peer_addr_len = sizeof(struct sockaddr_storage);
        cfd = accept(sfd, (struct sockaddr *)&peer_addr, &peer_addr_len);
        if (cfd == -1) {
            perror("accept");
            continue;
        }

        if (fork() == 0) { // Child process
            handler(cfd);
            exit(0);
        } else { // Parent process
            close(cfd); 
        }
    }
}