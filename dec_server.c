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

#define BUF_SIZE 5000
#define SECRET "dec_client"

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


void handler(int cfd) {
    char buf[BUF_SIZE];
    ssize_t nread, nwritten, to_write;
    
    // Keep buffers to store characters
    char plainText[BUF_SIZE];
    char key[BUF_SIZE];
    char cypherText[BUF_SIZE];
    int plainTextIndex = 0;
    int keyIndex = 0;
    int cypherIndex = 0;

    int isPlainText = 1; // Switches once '@' is encountered
    
    nread = read(cfd, buf, strlen(SECRET));
    if (nread < 0) {
        perror("read secret string");
        close(cfd);
        return;
    }

    // First thing in stream is always the secret string
    if (strcmp(buf, SECRET) != 0) {
        fprintf(stderr, "Connection not validated\n");
        close(cfd);
        return;
    }

    // Handle rest of the incoming data
    while ((nread = read(cfd, buf, BUF_SIZE)) > 0) {
        for (int i = 0; i < nread; i++) {
            if (buf[i] == '@') {
                // Incoming data in stream is now a Key 
                isPlainText = 0;
                continue;
            }

            // Trimming newline char for encoding
            if(buf[i] == '\n'){
                continue;
            }

            // Store the char in the appropriate array
            if (isPlainText) {
                plainText[plainTextIndex++] = buf[i];
            } else {              
                key[keyIndex++] = buf[i];
            }
        }
    }

    // Print the plain text array
    printf("Plain Text: ");
    for (int i = 0; i < plainTextIndex; i++) {
        printf("%c", plainText[i]);
    }
    printf("\n");

    // Print the key array
    printf("Key: ");
    for (int i = 0; i < keyIndex; i++) {
        printf("%c", key[i]);
    }
    printf("\n");

    // Do the encoding one char at a time 
    for(int i = 0; i < plainTextIndex; i++) {
        int plainTextChar;
        // Map 'A'-'Z' to 0-25 and space to 26
        if (plainText[i] == ' ') {
            plainTextChar = 26;
        } else {
            plainTextChar = plainText[i] - 'A';
        }

        int keyChar;
        if (key[i] == ' ') {
            keyChar = 26;
        } else {
            keyChar = key[i] - 'A';
        }

        // (Message + Key) mod 27 
        int cypherVal = (plainTextChar - keyChar) % 27; 

        // Map back to ASCII characters, 26 back to space
        char cypherChar;
        if (cypherVal == 26) {
            cypherChar = ' ';
        } else {
            cypherChar = 'A' + cypherVal;
        }

        printf("plain text char: %c\n", plainText[i]);
        printf("key text char: %c\n", key[i]);
        printf("cypher char: %c\n", cypherChar);

        cypherText[cypherIndex] = cypherChar;
        cypherIndex++;
    }
    cypherText[cypherIndex] = '\0'; // Null-terminate the cypherText string


    // Print the cypher array
    printf("cyphe!r: ");
    for (int i = 0; i < cypherIndex; i++) {
        printf("%c", cypherText[i]);
        if(key[i] == '\n'){
            printf("HERE");
        }
    }
    printf("\n");





        



    int charsRead = send(cfd, 
                    cypherText, cypherIndex, 0); 
    if (charsRead < 0){
      perror("ERROR writing to socket");
    }
    // Close the connection socket for this client
    close(cfd); 
                 

















    if (nread < 0) {
        perror("read");
    }

    close(cfd);  // Close the client connection
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
