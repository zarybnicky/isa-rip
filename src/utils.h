/**
 * ISA18: Tools for monitoring and sniffing RIP messages
 * FIT VUT Brno
 * Author: xzaryb00 - Jakub Zarybnický (xzaryb00)
 *
 * A set of utilities used throughout all three programs
 */

#ifndef ISA_UTILS_H
#define ISA_UTILS_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//Print the usage message and an error message, and exit
#define ERR_USAGE(...)                             \
  do {                                           \
    fprintf(stderr, USAGE, argv[0]);             \
    ERR(__VA_ARGS__);                            \
  } while(0);

//Print an error message, and exit
#define ERR(...) do {                              \
    fprintf(stderr, __VA_ARGS__);                \
    exit(EXIT_FAILURE);                          \
  } while(0);

//If `cond` is true, `perror`, close the socket, and exit
#define SOCK_WRAP(sock, err, cond)               \
  if (cond) {                                    \
    perror(err);                                 \
    close(sock);                                 \
    exit(EXIT_FAILURE);                          \
  }

int parse_number(const char *desc, const char *src, int lower, int upper);
void parse_address_mask(char *optarg, struct in6_addr *addr, u_char *mask);

#endif /* ISA_UTILS_H */
