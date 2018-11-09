#ifndef ISA_UTILS_H
#define ISA_UTILS_H

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

#endif /* ISA_UTILS_H */
